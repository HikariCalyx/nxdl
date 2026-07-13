//! NXL client download logic.
//!
//! Reference:
//!   https://github.com/Kagamia/WzComparer-dev-notes/blob/main/01-GMS-Client-Downloader/GMSClientDownloader.md
//!
//! ## Protocol summary
//!
//! 1. Obtain a `.manifest.hash` URL (requires Nexon authentication; **skipped** —
//!    the caller supplies this URL directly).
//! 2. Fetch that URL → a plain-text SHA-1 hash string.
//! 3. Construct the real manifest URL:
//!    `http://download2.nexon.net/Game/nxl/games/{appid}/{hash}`
//! 4. Download & decompress (zlib / raw deflate) → a JSON manifest.
//! 5. Parse the manifest: file paths are Base64-encoded UTF-16LE with a BOM.
//! 6. For each file, download its object blocks:
//!    `http://download2.nexon.net/Game/nxl/games/{appid}/{appid}/{first2chars}/{sha1}`
//! 7. Decompress each block, validate SHA-1, concatenate into the final file.

use std::collections::HashMap;
use std::io::{IsTerminal, Read};
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use flate2::read::ZlibDecoder;
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use sha1::{Digest, Sha1};

use crate::filter::FileFilter;

// ---------------------------------------------------------------------------
// Concurrency knobs
// ---------------------------------------------------------------------------

/// Number of files downloaded concurrently.
const PARALLEL_FILES: usize = 10;

/// Maximum number of object blocks downloaded concurrently within a single
/// file.
const PARALLEL_OBJECTS: usize = 5;

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

const STALL_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_read(STALL_TIMEOUT)
        .timeout_connect(CONNECT_TIMEOUT)
        .build()
}

/// GET a URL and return the raw response bytes, retrying on transient errors.
fn http_get_bytes(agent: &ureq::Agent, url: &str) -> Result<Vec<u8>> {
    const MAX_RETRIES: usize = 5;
    let mut last_err: Option<anyhow::Error> = None;

    for _ in 0..=MAX_RETRIES {
        match agent.get(url).call() {
            Ok(resp) => {
                let mut reader = resp.into_reader();
                let mut buf = Vec::new();
                match reader.read_to_end(&mut buf) {
                    Ok(_) => return Ok(buf),
                    Err(e) => {
                        last_err = Some(anyhow::Error::from(e).context("failed to read response"));
                    }
                }
            }
            Err(e) => {
                last_err = Some(anyhow::Error::from(e).context("HTTP request failed"));
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow!("no attempts made")))
}

// ---------------------------------------------------------------------------
// Manifest types
// ---------------------------------------------------------------------------

/// Top-level manifest structure as returned by the NXL CDN.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub struct Manifest {
    pub buildtime: Option<f64>,
    pub filepath_encoding: Option<String>,
    pub files: HashMap<String, ManifestFile>,
    pub platform: Option<String>,
    pub product: Option<String>,
    pub total_compressed_size: Option<u64>,
    pub total_objects: Option<u64>,
    pub total_uncompressed_size: Option<u64>,
    pub version: Option<String>,
}

/// A single file entry inside the manifest.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub struct ManifestFile {
    /// Uncompressed file size in bytes.
    pub fsize: u64,
    /// Modification time (Unix timestamp).
    pub mtime: Option<i64>,
    /// SHA-1 hex strings of each object block, or `["__DIR__"]` for directories.
    pub objects: Vec<String>,
    /// Uncompressed size of each object block.
    pub objects_fsize: Vec<u64>,
}

// ---------------------------------------------------------------------------
// Manifest fetching & parsing
// ---------------------------------------------------------------------------

/// Resolve a manifest hash from either a `.manifest.hash` URL or a raw SHA-1
/// hex string.
///
/// If `input` starts with `http://` or `https://` it is treated as a URL to
/// fetch; otherwise it is returned as-is after trimming whitespace.
fn resolve_hash(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        println!("Fetching manifest hash from: {trimmed}");
        let hash = fetch_manifest_hash(trimmed)?;
        println!("Manifest hash: {hash}");
        Ok(hash)
    } else {
        let hash = trimmed.to_owned();
        if hash.len() != 40 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!(
                "invalid manifest hash '{}': must be a 40-character hex string or an http(s) URL",
                hash
            );
        }
        println!("Using manifest hash: {hash}");
        Ok(hash)
    }
}

/// Fetch a `.manifest.hash` URL and return the plain-text SHA-1 hash inside.
fn fetch_manifest_hash(url: &str) -> Result<String> {
    let agent = agent();
    let bytes = http_get_bytes(&agent, url)
        .context("failed to fetch manifest hash")?;
    let hash = String::from_utf8_lossy(&bytes).trim().to_owned();
    if hash.is_empty() {
        bail!("manifest hash is empty");
    }
    Ok(hash)
}

/// Download, decompress, and parse the real manifest for the given `appid`
/// using the `hash` obtained from [`fetch_manifest_hash`].
pub fn fetch_manifest(appid: &str, hash: &str) -> Result<Manifest> {
    let url = format!("http://download2.nexon.net/Game/nxl/games/{appid}/{hash}");
    let agent = agent();

    let compressed = http_get_bytes(&agent, &url)
        .with_context(|| format!("failed to fetch manifest from {url}"))?;

    let json_bytes = decompress_zlib(&compressed)
        .context("failed to decompress manifest")?;

    let manifest: Manifest =
        serde_json::from_slice(&json_bytes).context("failed to parse manifest JSON")?;
    Ok(manifest)
}

// ---------------------------------------------------------------------------
// File-path decoding
// ---------------------------------------------------------------------------

/// Decode a Base64-encoded UTF-16LE file path (with BOM) from the manifest.
///
/// The keys in the `files` object are Base64 strings whose decoded bytes form
/// a UTF-16LE string.  The first character is typically a BOM (`\u{FEFF}`)
/// which is stripped.
pub fn decode_file_path(encoded: &str) -> Result<String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("failed to base64-decode file path")?;

    if bytes.len() % 2 != 0 {
        bail!("decoded path bytes have odd length (not valid UTF-16)");
    }

    // Interpret as UTF-16LE.
    let u16s: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();

    // Strip leading BOM if present.
    let start = if u16s.first() == Some(&0xFEFF) { 1 } else { 0 };

    String::from_utf16(&u16s[start..])
        .context("failed to decode UTF-16 file path")
}

// ---------------------------------------------------------------------------
// Object / block download
// ---------------------------------------------------------------------------

/// Download and decompress a single object block, returning the uncompressed
/// bytes.  The SHA-1 of the result must match `expected_sha1`.
pub fn download_object(agent: &ureq::Agent, appid: &str, object_id: &str) -> Result<Vec<u8>> {
    let first2 = &object_id[..2];
    let url = format!(
        "http://download2.nexon.net/Game/nxl/games/{appid}/{appid}/{first2}/{object_id}"
    );

    let compressed = http_get_bytes(agent, &url)
        .with_context(|| format!("failed to download object {object_id}"))?;

    let data = decompress_zlib(&compressed)
        .with_context(|| format!("failed to decompress object {object_id}"))?;

    // Verify SHA-1.
    let actual = hex::encode(Sha1::digest(&data));
    if !actual.eq_ignore_ascii_case(object_id) {
        bail!(
            "SHA-1 mismatch for object {object_id}: expected {object_id}, got {actual}"
        );
    }

    Ok(data)
}

// ---------------------------------------------------------------------------
// Main download orchestrator
// ---------------------------------------------------------------------------

/// A pre-resolved file entry ready for download.
struct ResolvedFile {
    rel_path: String,
    fsize: u64,
    objects: Vec<String>,
    objects_fsize: Vec<u64>,
}

/// Download a complete NXL client given a `.manifest.hash` URL (or a raw SHA-1
/// hash) and a target directory.
///
/// The `manifest_source` may be either:
/// - An `http(s)://` URL pointing to a `.manifest.hash` file, or
/// - A 40-character hex SHA-1 hash string.
///
/// The `appid` is used to construct CDN URLs (e.g. `10100` for GMS).
///
/// When `filter` is provided, only files whose decoded path matches the filter
/// are downloaded.
pub fn download_client(
    manifest_source: &str,
    appid: &str,
    target_dir: &Path,
    filter: Option<&FileFilter>,
) -> Result<()> {
    // Step 1: resolve the manifest hash (URL or raw hex).
    let hash = resolve_hash(manifest_source)?;

    // Step 2: fetch & parse the manifest.
    println!("Fetching and parsing manifest...");
    let manifest = fetch_manifest(appid, &hash)?;
    let total_files = manifest.files.len();
    let total_size: u64 = manifest.files.values().map(|f| f.fsize).sum();
    println!(
        "Manifest loaded: {total_files} file(s), {:.2} GiB total.",
        total_size as f64 / (1024.0 * 1024.0 * 1024.0)
    );

    // Step 3: resolve file paths, apply filter, separate dirs from files.
    let mut entries: Vec<ResolvedFile> = Vec::with_capacity(manifest.files.len());
    let mut dirs_created: usize = 0;
    let mut filtered_out: usize = 0;
    let mut failed_decode: usize = 0;

    for (encoded_path, file_info) in &manifest.files {
        let rel_path = match decode_file_path(encoded_path) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("warning: skipping unparseable path: {e}");
                failed_decode += 1;
                continue;
            }
        };

        // Apply the optional path filter.
        if let Some(f) = filter {
            if !f.matches(&rel_path) {
                filtered_out += 1;
                continue;
            }
        }

        // Handle directories eagerly (they're cheap).
        if file_info.objects.len() == 1 && file_info.objects[0] == "__DIR__" {
            let dir_path = target_dir.join(&rel_path);
            if let Err(e) = std::fs::create_dir_all(&dir_path) {
                eprintln!("warning: failed to create directory {}: {e}", dir_path.display());
            } else {
                dirs_created += 1;
            }
            continue;
        }

        entries.push(ResolvedFile {
            rel_path,
            fsize: file_info.fsize,
            objects: file_info.objects.clone(),
            objects_fsize: file_info.objects_fsize.clone(),
        });
    }

    let file_count = entries.len();
    let download_bytes: u64 = entries.iter().map(|e| e.fsize).sum();
    println!(
        "After filtering: {file_count} file(s) to download, {dirs_created} directories, \
         {filtered_out} filtered out ({failed_decode} path errors)."
    );
    if file_count == 0 {
        println!("Nothing to download.");
        return Ok(());
    }

    // ---- Progress bars ----
    let mp = MultiProgress::new();
    // Hide bars when stdout is not a terminal (piped / redirected).
    if !std::io::stdout().is_terminal() {
        mp.set_draw_target(ProgressDrawTarget::hidden());
    }
    let total_pb = mp.add(ProgressBar::new(download_bytes));
    total_pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] \
             {bytes}/{total_bytes} ({binary_bytes_per_sec}, ETA {eta})",
        )
        .unwrap()
        .progress_chars("=>-"),
    );
    total_pb.enable_steady_tick(Duration::from_millis(120));

    let worker_bars: Vec<ProgressBar> = (0..PARALLEL_FILES.min(file_count))
        .map(|_| {
            let pb = mp.add(ProgressBar::new(0));
            pb.set_style(
                ProgressStyle::with_template(
                    "  [{bar:25.green/white}] {bytes:>10}/{total_bytes:>10} \
                     ({binary_bytes_per_sec:>11}) {wide_msg}",
                )
                .unwrap()
                .progress_chars("=>-"),
            );
            pb.enable_steady_tick(Duration::from_millis(120));
            pb
        })
        .collect();

    // ---- Shared state ----
    let counter = AtomicUsize::new(0);
    let downloaded = AtomicUsize::new(0);
    let failed_count = AtomicUsize::new(0);
    let bytes_downloaded = AtomicU64::new(0);
    let failures: Mutex<Vec<String>> = Mutex::new(Vec::new());

    // Build a shared agent for all workers.
    let agent = agent();

    std::thread::scope(|scope| {
        let entries = &entries;
        let counter = &counter;
        let downloaded = &downloaded;
        let failed_count = &failed_count;
        let bytes_downloaded = &bytes_downloaded;
        let failures = &failures;
        let total_pb = &total_pb;
        let agent = &agent;

        for bar in worker_bars.iter().cloned() {
            scope.spawn(move || {
                loop {
                    let idx = counter.fetch_add(1, Ordering::Relaxed);
                    if idx >= entries.len() {
                        break;
                    }
                    let entry = &entries[idx];

                    bar.set_length(entry.fsize);
                    bar.set_position(0);
                    bar.set_message(entry.rel_path.clone());

                    let dest_path = target_dir.join(&entry.rel_path);

                    match download_one_file(
                        agent,
                        appid,
                        &entry.rel_path,
                        &entry.objects,
                        &entry.objects_fsize,
                        entry.fsize,
                        &dest_path,
                        &bar,
                        total_pb,
                    ) {
                        Ok(()) => {
                            downloaded.fetch_add(1, Ordering::Relaxed);
                            bytes_downloaded.fetch_add(entry.fsize, Ordering::Relaxed);
                        }
                        Err(e) => {
                            failed_count.fetch_add(1, Ordering::Relaxed);
                            failures.lock().unwrap().push(format!("{}: {:#}", entry.rel_path, e));
                        }
                    }

                    bar.finish_and_clear();
                }
            });
        }
    });

    total_pb.finish_and_clear();

    let downloaded = downloaded.load(Ordering::Relaxed);
    let failed = failed_count.load(Ordering::Relaxed);

    println!();
    println!(
        "Done: {downloaded} downloaded, {dirs_created} directories, \
         {filtered_out} filtered out, {failed} failed ({failed_decode} path errors)."
    );

    let failures = failures.into_inner().unwrap();
    if !failures.is_empty() {
        println!();
        println!("Failed files:");
        for f in &failures {
            println!("  {f}");
        }
        bail!("{} file(s) failed to download", failures.len());
    }

    Ok(())
}

/// Download all object blocks for one file, concatenate them, and write to
/// `dest_path`.  Objects are fetched with up to [`PARALLEL_OBJECTS`] concurrent
/// requests.
///
/// Supports resumption via a `.nxldl` sidecar file.  If a valid sidecar exists
/// and the partial file on disk has the expected size, already-completed
/// objects are skipped.
fn download_one_file(
    agent: &ureq::Agent,
    appid: &str,
    _rel_path: &str,
    objects: &[String],
    objects_fsize: &[u64],
    total_fsize: u64,
    dest_path: &Path,
    worker_bar: &ProgressBar,
    total_bar: &ProgressBar,
) -> Result<()> {
    use std::io::{Seek, SeekFrom, Write};

    // Ensure parent directory exists.
    if let Some(parent) = dest_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }

    let num_objects = objects.len();
    let progress_path = crate::resume::progress_path(dest_path);

    // Compute cumulative byte offsets for each object.
    let offsets: Vec<u64> = std::iter::once(0)
        .chain(objects_fsize.iter().scan(0, |acc, &sz| {
            *acc += sz;
            Some(*acc)
        }))
        .take(num_objects)
        .collect();

    // --- Check for a resumable sidecar ---
    let completed_mask: Vec<bool> = if let Some((bitmap, saved_objects, saved_size)) =
        crate::resume::read_progress(&progress_path)
    {
        if saved_objects as usize == num_objects
            && saved_size == total_fsize
            && dest_path.exists()
            && dest_path.metadata().map_or(false, |m| m.len() == total_fsize)
        {
            // Sidecar is valid — resume.
            let already_done: u64 = bitmap
                .iter()
                .enumerate()
                .filter(|(_, &b)| b != 0)
                .map(|(i, _)| objects_fsize.get(i).copied().unwrap_or(0))
                .sum();
            let done_count = bitmap.iter().filter(|&&b| b != 0).count();
            eprintln!(
                "resuming {} ({}/{} objects already done)",
                progress_path.display(),
                done_count,
                num_objects,
            );
            worker_bar.inc(already_done);
            total_bar.inc(already_done);
            bitmap.iter().map(|&b| b != 0).collect()
        } else {
            // Sidecar is stale (manifest changed?) — discard it.
            eprintln!(
                "discarding stale sidecar {} (manifest changed?)",
                progress_path.display(),
            );
            crate::resume::delete_progress(dest_path);
            let _ = std::fs::remove_file(dest_path);
            vec![false; num_objects]
        }
    } else {
        vec![false; num_objects]
    };

    let is_resuming = completed_mask.iter().any(|&b| b);

    // --- Pre-allocate / open the destination file ---
    if !is_resuming {
        if num_objects > 1 {
            eprintln!(
                "creating sidecar {} ({} objects)",
                progress_path.display(),
                num_objects,
            );
        }
        let file = std::fs::File::create(dest_path)
            .with_context(|| format!("failed to create {}", dest_path.display()))?;
        file.set_len(total_fsize)
            .with_context(|| format!("failed to size file {}", dest_path.display()))?;
        crate::resume::create_progress(dest_path, num_objects as u32, total_fsize)
            .with_context(|| format!("failed to create sidecar {}", progress_path.display()))?;
    }

    // --- Determine which objects still need downloading ---
    let pending: Vec<usize> = (0..num_objects)
        .filter(|&i| !completed_mask[i])
        .collect();

    if pending.is_empty() {
        // All objects already done — just clean up.
        crate::resume::delete_progress(dest_path);
        return Ok(());
    }

    if num_objects == 1 && !is_resuming {
        // Fast path: single object, no resume — download directly.
        let data = download_object(agent, appid, &objects[0])?;
        let expected = objects_fsize.first().copied().unwrap_or(0);
        if data.len() as u64 != expected {
            bail!(
                "object {} decompressed size mismatch: expected {}, got {}",
                &objects[0], expected, data.len()
            );
        }
        std::fs::write(dest_path, &data)
            .with_context(|| format!("failed to write {}", dest_path.display()))?;
        crate::resume::delete_progress(dest_path);
        worker_bar.inc(total_fsize);
        total_bar.inc(total_fsize);
        return Ok(());
    }

    // --- Download pending objects in parallel batches ---
    let object_counter = AtomicUsize::new(0);
    let object_failed = AtomicUsize::new(0);
    let first_err: Mutex<Option<anyhow::Error>> = Mutex::new(None);

    std::thread::scope(|scope| {
        for _ in 0..PARALLEL_OBJECTS.min(pending.len()).max(1) {
            scope.spawn(|| {
                loop {
                    if object_failed.load(Ordering::Relaxed) > 0 {
                        break;
                    }
                    let idx = object_counter.fetch_add(1, Ordering::Relaxed);
                    if idx >= pending.len() {
                        break;
                    }
                    let i = pending[idx];

                    let object_id = &objects[i];
                    let expected_size = objects_fsize.get(i).copied().unwrap_or(0);

                    match download_object(agent, appid, object_id) {
                        Ok(data) => {
                            if data.len() as u64 != expected_size {
                                let e = anyhow!(
                                    "object {object_id} decompressed size mismatch: \
                                     expected {expected_size}, got {}",
                                    data.len()
                                );
                                object_failed.fetch_add(1, Ordering::Relaxed);
                                first_err.lock().unwrap().get_or_insert(e);
                                return;
                            }

                            // Write object at its correct offset in the file.
                            match (|| -> Result<()> {
                                let mut file = std::fs::OpenOptions::new()
                                    .write(true)
                                    .open(dest_path)
                                    .with_context(|| {
                                        format!("failed to open {}", dest_path.display())
                                    })?;
                                file.seek(SeekFrom::Start(offsets[i]))
                                    .with_context(|| "seek failed")?;
                                file.write_all(&data)
                                    .with_context(|| "write failed")?;
                                Ok(())
                            })() {
                                Ok(()) => {}
                                Err(e) => {
                                    object_failed.fetch_add(1, Ordering::Relaxed);
                                    first_err.lock().unwrap().get_or_insert(e);
                                    return;
                                }
                            }

                            // Mark this object as done in the sidecar.
                            if let Err(e) = crate::resume::mark_done(dest_path, i as u32) {
                                object_failed.fetch_add(1, Ordering::Relaxed);
                                first_err
                                    .lock()
                                    .unwrap()
                                    .get_or_insert(anyhow::Error::from(e));
                                return;
                            }

                            // Update progress bars.
                            worker_bar.inc(expected_size);
                            total_bar.inc(expected_size);
                        }
                        Err(e) => {
                            object_failed.fetch_add(1, Ordering::Relaxed);
                            first_err.lock().unwrap().get_or_insert(e);
                            return;
                        }
                    }
                }
            });
        }
    });

    // Check for errors.
    if object_failed.load(Ordering::Relaxed) > 0 {
        if let Some(e) = first_err.lock().unwrap().take() {
            return Err(e);
        }
        bail!("one or more object downloads failed");
    }

    // All objects downloaded — clean up the sidecar.
    crate::resume::delete_progress(dest_path);

    Ok(())
}

// ---------------------------------------------------------------------------
// Check (dry-run) mode
// ---------------------------------------------------------------------------

/// Fetch the manifest and print a summary of the client without downloading.
///
/// The `manifest_source` may be either an `http(s)://` URL (`.manifest.hash`)
/// or a raw 40-character SHA-1 hex hash string.
///
/// When `verbose` is set, every file path and its size is listed.
/// The optional `filter` is applied to both the count/size summary and the
/// verbose listing.
pub fn check_client(
    manifest_source: &str,
    appid: &str,
    filter: Option<&FileFilter>,
    verbose: bool,
) -> Result<()> {
    // Step 1: resolve the manifest hash (URL or raw hex).
    let hash = resolve_hash(manifest_source)?;

    // Step 2: fetch & parse the manifest.
    println!("Fetching and parsing manifest...");
    let manifest = fetch_manifest(appid, &hash)?;
    let total_files = manifest.files.len();
    let total_size: u64 = manifest.files.values().map(|f| f.fsize).sum();
    println!(
        "Manifest loaded: {total_files} file(s), {:.2} GiB total.",
        total_size as f64 / (1024.0 * 1024.0 * 1024.0)
    );

    // Step 3: resolve paths, apply filter, and collect.
    let mut entries: Vec<(String, u64, usize)> = Vec::with_capacity(manifest.files.len());
    let mut dir_count: usize = 0;
    let mut filtered_out: usize = 0;
    let mut failed_decode: usize = 0;

    for (encoded_path, file_info) in &manifest.files {
        let rel_path = match decode_file_path(encoded_path) {
            Ok(p) => p,
            Err(e) => {
                if verbose {
                    eprintln!("warning: skipping unparseable path: {e}");
                }
                failed_decode += 1;
                continue;
            }
        };

        // Directories don't count toward download size.
        if file_info.objects.len() == 1 && file_info.objects[0] == "__DIR__" {
            dir_count += 1;
            continue;
        }

        // Apply the optional path filter.
        if let Some(f) = filter {
            if !f.matches(&rel_path) {
                filtered_out += 1;
                continue;
            }
        }

        entries.push((rel_path, file_info.fsize, file_info.objects.len()));
    }

    // Sort by path for deterministic output.
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let file_count = entries.len();
    let download_bytes: u64 = entries.iter().map(|e| e.1).sum();

    println!();
    println!("  product:      {appid}");
    println!("  files:        {file_count}");
    println!(
        "  total size:   {:.2} GiB ({bytes} bytes)",
        download_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
        bytes = format_bytes(download_bytes),
    );
    if filtered_out > 0 || failed_decode > 0 || dir_count > 0 {
        println!(
            "  ({} directories, {} filtered out, {} path errors)",
            dir_count, filtered_out, failed_decode,
        );
    }

    // Verbose: list every file.
    if verbose {
        println!();
        println!("{:<70} {:>8} {:>12}", "PATH", "CHUNKS", "SIZE");
        println!("{:-<70} {:-<8} {:-<12}", "", "", "");
        for (path, size, chunks) in &entries {
            println!("{:<70} {:>8} {:>12}", path, chunks, human_size(*size));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// Decompress raw zlib-wrapped data (header `78 9c`).
fn decompress_zlib(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(data);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .context("zlib decompression failed")?;
    Ok(out)
}

/// Format a byte count as a human-readable string (e.g. "1.5 GiB").
fn human_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;
    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }
    format!("{size:.1} {}", UNITS[unit_idx])
}

/// Format a byte count with thousands separators (e.g. "21,676,736,368").
fn format_bytes(bytes: u64) -> String {
    let s = bytes.to_string();
    let len = s.len();
    let mut result = String::with_capacity(len + (len.saturating_sub(1)) / 3);
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            result.push(',');
        }
        result.push(ch);
    }
    result
}
