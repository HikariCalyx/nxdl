//! GMS diff-based client patcher.
//!
//! Reference:
//!   https://github.com/Kagamia/WzComparer-dev-notes/blob/main/02-GMS-Patcher/GMSPatcher.md
//!
//! ## Protocol summary
//!
//! 1. Read source (current) hash from `<target>/patchdata/<appid>.manifest.hash`.
//! 2. Resolve the target hash from the supplied manifest URL or raw SHA-1.
//! 3. Construct the diff-manifest `.hash` URL:
//!    `http://download2.nexon.net/Game/nxl/games/{appid}/patches/patch-{src8}-{dst8}/diff_manifest.hash`
//! 4. Fetch that URL → plain-text SHA-1 hash of the diff manifest.
//! 5. Download & zlib-decompress the diff manifest JSON:
//!    `http://download2.nexon.net/Game/nxl/games/{appid}/patches/patch-{src8}-{dst8}/{hash}`
//! 6. For each `diff_result` entry, download the compressed `.diff` file:
//!    `http://download2.nexon.net/Game/nxl/games/{appid}/patches/patch-{src8}-{dst8}/{appid}/{path}.diff`
//! 7. Verify MD5 checksum of the compressed `.diff`, then zlib-decompress it.
//! 8. Apply the binary diff commands to the old file from `<target>/appdata/{path}`.
//! 9. Write the patched result to `<target>/patchdata/patched/{path}`.
//! 10. Record each completed path in `<target>/patchdata/.incomplete-{appid}_{target_hash}`.
//! 11. Files that fail to patch are re-downloaded from the new NXL manifest.
//! 12. Move all patched/downloaded files from `patchdata/patched/` to `appdata/`.
//! 13. Update `patchdata/<appid>.manifest.hash`; delete the `.incomplete` file.
//!
//! ## Diff command binary format
//!
//! ```text
//! {diff file}    := {diff command} [..n]
//! {diff command} := {flag} {position} {data length} [data bytes]
//!
//! flag (1 byte):
//!   bits 7-6  (aa): source — 00 = from old file, 01 = from diff file
//!   bits 5-4  (bb): position byte-width — 00 = 1B, 01 = 2B, 10 = 4B
//!   bits 3-2  (cc): data-length byte-width — 00 = 1B, 01 = 2B, 10 = 4B
//!   bits 1-0  (dd): unused, always 00
//!
//! For source 01 (from diff file) the position is the current write offset
//! in the new file and may be ignored.  For source 00 (from old file) the
//! position is the read offset in the old file.
//! ```

use std::collections::HashSet;
use std::io::{IsTerminal, Read};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use flate2::read::ZlibDecoder;
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PARALLEL_PATCHES: usize = 10;
const BASE_CDN: &str = "http://download2.nexon.net/Game/nxl/games";
const STALL_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// HTTP helpers (self-contained; mirrors nxl.rs / ngm.rs)
// ---------------------------------------------------------------------------

fn agent(allow_insecure: bool, proxy: Option<&str>) -> ureq::Agent {
    crate::net::agent(allow_insecure, proxy, STALL_TIMEOUT, CONNECT_TIMEOUT)
}

fn http_get_bytes(agent: &ureq::Agent, url: &str) -> Result<Vec<u8>> {
    const MAX_RETRIES: usize = 5;
    let mut last_err: Option<anyhow::Error> = None;
    for _ in 0..=MAX_RETRIES {
        match agent.get(url).call() {
            Ok(resp) => {
                let mut buf = Vec::new();
                match resp.into_reader().read_to_end(&mut buf) {
                    Ok(_) => return Ok(buf),
                    Err(e) => last_err = Some(anyhow::Error::from(e).context("failed to read response")),
                }
            }
            Err(e) => last_err = Some(anyhow::Error::from(e).context("HTTP request failed")),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("no attempts made")))
}

fn decompress_zlib(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    ZlibDecoder::new(data)
        .read_to_end(&mut out)
        .context("zlib decompression failed")?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Diff manifest types
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
pub struct DiffManifest {
    pub src_deploy_id: String,
    pub dst_deploy_id: String,
    pub diff_result: Vec<DiffEntry>,
    pub patcher_type: Option<String>,
    pub total_size: Option<u64>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct DiffEntry {
    pub path: String,
    /// MD5 hex string of the compressed `.diff` file.
    pub checksum: String,
    /// Byte size of the compressed `.diff` file.
    pub file_size: u64,
    #[serde(rename = "type")]
    #[allow(dead_code)]
    pub entry_type: u32,
}

// ---------------------------------------------------------------------------
// Target-hash resolution
// ---------------------------------------------------------------------------

/// Resolve the target manifest hash from one of three inputs:
///
/// - `"latest"` (case-insensitive): resolve via the branch API using the login
///   session stored in `nxl.ini` (same flow as `nxdl nxl --download <TARGET_PATH>`).
/// - An `http(s)://` URL pointing to a `.manifest.hash` file: fetch and return
///   the plain-text SHA-1 hash inside.
/// - A raw 40-character SHA-1 hex string: validate and return as-is.
fn resolve_target_hash(
    input: &str,
    appid: &str,
    allow_insecure: bool,
    proxy: Option<&str>,
) -> Result<String> {
    let trimmed = input.trim();

    if trimmed.eq_ignore_ascii_case("latest") {
        // Use the saved login session to resolve the public branch manifest.
        let ini_path = std::path::Path::new("nxl.ini");
        let session = crate::login::load_session(ini_path)?;
        println!(
            "  Resolving latest manifest via branch API ('{}' region)…",
            session.region.code()
        );
        let url = crate::login::resolve_public_manifest_url(
            &session,
            appid,
            allow_insecure,
            proxy,
        )?;
        println!("  Manifest hash URL: {url}");
        let bytes = http_get_bytes(&agent(allow_insecure, proxy), &url)
            .context("failed to fetch latest manifest hash")?;
        let hash = String::from_utf8_lossy(&bytes).trim().to_owned();
        if hash.is_empty() {
            bail!("latest manifest hash URL returned an empty response");
        }
        Ok(hash)
    } else if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        println!("Fetching target manifest hash from: {trimmed}");
        let bytes = http_get_bytes(&agent(allow_insecure, proxy), trimmed)
            .context("failed to fetch target manifest hash")?;
        let hash = String::from_utf8_lossy(&bytes).trim().to_owned();
        if hash.is_empty() {
            bail!("target manifest hash URL returned an empty response");
        }
        Ok(hash)
    } else {
        let hash = trimmed.to_owned();
        if hash.len() != 40 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!(
                "invalid target hash '{hash}': must be 'latest', \
                 a 40-character hex string, or an http(s) URL"
            );
        }
        Ok(hash)
    }
}

// ---------------------------------------------------------------------------
// Diff manifest fetching
// ---------------------------------------------------------------------------

/// `…/patches/patch-{src8}-{dst8}` base URL for all patch assets.
fn patch_base_url(appid: &str, src_hash: &str, dst_hash: &str) -> String {
    let src8 = &src_hash[..8];
    let dst8 = &dst_hash[..8];
    format!("{BASE_CDN}/{appid}/patches/patch-{src8}-{dst8}")
}

fn fetch_diff_manifest(
    appid: &str,
    src_hash: &str,
    dst_hash: &str,
    allow_insecure: bool,
    proxy: Option<&str>,
) -> Result<DiffManifest> {
    let base = patch_base_url(appid, src_hash, dst_hash);
    let ag = agent(allow_insecure, proxy);

    // Step A: fetch the hash of the diff manifest.
    let hash_url = format!("{base}/diff_manifest.hash");
    println!("Fetching diff manifest hash from: {hash_url}");
    let hash_bytes = http_get_bytes(&ag, &hash_url)
        .context("failed to fetch diff manifest hash")?;
    let manifest_hash = String::from_utf8_lossy(&hash_bytes).trim().to_owned();
    println!("Diff manifest hash: {manifest_hash}");

    // Step B: download and decompress the actual diff manifest JSON.
    let manifest_url = format!("{base}/{manifest_hash}");
    println!("Fetching diff manifest from: {manifest_url}");
    let compressed = http_get_bytes(&ag, &manifest_url)
        .context("failed to fetch diff manifest")?;
    let json_bytes = decompress_zlib(&compressed)
        .context("failed to decompress diff manifest")?;
    let manifest: DiffManifest = serde_json::from_slice(&json_bytes)
        .context("failed to parse diff manifest JSON")?;
    Ok(manifest)
}

// ---------------------------------------------------------------------------
// Binary diff application
// ---------------------------------------------------------------------------

/// Read `n` bytes (1, 2, or 4) at `offset` from `data` as a little-endian u32.
fn read_le_n(data: &[u8], offset: usize, n: usize) -> Result<u32> {
    match n {
        1 => data
            .get(offset)
            .map(|&b| b as u32)
            .ok_or_else(|| anyhow!("diff: read 1 byte at offset {offset} out of bounds (len {})", data.len())),
        2 => {
            if offset + 2 > data.len() {
                bail!("diff: read 2 bytes at offset {offset} out of bounds (len {})", data.len());
            }
            Ok(u16::from_le_bytes([data[offset], data[offset + 1]]) as u32)
        }
        4 => {
            if offset + 4 > data.len() {
                bail!("diff: read 4 bytes at offset {offset} out of bounds (len {})", data.len());
            }
            Ok(u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]))
        }
        _ => bail!("diff: unsupported byte-width {n}"),
    }
}

/// Apply all commands in a decompressed `.diff` buffer to `old_data` and
/// return the reconstructed new-file bytes.
///
/// Command flag layout (1 byte):
/// - bits 7–6 (aa): source — `00` = old file, `01` = diff data
/// - bits 5–4 (bb): position byte-width — `00`=1B, `01`=2B, `10`=4B
/// - bits 3–2 (cc): data-length byte-width — `00`=1B, `01`=2B, `10`=4B
/// - bits 1–0 (dd): unused
fn apply_diff(diff_data: &[u8], old_data: &[u8]) -> Result<Vec<u8>> {
    let mut output: Vec<u8> = Vec::new();
    let mut cursor: usize = 0;

    while cursor < diff_data.len() {
        let flag = diff_data[cursor];
        cursor += 1;

        let source      = (flag >> 6) & 0x03; // aa
        let pos_bitlen  = (flag >> 4) & 0x03; // bb
        let data_bitlen = (flag >> 2) & 0x03; // cc

        let pos_bytes = match pos_bitlen {
            0 => 1usize,
            1 => 2,
            2 => 4,
            _ => bail!(
                "diff: invalid position bitlen {pos_bitlen} in flag {flag:#04x} at offset {}",
                cursor - 1
            ),
        };
        let data_len_bytes = match data_bitlen {
            0 => 1usize,
            1 => 2,
            2 => 4,
            _ => bail!(
                "diff: invalid data-length bitlen {data_bitlen} in flag {flag:#04x} at offset {}",
                cursor - 1
            ),
        };

        let position = read_le_n(diff_data, cursor, pos_bytes)
            .with_context(|| format!("diff: reading position at offset {cursor}"))? as usize;
        cursor += pos_bytes;

        let data_len = read_le_n(diff_data, cursor, data_len_bytes)
            .with_context(|| format!("diff: reading data length at offset {cursor}"))? as usize;
        cursor += data_len_bytes;

        match source {
            0x00 => {
                // Copy `data_len` bytes from old file at `position`.
                let end = position + data_len;
                if end > old_data.len() {
                    bail!(
                        "diff: copy-from-old-file [{position}..{end}) out of bounds \
                         (old file is {} bytes)",
                        old_data.len()
                    );
                }
                output.extend_from_slice(&old_data[position..end]);
            }
            0x01 => {
                // Copy `data_len` bytes from diff data at `cursor`.
                // `position` is the current write offset in the new file (ignored).
                let _ = position;
                let end = cursor + data_len;
                if end > diff_data.len() {
                    bail!(
                        "diff: copy-from-diff [{cursor}..{end}) out of bounds \
                         (diff data is {} bytes)",
                        diff_data.len()
                    );
                }
                output.extend_from_slice(&diff_data[cursor..end]);
                cursor += data_len;
            }
            _ => bail!(
                "diff: unknown source flag {source:#04x} in flag {flag:#04x} at offset {}",
                cursor - 1
            ),
        }
    }

    Ok(output)
}

// ---------------------------------------------------------------------------
// Incomplete-file helpers
// ---------------------------------------------------------------------------

/// Load the set of already-completed relative paths from the `.incomplete` file.
fn load_completed(path: &Path) -> HashSet<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Append one completed path (newline-terminated) to the `.incomplete` file.
fn mark_completed(writer: &Mutex<std::fs::File>, rel_path: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = writer.lock().unwrap();
    writeln!(file, "{rel_path}")?;
    file.flush()
}

// ---------------------------------------------------------------------------
// Single-file patch
// ---------------------------------------------------------------------------

fn patch_one_file(
    ag: &ureq::Agent,
    appid: &str,
    patch_base: &str,
    entry: &DiffEntry,
    appdata_dir: &Path,
    patched_dir: &Path,
) -> Result<()> {
    // Download the compressed `.diff` file.
    let diff_url = format!("{patch_base}/{appid}/{}.diff", entry.path);
    let compressed = http_get_bytes(ag, &diff_url)
        .with_context(|| format!("failed to download diff for '{}'", entry.path))?;

    // Verify compressed size.
    if compressed.len() as u64 != entry.file_size {
        bail!(
            "diff '{}': compressed-size mismatch (expected {}, got {})",
            entry.path,
            entry.file_size,
            compressed.len()
        );
    }

    // Verify MD5 checksum of the compressed data.
    let actual_md5 = format!("{:x}", md5::compute(&compressed));
    if !actual_md5.eq_ignore_ascii_case(&entry.checksum) {
        bail!(
            "diff '{}': MD5 mismatch (expected {}, got {actual_md5})",
            entry.path,
            entry.checksum
        );
    }

    // Decompress.
    let diff_data = decompress_zlib(&compressed)
        .with_context(|| format!("failed to decompress diff for '{}'", entry.path))?;

    // Load the old file (empty slice if not present — handles brand-new files
    // whose diff commands are all "copy from diff").
    let old_path = appdata_dir.join(&entry.path);
    let old_data = if old_path.exists() {
        std::fs::read(&old_path)
            .with_context(|| format!("failed to read old file '{}'", old_path.display()))?
    } else {
        Vec::new()
    };

    // Apply the diff.
    let new_data = apply_diff(&diff_data, &old_data)
        .with_context(|| format!("failed to apply diff for '{}'", entry.path))?;

    // Write the patched file to `patchdata/patched/<path>`.
    let dest = patched_dir.join(&entry.path);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory '{}'", parent.display()))?;
    }
    std::fs::write(&dest, &new_data)
        .with_context(|| format!("failed to write patched file '{}'", dest.display()))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Fallback: download a single file from the NXL CDN (for patch failures)
// ---------------------------------------------------------------------------

fn fallback_download_file(
    ag: &ureq::Agent,
    appid: &str,
    objects: &[String],
    objects_fsize: &[u64],
    dest: &Path,
) -> Result<()> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory '{}'", parent.display()))?;
    }

    let mut out: Vec<u8> = Vec::new();
    for (obj_id, &expected_size) in objects.iter().zip(objects_fsize.iter()) {
        let data = crate::nxl::download_object(ag, appid, obj_id)?;
        if data.len() as u64 != expected_size {
            bail!(
                "object {obj_id}: size mismatch (expected {expected_size}, got {})",
                data.len()
            );
        }
        out.extend_from_slice(&data);
    }

    std::fs::write(dest, &out)
        .with_context(|| format!("failed to write '{}'", dest.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Main patch orchestrator
// ---------------------------------------------------------------------------

/// Patch an NXL client from its current version to the version described by
/// `manifest_source`.
///
/// - `manifest_source`: a `.manifest.hash` URL **or** a raw 40-char SHA-1 hex
///   string identifying the *target* version.
/// - `appid`: the numeric application ID (e.g. `"10100"` for GMS).
/// - `target_dir`: root client directory (must contain `appdata/` and
///   `patchdata/<appid>.manifest.hash`).
pub fn patch_client(
    manifest_source: &str,
    appid: &str,
    target_dir: &Path,
    allow_insecure: bool,
    proxy: Option<&str>,
) -> Result<()> {
    let patchdata_dir = target_dir.join("patchdata");
    let appdata_dir   = target_dir.join("appdata");
    let patched_dir   = patchdata_dir.join("patched");

    // Step 1 — read the source (current) hash.
    let hash_file = patchdata_dir.join(format!("{appid}.manifest.hash"));
    let src_hash = std::fs::read_to_string(&hash_file)
        .with_context(|| {
            format!(
                "failed to read current manifest hash from '{}' — \
                 has the client been downloaded yet?",
                hash_file.display()
            )
        })?
        .trim()
        .to_owned();
    println!("Current (source) hash: {src_hash}");

    // Step 2 — resolve the target hash.
    let dst_hash = resolve_target_hash(manifest_source, appid, allow_insecure, proxy)?;
    println!("Target hash:           {dst_hash}");

    if src_hash.eq_ignore_ascii_case(&dst_hash) {
        println!("Client is already at the target version — nothing to do.");
        return Ok(());
    }

    // Step 3 — create staging directories.
    std::fs::create_dir_all(&patched_dir).with_context(|| {
        format!("failed to create staging directory '{}'", patched_dir.display())
    })?;

    // Step 4 — open / create the `.incomplete` tracking file.
    let incomplete_path =
        patchdata_dir.join(format!(".incomplete-{appid}_{dst_hash}"));
    let completed_at_start = load_completed(&incomplete_path);
    if !completed_at_start.is_empty() {
        println!(
            "Resuming: {} file(s) already patched in a previous run.",
            completed_at_start.len()
        );
    }
    let incomplete_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&incomplete_path)
        .with_context(|| {
            format!("failed to open incomplete file '{}'", incomplete_path.display())
        })?;
    let incomplete_writer: Mutex<std::fs::File> = Mutex::new(incomplete_file);

    // Step 5 — fetch the diff manifest.
    println!();
    let diff_manifest =
        fetch_diff_manifest(appid, &src_hash, &dst_hash, allow_insecure, proxy)?;
    let total_entries = diff_manifest.diff_result.len();
    println!(
        "Diff manifest loaded: {total_entries} file(s) to patch, patcher_type = {:?}.",
        diff_manifest.patcher_type.as_deref().unwrap_or("unknown")
    );

    // Filter out files already completed in a previous run.
    let entries: Vec<DiffEntry> = diff_manifest
        .diff_result
        .into_iter()
        .filter(|e| !completed_at_start.contains(&e.path))
        .collect();
    let skip_count = total_entries - entries.len();
    if skip_count > 0 {
        println!("Skipping {skip_count} already-completed file(s).");
    }
    println!("{} file(s) remaining.", entries.len());

    // Step 6 — patch files in parallel (up to PARALLEL_PATCHES threads).
    println!();
    let patch_base = patch_base_url(appid, &src_hash, &dst_hash);
    let ag = agent(allow_insecure, proxy);

    let mp = MultiProgress::new();
    if !std::io::stdout().is_terminal() {
        mp.set_draw_target(ProgressDrawTarget::hidden());
    }

    let total_compressed: u64 = entries.iter().map(|e| e.file_size).sum();
    let total_pb = mp.add(ProgressBar::new(total_compressed));
    total_pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] \
             {bytes}/{total_bytes} ({binary_bytes_per_sec}, ETA {eta})",
        )
        .unwrap()
        .progress_chars("=>-"),
    );
    total_pb.enable_steady_tick(Duration::from_millis(120));

    let n_workers = PARALLEL_PATCHES.min(entries.len()).max(1);
    let worker_bars: Vec<ProgressBar> = (0..n_workers)
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

    let counter      = AtomicUsize::new(0);
    let patched_ok   = AtomicUsize::new(0);
    let failed_paths: Mutex<Vec<String>> = Mutex::new(Vec::new());

    std::thread::scope(|scope| {
        let entries          = &entries;
        let counter          = &counter;
        let patched_ok       = &patched_ok;
        let failed_paths     = &failed_paths;
        let total_pb         = &total_pb;
        let patch_base       = &patch_base;
        let ag               = &ag;
        let appdata_dir      = &appdata_dir;
        let patched_dir      = &patched_dir;
        let incomplete_writer = &incomplete_writer;

        for bar in worker_bars.iter().cloned() {
            scope.spawn(move || {
                loop {
                    let idx = counter.fetch_add(1, Ordering::Relaxed);
                    if idx >= entries.len() {
                        break;
                    }
                    let entry = &entries[idx];

                    bar.set_length(entry.file_size);
                    bar.set_position(0);
                    bar.set_message(entry.path.clone());

                    match patch_one_file(
                        ag,
                        appid,
                        patch_base,
                        entry,
                        appdata_dir,
                        patched_dir,
                    ) {
                        Ok(()) => {
                            patched_ok.fetch_add(1, Ordering::Relaxed);
                            total_pb.inc(entry.file_size);
                            bar.inc(entry.file_size);
                            if let Err(e) =
                                mark_completed(incomplete_writer, &entry.path)
                            {
                                bar.println(format!(
                                    "warning: could not record '{}' as completed: {e}",
                                    entry.path
                                ));
                            }
                        }
                        Err(e) => {
                            total_pb.inc(entry.file_size);
                            bar.inc(entry.file_size);
                            bar.println(format!(
                                "warning: patch failed for '{}': {e:#}  → will download.",
                                entry.path
                            ));
                            failed_paths.lock().unwrap().push(entry.path.clone());
                        }
                    }
                }
                bar.finish_and_clear();
            });
        }
    });

    total_pb.finish_and_clear();

    let n_patched = patched_ok.load(Ordering::Relaxed);
    let failed_paths = failed_paths.into_inner().unwrap();
    println!();
    println!(
        "Patching: {n_patched} patched, {} failed, {skip_count} already done.",
        failed_paths.len()
    );

    // Step 7 — re-download files that could not be patched.
    if !failed_paths.is_empty() {
        println!();
        println!(
            "Downloading {} failed file(s) from the new manifest…",
            failed_paths.len()
        );

        let new_manifest =
            crate::nxl::fetch_manifest(appid, &dst_hash, allow_insecure, proxy)
                .context("failed to fetch new manifest for fallback downloads")?;

        // Build a decoded-path → entry lookup table.
        let mut manifest_lookup = std::collections::HashMap::new();
        for (encoded, file_info) in &new_manifest.files {
            if let Ok(decoded) = crate::nxl::decode_file_path(encoded) {
                manifest_lookup.insert(decoded, file_info);
            }
        }

        let mut dl_ok: usize = 0;
        let mut dl_fail: usize = 0;
        let mut dl_fail_paths: Vec<String> = Vec::new();

        for path in &failed_paths {
            // Diff-manifest paths use forward slashes; decoded manifest paths
            // may differ on Windows.  Try a few normalisations.
            let fwd = path.replace('\\', "/");
            let bwd = path.replace('/', "\\");
            let file_info = manifest_lookup
                .get(path.as_str())
                .or_else(|| manifest_lookup.get(fwd.as_str()))
                .or_else(|| manifest_lookup.get(bwd.as_str()));

            match file_info {
                Some(info) => {
                    let dest = patched_dir.join(path);
                    match fallback_download_file(
                        &ag,
                        appid,
                        &info.objects,
                        &info.objects_fsize,
                        &dest,
                    ) {
                        Ok(()) => {
                            dl_ok += 1;
                            if let Err(e) = mark_completed(&incomplete_writer, path) {
                                eprintln!(
                                    "warning: could not record '{}' as completed: {e}",
                                    path
                                );
                            }
                        }
                        Err(e) => {
                            eprintln!("error: fallback download failed for '{path}': {e:#}");
                            dl_fail += 1;
                            dl_fail_paths.push(path.clone());
                        }
                    }
                }
                None => {
                    eprintln!("warning: '{path}' not found in new manifest — cannot download.");
                    dl_fail += 1;
                    dl_fail_paths.push(path.clone());
                }
            }
        }

        println!("Fallback downloads: {dl_ok} succeeded, {dl_fail} failed.");
        for p in &dl_fail_paths {
            eprintln!("  still failed: {p}");
        }
    }

    // Step 8 — move patched files into appdata/.
    println!();
    println!("Moving patched files into appdata…");

    // Reload the completed set so we pick up both the previous-run files and
    // everything just patched / downloaded this run.
    let all_completed = load_completed(&incomplete_path);
    let mut move_ok:   usize = 0;
    let mut move_fail: usize = 0;

    for rel_path in &all_completed {
        let src = patched_dir.join(rel_path);
        if !src.exists() {
            continue; // was listed but file is absent — skip silently.
        }
        let dst = appdata_dir.join(rel_path);
        if let Some(parent) = dst.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!(
                    "error: failed to create '{}': {e}",
                    parent.display()
                );
                move_fail += 1;
                continue;
            }
        }
        // Try an atomic rename first; fall back to copy + delete.
        let result = std::fs::rename(&src, &dst).or_else(|_| {
            std::fs::copy(&src, &dst).and_then(|_| std::fs::remove_file(&src))
        });
        match result {
            Ok(()) => move_ok += 1,
            Err(e) => {
                eprintln!("error: failed to move '{rel_path}': {e}");
                move_fail += 1;
            }
        }
    }

    println!("Moved {move_ok} file(s) into appdata ({move_fail} failed).");

    // Step 9 — update the hash file and clean up.
    if move_fail == 0 {
        std::fs::write(&hash_file, &dst_hash).with_context(|| {
            format!("failed to update manifest hash file '{}'", hash_file.display())
        })?;
        println!("Manifest hash updated to: {dst_hash}");
        let _ = std::fs::remove_file(&incomplete_path);
        println!("Patch complete.");
    } else {
        println!(
            "Warning: {move_fail} file(s) could not be moved — \
             manifest hash NOT updated.  Re-run to retry."
        );
    }

    Ok(())
}
