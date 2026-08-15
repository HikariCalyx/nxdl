//! NGM (NX Game Manager) client check logic.
//!
//! Protocol:
//! 1. Fetch game info from `https://ngmapi.nexon.com/game-info/{appid}`
//! 2. Extract `setup_file_url` and `manifest_name`
//! 3. Download manifest from `{setup_file_url}/{manifest_name}`
//! 4. Parse manifest entries (base64-encoded UTF-8 file paths, chunk objects,
//!    decompressed sizes, SHA-1 hashes)
//! 5. Print summary (and file list when verbose).
//!
//! Patch protocol:
//! 1. Read the current manifest hash from
//!    `<target>/<stripped_appid>.manifest.hash`
//! 2. Resolve the target manifest hash: an explicit hash, or the latest
//!    one from the game-info API
//! 3. Download the patch manifest from `{setup_file_url}/{target}-{current}`
//!    into `<target>/patchdata/patch_<target8>-<current8>.json`
//! 4. Download, decompress, and concatenate the `.nxdelta` chunks of each
//!    patched file into `<target>/patchdata/patches/<encoded>.nxdlpatch`
//! 5. (TODO) Apply the patch files to the client.

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
#[allow(dead_code)]
const PARALLEL_OBJECTS: usize = 5;

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

const STALL_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

fn agent(allow_insecure: bool, proxy: Option<&str>) -> ureq::Agent {
    crate::net::agent(allow_insecure, proxy, STALL_TIMEOUT, CONNECT_TIMEOUT)
}

/// GET a URL and return the response body as a String, retrying on transient
/// errors.
fn http_get_string(agent: &ureq::Agent, url: &str) -> Result<String> {
    const MAX_RETRIES: usize = 5;
    let mut last_err: Option<anyhow::Error> = None;

    for _ in 0..=MAX_RETRIES {
        match agent.get(url).call() {
            Ok(resp) => match resp.into_string() {
                Ok(s) => return Ok(s),
                Err(e) => {
                    last_err =
                        Some(anyhow::Error::from(e).context("failed to read response body"));
                }
            },
            Err(e) => {
                last_err = Some(anyhow::Error::from(e).context("HTTP request failed"));
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no attempts made")))
}

/// Like [`http_get_string`] but also captures the `Last-Modified` header.
fn http_get_string_with_modified(
    agent: &ureq::Agent,
    url: &str,
) -> Result<(String, Option<String>)> {
    const MAX_RETRIES: usize = 5;
    let mut last_err: Option<anyhow::Error> = None;

    for _ in 0..=MAX_RETRIES {
        match agent.get(url).call() {
            Ok(resp) => {
                let last_modified = resp.header("Last-Modified").map(|s| s.to_owned());
                match resp.into_string() {
                    Ok(body) => return Ok((body, last_modified)),
                    Err(e) => {
                        last_err = Some(
                            anyhow::Error::from(e).context("failed to read response body"),
                        );
                    }
                }
            }
            Err(e) => {
                last_err = Some(anyhow::Error::from(e).context("HTTP request failed"));
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no attempts made")))
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
                        last_err =
                            Some(anyhow::Error::from(e).context("failed to read response"));
                    }
                }
            }
            Err(e) => {
                last_err = Some(anyhow::Error::from(e).context("HTTP request failed"));
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no attempts made")))
}

/// Decompress raw zlib-wrapped data (header `78 9c`).
fn decompress_zlib(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(data);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .context("zlib decompression failed")?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// NGM API types
// ---------------------------------------------------------------------------

/// Response from `GET /game-info/{appid}`.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
struct GameInfo {
    game_name: String,
    setup_file_url: String,
    manifest_name: Option<String>,
}

// ---------------------------------------------------------------------------
// NGM manifest types
// ---------------------------------------------------------------------------

/// A single file entry inside the NGM manifest.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
struct NgmManifestFile {
    /// Map of chunk index (as string) → chunk SHA-1 hex hash.
    objects: HashMap<String, String>,
    /// Decompressed file size in bytes.
    uncompressed_size: u64,
    /// SHA-1 hex hash of the complete file.
    hash: String,
}

/// Top-level NGM manifest structure.
///
/// Example:
/// ```json
/// {
///     "files": { "<base64-path>": { "objects": {...}, "uncompressed_size": N, "hash": "..." } },
///     "version": "1.0",
///     "total_uncompressed_size": 68180139433
/// }
/// ```
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
struct NgmManifest {
    files: HashMap<String, NgmManifestFile>,
    #[allow(dead_code)]
    version: Option<String>,
    #[allow(dead_code)]
    total_uncompressed_size: Option<u64>,
}

// ---------------------------------------------------------------------------
// Path decoding
// ---------------------------------------------------------------------------

/// Decode a Base64-encoded file path (UTF-8) from the NGM manifest.
///
/// The keys in the `files` object are Base64 strings whose decoded bytes form
/// a UTF-8 path.  Backslashes are used as path separators.
fn decode_path(encoded: &str) -> Result<String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("failed to base64-decode file path")?;

    String::from_utf8(bytes).context("failed to decode file path as UTF-8")
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// JSON output for `--check --json`.
#[derive(serde::Serialize)]
struct CheckResult {
    appid: String,
    game_name: String,
    manifest_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_modified: Option<i64>,
    files_in_manifest: usize,
    files_to_download: usize,
    total_size: u64,
    /// Mushroom game client version read from `Base.wz`, when present in the
    /// manifest.
    #[serde(skip_serializing_if = "Option::is_none")]
    client_version: Option<i16>,
}

/// Parse an RFC 2822 HTTP date (e.g. "Fri, 03 Jul 2026 03:38:51 GMT") into a
/// Unix timestamp.  Returns `None` if the string cannot be parsed.
fn parse_http_date(s: &str) -> Option<i64> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 6 {
        return None;
    }
    let day: i64 = parts[1].parse().ok()?;
    let month: i64 = match parts[2] {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year: i64 = parts[3].parse().ok()?;
    let time: Vec<&str> = parts[4].split(':').collect();
    if time.len() != 3 {
        return None;
    }
    let hour: i64 = time[0].parse().ok()?;
    let min: i64 = time[1].parse().ok()?;
    let sec: i64 = time[2].parse().ok()?;

    // Convert to days since Unix epoch (1970-01-01).
    let days = days_from_civil(year as i32, month as u8, day as u8)?;
    let ts = days * 86400 + hour * 3600 + min * 60 + sec;
    Some(ts)
}

/// Returns the number of days since 1970-01-01 for the given date.
/// Uses the algorithm from Howard Hinnant.
fn days_from_civil(y: i32, m: u8, d: u8) -> Option<i64> {
    if m < 1 || m > 12 || d < 1 || d > 31 {
        return None;
    }
    let y = y as i64;
    let m = m as i64;
    let d = d as i64;
    // Shift year so that March is the first month.
    let y = if m <= 2 { y - 1 } else { y };
    let m = if m <= 2 { m + 9 } else { m - 3 };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400) as u64;
    let doy = (153 * m as u64 + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era as i64 * 146097 + doe as i64 - 719468;
    Some(days)
}

// ---------------------------------------------------------------------------
// Base.wz version detection
// ---------------------------------------------------------------------------

/// A `Base.wz` entry located in the manifest, ready to have its version read.
struct BaseWzCandidate {
    /// Base64-encoded manifest key (used to build the chunk URL).
    encoded_path: String,
    /// Decoded, human-readable path (for reporting).
    rel_path: String,
    /// Total (uncompressed) file size, used for header validation.
    fsize: u64,
    /// The first chunk: `(chunk_id, chunk_hash)`.
    first_chunk: (u32, String),
}

/// Build a [`BaseWzCandidate`] from a manifest entry, picking the
/// lowest-numbered chunk (chunk 0). Returns `None` if the entry has no usable
/// chunks (e.g. it is a directory marker).
fn base_wz_candidate(
    encoded_path: &str,
    rel_path: &str,
    file_info: &NgmManifestFile,
) -> Option<BaseWzCandidate> {
    let first_chunk = file_info
        .objects
        .iter()
        .filter_map(|(k, v)| {
            if v == "__DIR__" {
                None
            } else {
                k.parse::<u32>().ok().map(|id| (id, v.clone()))
            }
        })
        .min_by_key(|(id, _)| *id)?;

    Some(BaseWzCandidate {
        encoded_path: encoded_path.to_owned(),
        rel_path: rel_path.to_owned(),
        fsize: file_info.uncompressed_size,
        first_chunk,
    })
}

/// Download the first chunk of the given `Base.wz` and read its client version.
fn read_base_wz_version(
    agent: &ureq::Agent,
    setup_base: &str,
    candidate: &BaseWzCandidate,
) -> Result<crate::miniwzlib::WzVersion> {
    let (chunk_id, chunk_hash) = &candidate.first_chunk;
    let data = download_ngm_chunk(
        agent,
        setup_base,
        &candidate.encoded_path,
        *chunk_id,
        chunk_hash,
    )
    .with_context(|| format!("failed to fetch first chunk of {}", candidate.rel_path))?;

    crate::miniwzlib::get_wz_version_from_bytes(&data, candidate.fsize)
        .map_err(|e| anyhow!("failed to read version from {}: {e}", candidate.rel_path))
}

/// Check NGM client info: fetch game info, download the manifest, and print
/// a summary.  When `verbose` is true, list every file.
/// When `json` is true, output a single JSON object to stdout.
pub fn check_ngm(
    appid: &str,
    verbose: bool,
    json: bool,
    filter: Option<&FileFilter>,
    allow_insecure: bool,
    proxy: Option<&str>,
) -> Result<()> {
    let agent = agent(allow_insecure, proxy);

    // ---- Step 1: fetch game info ----
    let info_url = format!("https://ngmapi.nexon.com/game-info/{appid}");
    if !json {
        println!("Game info URL: {info_url}");
    }
    let info_json = http_get_string(&agent, &info_url)
        .with_context(|| format!("failed to fetch game info from {info_url}"))?;
    let info: GameInfo =
        serde_json::from_str(&info_json).context("failed to parse game-info response")?;

    // ---- Step 2: construct and fetch manifest (if available) ----
    let manifest_name = match &info.manifest_name {
        Some(name) => name,
        None => {
            if json {
                let result = CheckResult {
                    appid: appid.to_owned(),
                    game_name: info.game_name.clone(),
                    manifest_url: String::new(),
                    last_modified: None,
                    files_in_manifest: 0,
                    files_to_download: 0,
                    total_size: 0,
                    client_version: None,
                };
                println!("{}", serde_json::to_string(&result)?);
            } else {
                println!();
                println!("  game:      {}", info.game_name);
                println!("  product:   {appid}");
                println!("  (no manifest available)");
            }
            return Ok(());
        }
    };
    let setup_base = info.setup_file_url.trim_end_matches('/');
    let manifest_url = format!("{setup_base}/{manifest_name}");
    if !json {
        println!("Manifest URL:  {manifest_url}");
    }

    let (manifest_json, last_modified) =
        http_get_string_with_modified(&agent, &manifest_url)
            .with_context(|| format!("failed to fetch manifest from {manifest_url}"))?;
    if !json {
        if let Some(ref lm) = last_modified {
            println!("  Last-Modified: {lm}");
        }
    }
    let manifest: NgmManifest =
        serde_json::from_str(&manifest_json).context("failed to parse manifest JSON")?;

    // ---- Step 3: decode paths, apply filter, collect stats ----
    let total_in_manifest = manifest.files.len();
    let mut entries: Vec<(String, u64, usize)> = Vec::with_capacity(manifest.files.len());
    let mut dir_count: usize = 0;
    let mut filtered_out: usize = 0;
    let mut failed_decode: usize = 0;
    // The client `Base.wz` (root or Data\Base\Base.wz), if present. Detected
    // across the full manifest, independent of any active filter.
    let mut base_wz: Option<BaseWzCandidate> = None;

    for (encoded_path, file_info) in &manifest.files {
        let rel_path = match decode_path(encoded_path) {
            Ok(p) => p,
            Err(e) => {
                if verbose {
                    eprintln!("warning: skipping unparseable path: {e}");
                }
                failed_decode += 1;
                continue;
            }
        };

        // Remember the client Base.wz so we can read its version later. Prefer
        // a Data\Base\Base.wz match (longer path) over a root-level Base.wz.
        if crate::miniwzlib::is_base_wz(&rel_path) {
            let better = match &base_wz {
                None => true,
                Some(existing) => rel_path.len() > existing.rel_path.len(),
            };
            if better {
                if let Some(c) = base_wz_candidate(encoded_path, &rel_path, file_info) {
                    base_wz = Some(c);
                }
            }
        }

        // Directories: 0 objects or a single "__DIR__" marker.
        if file_info.objects.is_empty()
            || (file_info.objects.len() == 1
                && file_info.objects.values().next().map_or(false, |v| v == "__DIR__"))
        {
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

        entries.push((
            rel_path,
            file_info.uncompressed_size,
            file_info.objects.len(),
        ));
    }

    // Sort by path for deterministic output.
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let file_count = entries.len();
    let download_bytes: u64 = entries.iter().map(|e| e.1).sum();

    // ---- Read the client version from Base.wz, if the manifest lists it ----
    let client_version: Option<i16> = match &base_wz {
        Some(candidate) => match read_base_wz_version(&agent, setup_base, candidate) {
            Ok(v) if v.version != 0 => Some(v.version),
            Ok(_) => None, // PKG2 / unknown header → no version
            Err(e) => {
                if !json {
                    eprintln!("warning: {e}");
                }
                None
            }
        },
        None => None,
    };

    // ---- Step 4: print results ----
    if json {
        let result = CheckResult {
            appid: appid.to_owned(),
            game_name: info.game_name.clone(),
            manifest_url,
            last_modified: last_modified.as_deref().and_then(parse_http_date),
            files_in_manifest: total_in_manifest,
            files_to_download: file_count,
            total_size: download_bytes,
            client_version,
        };
        println!("{}", serde_json::to_string(&result)?);
    } else {
        println!();
        println!("  game:                {}", info.game_name);
        println!("  product:             {appid}");
        println!("  files in manifest:   {total_in_manifest}");
        println!("  files to download:   {file_count}");
        println!(
            "  total size:          {:.2} GiB ({} bytes)",
            download_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
            format_bytes(download_bytes),
        );
        if let Some(ver) = client_version {
            println!("  client version:      v{ver} (from Base.wz)");
        }
        if filtered_out > 0 || failed_decode > 0 || dir_count > 0 {
            println!(
                "  ({} directories, {} filtered out, {} path errors)",
                dir_count, filtered_out, failed_decode,
            );
        }

        if verbose && file_count > 0 {
            println!();
            println!("{:<70} {:>8} {:>12}", "PATH", "CHUNKS", "SIZE");
            println!("{:-<70} {:-<8} {:-<12}", "", "", "");
            for (path, size, num_objects) in &entries {
                println!(
                    "{:<70} {:>8} {:>12}",
                    path, num_objects, human_size(*size)
                );
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Download: shared fetch & manifest helpers
// ---------------------------------------------------------------------------

/// Fetch game info and manifest.  Returns `(GameInfo, NgmManifest, setup_base)`.
fn fetch_game_and_manifest(
    appid: &str,
    allow_insecure: bool,
    proxy: Option<&str>,
) -> Result<(GameInfo, NgmManifest, String)> {
    let agent = agent(allow_insecure, proxy);

    let info_url = format!("https://ngmapi.nexon.com/game-info/{appid}");
    let info_json = http_get_string(&agent, &info_url)
        .with_context(|| format!("failed to fetch game info from {info_url}"))?;
    let info: GameInfo =
        serde_json::from_str(&info_json).context("failed to parse game-info response")?;

    let manifest_name = info
        .manifest_name
        .as_deref()
        .ok_or_else(|| anyhow!("no manifest available for {appid}"))?;

    let setup_base = info.setup_file_url.trim_end_matches('/').to_owned();
    let manifest_url = format!("{setup_base}/{manifest_name}");

    let manifest_json = http_get_string(&agent, &manifest_url)
        .with_context(|| format!("failed to fetch manifest from {manifest_url}"))?;
    let manifest: NgmManifest =
        serde_json::from_str(&manifest_json).context("failed to parse manifest JSON")?;

    Ok((info, manifest, setup_base))
}

// ---------------------------------------------------------------------------
// Patch: manifest hash helpers
// ---------------------------------------------------------------------------

/// Strip the `@suffix` from an NGM appid, keeping only the leading numeric
/// part.  Examples: `"2982@2141"` → `"2982"`, `"589825"` → `"589825"`.
fn stripped_appid(appid: &str) -> &str {
    appid.split('@').next().unwrap_or(appid)
}

/// Path of the manifest-hash file for an appid inside `target_dir`:
/// `<target_dir>/<stripped_appid>.manifest.hash`.
fn manifest_hash_path(target_dir: &Path, appid: &str) -> std::path::PathBuf {
    target_dir.join(format!("{}.manifest.hash", stripped_appid(appid)))
}

/// Write the manifest name of the current version to
/// `<target_dir>/<stripped_appid>.manifest.hash`.
pub fn write_manifest_hash(
    target_dir: &Path,
    appid: &str,
    manifest_name: &str,
) -> Result<()> {
    std::fs::create_dir_all(target_dir).with_context(|| {
        format!("failed to create directory {}", target_dir.display())
    })?;
    let hash_path = manifest_hash_path(target_dir, appid);
    std::fs::write(&hash_path, manifest_name)
        .with_context(|| format!("failed to write manifest hash to {}", hash_path.display()))?;
    println!("Saved manifest hash to: {}", hash_path.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// Download: chunk fetching
// ---------------------------------------------------------------------------

/// Download and decompress a single NGM chunk (`.nxgz`), verifying its SHA-1.
///
/// URL: `{setup_base}/{encoded_path}.{chunk_id}.{chunk_hash}.nxgz`
fn download_ngm_chunk(
    agent: &ureq::Agent,
    setup_base: &str,
    encoded_path: &str,
    chunk_id: u32,
    chunk_hash: &str,
) -> Result<Vec<u8>> {
    let url = format!(
        "{setup_base}/{encoded_path}.{chunk_id}.{chunk_hash}.nxgz"
    );

    let compressed = http_get_bytes(agent, &url)
        .with_context(|| format!("failed to download chunk {chunk_hash}"))?;

    let data = decompress_zlib(&compressed)
        .with_context(|| format!("failed to decompress chunk {chunk_hash}"))?;

    // Verify SHA-1.
    let actual = hex::encode(Sha1::digest(&data));
    if !actual.eq_ignore_ascii_case(chunk_hash) {
        bail!(
            "SHA-1 mismatch for chunk {chunk_hash}: expected {chunk_hash}, got {actual}"
        );
    }

    Ok(data)
}

// ---------------------------------------------------------------------------
// Download: one file (with resume support)
// ---------------------------------------------------------------------------

/// A single resolved file ready for download.
struct ResolvedNgmFile {
    rel_path: String,
    encoded_path: String,
    fsize: u64,
    /// Ordered list of `(chunk_id, chunk_hash)` sorted by chunk_id.
    chunks: Vec<(u32, String)>,
}

/// Download all chunks for one file, write to `dest_path`, with resume support
/// via `.ngmdl` sidecar.
fn download_ngm_one_file(
    agent: &ureq::Agent,
    setup_base: &str,
    entry: &ResolvedNgmFile,
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

    let num_objects = entry.chunks.len();
    let total_fsize = entry.fsize;
    let progress_path =
        crate::resume::progress_path(dest_path, &crate::resume::SIDECAR_NGM);

    // Compute cumulative byte offsets. We don't have per-chunk sizes in the
    // NGM manifest, so we can't pre-allocate.  We'll download all chunks,
    // verify total size, then write sequentially.
    //
    // For multi-chunk files we do pre-allocation to support resume; we guess
    // chunk sizes from the total.  For the common single-chunk case we skip
    // the sidecar entirely.

    // --- Check for a resumable sidecar ---
    let completed_mask: Vec<bool> = if num_objects > 1 {
        if let Some((bitmap, saved_objects, saved_size)) =
            crate::resume::read_progress(&progress_path, &crate::resume::SIDECAR_NGM)
        {
            if saved_objects as usize == num_objects
                && saved_size == total_fsize
                && dest_path.exists()
                && dest_path.metadata().map_or(false, |m| m.len() == total_fsize)
            {
                let done = bitmap.iter().filter(|&&b| b != 0).count();
                if done > 0 {
                    worker_bar.println(format!(
                        "resuming {} ({done}/{num_objects} objects already done)",
                        progress_path.display(),
                    ));
                }
                bitmap.iter().map(|&b| b != 0).collect()
            } else {
                worker_bar.println(format!(
                    "discarding stale sidecar {}",
                    progress_path.display(),
                ));
                crate::resume::delete_progress(dest_path, &crate::resume::SIDECAR_NGM);
                let _ = std::fs::remove_file(dest_path);
                vec![false; num_objects]
            }
        } else {
            vec![false; num_objects]
        }
    } else {
        vec![false; num_objects]
    };

    let is_resuming = completed_mask.iter().any(|&b| b);

    // --- Single-chunk fast path ---
    if num_objects == 1 && !is_resuming {
        let (_, chunk_hash) = &entry.chunks[0];
        let data = download_ngm_chunk(agent, setup_base, &entry.encoded_path, 0, chunk_hash)?;
        if data.len() as u64 != total_fsize {
            bail!(
                "chunk {} decompressed size mismatch: expected {}, got {}",
                chunk_hash,
                total_fsize,
                data.len()
            );
        }
        std::fs::write(dest_path, &data)
            .with_context(|| format!("failed to write {}", dest_path.display()))?;
        worker_bar.inc(total_fsize);
        total_bar.inc(total_fsize);
        return Ok(());
    }

    // --- Multi-chunk path ---
    // Pre-allocate the destination file and create sidecar on first run.
    if !is_resuming {
        let file = std::fs::File::create(dest_path)
            .with_context(|| format!("failed to create {}", dest_path.display()))?;
        file.set_len(total_fsize)
            .with_context(|| format!("failed to size file {}", dest_path.display()))?;
        crate::resume::create_progress(
            dest_path,
            num_objects as u32,
            total_fsize,
            &crate::resume::SIDECAR_NGM,
        )
        .with_context(|| format!("failed to create sidecar {}", progress_path.display()))?;
    }

    // Determine which chunks still need downloading.
    let pending: Vec<usize> = (0..num_objects)
        .filter(|&i| !completed_mask[i])
        .collect();

    if pending.is_empty() {
        crate::resume::delete_progress(dest_path, &crate::resume::SIDECAR_NGM);
        return Ok(());
    }

    // Download pending chunks sequentially (we need ordered output anyway).
    // Since NGM chunks don't have known sizes upfront, we write each chunk
    // to a temp buffer, track its position, then assemble at the end.
    //
    // For simplicity, download all pending chunks into memory first, then
    // write them in order.  This is fine for typical NGM files.
    let mut chunk_data: Vec<(usize, Vec<u8>)> = Vec::with_capacity(pending.len());

    for &i in &pending {
        let (chunk_id, chunk_hash) = &entry.chunks[i];
        match download_ngm_chunk(agent, setup_base, &entry.encoded_path, *chunk_id, chunk_hash) {
            Ok(data) => {
                let len = data.len() as u64;
                chunk_data.push((i, data));
                worker_bar.inc(len);
                total_bar.inc(len);
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    // Write chunks at their positions.
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(dest_path)
            .with_context(|| format!("failed to open {}", dest_path.display()))?;

        // For position tracking we need to know each chunk's decompressed
        // size.  Since the manifest doesn't give per-chunk sizes, we write
        // sequentially and assume the chunks are in order.
        let mut offset: u64 = 0;
        let mut all_chunks: Vec<Option<Vec<u8>>> = vec![None; num_objects];

        // Fill in chunks we already have from resume.
        for (i, data) in chunk_data {
            all_chunks[i] = Some(data);
        }

        // Write in order.  Already-completed chunks are assumed to already
        // be on disk at the correct position.
        for i in 0..num_objects {
            if let Some(ref data) = all_chunks[i] {
                file.seek(SeekFrom::Start(offset))
                    .with_context(|| "seek failed")?;
                file.write_all(data)
                    .with_context(|| "write failed")?;

                // Mark as done in sidecar.
                crate::resume::mark_done(
                    dest_path,
                    i as u32,
                    &crate::resume::SIDECAR_NGM,
                )?;
            }
            // Advance offset by this chunk's size.
            // Since we don't know individual chunk sizes from the manifest,
            // we approximate: for completed chunks, they're already on disk;
            // for newly-written chunks we used the actual data length.
            offset += all_chunks[i]
                .as_ref()
                .map(|d| d.len() as u64)
                .unwrap_or(0);
        }
    }

    // Verify total size.
    let actual_size = std::fs::metadata(dest_path)
        .map(|m| m.len())
        .unwrap_or(0);
    if actual_size != total_fsize {
        bail!(
            "file size mismatch for {}: expected {}, got {}",
            entry.rel_path,
            total_fsize,
            actual_size,
        );
    }

    crate::resume::delete_progress(dest_path, &crate::resume::SIDECAR_NGM);
    Ok(())
}

// ---------------------------------------------------------------------------
// Download: main orchestrator
// ---------------------------------------------------------------------------

/// Download a complete NGM client.
///
/// `appid` is the resolved application ID (e.g. `16785939@bb01` for JMS).
/// `target_dir` is where the client tree will be written.
/// When `filter` is provided, only matching files are downloaded.
pub fn download_ngm(
    appid: &str,
    target_dir: &Path,
    filter: Option<&FileFilter>,
    allow_insecure: bool,
    proxy: Option<&str>,
) -> Result<()> {
    // ---- Step 1 & 2: fetch game info and manifest ----
    let (info, manifest, setup_base) = fetch_game_and_manifest(appid, allow_insecure, proxy)?;
    println!("Game:         {}", info.game_name);
    println!("Manifest URL: {setup_base}/{}", info.manifest_name.as_deref().unwrap_or("?"));
    let total_files = manifest.files.len();
    let manifest_total: u64 = manifest.files.values().map(|f| f.uncompressed_size).sum();
    println!(
        "Manifest loaded: {total_files} file(s), {:.2} GiB total.",
        manifest_total as f64 / (1024.0 * 1024.0 * 1024.0)
    );

    // ---- Step 3: resolve paths, apply filter ----
    let mut entries: Vec<ResolvedNgmFile> = Vec::with_capacity(manifest.files.len());
    let mut dirs_created: usize = 0;
    let mut filtered_out: usize = 0;
    let mut failed_decode: usize = 0;

    for (encoded_path, file_info) in &manifest.files {
        let rel_path = match decode_path(encoded_path) {
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

        // Directories.
        if file_info.objects.is_empty()
            || (file_info.objects.len() == 1
                && file_info
                    .objects
                    .values()
                    .next()
                    .map_or(false, |v| v == "__DIR__"))
        {
            let dir_path = target_dir.join(&rel_path);
            if let Err(e) = std::fs::create_dir_all(&dir_path) {
                eprintln!("warning: failed to create directory {}: {e}", dir_path.display());
            } else {
                dirs_created += 1;
            }
            continue;
        }

        // Sort object chunks by numeric index.
        let mut sorted_chunks: Vec<(u32, String)> = file_info
            .objects
            .iter()
            .filter_map(|(k, v)| k.parse::<u32>().ok().map(|id| (id, v.clone())))
            .collect();
        sorted_chunks.sort_by_key(|(id, _)| *id);

        entries.push(ResolvedNgmFile {
            rel_path,
            encoded_path: encoded_path.clone(),
            fsize: file_info.uncompressed_size,
            chunks: sorted_chunks,
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
    // One overall bar plus one reusable bar per worker (mirrors cmsdl). Each
    // worker keeps a single bar for its whole lifetime and only clears it once
    // it has finished all its files, which avoids the flicker/smearing caused
    // by clearing and reviving a bar on every file.
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

    // Reflect overall progress on the OS taskbar / dock (cleared on drop).
    let mut _taskbar = crate::taskprogress::watch(total_pb.clone(), download_bytes);

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

    let agent = agent(allow_insecure, proxy);

    std::thread::scope(|scope| {
        let entries = &entries;
        let counter = &counter;
        let downloaded = &downloaded;
        let failed_count = &failed_count;
        let bytes_downloaded = &bytes_downloaded;
        let failures = &failures;
        let total_pb = &total_pb;
        let agent = &agent;
        let setup_base = &setup_base;

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

                    match download_ngm_one_file(
                        agent,
                        setup_base,
                        entry,
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
                            failures
                                .lock()
                                .unwrap()
                                .push(format!("{}: {:#}", entry.rel_path, e));
                        }
                    }
                }
                bar.finish_and_clear();
            });
        }
    });

    total_pb.finish_and_clear();
    _taskbar.finish();

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

    // ---- Persist the current manifest name (used by future patches) ----
    if let Some(name) = info.manifest_name.as_deref() {
        write_manifest_hash(target_dir, appid, name)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Patch: patch manifest & .nxdelta download
// ---------------------------------------------------------------------------

/// A single patch file entry inside an NGM patch manifest.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
struct NgmPatchFile {
    /// Map of chunk index (as string) → chunk SHA-1 hex hash.
    objects: HashMap<String, String>,
    /// Per-chunk sizes (not needed yet; kept for future patch application).
    #[allow(dead_code)]
    object_sizes: HashMap<String, u64>,
    /// Decompressed size of the complete patch file.
    uncompressed_size: u64,
    /// Compressed size of the complete patch file (used for progress bars).
    #[allow(dead_code)]
    compressed_size: u64,
    /// SHA-1 hex hash of the complete patch file.
    #[allow(dead_code)]
    hash: String,
}

/// Top-level NGM patch manifest.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
struct NgmPatchManifest {
    files: HashMap<String, NgmPatchFile>,
    #[allow(dead_code)]
    version: Option<String>,
}

/// A single resolved patch entry ready for download.
struct ResolvedNgmPatch {
    /// Base64-encoded file name (the manifest key, also the URL component).
    encoded_path: String,
    /// File-level SHA-1 hash (the `<total_hash>` component in chunk URLs).
    file_hash: String,
    /// Ordered list of `(chunk_id, chunk_hash)` sorted by chunk_id.
    chunks: Vec<(u32, String)>,
    /// Decompressed size of the complete patch file.
    uncompressed_size: u64,
    /// Compressed size of the complete patch file.
    compressed_size: u64,
}

/// First 8 characters of `s` (used to build patch file names).
fn first8(s: &str) -> &str {
    s.get(..8).unwrap_or(s)
}

/// Download all `.nxdelta` chunks for one patch entry, decompress each of
/// them, and concatenate them into a single patch file at `dest_path`.
///
/// Chunk URL:
/// `{setup_base}/{encoded_path}.{chunk_id}.{chunk_hash}.{file_hash}.nxdelta`
fn download_ngm_patch_file(
    agent: &ureq::Agent,
    setup_base: &str,
    entry: &ResolvedNgmPatch,
    dest_path: &Path,
    worker_bar: &ProgressBar,
    total_bar: &ProgressBar,
) -> Result<()> {
    if let Some(parent) = dest_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }

    let mut out: Vec<u8> = Vec::with_capacity(entry.uncompressed_size as usize);

    for (chunk_id, chunk_hash) in &entry.chunks {
        let url = format!(
            "{setup_base}/{}.{chunk_id}.{chunk_hash}.{}.nxdelta",
            entry.encoded_path, entry.file_hash,
        );
        let compressed = http_get_bytes(agent, &url)
            .with_context(|| format!("failed to download patch chunk {chunk_hash}"))?;
        let data = decompress_zlib(&compressed)
            .with_context(|| format!("failed to decompress patch chunk {chunk_hash}"))?;

        // Verify the chunk SHA-1 against the patch manifest.
        let actual = hex::encode(Sha1::digest(&data));
        if !actual.eq_ignore_ascii_case(chunk_hash) {
            bail!(
                "SHA-1 mismatch for patch chunk {chunk_hash}: expected {chunk_hash}, got {actual}"
            );
        }

        worker_bar.inc(compressed.len() as u64);
        total_bar.inc(compressed.len() as u64);
        out.extend_from_slice(&data);
    }

    if out.len() as u64 != entry.uncompressed_size {
        bail!(
            "patch size mismatch for {}: expected {}, got {}",
            entry.encoded_path,
            entry.uncompressed_size,
            out.len()
        );
    }

    std::fs::write(dest_path, &out)
        .with_context(|| format!("failed to write patch file {}", dest_path.display()))?;
    Ok(())
}

/// Patch an NGM client from its current version to a newer version.
///
/// `manifest_source` selects the *target* version: `None` or `"latest"`
/// resolves the newest manifest from the NGM API; any other value is used
/// directly as the target manifest hash.
///
/// The current version is read from
/// `<target_dir>/<stripped_appid>.manifest.hash`.  The patch manifest is
/// downloaded into
/// `<target_dir>/patchdata/patch_<target8>-<current8>.json`, and the
/// `.nxdelta` chunks of each patched file are downloaded, decompressed, and
/// concatenated into `<target_dir>/patchdata/patches/<encoded>.nxdlpatch`.
///
/// Applying the patches to the client files is not implemented yet.
pub fn patch_ngm(
    appid: &str,
    manifest_source: Option<&str>,
    target_dir: &Path,
    allow_insecure: bool,
    proxy: Option<&str>,
) -> Result<()> {
    let agent = agent(allow_insecure, proxy);

    // ---- Step 1: read the current manifest hash ----
    let hash_file = manifest_hash_path(target_dir, appid);
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
    if src_hash.is_empty() {
        bail!("current manifest hash in '{}' is empty", hash_file.display());
    }
    println!("Current (source) manifest hash: {src_hash}");

    // ---- Step 2: fetch game info (setup_file_url + latest manifest hash) ----
    let info_url = format!("https://ngmapi.nexon.com/game-info/{appid}");
    let info_json = http_get_string(&agent, &info_url)
        .with_context(|| format!("failed to fetch game info from {info_url}"))?;
    let info: GameInfo =
        serde_json::from_str(&info_json).context("failed to parse game-info response")?;
    let setup_base = info.setup_file_url.trim_end_matches('/');
    let latest_hash = info
        .manifest_name
        .as_deref()
        .ok_or_else(|| anyhow!("no manifest available for {appid}"))?;
    println!("Latest manifest hash:      {latest_hash}");

    // Resolve the target version: an explicit hash, `latest`, or (when no
    // source was given) the newest manifest from the API.
    let dst_hash: &str = match manifest_source.map(str::trim) {
        None => latest_hash,
        Some(src) if src.eq_ignore_ascii_case("latest") => latest_hash,
        Some(src) => src,
    };
    if dst_hash.is_empty() {
        bail!("target manifest hash must not be empty");
    }
    println!("Target manifest hash:      {dst_hash}");

    if src_hash.eq_ignore_ascii_case(dst_hash) {
        println!("Client is already at the target version — nothing to do.");
        return Ok(());
    }

    // ---- Step 3: download the patch manifest ----
    let patchdata_dir = target_dir.join("patchdata");
    std::fs::create_dir_all(&patchdata_dir).with_context(|| {
        format!("failed to create directory {}", patchdata_dir.display())
    })?;

    let patch_manifest_url = format!("{setup_base}/{dst_hash}-{src_hash}");
    println!("Patch manifest URL:       {patch_manifest_url}");

    let patch_json_name = format!("patch_{}-{}.json", first8(dst_hash), first8(&src_hash));
    let patch_json_path = patchdata_dir.join(patch_json_name);

    let patch_bytes = http_get_bytes(&agent, &patch_manifest_url).with_context(|| {
        format!("failed to download patch manifest from {patch_manifest_url}")
    })?;
    std::fs::write(&patch_json_path, &patch_bytes).with_context(|| {
        format!(
            "failed to write patch manifest to {}",
            patch_json_path.display()
        )
    })?;
    println!("Saved patch manifest to:  {}", patch_json_path.display());

    let patch_manifest: NgmPatchManifest = serde_json::from_slice(&patch_bytes).with_context(
        || format!("failed to parse patch manifest {}", patch_json_path.display()),
    )?;

    // ---- Step 4: resolve patch entries ----
    let mut entries: Vec<ResolvedNgmPatch> = Vec::with_capacity(patch_manifest.files.len());
    for (encoded_path, file_info) in &patch_manifest.files {
        let mut chunks: Vec<(u32, String)> = file_info
            .objects
            .iter()
            .filter_map(|(k, v)| k.parse::<u32>().ok().map(|id| (id, v.clone())))
            .collect();
        chunks.sort_by_key(|(id, _)| *id);
        if chunks.is_empty() {
            eprintln!("warning: skipping patch entry with no chunks: {encoded_path}");
            continue;
        }
        entries.push(ResolvedNgmPatch {
            encoded_path: encoded_path.clone(),
            file_hash: file_info.hash.clone(),
            chunks,
            uncompressed_size: file_info.uncompressed_size,
            compressed_size: file_info.compressed_size,
        });
    }
    entries.sort_by(|a, b| a.encoded_path.cmp(&b.encoded_path));

    let total_compressed: u64 = entries.iter().map(|e| e.compressed_size).sum();
    println!(
        "Patch manifest loaded: {} file(s) to patch ({:.2} MiB compressed).",
        entries.len(),
        total_compressed as f64 / (1024.0 * 1024.0),
    );
    if entries.is_empty() {
        println!("Nothing to download.");
        return Ok(());
    }

    // ---- Progress bars ----
    let mp = MultiProgress::new();
    if !std::io::stdout().is_terminal() {
        mp.set_draw_target(ProgressDrawTarget::hidden());
    }
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

    // Reflect overall progress on the OS taskbar / dock (cleared on drop).
    let mut _taskbar = crate::taskprogress::watch(total_pb.clone(), total_compressed);

    let worker_bars: Vec<ProgressBar> = (0..PARALLEL_FILES.min(entries.len()))
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
    let failures: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let patches_dir = patchdata_dir.join("patches");

    std::thread::scope(|scope| {
        let entries = &entries;
        let counter = &counter;
        let downloaded = &downloaded;
        let failed_count = &failed_count;
        let failures = &failures;
        let total_pb = &total_pb;
        let agent = &agent;
        let setup_base = &setup_base;
        let patches_dir = &patches_dir;

        for bar in worker_bars.iter().cloned() {
            scope.spawn(move || {
                loop {
                    let idx = counter.fetch_add(1, Ordering::Relaxed);
                    if idx >= entries.len() {
                        break;
                    }
                    let entry = &entries[idx];

                    bar.set_length(entry.compressed_size);
                    bar.set_position(0);
                    bar.set_message(entry.encoded_path.clone());

                    let dest_path =
                        patches_dir.join(format!("{}.nxdlpatch", entry.encoded_path));

                    match download_ngm_patch_file(
                        agent,
                        setup_base,
                        entry,
                        &dest_path,
                        &bar,
                        total_pb,
                    ) {
                        Ok(()) => {
                            downloaded.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => {
                            failed_count.fetch_add(1, Ordering::Relaxed);
                            failures
                                .lock()
                                .unwrap()
                                .push(format!("{}: {:#}", entry.encoded_path, e));
                        }
                    }
                }
                bar.finish_and_clear();
            });
        }
    });

    total_pb.finish_and_clear();
    _taskbar.finish();

    let downloaded = downloaded.load(Ordering::Relaxed);
    let failed = failed_count.load(Ordering::Relaxed);

    println!();
    println!("Done: {downloaded} patch file(s) downloaded, {failed} failed.");

    let failures = failures.into_inner().unwrap();
    if !failures.is_empty() {
        println!();
        println!("Failed patch files:");
        for f in &failures {
            println!("  {f}");
        }
        bail!("{} patch file(s) failed to download", failures.len());
    }

    Ok(())
}
