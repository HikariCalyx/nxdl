//! NGM (NX Game Manager) client check / download / patch logic.
//!
//! Games whose game-info response carries a `manifest_name` use the per-file
//! patch protocol below.  Games without one (e.g. KMS `589825`, Mabinogi JP
//! `16785925`) ship as a *setup package*: `setup_file_url` points at a
//! `.sting` or `.nfo` manifest that describes a full-client download split
//! into numbered parts, which are downloaded as-is (see the "Setup packages"
//! section further down).
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
//!    patched file into `<target>/patchdata/patches/<decoded_path>.nxdlpatch`
//! 5. Apply each `.nxdlpatch` to its target file: the patched result is
//!    first written to `<target>/patchdata/applied/<path>`, then moved over
//!    the original file and the patch file is deleted.

use std::collections::HashMap;
use std::io::{IsTerminal, Read, Seek, SeekFrom};
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
/// a UTF-8 path.  Backslashes are used as path separators, so the result is
/// normalised to `/` — see [`crate::relpath`] for why.
fn decode_path(encoded: &str) -> Result<String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("failed to base64-decode file path")?;

    let path = String::from_utf8(bytes).context("failed to decode file path as UTF-8")?;
    Ok(crate::relpath::normalize(&path))
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
            // No per-file patch manifest: `setup_file_url` points at a setup
            // package manifest (`.sting` / `.nfo`) that describes a
            // full-client download.  Check that instead.
            return check_ngm_setup(appid, &info, verbose, json, &agent);
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
// Setup packages (.sting / .nfo) — full-client downloads with no manifest
// ---------------------------------------------------------------------------
//
// Some NGM games (e.g. KMS `589825`, Mabinogi JP `16785925`) have no
// `manifest_name` in the game-info response.  For those, `setup_file_url`
// points directly at a *setup package* manifest that describes a full-client
// download split into numbered parts:
//
// - `.sting` — a JSON document describing `compressed_file_count` parts named
//   `<sting_name>.pegNN`.
// - `.nfo`   — a legacy NFO file listing `<name>.zNN` split archives.
//
// The parts are downloaded as-is into the target directory.  `.sting` parts
// (PEG packages, see [`crate::peg`]) are then decompressed into the final
// game tree; decompressing the `.nfo` split archives is not implemented yet.

/// JSON output for `--check --json` on a setup-package (no-manifest) game.
#[derive(serde::Serialize)]
struct SetupCheckResult {
    appid: String,
    game_name: String,
    /// `"sting"` or `"nfo"`.
    manifest_type: &'static str,
    manifest_url: String,
    /// Release/build date as Unix seconds when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    release_date: Option<i64>,
    /// Number of parts to download.
    archive_count: usize,
    /// Total number of bytes that will be downloaded.
    total_size: u64,
    /// Byte size of every part, in part order (sting parts are HEADed so the
    /// exact sizes are known).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    part_sizes: Vec<u64>,
    /// Installed (uncompressed) size, when the sting declares it.
    #[serde(skip_serializing_if = "Option::is_none")]
    original_size: Option<u64>,
    /// Base part name from the sting (e.g. "maplestory" → `maplestory.peg00`).
    #[serde(skip_serializing_if = "Option::is_none")]
    sting_name: Option<String>,
}

/// Lower-cased file extension (without the dot) of `url`, if its path has one.
fn url_extension(url: &str) -> Option<String> {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    let name = path.rsplit('/').next().unwrap_or(path);
    let (stem, ext) = name.rsplit_once('.')?;
    if stem.is_empty() || ext.is_empty() {
        return None;
    }
    Some(ext.to_ascii_lowercase())
}

/// Directory portion of `url` — everything up to, but not including, the
/// final `/`-separated segment — with no trailing slash.
fn url_base_dir(url: &str) -> String {
    let trimmed = url.trim_end_matches('/');
    match trimmed.rfind('/') {
        Some(idx) => trimmed[..idx].to_owned(),
        None => trimmed.to_owned(),
    }
}

/// Contents of a `.sting` setup manifest (JSON).
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
struct StingInfo {
    #[serde(default)]
    version: Option<i64>,
    /// Build time as Unix seconds.
    #[serde(default)]
    time_stamp: Option<i64>,
    /// Total uncompressed (installed) size in bytes.
    #[serde(default)]
    original_size: Option<u64>,
    /// Total compressed size of all `.peg` parts in bytes.
    #[serde(default)]
    compressed_size: Option<u64>,
    /// Base name of the `.pegNN` parts (e.g. "maplestory").
    sting_name: String,
    /// Number of `.pegNN` parts.
    compressed_file_count: u32,
}

impl StingInfo {
    /// Names of the numbered parts: `<sting_name>.peg00` … `.pegNN`.
    fn part_files(&self) -> Vec<String> {
        (0..self.compressed_file_count)
            .map(|i| format!("{}.peg{:02}", self.sting_name, i))
            .collect()
    }
}

/// One archive listed in an `.nfo` setup manifest.
#[derive(Debug, Clone)]
struct NfoPart {
    /// Archive file name, e.g. `Mabinogi.z00`.
    name: String,
    /// Byte size.
    size: u64,
}

/// Parse a legacy `.nfo` setup manifest:
///
/// ```text
/// NFO300,9526927360; DO NOT edit this line manually
/// "Mabinogi.z00","819766191","3145492277"
/// "Mabinogi.z01","-1532145412","3142701016"
/// ```
///
/// The first line is a header; every other line holds three comma-separated,
/// double-quoted fields: file name, CRC-32 (signed), and byte size.
fn parse_nfo(content: &str) -> Result<Vec<NfoPart>> {
    let mut parts = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("NFO") || !line.starts_with('"') {
            continue;
        }
        let fields: Vec<&str> = line.trim_matches('"').split("\",\"").collect();
        if fields.len() != 3 {
            bail!("malformed NFO entry (expected 3 fields): {line}");
        }
        let name = fields[0].trim().to_owned();
        if name.is_empty() {
            bail!("NFO entry with an empty archive name: {line}");
        }
        let size: u64 = fields[2]
            .trim()
            .parse()
            .with_context(|| format!("invalid archive size in NFO entry: {line}"))?;
        parts.push(NfoPart { name, size });
    }
    if parts.is_empty() {
        bail!("no archives listed in the NFO file");
    }
    Ok(parts)
}

/// One file part of a setup-package download.
#[derive(Debug, Clone)]
struct SetupPart {
    /// File name under the target directory (e.g. `maplestory.peg03`).
    filename: String,
    /// Absolute download URL.
    url: String,
    /// Expected byte size when known (from the NFO, or a HEAD request).
    size: Option<u64>,
}

/// A parsed setup package (`.sting` or `.nfo`).
#[derive(Debug)]
struct SetupPackage {
    /// `"sting"` or `"nfo"`.
    format: &'static str,
    /// Source manifest URL (the `setup_file_url`).
    url: String,
    /// Parts to download, in order.
    parts: Vec<SetupPart>,
    /// Raw HTTP `Last-Modified` value (NFO only) — shown to the user.
    release_date_raw: Option<String>,
    /// Release/build date as Unix seconds when derivable (the NFO's
    /// `Last-Modified` header, or the sting's `time_stamp`).
    release_date: Option<i64>,
    /// Parsed sting metadata, when the package is a `.sting`.
    sting: Option<StingInfo>,
}

/// Fetch and parse the setup package that `setup_file_url` points at.
///
/// The package type is chosen by the extension of `setup_file_url`: `.sting`
/// or `.nfo`.  Anything else fails with "Unknown manifest type : <ext>".
fn fetch_setup_package(agent: &ureq::Agent, setup_file_url: &str) -> Result<SetupPackage> {
    let ext = url_extension(setup_file_url)
        .ok_or_else(|| anyhow!("cannot determine manifest type from URL: {setup_file_url}"))?;
    let base_url = url_base_dir(setup_file_url);

    match ext.as_str() {
        "sting" => {
            let json = http_get_string(agent, setup_file_url).with_context(|| {
                format!("failed to fetch sting manifest from {setup_file_url}")
            })?;
            let sting: StingInfo = serde_json::from_str(&json)
                .context("failed to parse sting manifest JSON")?;
            if sting.sting_name.is_empty() {
                bail!("sting manifest has an empty sting_name");
            }
            let parts = sting
                .part_files()
                .into_iter()
                .map(|filename| SetupPart {
                    url: format!("{base_url}/{filename}"),
                    filename,
                    size: None,
                })
                .collect();
            Ok(SetupPackage {
                format: "sting",
                url: setup_file_url.to_owned(),
                parts,
                release_date_raw: None,
                release_date: sting.time_stamp,
                sting: Some(sting),
            })
        }
        "nfo" => {
            let (content, last_modified) =
                http_get_string_with_modified(agent, setup_file_url).with_context(|| {
                    format!("failed to fetch NFO manifest from {setup_file_url}")
                })?;
            let parts = parse_nfo(&content)?
                .into_iter()
                .map(|p| SetupPart {
                    url: format!("{base_url}/{}", p.name),
                    filename: p.name,
                    size: Some(p.size),
                })
                .collect();
            Ok(SetupPackage {
                format: "nfo",
                url: setup_file_url.to_owned(),
                parts,
                release_date_raw: last_modified.clone(),
                release_date: last_modified.as_deref().and_then(parse_http_date),
                sting: None,
            })
        }
        other => bail!("Unknown manifest type : {other}"),
    }
}

/// Total compressed bytes of a setup package: the sum of the part sizes when
/// every part has one (NFO, or fully-resolved sting parts), otherwise the
/// sting's declared `compressed_size`.
fn setup_total_size(package: &SetupPackage) -> u64 {
    let known_count = package.parts.iter().filter(|p| p.size.is_some()).count();
    if known_count == package.parts.len() && known_count > 0 {
        return package.parts.iter().filter_map(|p| p.size).sum();
    }
    package
        .sting
        .as_ref()
        .and_then(|s| s.compressed_size)
        .unwrap_or_else(|| package.parts.iter().filter_map(|p| p.size).sum())
}

/// Best-effort: HEAD any part whose size is unknown (sting parts carry no
/// sizes in the manifest) so totals / JSON can show real byte sizes.  Returns
/// the number of parts whose size is still unknown.
fn resolve_part_sizes(agent: &ureq::Agent, parts: &mut [SetupPart]) -> usize {
    let mut unknown = 0usize;
    for part in parts.iter_mut().filter(|p| p.size.is_none()) {
        match agent.head(&part.url).call() {
            Ok(resp) => {
                part.size = resp.header("Content-Length").and_then(|s| s.parse().ok());
                if part.size.is_none() {
                    unknown += 1;
                }
            }
            Err(_) => unknown += 1,
        }
    }
    unknown
}

/// Check a setup-package game (no `manifest_name`): fetch the `.sting`/`.nfo`
/// manifest from `setup_file_url` and print a summary of the parts.
fn check_ngm_setup(
    appid: &str,
    info: &GameInfo,
    verbose: bool,
    json: bool,
    agent: &ureq::Agent,
) -> Result<()> {
    let mut package = fetch_setup_package(agent, &info.setup_file_url)?;

    // `--check --json` reports the exact byte size of every part; sting parts
    // (which the manifest leaves un-sized) are learned via HEAD requests.
    if json {
        resolve_part_sizes(agent, &mut package.parts);
    }

    let archive_count = package.parts.len();
    let total_size = setup_total_size(&package);

    if json {
        let part_sizes: Vec<u64> = package.parts.iter().map(|p| p.size.unwrap_or(0)).collect();
        let result = SetupCheckResult {
            appid: appid.to_owned(),
            game_name: info.game_name.clone(),
            manifest_type: package.format,
            manifest_url: package.url.clone(),
            release_date: package.release_date,
            archive_count,
            total_size,
            part_sizes,
            original_size: package.sting.as_ref().and_then(|s| s.original_size),
            sting_name: package.sting.as_ref().map(|s| s.sting_name.clone()),
        };
        println!("{}", serde_json::to_string(&result)?);
    } else {
        println!();
        println!("  game:           {}", info.game_name);
        println!("  product:        {appid}");
        println!("  setup type:     {} ({})", package.format, package.url);
        // Human-readable release date (Unix seconds are kept only in JSON).
        match package.release_date {
            Some(ts) => println!("  release date:   {} (UTC)", format_unix_utc(ts)),
            None => {
                if let Some(ref raw) = package.release_date_raw {
                    println!("  release date:   {raw}");
                }
            }
        }
        if let Some(ref sting) = package.sting {
            if let Some(v) = sting.version {
                println!("  version:        {v}");
            }
            if let Some(os) = sting.original_size {
                println!(
                    "  installed size: {:.2} GiB ({} bytes)",
                    os as f64 / (1024.0 * 1024.0 * 1024.0),
                    format_bytes(os),
                );
            }
        }
        println!("  parts:          {archive_count}");
        println!(
            "  total size:     {:.2} GiB ({} bytes)",
            total_size as f64 / (1024.0 * 1024.0 * 1024.0),
            format_bytes(total_size),
        );

        if verbose && archive_count > 0 {
            if package.format == "sting" {
                // Read each `.pegNN` part's index over HTTP and list the
                // files it will extract.
                list_peg_contents(agent, &package)?;
            } else {
                println!();
                println!("{:<40} {:>16}", "PART", "SIZE");
                println!("{:-<40} {:-<16}", "", "");
                for part in &package.parts {
                    let size = match part.size {
                        Some(s) => human_size(s),
                        None => "?".to_owned(),
                    };
                    println!("{:<40} {:>16}", part.filename, size);
                }
            }
        }
    }

    Ok(())
}

/// Path of the temporary partial file used while downloading a setup part.
fn part_path(dest: &Path) -> std::path::PathBuf {
    let mut s = dest.as_os_str().to_owned();
    s.push(".part");
    std::path::PathBuf::from(s)
}

// ---------------------------------------------------------------------------
// Setup packages: listing a `.pegNN` part's contents over HTTP
// ---------------------------------------------------------------------------

/// Byte window fetched per HTTP range request while walking a PEG index.
///
/// A file entry's header (magic + sizes + hash + name) is only a few hundred
/// bytes and its payload is skipped with a seek, so a small window keeps the
/// bytes pulled from the server to roughly `entries × window` at most.
/// Payload bytes are never downloaded.
const PEG_RANGE_WINDOW: u64 = 16 * 1024;

/// A read-only view of a remote file, backed by HTTP `Range` requests.
///
/// Only a window around the cursor is buffered, so skipping forward over PEG
/// payloads costs no data transfer.  Implements [`std::io::Read`] +
/// [`std::io::Seek`] so the PEG structure walker in [`crate::peg`] can run
/// against it directly.
struct HttpRangeReader {
    agent: ureq::Agent,
    url: String,
    length: u64,
    pos: u64,
    buf: Vec<u8>,
    buf_start: u64,
    /// Total bytes actually read from the server (for reporting).
    fetched: u64,
}

impl HttpRangeReader {
    fn new(agent: &ureq::Agent, url: &str) -> Self {
        HttpRangeReader {
            agent: agent.clone(),
            url: url.to_owned(),
            length: 0,
            pos: 0,
            buf: Vec::new(),
            buf_start: 0,
            fetched: 0,
        }
    }

    /// Total number of bytes read from the server so far.
    fn bytes_fetched(&self) -> u64 {
        self.fetched
    }

    /// Fetch the window covering `self.pos`.
    fn fill(&mut self) -> std::io::Result<()> {
        if self.length != 0 && self.pos >= self.length {
            self.buf.clear();
            return Ok(()); // at EOF
        }
        let end = self.pos + PEG_RANGE_WINDOW;
        let range = format!("bytes={}-{}", self.pos, end - 1);
        let resp = match self.agent.get(&self.url).set("Range", &range).call() {
            Ok(r) => r,
            Err(ureq::Error::Status(416, _)) => {
                // Range not satisfiable → past the end of the file (EOF).
                self.buf.clear();
                return Ok(());
            }
            Err(e) => {
                return Err(std::io::Error::other(format!(
                    "HTTP range request failed: {e}"
                )))
            }
        };
        let status = resp.status();
        match status {
            206 => {
                // Content-Range: "bytes start-end/total" — learn the length.
                if let Some(total) = resp
                    .header("Content-Range")
                    .and_then(|cr| cr.rsplit('/').next())
                    .and_then(|t| t.trim().parse::<u64>().ok())
                {
                    self.length = total;
                }
            }
            200 if self.pos == 0 => {
                // Server ignored the Range header, but we are at offset 0 so
                // the body is fine; only ever read up to a window of it.
                self.length = resp
                    .header("Content-Length")
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(self.length);
            }
            200 => {
                return Err(std::io::Error::other(
                    "server ignored the Range request; cannot stream a PEG index",
                ))
            }
            other => {
                return Err(std::io::Error::other(format!(
                    "unexpected HTTP status {other} fetching {}",
                    self.url
                )))
            }
        }

        self.buf.clear();
        self.buf_start = self.pos;
        resp.into_reader()
            .take(PEG_RANGE_WINDOW)
            .read_to_end(&mut self.buf)?;
        self.fetched += self.buf.len() as u64;
        Ok(())
    }
}

impl Read for HttpRangeReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.length != 0 && self.pos >= self.length {
            return Ok(0); // EOF
        }
        // (Re)fill the window when the cursor has moved outside of it.
        if self.buf.is_empty()
            || self.pos < self.buf_start
            || self.pos >= self.buf_start + self.buf.len() as u64
        {
            self.fill()?;
        }
        if self.buf.is_empty() {
            return Ok(0);
        }
        let off = (self.pos - self.buf_start) as usize;
        if off >= self.buf.len() {
            return Ok(0);
        }
        let n = out.len().min(self.buf.len() - off);
        out[..n].copy_from_slice(&self.buf[off..off + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for HttpRangeReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(p) => p,
            SeekFrom::End(delta) => {
                if self.length == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "seek from end with unknown length",
                    ));
                }
                (self.length as i64 + delta).max(0) as u64
            }
            SeekFrom::Current(delta) => (self.pos as i64 + delta).max(0) as u64,
        };
        // Drop the window only when the new position lies outside it; small
        // in-window skips (e.g. over tiny payloads) keep it cached.
        if self.buf.is_empty()
            || new_pos < self.buf_start
            || new_pos > self.buf_start + self.buf.len() as u64
        {
            self.buf.clear();
        }
        self.pos = new_pos;
        Ok(new_pos)
    }
}

/// FILETIME (100 ns since 1601-01-01) → Unix seconds.
fn filetime_to_unix(filetime: u64) -> Option<i64> {
    const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000; // 1601→1970, 100 ns units
    if filetime == 0 || filetime < FILETIME_UNIX_EPOCH {
        return None;
    }
    Some(((filetime - FILETIME_UNIX_EPOCH) / 10_000_000) as i64)
}

/// Days since epoch → `(year, month, day)` (proleptic Gregorian).  Inverse of
/// [`days_from_civil`], from Howard Hinnant's algorithms.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Format a Unix timestamp as `YYYY-MM-DD HH:MM:SS` (UTC).
fn format_unix_utc(ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let (y, mo, d) = civil_from_days(days);
    let (h, mi, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}")
}

/// Format a PEG FILETIME for display (or "N/A" when unset).
fn format_filetime(filetime: u64) -> String {
    match filetime_to_unix(filetime) {
        Some(ts) => format_unix_utc(ts),
        None => "N/A".to_owned(),
    }
}

/// Truncate `s` to at most `n` characters (appending `..`) for table output.
fn clip_to(s: &str, n: usize) -> String {
    let len = s.chars().count();
    if len <= n {
        return s.to_owned();
    }
    let keep = n.saturating_sub(2);
    let mut out: String = s.chars().take(keep).collect();
    out.push_str("..");
    out
}

/// One item streamed out of a part walker, in parse order.
enum PegListEvent {
    Header(crate::peg::PegHeaderInfo),
    File(crate::peg::PegFileInfo),
    Done { dirs: u64, fetched: u64 },
    Error(String),
}

/// Print the file-table column header (once, before streaming starts).
fn print_file_header() {
    println!();
    println!(
        "    {:<52} {:>14} {:>14} {:>8}  {}",
        "PATH", "UNCOMP", "COMP", "CRC32", "MODIFIED (UTC)"
    );
    println!(
        "    {:-<52} {:-<14} {:-<14} {:-<8}  {:-<19}",
        "", "", "", "", ""
    );
}

/// Print one streamed file row.
fn print_file_row(f: &crate::peg::PegFileInfo) {
    println!(
        "    {:<52} {:>14} {:>14} {:>08x}  {}",
        clip_to(&f.name, 52),
        format_bytes(f.uncompressed_size),
        format_bytes(f.compressed_size),
        f.crc32,
        format_filetime(f.filetime),
    );
}

/// Fetch and print the file index of every `.pegNN` part in a sting package.
///
/// Each part is parsed on its own thread and its entries are streamed to this
/// thread over a per-part channel, so a file line is printed as soon as its
/// entry is found.  Later parts are parsed concurrently in the background and
/// their (buffered) entries print when their turn comes, keeping the output in
/// part order.
fn list_peg_contents(agent: &ureq::Agent, package: &SetupPackage) -> Result<()> {
    use std::sync::mpsc;

    let parts = &package.parts;
    let count = parts.len();
    println!();
    println!(
        "Reading the file index of {count} .peg part(s) from the CDN \
         (~1 request per file entry); streaming files as they are found ..."
    );

    // One unbounded channel per part: the worker for part `i` pushes entries
    // as it parses them; the printer below consumes them in part order.
    let mut senders = Vec::with_capacity(count);
    let mut receivers = Vec::with_capacity(count);
    for _ in 0..count {
        let (tx, rx) = mpsc::channel::<PegListEvent>();
        senders.push(tx);
        receivers.push(rx);
    }

    let mut total_files = 0u64;
    let mut total_dirs = 0u64;
    let mut total_uncompressed = 0u64;
    let mut total_fetched = 0u64;
    let mut failures: Vec<String> = Vec::new();

    std::thread::scope(|scope| {
        for (idx, part) in parts.iter().enumerate() {
            let tx = senders[idx].clone();
            let url = part.url.clone();
            scope.spawn(move || {
                let result = (|| -> Result<()> {
                    let mut r = HttpRangeReader::new(agent, &url);
                    let dirs = crate::peg::walk_entries(
                        &mut r,
                        &mut |h| {
                            let _ = tx.send(PegListEvent::Header(h.clone()));
                        },
                        &mut |f| {
                            let _ = tx.send(PegListEvent::File(f.clone()));
                        },
                    )
                    .with_context(|| format!("failed to list {url}"))?;
                    let _ = tx.send(PegListEvent::Done {
                        dirs,
                        fetched: r.bytes_fetched(),
                    });
                    Ok(())
                })();
                if let Err(e) = result {
                    let _ = tx.send(PegListEvent::Error(format!("{e:#}")));
                }
            });
        }
        drop(senders); // only the worker clones remain; they close on completion

        print_file_header();

        for cur in 0..count {
            let part = &parts[cur];
            let mut files = 0u64;
            let mut uncompressed = 0u64;
            let mut dirs = 0u64;
            let mut fetched = 0u64;
            let mut failed: Option<String> = None;

            // Drain this part's channel, printing each file as it arrives.
            loop {
                match receivers[cur].recv() {
                    Ok(PegListEvent::Header(h)) => {
                        let size_str = if h.declared_file_size > 0 {
                            format_bytes(h.declared_file_size)
                        } else {
                            "?".to_owned()
                        };
                        let declared_str = if h.declared_uncompressed > 0 {
                            human_size(h.declared_uncompressed)
                        } else {
                            "?".to_owned()
                        };
                        println!();
                        println!(
                            "  [peg {}/{count}] {}  (part {}/{}, part size {}, \
                             declared {declared_str} uncompressed)",
                            cur + 1,
                            part.filename,
                            h.peg_number,
                            h.total_pegs,
                            size_str,
                        );
                    }
                    Ok(PegListEvent::File(f)) => {
                        files += 1;
                        uncompressed += f.uncompressed_size;
                        print_file_row(&f);
                    }
                    Ok(PegListEvent::Done {
                        dirs: d,
                        fetched: ft,
                    }) => {
                        dirs = d;
                        fetched = ft;
                        break;
                    }
                    Ok(PegListEvent::Error(msg)) => {
                        failed = Some(msg);
                        break;
                    }
                    Err(_) => break, // channel closed without a Done event
                }
            }

            match failed {
                Some(msg) => {
                    failures.push(format!("{}: {msg}", part.filename));
                    println!(
                        "  [peg {}/{count}] {}: FAILED - {msg}",
                        cur + 1,
                        part.filename
                    );
                }
                None => {
                    total_files += files;
                    total_dirs += dirs;
                    total_uncompressed += uncompressed;
                    total_fetched += fetched;
                    println!(
                        "  [done] {}: {files} file(s), {dirs} dir(s), {} decompressed \
                         (read {} for the index)",
                        part.filename,
                        human_size(uncompressed),
                        format_bytes(fetched),
                    );
                }
            }
        }
    });

    if !failures.is_empty() {
        println!();
        println!("Failed to read some .peg parts:");
        for f in &failures {
            println!("  {f}");
        }
    }
    println!();
    println!(
        "  Totals: {total_files} file(s), {total_dirs} dir(s), {} decompressed \
         across {count} part(s)",
        human_size(total_uncompressed),
    );
    println!(
        "  Bytes read from the CDN for the indexes: {} (the .peg payloads were \
         skipped, not downloaded).",
        format_bytes(total_fetched),
    );
    if !failures.is_empty() {
        bail!("{} .peg part(s) could not be read", failures.len());
    }
    Ok(())
}

/// Download one whole setup part into `dest_path`, resuming from the bytes
/// already staged in `dest_path.part`.
///
/// The body is streamed to disk (parts can be several GiB), so a transient
/// failure resumes from where it left off via an HTTP `Range` request.  When
/// the server ignores the range (it replies `200` to our `Range` request) the
/// partial file is discarded and the part is re-downloaded from scratch.
/// Returns `Ok(true)` when bytes were downloaded and `Ok(false)` when the
/// destination already held the full expected size.
fn download_setup_part(
    agent: &ureq::Agent,
    url: &str,
    dest_path: &Path,
    expected_size: Option<u64>,
    worker_bar: &ProgressBar,
    total_bar: &ProgressBar,
) -> Result<bool> {
    use std::io::{Seek, SeekFrom, Write};

    if let Some(parent) = dest_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }

    // Already complete → nothing to download.
    if let Some(expected) = expected_size {
        if dest_path.exists()
            && dest_path.metadata().map_or(false, |m| m.len() == expected)
        {
            worker_bar.set_length(expected);
            worker_bar.set_position(expected);
            total_bar.inc(expected);
            return Ok(false);
        }
    }

    let part_file = part_path(dest_path);

    // Resume from whatever the partial file already holds.
    let mut offset = part_file.metadata().map(|m| m.len()).unwrap_or(0);
    if let Some(expected) = expected_size {
        if offset == expected {
            // A previous run finished writing the partial but was interrupted
            // before renaming it into place — just move it now.
            std::fs::rename(&part_file, dest_path).with_context(|| {
                format!(
                    "failed to move {} into place as {}",
                    part_file.display(),
                    dest_path.display()
                )
            })?;
            worker_bar.set_length(expected);
            worker_bar.set_position(expected);
            total_bar.inc(expected);
            return Ok(true);
        }
        if offset > expected {
            // The partial is longer than the real file — start over.
            let _ = std::fs::remove_file(&part_file);
            offset = 0;
        }
    }

    worker_bar.set_length(expected_size.unwrap_or(0));
    worker_bar.set_position(offset);
    worker_bar.set_message(
        dest_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| url.to_owned()),
    );

    const MAX_ATTEMPTS: usize = 8;
    let mut last_err: Option<anyhow::Error> = None;

    for _ in 0..MAX_ATTEMPTS {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&part_file)
            .with_context(|| format!("failed to open {}", part_file.display()))?;
        // Truncate when starting fresh; otherwise just seek to the resume
        // point (the partial already contains `offset` good bytes).
        file.set_len(offset)
            .with_context(|| format!("failed to size {}", part_file.display()))?;
        file.seek(SeekFrom::Start(offset))
            .with_context(|| "seek failed")?;

        // Ask for the remainder when resuming.
        let mut req = agent.get(url);
        if offset > 0 {
            req = req.set("Range", &format!("bytes={offset}-"));
        }
        let resp = match req.call() {
            Ok(r) => r,
            Err(e) => {
                last_err = Some(anyhow!("HTTP request failed: {e}"));
                drop(file);
                continue; // retry from the same offset
            }
        };

        let status = resp.status();
        if offset > 0 && status == 200 {
            // The server ignored our Range header and sent the whole file.
            drop(file);
            let _ = std::fs::remove_file(&part_file);
            offset = 0;
            continue; // restart from scratch
        }
        if status != 200 && status != 206 {
            drop(file);
            bail!("unexpected HTTP status {status} while downloading {url}");
        }

        // Stream the remainder of the body to disk.
        let mut reader = resp.into_reader();
        let mut buf = [0u8; 256 * 1024];
        let mut complete = false;
        loop {
            match reader.read(&mut buf) {
                Ok(0) => {
                    complete = true;
                    break;
                }
                Ok(n) => {
                    if let Err(e) = file.write_all(&buf[..n]) {
                        last_err = Some(e.into());
                        break;
                    }
                    offset += n as u64;
                    worker_bar.inc(n as u64);
                    total_bar.inc(n as u64);
                }
                Err(e) => {
                    last_err = Some(e.into());
                    break;
                }
            }
        }
        drop(file);

        if !complete {
            continue; // retry from the (updated) offset
        }

        if let Some(expected) = expected_size {
            if offset != expected {
                last_err = Some(anyhow!(
                    "size mismatch for {}: expected {expected} bytes, got {offset}",
                    dest_path.display()
                ));
                continue; // resume from `offset` to fetch the remainder
            }
        }

        std::fs::rename(&part_file, dest_path).with_context(|| {
            format!(
                "failed to move {} into place as {}",
                part_file.display(),
                dest_path.display()
            )
        })?;
        return Ok(true);
    }

    Err(last_err.unwrap_or_else(|| anyhow!("failed to download {url}")))
}

/// Number of byte-range segments each setup part is split into when it is
/// downloaded in default (non-streamed) mode.
const PART_SEGMENTS: usize = 5;

/// How many setup parts are downloaded at once.  Every active part fetches its
/// `PART_SEGMENTS` ranges on its own threads, so the total number of
/// concurrent connections is `PART_SEGMENTS * PARTS_IN_PARALLEL` (= 10).
const PARTS_IN_PARALLEL: usize = 2;

/// Split `size` bytes into `segments` contiguous `(start, end)` ranges; the
/// final range absorbs any remainder so the ranges exactly cover `[0, size)`
/// with no gaps or overlaps.
fn segment_ranges(size: u64, segments: usize) -> Vec<(u64, u64)> {
    (0..segments)
        .map(|i| {
            (
                size * i as u64 / segments as u64,
                size * (i + 1) as u64 / segments as u64,
            )
        })
        .collect()
}

/// Ask the server whether it honours byte ranges and, if so, the full size of
/// `url`, using a tiny `Range: bytes=0-0` request.
///
/// Returns `Some(total_size)` when the server answers `206` (ranges work) and
/// `None` when it answers `200` (the range header was ignored — the caller
/// must fall back to a single sequential stream).
fn probe_range_size(agent: &ureq::Agent, url: &str) -> Result<Option<u64>> {
    let resp = agent
        .get(url)
        .set("Range", "bytes=0-0")
        .call()
        .with_context(|| format!("failed to probe {url}"))?;
    match resp.status() {
        206 => {
            let cr = resp
                .header("Content-Range")
                .ok_or_else(|| anyhow!("206 response without Content-Range for {url}"))?;
            let total = cr
                .rsplit('/')
                .next()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .ok_or_else(|| anyhow!("cannot parse Content-Range {cr:?} for {url}"))?;
            Ok(Some(total))
        }
        200 => Ok(None),
        status => bail!("unexpected HTTP status {status} while probing {url}"),
    }
}

/// Download one whole setup part with a single sequential stream (the fallback
/// when a part's size is unknown or the server does not support ranges).
///
/// Delegates to [`download_setup_part`] with a hidden worker bar (progress is
/// folded into the overall `total_pb`).
fn download_part_single(
    agent: &ureq::Agent,
    url: &str,
    dest_path: &Path,
    expected: Option<u64>,
    total_pb: &ProgressBar,
) -> Result<bool> {
    let hidden = ProgressBar::new(0);
    hidden.set_draw_target(ProgressDrawTarget::hidden());
    download_setup_part(agent, url, dest_path, expected, &hidden, total_pb)
}

/// Download one setup part into `target_dir` (as `target_dir/<filename>`).
///
/// Prefers the segmented path: the part is split into [`PART_SEGMENTS`]
/// byte-range requests that run concurrently (see [`download_part_segmented`]).
/// Falls back to a single sequential stream when the exact size cannot be
/// determined or the server ignores `Range`.  Returns `Ok(true)` when bytes
/// were written, `Ok(false)` when the part was already present.
fn download_one_part(
    agent: &ureq::Agent,
    part: &SetupPart,
    target_dir: &Path,
    total_pb: &ProgressBar,
) -> Result<bool> {
    let dest_path = target_dir.join(&part.filename);
    if let Some(parent) = dest_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }

    // Already fully downloaded → skip (bytes counted so the total bar adds up),
    // and clear any stray staging/sidecar files left next to it.
    if let Some(expected) = part.size {
        if expected > 0
            && dest_path.exists()
            && dest_path.metadata().map_or(false, |m| m.len() == expected)
        {
            let staged = part_path(&dest_path);
            crate::resume::delete_progress(&staged, &crate::resume::SIDECAR_PEG);
            let _ = std::fs::remove_file(&staged);
            total_pb.inc(expected);
            return Ok(false);
        }
    }

    // Segmenting needs the exact size.  The manifest usually gives it (NFO) or
    // a HEAD request resolved it (sting); probe as a last resort.
    let size = match part.size {
        Some(s) if s > 0 => s,
        Some(_) => {
            return download_part_single(agent, &part.url, &dest_path, Some(0), total_pb)
        }
        None => match probe_range_size(agent, &part.url)? {
            Some(s) if s > 0 => s,
            _ => {
                return download_part_single(agent, &part.url, &dest_path, None, total_pb)
            }
        },
    };

    download_part_segmented(agent, &part.url, &dest_path, size, total_pb)
}

/// Download `size` bytes of `url` into `dest_path` (the final part name),
/// splitting the file into [`PART_SEGMENTS`] contiguous byte ranges that are
/// fetched concurrently.
///
/// Bytes are staged in `dest_path.part` (pre-allocated to `size`) with a
/// `.nxdlseg` sidecar recording which ranges are already on disk, so an
/// interrupted download resumes exactly the missing ranges.  When every range
/// is written the staged file is renamed over `dest_path` and the sidecar is
/// deleted.
fn download_part_segmented(
    agent: &ureq::Agent,
    url: &str,
    dest_path: &Path,
    size: u64,
    total_pb: &ProgressBar,
) -> Result<bool> {
    use std::sync::{Arc, Mutex};

    let part_file = part_path(dest_path); // staging: `<name>.pegNN.part`
    let sidecar = crate::resume::progress_path(&part_file, &crate::resume::SIDECAR_PEG);

    // Contiguous `[start, end)` ranges, one per segment.
    let ranges = segment_ranges(size, PART_SEGMENTS);

    // Completion state carried over from a previous run's sidecar.
    let mut done: Vec<bool> = vec![false; PART_SEGMENTS];
    if let Some((bitmap, saved_objs, saved_size)) =
        crate::resume::read_progress(&sidecar, &crate::resume::SIDECAR_PEG)
    {
        if saved_objs as usize == PART_SEGMENTS && saved_size == size {
            done = bitmap.into_iter().map(|b| b != 0).collect();
        } else {
            // Stale sidecar (different segment count / size) → restart.
            crate::resume::delete_progress(&part_file, &crate::resume::SIDECAR_PEG);
            let _ = std::fs::remove_file(&part_file);
        }
    } else if part_file.exists() {
        // No sidecar.  A full-size staging file means every range was already
        // written and we only crashed before renaming — finish it now.
        // Anything shorter is a stale leftover and is discarded.
        if part_file.metadata().map_or(false, |m| m.len() == size) {
            std::fs::rename(&part_file, dest_path).with_context(|| {
                format!(
                    "failed to move {} into place as {}",
                    part_file.display(),
                    dest_path.display()
                )
            })?;
            total_pb.inc(size);
            return Ok(true);
        }
        let _ = std::fs::remove_file(&part_file);
    }

    // Resuming but the staging file is gone / the wrong size → restart.
    if done.iter().any(|&b| b)
        && !(part_file.exists()
            && part_file.metadata().map_or(false, |m| m.len() == size))
    {
        crate::resume::delete_progress(&part_file, &crate::resume::SIDECAR_PEG);
        let _ = std::fs::remove_file(&part_file);
        done = vec![false; PART_SEGMENTS];
    }

    // No completed ranges → build a fresh full-size staging file + sidecar.
    if !done.iter().any(|&b| b) {
        crate::resume::delete_progress(&part_file, &crate::resume::SIDECAR_PEG);
        let _ = std::fs::remove_file(&part_file);
        let file = std::fs::File::create(&part_file)
            .with_context(|| format!("failed to create {}", part_file.display()))?;
        file.set_len(size)
            .with_context(|| format!("failed to size {}", part_file.display()))?;
        crate::resume::create_progress(
            &part_file,
            PART_SEGMENTS as u32,
            size,
            &crate::resume::SIDECAR_PEG,
        )
        .with_context(|| format!("failed to create sidecar {}", sidecar.display()))?;
    }

    // Account for ranges already on disk so the overall bar reflects them now.
    let resumed = done.iter().filter(|&&b| b).count();
    for (i, &b) in done.iter().enumerate() {
        if b {
            let (s, e) = ranges[i];
            total_pb.inc(e - s);
        }
    }
    if resumed > 0 {
        println!(
            "  {}: resuming ({resumed}/{} ranges already on disk)",
            dest_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| dest_path.display().to_string()),
            PART_SEGMENTS
        );
    }

    // Fetch the missing ranges concurrently (one thread per range).
    let mark = Arc::new(Mutex::new(()));
    let results: Vec<Result<()>> = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for i in 0..PART_SEGMENTS {
            if done[i] {
                continue;
            }
            let (start, end) = ranges[i];
            let agent = agent.clone();
            let part_file = part_file.clone();
            let pb = total_pb.clone();
            let mark = Arc::clone(&mark);
            handles.push(scope.spawn(move || {
                fetch_range(&agent, url, start, end, &part_file, i, &pb, mark)
            }));
        }
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for r in results {
        r.with_context(|| {
            format!("failed to download ranges of {}", dest_path.display())
        })?;
    }

    // Every range is on disk: drop the sidecar and move the part into place.
    crate::resume::delete_progress(&part_file, &crate::resume::SIDECAR_PEG);
    std::fs::rename(&part_file, dest_path).with_context(|| {
        format!(
            "failed to move {} into place as {}",
            part_file.display(),
            dest_path.display()
        )
    })?;
    Ok(true)
}

/// Fetch one byte range `[start, end)` of `url` and write it into `part_file`
/// at the same offset (the file is pre-allocated).  Once the whole range is on
/// disk it is marked done in the part's sidecar (under `mark`, so concurrent
/// writers do not clobber each other's sidecar updates).  Retries a few times
/// on transient failures.
fn fetch_range(
    agent: &ureq::Agent,
    url: &str,
    start: u64,
    end: u64,
    part_file: &Path,
    seg_index: usize,
    total_pb: &ProgressBar,
    mark: std::sync::Arc<std::sync::Mutex<()>>,
) -> Result<()> {
    use std::io::{Seek, SeekFrom, Write};

    if start == end {
        return Ok(());
    }
    let want = end - start;
    const ATTEMPTS: usize = 8;
    let mut last_err: Option<anyhow::Error> = None;

    for _ in 0..ATTEMPTS {
        let resp = match agent
            .get(url)
            .set("Range", &format!("bytes={start}-{}", end - 1))
            .call()
        {
            Ok(r) => r,
            Err(e) => {
                last_err = Some(anyhow!("HTTP request failed: {e}"));
                continue;
            }
        };
        match resp.status() {
            206 => {}
            200 => {
                bail!(
                    "server ignored the Range request for {url}; cannot fetch \
                     segment {seg_index} of {start}-{end}"
                );
            }
            status => {
                bail!("unexpected HTTP status {status} for range {start}-{end} of {url}");
            }
        }

        let mut file = match std::fs::OpenOptions::new().write(true).open(part_file) {
            Ok(f) => f,
            Err(e) => {
                last_err = Some(e.into());
                continue;
            }
        };
        if let Err(e) = file.seek(SeekFrom::Start(start)) {
            last_err = Some(e.into());
            continue;
        }
        let mut reader = resp.into_reader();
        let mut buf = [0u8; 256 * 1024];
        let mut got: u64 = 0;
        let mut failed = false;
        while got < want {
            match reader.read(&mut buf) {
                Ok(0) => break, // connection ended early
                Ok(n) => {
                    let take = ((want - got) as usize).min(n);
                    if let Err(e) = file.write_all(&buf[..take]) {
                        last_err = Some(e.into());
                        failed = true;
                        break;
                    }
                    got += take as u64;
                    total_pb.inc(take as u64);
                    if take < n {
                        break; // server sent more than requested; we have it all
                    }
                }
                Err(e) => {
                    last_err = Some(anyhow!("read error: {e}"));
                    failed = true;
                    break;
                }
            }
        }
        drop(file);
        if failed {
            continue;
        }
        if got == want {
            let _g = mark.lock().unwrap();
            crate::resume::mark_done(part_file, seg_index as u32, &crate::resume::SIDECAR_PEG)?;
            return Ok(());
        }
        last_err = Some(anyhow!("short read: got {got} of {want} bytes"));
    }

    Err(last_err.unwrap_or_else(|| anyhow!("failed to fetch segment {seg_index} of {url}")))
}

/// Download every part of a setup package into `target_dir`, showing an
/// overall progress bar.  Parts are processed a few at a time
/// ([`PARTS_IN_PARALLEL`]) and each part is split into [`PART_SEGMENTS`]
/// concurrent byte-range downloads, so up to
/// `PART_SEGMENTS * PARTS_IN_PARALLEL` (10) connections run at once.  An
/// interrupted part resumes from the ranges already staged (`.part` +
/// `.nxdlseg` sidecar).  Bails only if a part could not be fetched
/// (already-present parts are reported as skipped).
fn download_parts(
    agent: &ureq::Agent,
    parts: &[SetupPart],
    target_dir: &Path,
    total_size: u64,
) -> Result<()> {
    // ---- Progress bars (overall only; per-part lines go to stdout) ----
    let mp = MultiProgress::new();
    // Hide bars when stdout is not a terminal (piped / redirected).
    if !std::io::stdout().is_terminal() {
        mp.set_draw_target(ProgressDrawTarget::hidden());
    }
    let total_pb = mp.add(ProgressBar::new(total_size));
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
    let mut _taskbar = crate::taskprogress::watch(total_pb.clone(), total_size);

    let mut downloaded = 0usize;
    let mut skipped = 0usize;
    let mut failures: Vec<String> = Vec::new();

    let mut queue: &[SetupPart] = parts;
    while !queue.is_empty() {
        let batch = &queue[..queue.len().min(PARTS_IN_PARALLEL)];
        queue = &queue[batch.len()..];

        let results: Vec<Result<bool>> = std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for part in batch {
                let agent = agent.clone();
                let pb = total_pb.clone();
                handles.push(scope.spawn(move || {
                    download_one_part(&agent, part, target_dir, &pb)
                }));
            }
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });

        for (r, part) in results.into_iter().zip(batch.iter()) {
            match r {
                Ok(true) => {
                    downloaded += 1;
                    println!("  {}: downloaded", part.filename);
                }
                Ok(false) => {
                    skipped += 1;
                    println!("  {}: already present", part.filename);
                }
                Err(e) => failures.push(format!("{}: {e:#}", part.filename)),
            }
        }
    }

    total_pb.finish_and_clear();
    _taskbar.finish();

    let failed = failures.len();
    println!();
    println!(
        "Done: {downloaded} part(s) downloaded, {skipped} already present, \
         {failed} failed."
    );
    if !failures.is_empty() {
        for f in &failures {
            println!("  {f}");
        }
        bail!("{failed} part(s) failed to download");
    }
    Ok(())
}

/// Name of the sub-folder (under the download target) that a `.sting` client
/// is extracted into: the leading token of the sting's part base name
/// (e.g. `MapleStoryM_2.430.6284_Live_1717` → `MapleStoryM`), falling back to
/// `game`.
fn sting_game_dir_name(package: &SetupPackage) -> String {
    package
        .sting
        .as_ref()
        .and_then(|s| s.sting_name.split('_').next())
        .filter(|t| !t.is_empty())
        .unwrap_or("game")
        .to_owned()
}

// ---------------------------------------------------------------------------
// `.incomplete` install marker (pipelined default-mode `.sting` install)
// ---------------------------------------------------------------------------

/// Path of the `.incomplete` install marker for a `.sting` download:
/// `target_dir/.incomplete`.  Its presence means the download/install is not
/// finished yet; it lists, one PEG part file name per line, the parts that
/// have already finished downloading AND installing.  It is removed once every
/// part is done.
fn incomplete_marker_path(target_dir: &Path) -> std::path::PathBuf {
    target_dir.join(".incomplete")
}

/// Read the parts already fully installed from the `.incomplete` marker
/// (empty when the marker is absent).
fn read_installed_parts(marker: &Path) -> Vec<String> {
    std::fs::read_to_string(marker)
        .map(|s| {
            s.lines()
                .map(|l| l.trim().to_owned())
                .filter(|l| !l.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Record `filename` as fully downloaded + installed by (re)writing the
/// `.incomplete` marker with it included.  Concurrent calls must be
/// serialised by the caller (workers share a mutex).
fn mark_part_installed(marker: &Path, filename: &str) {
    let mut names = read_installed_parts(marker);
    if !names.iter().any(|n| n == filename) {
        names.push(filename.to_owned());
    }
    if let Err(e) = std::fs::write(marker, names.join("\n") + "\n") {
        eprintln!(
            "warning: failed to write install marker {}: {e}",
            marker.display()
        );
    }
}

/// Remove the `.incomplete` marker once every part is installed.
fn clear_incomplete_marker(marker: &Path) {
    let _ = std::fs::remove_file(marker);
}

/// True when `dir` exists and contains at least one entry.
fn dir_has_entries(dir: &Path) -> bool {
    std::fs::read_dir(dir)
        .map(|mut it| it.next().is_some())
        .unwrap_or(false)
}

/// Download one part (if its `.pegNN` is not already fully on disk), extract
/// it into `game_dir`, then delete the part file.
///
/// Runs on a worker thread so its extraction overlaps other parts that are
/// still downloading.  The part is recorded in the `.incomplete` marker (under
/// `marker_lock`) only after extraction succeeds; if extraction fails the
/// `.pegNN` file is left in place and not recorded, so a re-run only retries
/// that part.
fn install_one_part(
    agent: &ureq::Agent,
    part: &SetupPart,
    target_dir: &Path,
    game_dir: &Path,
    marker: &Path,
    marker_lock: &std::sync::Mutex<()>,
    total_pb: &ProgressBar,
) -> Result<crate::peg::PegStats> {
    let dest = target_dir.join(&part.filename);

    download_one_part(agent, part, target_dir, total_pb)
        .with_context(|| format!("failed to download {}", part.filename))?;

    let stats = crate::peg::extract_peg_local(&dest, game_dir, false)
        .with_context(|| format!("failed to extract {}", part.filename))?;

    // Record first, then reclaim the part file: if we crash in between, the
    // part is already marked done (a leftover `.pegNN` is cleaned up at the
    // end of the install).
    {
        let _g = marker_lock.lock().unwrap();
        mark_part_installed(marker, &part.filename);
    }
    if let Err(e) = std::fs::remove_file(&dest) {
        eprintln!("warning: failed to delete {}: {e}", dest.display());
    }
    Ok(stats)
}

/// Default (non-`--streamed`) `.sting` install: download the `.pegNN` parts
/// into `target_dir` and extract each one into `target_dir/<game>` as soon as
/// that part's download finishes, so extraction overlaps the parts that are
/// still downloading (pipelined; up to [`PARTS_IN_PARALLEL`] parts download at
/// once, each split into [`PART_SEGMENTS`] byte ranges).  Each part is
/// verified (size + CRC-32) on extraction and its `.pegNN` file is deleted
/// immediately afterwards.
///
/// Progress is recorded in a `target_dir/.incomplete` marker that lists which
/// parts have finished download + install, so an interrupted run resumes only
/// the parts that are not yet done (and a fully installed client is never
/// re-downloaded).  The marker is removed once every part is done.
fn download_then_extract_sting(
    agent: &ureq::Agent,
    target_dir: &Path,
    package: &SetupPackage,
) -> Result<()> {
    let game_dir = target_dir.join(sting_game_dir_name(package));
    let marker = incomplete_marker_path(target_dir);
    let total = package.parts.len();

    std::fs::create_dir_all(target_dir).with_context(|| {
        format!(
            "failed to create target directory {}",
            target_dir.display()
        )
    })?;

    let installed = read_installed_parts(&marker);

    // No marker at all → either the client was fully installed earlier (the
    // marker is removed on completion) or this is a fresh start.
    if installed.is_empty() && !marker.exists() {
        if dir_has_entries(&game_dir) {
            println!();
            println!(
                "{} already contains an installed game (no `.incomplete` \
                 marker present). Delete it to reinstall.",
                game_dir.display()
            );
            return Ok(());
        }
    }

    // Only the parts not yet marked as fully installed need work.
    let pending: Vec<&SetupPart> = package
        .parts
        .iter()
        .filter(|p| !installed.iter().any(|n| n == &p.filename))
        .collect();

    if pending.is_empty() {
        clear_incomplete_marker(&marker);
        println!();
        println!(
            "Already installed into {} ({total} part(s)).",
            game_dir.display()
        );
        return Ok(());
    }

    let resumed = installed.len();
    let count = pending.len();
    let pending_size: u64 = pending.iter().filter_map(|p| p.size).sum();

    println!();
    if resumed > 0 {
        println!(
            "Resuming: {resumed}/{total} part(s) already downloaded and installed."
        );
    }
    println!(
        "Downloading and installing {count} .peg part(s) into {} ...",
        target_dir.display()
    );

    // Overall progress bar for the bytes still to be downloaded.
    let mp = MultiProgress::new();
    if !std::io::stdout().is_terminal() {
        mp.set_draw_target(ProgressDrawTarget::hidden());
    }
    let total_pb = mp.add(ProgressBar::new(pending_size));
    total_pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] \
             {bytes}/{total_bytes} ({binary_bytes_per_sec}, ETA {eta})",
        )
        .unwrap()
        .progress_chars("=>-"),
    );
    total_pb.enable_steady_tick(Duration::from_millis(120));
    let mut _taskbar = crate::taskprogress::watch(total_pb.clone(), pending_size);

    let marker_lock = std::sync::Arc::new(std::sync::Mutex::new(()));
    let mut total_files = 0u64;
    let mut total_dirs = 0u64;
    let mut total_bytes = 0u64;
    let mut failures: Vec<String> = Vec::new();

    // References (Copy) so the per-part worker closures can share them without
    // moving the owning PathBufs into the first spawned thread.
    let marker_ref: &Path = &marker;
    let game_dir_ref: &Path = &game_dir;

    // Process pending parts in small batches: each worker downloads its part
    // (5 parallel ranges), then extracts + deletes it — overlapping with the
    // sibling part that is still downloading.
    let mut queue: &[&SetupPart] = &pending;
    while !queue.is_empty() {
        let batch = &queue[..queue.len().min(PARTS_IN_PARALLEL)];
        queue = &queue[batch.len()..];

        let outcomes: Vec<(String, Result<crate::peg::PegStats>)> =
            std::thread::scope(|scope| {
                let mut handles = Vec::new();
                for part in batch.iter().copied() {
                    let agent = agent.clone();
                    let pb = total_pb.clone();
                    let lock = std::sync::Arc::clone(&marker_lock);
                    handles.push(scope.spawn(move || {
                        let r = install_one_part(
                            &agent,
                            part,
                            target_dir,
                            game_dir_ref,
                            marker_ref,
                            &lock,
                            &pb,
                        );
                        (part.filename.clone(), r)
                    }));
                }
                handles.into_iter().map(|h| h.join().unwrap()).collect()
            });

        for (filename, result) in outcomes {
            match result {
                Ok(stats) => {
                    total_files += stats.files;
                    total_dirs += stats.dirs;
                    total_bytes += stats.uncompressed_bytes;
                    let skipped = if stats.skipped_files > 0 {
                        format!(", {} skipped (CRC ok)", stats.skipped_files)
                    } else {
                        String::new()
                    };
                    println!(
                        "  {filename}: {} file(s){}, {} dir(s), {:.2} GiB \
                         decompressed; part deleted",
                        stats.files,
                        skipped,
                        stats.dirs,
                        stats.uncompressed_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
                    );
                }
                Err(e) => failures.push(format!("{filename}: {e:#}")),
            }
        }
    }

    total_pb.finish_and_clear();
    _taskbar.finish();

    println!();
    if !failures.is_empty() {
        println!("Failed parts (kept on disk for retry):");
        for f in &failures {
            println!("  {f}");
        }
        println!(
            "Note: fully installed parts are recorded in {}; re-run to finish \
             the remaining part(s).",
            marker.display()
        );
        bail!("{} part(s) failed to install", failures.len());
    }

    // Everything is installed: drop the marker and clean any stray `.pegNN`
    // that a crash may have left behind after a part was recorded.
    clear_incomplete_marker(&marker);
    for part in &package.parts {
        let _ = std::fs::remove_file(target_dir.join(&part.filename));
    }

    println!(
        "Installed {} file(s) in {} dir(s) ({} bytes decompressed) into {}",
        total_files,
        total_dirs,
        format_bytes(total_bytes),
        game_dir.display()
    );
    println!(
        "All file CRC-32 checks passed; each .peg part was deleted as soon as \
         it was extracted."
    );
    Ok(())
}

/// Download a setup-package client (no `manifest_name`): fetch the
/// `.sting`/`.nfo` manifest from `setup_file_url` and install the client into
/// `target_dir`.
///
/// `.sting` PEG packages install two ways:
/// - default (`streamed == false`): download the `.pegNN` parts into
///   `target_dir`, extract them into a sub-folder of it, then delete the
///   parts;
/// - `--streamed`: download + extract in one pass from the CDN (no part file
///   kept on disk).
///
/// `.nfo` split archives are downloaded first (their extraction is not
/// implemented yet).
fn download_ngm_setup(
    appid: &str,
    target_dir: &Path,
    info: &GameInfo,
    agent: &ureq::Agent,
    streamed: bool,
) -> Result<()> {
    let mut package = fetch_setup_package(agent, &info.setup_file_url)?;

    // The `.sting` format does not list per-part sizes, so ask each server for
    // its `Content-Length` (best-effort) to show accurate progress.
    resolve_part_sizes(agent, &mut package.parts);

    let archive_count = package.parts.len();
    let total_size = setup_total_size(&package);
    let unknown = package.parts.iter().filter(|p| p.size.is_none()).count();

    println!("Game:         {}", info.game_name);
    println!("Product:      {appid}");
    println!("Setup type:   {}", package.format);
    println!("Setup file:   {}", package.url);
    if let Some(ref raw) = package.release_date_raw {
        println!("Release date: {raw}");
    }
    if let Some(ref sting) = package.sting {
        if let Some(ts) = sting.time_stamp {
            println!("Time stamp:   {ts}");
        }
    }
    println!("Parts:        {archive_count}");
    if unknown > 0 {
        println!("  (size of {unknown} part(s) unknown)");
    }
    println!(
        "Total size:   {:.2} GiB ({} bytes)",
        total_size as f64 / (1024.0 * 1024.0 * 1024.0),
        format_bytes(total_size),
    );
    if archive_count == 0 {
        println!("Nothing to download.");
        return Ok(());
    }

    std::fs::create_dir_all(target_dir).with_context(|| {
        format!(
            "failed to create target directory {}",
            target_dir.display()
        )
    })?;

    // `.sting` packages: with `--streamed` they install straight from the CDN
    // stream (no part kept on disk); by default the `.pegNN` parts are
    // downloaded into `target_dir` first, then extracted from disk and deleted.
    if package.format == "sting" {
        if streamed {
            return stream_extract_sting(agent, target_dir, &package);
        }
        return download_then_extract_sting(agent, target_dir, &package);
    }

    // `.nfo` packages are downloaded as `.zNN` split archives (their
    // extraction is not implemented yet).
    println!(
        "Downloading {} archive(s) into {} ...",
        archive_count,
        target_dir.display()
    );
    download_parts(agent, &package.parts, target_dir, total_size)?;
    println!("Downloaded setup archives to: {}", target_dir.display());
    println!(
        "note: extracting the downloaded `.nfo` archives into the game tree \
         is not implemented yet."
    );

    Ok(())
}

/// A `Read` wrapper that feeds the downloaded-byte count into the progress
/// bars while a `.pegNN` part is streamed off the CDN.
struct DownloadProgressRead<'a, R: Read> {
    inner: R,
    worker: &'a ProgressBar,
    total: &'a ProgressBar,
}

impl<R: Read> Read for DownloadProgressRead<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.worker.inc(n as u64);
            self.total.inc(n as u64);
        }
        Ok(n)
    }
}

/// Path of the tiny resume marker that records how far a `.pegNN` part has
/// been installed (byte offset of the next entry).  Only this offset is ever
/// kept — never the part itself.
fn peg_checkpoint_path(output_dir: &Path, part: &SetupPart) -> std::path::PathBuf {
    output_dir.join(format!(".{}.nxdlckpt", part.filename))
}

fn write_checkpoint(path: &Path, offset: u64) {
    if let Err(e) = std::fs::write(path, offset.to_string()) {
        eprintln!("warning: failed to write resume marker {}: {e}", path.display());
    }
}

fn read_checkpoint(path: &Path) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn clear_checkpoint(path: &Path) {
    let _ = std::fs::remove_file(path);
}

/// Stream-download and install a single `.pegNN` part, resuming where a
/// previous attempt left off.
///
/// The part body is streamed from the CDN into
/// [`crate::peg::extract_peg_install`], which decompresses each file into
/// `output_dir` (verifying size + CRC-32) and skips any file whose target
/// already exists with the expected CRC-32.  A tiny `.nxdlckpt` marker records
/// the byte offset of the *next* entry after every handled file, so if the
/// stream breaks the part is re-fetched with an HTTP `Range` request starting
/// at that offset — already-installed files are not re-downloaded.  The
/// `.pegNN` part itself is never stored.
fn stream_extract_part(
    agent: &ureq::Agent,
    part: &SetupPart,
    output_dir: &Path,
    worker: &ProgressBar,
    total: &ProgressBar,
) -> Result<crate::peg::PegStats> {
    const ATTEMPTS: usize = 8;
    let mut last_err: Option<anyhow::Error> = None;
    let checkpoint = peg_checkpoint_path(output_dir, part);

    for attempt in 1..=ATTEMPTS {
        // Where to resume: the offset right after the last fully-installed
        // entry (from a previous run or a failed attempt in this run).
        let start_at = read_checkpoint(&checkpoint).unwrap_or(0);
        if let Some(size) = part.size {
            if size > 0 && start_at >= size {
                // This part was fully installed earlier; nothing left to do.
                clear_checkpoint(&checkpoint);
                return Ok(crate::peg::PegStats::default());
            }
        }

        worker.set_position(start_at.min(part.size.unwrap_or(0)));
        worker.set_message(if attempt > 1 {
            format!("{} (attempt {attempt}, resuming at byte {start_at})", part.filename)
        } else if start_at > 0 {
            format!("{} (resuming at byte {start_at})", part.filename)
        } else {
            part.filename.clone()
        });

        let mut req = agent.get(&part.url);
        if start_at > 0 {
            req = req.set("Range", &format!("bytes={start_at}-"));
        }
        let resp = match req.call() {
            Ok(r) => r,
            Err(e) => {
                last_err = Some(anyhow!("HTTP request failed: {e}"));
                continue;
            }
        };

        let status = resp.status();
        if start_at > 0 && status == 200 {
            // The server ignored our Range request — fall back to downloading
            // the whole part again from the beginning.
            clear_checkpoint(&checkpoint);
            continue;
        }
        if status != 200 && status != 206 {
            last_err = Some(anyhow!("unexpected HTTP status {status}"));
            continue;
        }

        let body = DownloadProgressRead {
            inner: resp.into_reader(),
            worker,
            total,
        };
        let mut buffered = std::io::BufReader::new(body);

        let result = crate::peg::extract_peg_install(
            &mut buffered,
            output_dir,
            start_at,
            |next| write_checkpoint(&checkpoint, next),
        );

        match result {
            Ok(stats) => {
                clear_checkpoint(&checkpoint);
                return Ok(stats);
            }
            Err(e) => {
                // The marker now points at the first entry that was not fully
                // installed; the next attempt (or a later run) resumes there.
                last_err = Some(e);
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow!("failed to install {}", part.filename)))
}

/// Stream-install a `.sting` client: every `.pegNN` part is downloaded and
/// extracted straight into `target_dir` in one pass, verifying each file's
/// CRC-32.  No `.pegNN` file is stored on disk.
fn stream_extract_sting(
    agent: &ureq::Agent,
    target_dir: &Path,
    package: &SetupPackage,
) -> Result<()> {
    let parts = &package.parts;
    let count = parts.len();
    let total_size = setup_total_size(package);
    println!();
    println!(
        "Stream-installing {count} .peg part(s) into {} (no part files stored) ...",
        target_dir.display()
    );

    let mp = MultiProgress::new();
    // Hide bars when stdout is not a terminal (piped / redirected).
    if !std::io::stdout().is_terminal() {
        mp.set_draw_target(ProgressDrawTarget::hidden());
    }
    let total_pb = mp.add(ProgressBar::new(total_size));
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
    let mut _taskbar = crate::taskprogress::watch(total_pb.clone(), total_size);

    let worker_pb = mp.add(ProgressBar::new(0));
    worker_pb.set_style(
        ProgressStyle::with_template(
            "  [{bar:25.green/white}] {bytes:>10}/{total_bytes:>10} \
             ({binary_bytes_per_sec:>11}) {wide_msg}",
        )
        .unwrap()
        .progress_chars("=>-"),
    );
    worker_pb.enable_steady_tick(Duration::from_millis(120));

    let mut total_files = 0u64;
    let mut total_skipped = 0u64;
    let mut total_bytes = 0u64;
    let mut failures: Vec<String> = Vec::new();

    for (idx, part) in parts.iter().enumerate() {
        let part_size = part.size.unwrap_or(0);
        worker_pb.set_length(part_size);
        worker_pb.set_message(part.filename.clone());
        worker_pb.set_position(0);

        match stream_extract_part(agent, part, target_dir, &worker_pb, &total_pb) {
            Ok(stats) => {
                total_files += stats.files;
                total_skipped += stats.skipped_files;
                total_bytes += stats.uncompressed_bytes;
                let skipped = if stats.skipped_files > 0 {
                    format!(", {} skipped (CRC ok)", stats.skipped_files)
                } else {
                    String::new()
                };
                println!(
                    "  [peg {}/{count}] {}: {} file(s){}, {} dir(s), {} decompressed",
                    idx + 1,
                    part.filename,
                    stats.files,
                    skipped,
                    stats.dirs,
                    human_size(stats.uncompressed_bytes),
                );
            }
            Err(e) => failures.push(format!("{}: {:#}", part.filename, e)),
        }
    }

    worker_pb.finish_and_clear();
    total_pb.finish_and_clear();
    _taskbar.finish();

    println!();
    if !failures.is_empty() {
        println!("Failed parts:");
        for f in &failures {
            println!("  {f}");
        }
        println!(
            "Note: installed files were kept; re-run to finish. Each failed part \
             resumes from where it stopped (Range request), so already-installed \
             files are not re-downloaded."
        );
        bail!("{} part(s) failed to install", failures.len());
    }
    let skipped_note = if total_skipped > 0 {
        format!(", {} skipped (already present)", total_skipped)
    } else {
        String::new()
    };
    println!(
        "Installed {total_files} file(s){skipped_note} ({total_bytes} bytes \
         decompressed) into {}",
        target_dir.display()
    );
    println!("All file CRC-32 checks passed; no .peg part files were stored.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Download: shared fetch & manifest helpers
// ---------------------------------------------------------------------------

/// Fetch and parse the game-info response for `appid`.
fn fetch_game_info(agent: &ureq::Agent, appid: &str) -> Result<GameInfo> {
    let info_url = format!("https://ngmapi.nexon.com/game-info/{appid}");
    let info_json = http_get_string(agent, &info_url)
        .with_context(|| format!("failed to fetch game info from {info_url}"))?;
    serde_json::from_str(&info_json).context("failed to parse game-info response")
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
    streamed: bool,
) -> Result<()> {
    // ---- Step 1: fetch game info ----
    let agent = agent(allow_insecure, proxy);
    let info = fetch_game_info(&agent, appid)?;

    // No `manifest_name`: the game is distributed as a setup package whose
    // `.sting` / `.nfo` manifest sits at `setup_file_url`.  Download its parts.
    if info.manifest_name.is_none() {
        return download_ngm_setup(appid, target_dir, &info, &agent, streamed);
    }

    // ---- Step 2: download & parse the per-file patch manifest ----
    let setup_base = info.setup_file_url.trim_end_matches('/').to_owned();
    let manifest_name = info.manifest_name.as_deref().unwrap();
    let manifest_url = format!("{setup_base}/{manifest_name}");
    let manifest_json = http_get_string(&agent, &manifest_url)
        .with_context(|| format!("failed to fetch manifest from {manifest_url}"))?;
    let manifest: NgmManifest =
        serde_json::from_str(&manifest_json).context("failed to parse manifest JSON")?;

    println!("Game:         {}", info.game_name);
    println!("Manifest URL: {setup_base}/{manifest_name}");
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
            let dir_path = crate::relpath::join(target_dir, &rel_path);
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

                    let dest_path = crate::relpath::join(target_dir, &entry.rel_path);

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
    /// Decoded, human-readable path (also the on-disk patch file name).
    decoded_path: String,
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
            entry.decoded_path,
            entry.uncompressed_size,
            out.len()
        );
    }

    std::fs::write(dest_path, &out)
        .with_context(|| format!("failed to write patch file {}", dest_path.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Patch: applying .nxdlpatch files
// ---------------------------------------------------------------------------

/// Copy exactly `count` bytes from `src` to `dst`, using `buf` as scratch
/// space.
fn copy_bytes<R: std::io::Read, W: std::io::Write>(
    src: &mut R,
    dst: &mut W,
    buf: &mut [u8],
    count: usize,
) -> Result<()> {
    let mut remaining = count;
    while remaining > 0 {
        let chunk = remaining.min(buf.len());
        let n = src
            .read(&mut buf[..chunk])
            .context("unexpected end of input while copying")?;
        if n == 0 {
            bail!("unexpected end of input while copying {count} bytes");
        }
        dst.write_all(&buf[..n])
            .context("failed to write output")?;
        remaining -= n;
    }
    Ok(())
}

/// Seek `src` to `offset`, then copy `count` bytes from it to `dst`.
fn seek_and_copy<R: std::io::Read + std::io::Seek, W: std::io::Write>(
    src: &mut R,
    dst: &mut W,
    buf: &mut [u8],
    offset: u64,
    count: usize,
) -> Result<()> {
    src.seek(std::io::SeekFrom::Start(offset))
        .with_context(|| format!("failed to seek to offset {offset}"))?;
    copy_bytes(src, dst, buf, count)
}

/// Apply a single `.nxdlpatch` file to the old file, writing the result to
/// `out_path`.
///
/// The patch is a stream of opcodes:
/// - `0x00`: end of patch
/// - `0x04`: u8 offset, u16 count — copy `count` bytes from the old file
///   at `offset`
/// - `0x10`: u16 offset, u8 count — copy from the old file at `offset`
/// - `0x14`: u16 offset, u16 count — copy from the old file at `offset`
/// - `0x20`: u32 offset, u8 count — copy from the old file at `offset`
/// - `0x24`: u32 offset, u16 count — copy from the old file at `offset`
/// - `0x28`: u32 offset, u32 count — copy from the old file at `offset`
/// - `0x40`: u8 count — copy `count` literal bytes from the patch
/// - `0x44`: u16 count — copy `count` literal bytes from the patch
/// - `0x48`: u32 count — copy `count` literal bytes from the patch
fn apply_ngm_patch(old_path: &Path, patch_path: &Path, out_path: &Path) -> Result<()> {
    use std::io::{Read, Write};

    let mut old_file = std::fs::File::open(old_path)
        .with_context(|| format!("failed to open {}", old_path.display()))?;
    let mut patch_file = std::fs::File::open(patch_path)
        .with_context(|| format!("failed to open {}", patch_path.display()))?;
    let mut out_file = std::fs::File::create(out_path)
        .with_context(|| format!("failed to create {}", out_path.display()))?;

    let mut buf = vec![0u8; 0x10000];

    loop {
        let mut op = [0u8; 1];
        if patch_file.read(&mut op)? == 0 {
            // The stream may simply end without an explicit 0x00 terminator.
            break;
        }
        match op[0] {
            0x00 => break,
            0x04 => {
                let mut arg = [0u8; 3];
                patch_file
                    .read_exact(&mut arg)
                    .context("truncated 0x04 opcode")?;
                let offset = arg[0] as u64;
                let count = u16::from_le_bytes([arg[1], arg[2]]) as usize;
                seek_and_copy(&mut old_file, &mut out_file, &mut buf, offset, count)
                    .context("0x04: copy from old file")?;
            }
            0x10 => {
                let mut arg = [0u8; 3];
                patch_file
                    .read_exact(&mut arg)
                    .context("truncated 0x10 opcode")?;
                let offset = u16::from_le_bytes([arg[0], arg[1]]) as u64;
                let count = arg[2] as usize;
                seek_and_copy(&mut old_file, &mut out_file, &mut buf, offset, count)
                    .context("0x10: copy from old file")?;
            }
            0x14 => {
                let mut arg = [0u8; 4];
                patch_file
                    .read_exact(&mut arg)
                    .context("truncated 0x14 opcode")?;
                let offset = u16::from_le_bytes([arg[0], arg[1]]) as u64;
                let count = u16::from_le_bytes([arg[2], arg[3]]) as usize;
                seek_and_copy(&mut old_file, &mut out_file, &mut buf, offset, count)
                    .context("0x14: copy from old file")?;
            }
            0x20 => {
                let mut arg = [0u8; 5];
                patch_file
                    .read_exact(&mut arg)
                    .context("truncated 0x20 opcode")?;
                let offset = u32::from_le_bytes([arg[0], arg[1], arg[2], arg[3]]) as u64;
                let count = arg[4] as usize;
                seek_and_copy(&mut old_file, &mut out_file, &mut buf, offset, count)
                    .context("0x20: copy from old file")?;
            }
            0x24 => {
                let mut arg = [0u8; 6];
                patch_file
                    .read_exact(&mut arg)
                    .context("truncated 0x24 opcode")?;
                let offset = u32::from_le_bytes([arg[0], arg[1], arg[2], arg[3]]) as u64;
                let count = u16::from_le_bytes([arg[4], arg[5]]) as usize;
                seek_and_copy(&mut old_file, &mut out_file, &mut buf, offset, count)
                    .context("0x24: copy from old file")?;
            }
            0x28 => {
                let mut arg = [0u8; 8];
                patch_file
                    .read_exact(&mut arg)
                    .context("truncated 0x28 opcode")?;
                let offset = u32::from_le_bytes([arg[0], arg[1], arg[2], arg[3]]) as u64;
                let count = u32::from_le_bytes([arg[4], arg[5], arg[6], arg[7]]) as usize;
                seek_and_copy(&mut old_file, &mut out_file, &mut buf, offset, count)
                    .context("0x28: copy from old file")?;
            }
            0x40 => {
                let mut arg = [0u8; 1];
                patch_file
                    .read_exact(&mut arg)
                    .context("truncated 0x40 opcode")?;
                let count = arg[0] as usize;
                copy_bytes(&mut patch_file, &mut out_file, &mut buf, count)
                    .context("0x40: copy literal bytes from patch")?;
            }
            0x44 => {
                let mut arg = [0u8; 2];
                patch_file
                    .read_exact(&mut arg)
                    .context("truncated 0x44 opcode")?;
                let count = u16::from_le_bytes(arg) as usize;
                copy_bytes(&mut patch_file, &mut out_file, &mut buf, count)
                    .context("0x44: copy literal bytes from patch")?;
            }
            0x48 => {
                let mut arg = [0u8; 4];
                patch_file
                    .read_exact(&mut arg)
                    .context("truncated 0x48 opcode")?;
                let count = u32::from_le_bytes(arg) as usize;
                copy_bytes(&mut patch_file, &mut out_file, &mut buf, count)
                    .context("0x48: copy literal bytes from patch")?;
            }
            other => bail!(
                "unknown patch opcode 0x{other:02x} in {}",
                patch_path.display()
            ),
        }
    }

    out_file.flush()?;
    Ok(())
}

/// Apply one downloaded `.nxdlpatch` to the corresponding client file and
/// move the result into place.
///
/// The patched file is first written to
/// `<patchdata_dir>/applied/<rel_path>`; once complete, it overwrites
/// `<target_dir>/<rel_path>`, and the `.nxdlpatch` file (named
/// `<rel_path>.nxdlpatch` under `patches_dir`) is deleted.
fn apply_and_install_patch(
    target_dir: &Path,
    patchdata_dir: &Path,
    patches_dir: &Path,
    rel_path: &str,
) -> Result<()> {
    let old_path = crate::relpath::join(target_dir, rel_path);
    let patch_path = crate::relpath::join_with_suffix(patches_dir, rel_path, ".nxdlpatch");
    let applied_path =
        crate::relpath::join(&patchdata_dir.join("applied"), rel_path);

    if let Some(parent) = applied_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }

    apply_ngm_patch(&old_path, &patch_path, &applied_path)
        .with_context(|| format!("failed to apply patch for {rel_path}"))?;

    // Overwrite the target file with the patched result.
    if let Some(parent) = old_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }
    std::fs::rename(&applied_path, &old_path).with_context(|| {
        format!(
            "failed to overwrite {} with {}",
            old_path.display(),
            applied_path.display()
        )
    })?;

    // The patch file is no longer needed.
    if let Err(e) = std::fs::remove_file(&patch_path) {
        eprintln!(
            "warning: failed to delete patch file {}: {e}",
            patch_path.display()
        );
    }
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
/// concatenated into
/// `<target_dir>/patchdata/patches/<decoded_path>.nxdlpatch`.
/// Each patch is then applied: the patched file is staged in
/// `<target_dir>/patchdata/applied/<path>` and then moved over the original
/// file.  The patch file is deleted after it is applied.  On success the
/// manifest hash file is updated.
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
        let decoded_path = decode_path(encoded_path)
            .with_context(|| format!("failed to decode patch path {encoded_path}"))?;
        let mut chunks: Vec<(u32, String)> = file_info
            .objects
            .iter()
            .filter_map(|(k, v)| k.parse::<u32>().ok().map(|id| (id, v.clone())))
            .collect();
        chunks.sort_by_key(|(id, _)| *id);
        if chunks.is_empty() {
            eprintln!("warning: skipping patch entry with no chunks: {decoded_path}");
            continue;
        }
        entries.push(ResolvedNgmPatch {
            encoded_path: encoded_path.clone(),
            decoded_path,
            file_hash: file_info.hash.clone(),
            chunks,
            uncompressed_size: file_info.uncompressed_size,
            compressed_size: file_info.compressed_size,
        });
    }
    entries.sort_by(|a, b| a.decoded_path.cmp(&b.decoded_path));

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
                    bar.set_message(entry.decoded_path.clone());

                    let dest_path = crate::relpath::join_with_suffix(
                        patches_dir,
                        &entry.decoded_path,
                        ".nxdlpatch",
                    );

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
                                .push(format!("{}: {:#}", entry.decoded_path, e));
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

    // ---- Step 5: apply the downloaded patches ----
    let apply_entries: Vec<String> = entries
        .iter()
        .map(|e| e.decoded_path.clone())
        .collect();

    let applied = AtomicUsize::new(0);
    let apply_failed = AtomicUsize::new(0);
    let apply_failures: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let counter = AtomicUsize::new(0);

    std::thread::scope(|scope| {
        let apply_entries = &apply_entries;
        let counter = &counter;
        let applied = &applied;
        let apply_failed = &apply_failed;
        let apply_failures = &apply_failures;
        let patchdata_dir = &patchdata_dir;
        let patches_dir = &patches_dir;

        for _ in 0..PARALLEL_FILES.min(apply_entries.len()) {
            scope.spawn(move || {
                loop {
                    let idx = counter.fetch_add(1, Ordering::Relaxed);
                    if idx >= apply_entries.len() {
                        break;
                    }
                    let rel_path = &apply_entries[idx];
                    match apply_and_install_patch(
                        target_dir,
                        patchdata_dir,
                        patches_dir,
                        rel_path,
                    ) {
                        Ok(()) => {
                            applied.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => {
                            apply_failed.fetch_add(1, Ordering::Relaxed);
                            apply_failures
                                .lock()
                                .unwrap()
                                .push(format!("{rel_path}: {e:#}"));
                        }
                    }
                }
            });
        }
    });

    let applied = applied.load(Ordering::Relaxed);
    let apply_failed = apply_failed.load(Ordering::Relaxed);

    println!();
    println!("Patched: {applied} file(s) applied, {apply_failed} failed.");

    let apply_failures = apply_failures.into_inner().unwrap();
    if !apply_failures.is_empty() {
        println!();
        println!("Failed patch applications:");
        for f in &apply_failures {
            println!("  {f}");
        }
        bail!("{} patch file(s) failed to apply", apply_failures.len());
    }

    // ---- Step 6: record the new version ----
    write_manifest_hash(target_dir, appid, dst_hash)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live smoke test of the HTTP range reader against one real KMS `.peg`
    /// part (structure only, no payload transfer).  Opt-in because it needs
    /// the network and issues roughly one request per file entry.
    #[test]
    fn lists_kms_peg00_over_http() {
        if std::env::var("NXDL_LIVE_PEG").as_deref() != Ok("1") {
            return;
        }
        let agent = agent(false, None);
        let url = "http://maplestory.dn.nexoncdn.co.kr/maplestory.peg00";
        let mut r = HttpRangeReader::new(&agent, url);
        let index = crate::peg::list_package(&mut r).unwrap();
        let fetched = r.bytes_fetched();

        let h = index.header.as_ref().expect("header present");
        assert_eq!(h.peg_number, 0);
        assert_eq!(h.total_pegs, 16);
        assert!(
            index.files.len() > 100,
            "expected many files, got {}",
            index.files.len()
        );
        assert!(index.total_uncompressed() > 0);
        assert!(index.files.iter().any(|f| f.name.contains("BlackCipher")));

        // The whole point of listing is to NOT download the payloads: bytes
        // fetched must be tiny compared with the part itself.
        eprintln!(
            "peg00: {} file entries, part size ~{} bytes, fetched {} bytes for the index",
            index.files.len(),
            h.declared_file_size,
            fetched,
        );
        assert!(fetched > 0, "expected some index bytes to be fetched");
        assert!(
            fetched < h.declared_file_size / 100,
            "fetched too much: {fetched} bytes vs part size {}",
            h.declared_file_size
        );
    }

    #[test]
    fn apply_reference_patch() {
        let base = Path::new("reference");
        let old = base.join("Maplestory_Classic.exe.old");
        let patch = base.join("TWFwbGVzdG9yeV9DbGFzc2ljLmV4ZQ==.nxdlpatch");
        let out = base.join("Maplestory_Classic.exe.verified");
        if !old.exists() || !patch.exists() {
            // Reference fixtures are not always checked out.
            return;
        }
        apply_ngm_patch(&old, &patch, &out).unwrap();

        let data = std::fs::read(&out).unwrap();
        // Size must match the old file.
        assert_eq!(
            data.len(),
            std::fs::metadata(&old).unwrap().len() as usize,
            "patched size mismatch"
        );
        // The decoded PE must be self-consistent: its stored CheckSum field
        // must equal the checksum computed over the file (with the field
        // zeroed).
        let lfa = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
        let csum_off = lfa + 4 + 20 + 64;
        let stored = u32::from_le_bytes(data[csum_off..csum_off + 4].try_into().unwrap());
        let mut b = data;
        b[csum_off..csum_off + 4].copy_from_slice(&[0, 0, 0, 0]);
        let mut s: u64 = 0;
        let mut i = 0;
        while i + 1 < b.len() {
            s += u16::from_le_bytes([b[i], b[i + 1]]) as u64;
            s = (s & 0xFFFF) + (s >> 16);
            i += 2;
        }
        if i < b.len() {
            s += b[i] as u64;
        }
        s = (s & 0xFFFF) + (s >> 16);
        let computed = (s + b.len() as u64) & 0xFFFF_FFFF;
        assert_eq!(
            computed as u32, stored,
            "decoded PE checksum does not match stored checksum"
        );

        let _ = std::fs::remove_file(&out);
    }

    // ---- Setup package (.sting / .nfo) parsing ----

    #[test]
    fn sting_parses_real_sample() {
        let json = r#"{
    "version": 100,
    "time_stamp": 1787132677,
    "original_size": 64685940445,
    "compressed_size": 61581778412,
    "sting_name": "maplestory",
    "compressed_file_count": 16
}"#;
        let sting: StingInfo = serde_json::from_str(json).unwrap();
        assert_eq!(sting.version, Some(100));
        assert_eq!(sting.time_stamp, Some(1787132677));
        assert_eq!(sting.original_size, Some(64_685_940_445));
        assert_eq!(sting.compressed_size, Some(61_581_778_412));
        assert_eq!(sting.sting_name, "maplestory");
        assert_eq!(sting.compressed_file_count, 16);

        let files: Vec<String> = sting.part_files();
        assert_eq!(files.len(), 16);
        assert_eq!(files[0], "maplestory.peg00");
        assert_eq!(files[15], "maplestory.peg15");
    }

    #[test]
    fn nfo_parses_real_sample() {
        let nfo = "NFO300,9526927360; DO NOT edit this line manually\r\n\
                   \"Mabinogi.z00\",\"819766191\",\"3145492277\"\r\n\
                   \"Mabinogi.z01\",\"-1532145412\",\"3142701016\"\r\n\
                   \"Mabinogi.z02\",\"1976795850\",\"2788447889\"\r\n";
        let parts = parse_nfo(nfo).unwrap();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].name, "Mabinogi.z00");
        assert_eq!(parts[0].size, 3145492277);
        assert_eq!(parts[1].name, "Mabinogi.z01");
        assert_eq!(parts[1].size, 3142701016);
        assert_eq!(parts[2].name, "Mabinogi.z02");
        assert_eq!(parts[2].size, 2788447889);

        // The NFO's per-archive third field is the byte size (verified against
        // the live Content-Length of the .zNN files), so the total is the sum.
        let total: u64 = parts.iter().map(|p| p.size).sum();
        assert_eq!(total, 3145492277 + 3142701016 + 2788447889);
    }

    #[test]
    fn url_helpers_split_extension_and_dir() {
        assert_eq!(
            url_extension("http://maplestory.dn.nexoncdn.co.kr/589825.sting").as_deref(),
            Some("sting")
        );
        assert_eq!(
            url_extension("http://webdown2.nexon.co.jp/mabinogi/inst/Mabinogi.nfo").as_deref(),
            Some("nfo")
        );
        assert_eq!(
            url_extension("http://example.com/archive.ZIP").as_deref(),
            Some("zip")
        );
        assert_eq!(url_extension("http://example.com/noext"), None);
        assert_eq!(
            url_base_dir("http://maplestory.dn.nexoncdn.co.kr/589825.sting"),
            "http://maplestory.dn.nexoncdn.co.kr"
        );
        assert_eq!(
            url_base_dir("http://webdown2.nexon.co.jp/mabinogi/inst/Mabinogi.nfo"),
            "http://webdown2.nexon.co.jp/mabinogi/inst"
        );
    }

    #[test]
    fn segment_ranges_cover_the_whole_size_exactly() {
        // Exact multiples split evenly.
        assert_eq!(
            segment_ranges(100, 5),
            vec![(0, 20), (20, 40), (40, 60), (60, 80), (80, 100)]
        );
        // A remainder is absorbed by the final range, with no gaps or overlaps.
        let ranges = segment_ranges(103, 5);
        assert_eq!(ranges.len(), 5);
        assert_eq!(ranges.first(), Some(&(0, 20)));
        let mut pos = 0u64;
        for &(s, e) in &ranges {
            assert_eq!(s, pos, "range must start where the previous ended");
            assert!(e > s, "empty range: {s}-{e}");
            pos = e;
        }
        assert_eq!(pos, 103);
        assert_eq!(ranges.last(), Some(&(82, 103)));

        // Tiny files still split cleanly into 5 non-empty ranges only when
        // the file is big enough; a 1-byte file leaves 4 empty ranges.
        let ranges = segment_ranges(1, 5);
        assert_eq!(ranges[0], (0, 0));
        assert_eq!(ranges[4], (0, 1));
    }

    #[test]
    fn incomplete_marker_round_trips() {
        let mut dir = std::env::temp_dir();
        dir.push(format!("nxdl-incomplete-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let marker = dir.join(".incomplete");

        // No marker → no installed parts; an empty dir has no entries.
        assert!(read_installed_parts(&marker).is_empty());
        assert!(!dir_has_entries(&dir));

        // Marking is idempotent and appends distinct parts.
        mark_part_installed(&marker, "maplestory.peg00");
        mark_part_installed(&marker, "maplestory.peg00");
        mark_part_installed(&marker, "maplestory.peg01");
        assert_eq!(
            read_installed_parts(&marker),
            ["maplestory.peg00", "maplestory.peg01"]
        );
        assert!(marker.exists());
        assert!(dir_has_entries(&dir)); // now contains the marker

        // Clearing removes the marker; reads become empty again.
        clear_incomplete_marker(&marker);
        assert!(read_installed_parts(&marker).is_empty());
        assert!(!marker.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn setup_total_size_falls_back_to_sting_compressed_size() {
        let sting = StingInfo {
            version: Some(100),
            time_stamp: None,
            original_size: Some(1000),
            compressed_size: Some(800),
            sting_name: "game".to_owned(),
            compressed_file_count: 2,
        };
        let package = SetupPackage {
            format: "sting",
            url: "http://x/game.sting".to_owned(),
            parts: vec![
                SetupPart {
                    filename: "game.peg00".into(),
                    url: "http://x/game.peg00".into(),
                    size: None,
                },
                SetupPart {
                    filename: "game.peg01".into(),
                    url: "http://x/game.peg01".into(),
                    size: None,
                },
            ],
            release_date_raw: None,
            release_date: None,
            sting: Some(sting),
        };
        assert_eq!(setup_total_size(&package), 800);
    }

    #[test]
    fn setup_total_size_sums_known_part_sizes() {
        let package = SetupPackage {
            format: "nfo",
            url: "http://x/Mabinogi.nfo".to_owned(),
            parts: vec![
                SetupPart {
                    filename: "Mabinogi.z00".into(),
                    url: "http://x/Mabinogi.z00".into(),
                    size: Some(10),
                },
                SetupPart {
                    filename: "Mabinogi.z01".into(),
                    url: "http://x/Mabinogi.z01".into(),
                    size: Some(20),
                },
            ],
            release_date_raw: None,
            release_date: None,
            sting: None,
        };
        assert_eq!(setup_total_size(&package), 30);
    }

    #[test]
    fn unknown_manifest_type_is_rejected() {
        let agent = agent(false, None);
        let err = fetch_setup_package(&agent, "http://example.com/install.exe").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("Unknown manifest type : exe"), "got: {msg}");
    }
}
