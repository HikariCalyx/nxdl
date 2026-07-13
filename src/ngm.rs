//! NGM (NX Game Manager) client check logic.
//!
//! Protocol:
//! 1. Fetch game info from `https://ngmapi.nexon.com/game-info/{appid}`
//! 2. Extract `setup_file_url` and `manifest_name`
//! 3. Download manifest from `{setup_file_url}/{manifest_name}`
//! 4. Parse manifest entries (base64-encoded UTF-8 file paths, chunk objects,
//!    decompressed sizes, SHA-1 hashes)
//! 5. Print summary (and file list when verbose).

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine;

use crate::filter::FileFilter;

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

/// Check NGM client info: fetch game info, download the manifest, and print
/// a summary.  When `verbose` is true, list every file.
pub fn check_ngm(appid: &str, verbose: bool, filter: Option<&FileFilter>) -> Result<()> {
    let agent = agent();

    // ---- Step 1: fetch game info ----
    let info_url = format!("https://ngmapi.nexon.com/game-info/{appid}");
    println!("Game info URL: {info_url}");
    let info_json = http_get_string(&agent, &info_url)
        .with_context(|| format!("failed to fetch game info from {info_url}"))?;
    let info: GameInfo =
        serde_json::from_str(&info_json).context("failed to parse game-info response")?;

    // ---- Step 2: construct and fetch manifest (if available) ----
    let manifest_name = match &info.manifest_name {
        Some(name) => name,
        None => {
            println!();
            println!("  game:      {}", info.game_name);
            println!("  product:   {appid}");
            println!("  (no manifest available)");
            return Ok(());
        }
    };
    let setup_base = info.setup_file_url.trim_end_matches('/');
    let manifest_url = format!("{setup_base}/{manifest_name}");
    println!("Manifest URL:  {manifest_url}");

    let manifest_json = http_get_string(&agent, &manifest_url)
        .with_context(|| format!("failed to fetch manifest from {manifest_url}"))?;
    let manifest: NgmManifest =
        serde_json::from_str(&manifest_json).context("failed to parse manifest JSON")?;

    // ---- Step 3: decode paths, apply filter, collect stats ----
    let total_in_manifest = manifest.files.len();
    let mut entries: Vec<(String, u64, usize)> = Vec::with_capacity(manifest.files.len());
    let mut dir_count: usize = 0;
    let mut filtered_out: usize = 0;
    let mut failed_decode: usize = 0;

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

    // ---- Step 4: print results ----
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
            println!("{:<70} {:>8} {:>12}", path, num_objects, human_size(*size));
        }
    }

    Ok(())
}
