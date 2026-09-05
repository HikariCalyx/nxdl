//! PEG package reader / decompressor.
//!
//! Nexon full-client setups (`.sting` → `<name>.pegNN`) store the game files
//! in "PEG" containers.  Each `.pegNN` file is a self-contained archive whose
//! entries are zstd-compressed:
//!
//! ```text
//! header:
//!   4 bytes  magic        "1984"
//!   u64 LE   declared uncompressed size (informational; not always accurate)
//!   u16 LE   unknown flag (usually 1)
//!   u16 LE   total number of PEG parts
//!   u16 LE   this part's number (0-based)
//!   u64 LE   declared file size (informational)
//!
//! then entries until EOF / an unknown magic:
//!   4 bytes  magic  "1982"  → directory entry
//!     u16 LE  name length (UTF-16 code units) + UTF-16-LE name
//!   4 bytes  magic  "1989"  → file entry
//!     u64 LE  compressed size
//!     u64 LE  uncompressed size
//!     12 bytes hash: u32 LE CRC-32 + u64 LE FILETIME (100 ns since 1601-01-01)
//!     u16 LE  name length + UTF-16-LE name
//!     <compressed size> bytes of zstd frame data
//! ```
//!
//! Reverse-engineered; see `reference/extractpeg.py`.

use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use indicatif::{ProgressBar, ProgressStyle};

/// Statistics for one extracted `.pegNN` file.
#[derive(Debug, Default)]
pub struct PegStats {
    /// Directories created.
    pub dirs: u64,
    /// Files written (entries that decompressed successfully).
    pub files: u64,
    /// Files skipped because the target already existed with a matching CRC-32.
    pub skipped_files: u64,
    /// Compressed payload bytes of the written files.
    pub compressed_bytes: u64,
    /// Decompressed bytes written.
    pub uncompressed_bytes: u64,
    /// Entries whose zstd payload could not be decompressed.
    pub decode_errors: u64,
    /// Entries whose decompressed size disagreed with the header.
    pub size_mismatches: u64,
    /// Entries whose decompressed data failed the stored CRC-32.
    pub crc_mismatches: u64,
}

const HEADER_MAGIC: &[u8; 4] = b"1984";
const DIR_MAGIC: &[u8; 4] = b"1982";
const FILE_MAGIC: &[u8; 4] = b"1989";

/// Maximum zstd window we accept when decompressing entries.  Real files use
/// at most a few hundred MiB; this keeps permissive decoding while capping
/// the scratch allocation a hostile frame could request.
const MAX_ZSTD_WINDOW: u64 = 1 << 30; // 1 GiB

/// Read `buf.len()` bytes, returning `Ok(false)` on a clean EOF at the very
/// start (used to detect the end of the entry stream).  A partial read is an
/// error.
fn read_exact_or_eof(r: &mut impl Read, buf: &mut [u8]) -> io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => {
                if filled == 0 {
                    return Ok(false);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected end of PEG data",
                ));
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

fn read_u16le(r: &mut impl Read) -> Result<u16> {
    let mut b = [0u8; 2];
    r.read_exact(&mut b)?;
    Ok(u16::from_le_bytes(b))
}

fn read_u64le(r: &mut impl Read) -> Result<u64> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

/// Read a length-prefixed UTF-16-LE string (PEG entry names).
fn read_wstring(r: &mut impl Read) -> Result<String> {
    let len = read_u16le(r)?;
    let raw = read_bytes(r, len as usize * 2)?;
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&units).context("PEG entry name is not valid UTF-16")
}

fn read_bytes(r: &mut impl Read, n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Decompress a `compressed_size`-byte zstd payload that begins at
/// Decompress a `compressed_size`-byte zstd payload read from `reader`,
/// streaming the output into `out` while computing its CRC-32.
///
/// A payload is a run of concatenated zstd frames (each frame usually
/// decompressing to 128 KiB), so frames are decoded one after another until
/// the payload is exhausted.  Returns `(bytes_written, crc32)`.
fn decode_zstd<R: Read>(
    reader: &mut R,
    compressed_size: u64,
    out: &mut dyn Write,
    progress: Option<&ProgressBar>,
) -> Result<(u64, u32)> {
    if compressed_size == 0 {
        return Ok((0, 0));
    }

    // Read the whole (single-entry) payload so frame boundaries can be walked
    // precisely.  A payload is at most one game file; the reference tool
    // buffers the entire PEG file, so this is well within its memory profile.
    let payload = read_bytes(reader, usize::try_from(compressed_size)?)?;

    let mut hasher = crc32fast::Hasher::new();
    let mut buf = vec![0u8; 256 * 1024];
    let mut written: u64 = 0;
    let mut rest: &[u8] = &payload;

    while !rest.is_empty() {
        let mut decoder = match ruzstd::decoding::StreamingDecoder::new_with_max_window_size(
            rest,
            MAX_ZSTD_WINDOW,
        ) {
            Ok(d) => d,
            Err(e) => {
                // Nothing decodable remains: a corrupt first frame, or trailing
                // non-frame padding after a clean run.
                if written == 0 {
                    return Err(anyhow!("zstd: {e}"));
                }
                break;
            }
        };

        loop {
            match decoder.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    out.write_all(&buf[..n])
                        .context("failed to write decompressed data")?;
                    hasher.update(&buf[..n]);
                    written += n as u64;
                    if let Some(pb) = progress {
                        pb.inc(n as u64);
                    }
                }
                Err(e) => return Err(anyhow!("zstd decode failed: {e}")),
            }
        }

        // `rest` has advanced past the frame that was just decoded.
        rest = decoder.into_inner();
    }

    Ok((written, hasher.finalize()))
}

/// Compute the CRC-32 of a whole file on disk (used to resume installs: a
/// target file whose CRC-32 already matches the PEG entry can be skipped).
fn crc32_of_file(path: &Path) -> Result<u32> {
    let mut f =
        File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut hasher = crc32fast::Hasher::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize())
}

/// Wraps a reader and feeds every byte pulled from it into a [`ProgressBar`],
/// so the bar can show how much of a local `.pegNN` part has been parsed
/// (its length should be the part's file size on disk).
struct ProgressRead<R: Read> {
    inner: R,
    pb: ProgressBar,
}

impl<R: Read> ProgressRead<R> {
    fn new(inner: R, pb: &ProgressBar) -> Self {
        Self {
            inner,
            pb: pb.clone(),
        }
    }
}

impl<R: Read> Read for ProgressRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.pb.inc(n as u64);
        Ok(n)
    }
}

/// Extract a PEG package read sequentially from `r` (no seek needed, so it can
/// be fed directly from an HTTP stream).
///
/// Every directory / file entry is materialised under `output_dir` (paths are
/// relative to the game root).
///
/// `strict` controls per-file error handling:
/// - `true` — used when installing straight from the CDN.  A decode failure,
///   a decompressed-size mismatch or a CRC-32 mismatch aborts the package
///   (the partial target file is removed) so the caller can retry the part;
///   files written earlier are left in place.  When a target file already
///   exists with the expected CRC-32 it is skipped.
/// - `false` — local files.  Problems are reported to stderr and counted in
///   the returned [`PegStats`] rather than aborting, mirroring
///   `reference/extractpeg.py`.
///
/// `start_at` is the byte offset within the part at which `r` is positioned:
/// `0` parses the 26-byte header first; a non-zero value (used when resuming)
/// must point at the start of a directory / file entry.  `on_checkpoint` is
/// called with the byte offset of the *next* entry after each entry has been
/// fully handled, letting the caller persist a resume point.  `on_file`, when
/// given, is called with each file's (normalised) name just before it is
/// written, letting a caller show a live "extracting <file>" progress message.
///
/// Structural problems (bad header, truncated record) always return an error.
fn extract_reader<R: Read>(
    r: &mut R,
    output_dir: &Path,
    label: &str,
    progress: Option<&ProgressBar>,
    verbose: bool,
    strict: bool,
    start_at: u64,
    mut on_checkpoint: Option<&mut dyn FnMut(u64)>,
    mut on_file: Option<&mut dyn FnMut(&str)>,
) -> Result<PegStats> {
    let mut stats = PegStats::default();
    let mut offset = start_at;

    // ---- Header (only when starting from the beginning) ----
    if start_at == 0 {
        let mut magic = [0u8; 4];
        if !read_exact_or_eof(r, &mut magic)? {
            bail!("{label}: empty file");
        }
        if &magic != HEADER_MAGIC {
            bail!(
                "{label}: bad PEG magic {:?} (expected \"1984\")",
                String::from_utf8_lossy(&magic)
            );
        }
        offset += 4;
        let _declared_total = read_u64le(r)?;
        offset += 8;
        let _unknown_flag = read_u16le(r)?;
        offset += 2;
        let total_pegs = read_u16le(r)?;
        offset += 2;
        let peg_number = read_u16le(r)?;
        offset += 2;
        let _declared_size = read_u64le(r)?;
        offset += 8;
        debug_assert_eq!(offset, 26);

        if verbose {
            println!("[peg header] part {peg_number}/{total_pegs}, path {label}");
        }
    }

    // ---- Entries ----
    loop {
        let mut magic = [0u8; 4];
        if !read_exact_or_eof(r, &mut magic)? {
            break; // clean end of stream
        }
        offset += 4;
        match &magic {
            DIR_MAGIC => {
                let name = read_wstring(r)
                    .with_context(|| format!("{label}: bad directory name"))?;
                offset += 2 + (name.encode_utf16().count() as u64) * 2;
                stats.dirs += 1;
                if !name.trim().is_empty() {
                    let dir = crate::relpath::join(output_dir, &name);
                    std::fs::create_dir_all(&dir).with_context(|| {
                        format!(
                            "failed to create directory {} (from PEG entry {:?})",
                            dir.display(),
                            name
                        )
                    })?;
                }
                if verbose {
                    println!("  [dir ] {name}");
                }
                if let Some(cb) = on_checkpoint.as_mut() {
                    cb(offset);
                }
            }
            FILE_MAGIC => {
                let compressed_size = read_u64le(r)?;
                offset += 8;
                let uncompressed_size = read_u64le(r)?;
                offset += 8;
                let hash = read_bytes(r, 12)?;
                offset += 12;
                let name = read_wstring(r)
                    .with_context(|| format!("{label}: bad file name"))?;
                offset += 2 + (name.encode_utf16().count() as u64) * 2;
                let out_path = crate::relpath::join(output_dir, &name);
                let stored_crc =
                    u32::from_le_bytes(hash[0..4].try_into().expect("hash is 12 bytes"));

                // Nameless entries: skip the payload but stay aligned.
                if name.trim().is_empty() {
                    if !strict {
                        eprintln!("warning: {label}: file entry with an empty name; skipping");
                    }
                    let n = usize::try_from(compressed_size)?;
                    read_bytes(r, n)?;
                    offset += compressed_size;
                    continue;
                }

                // Resume rule: if the target file already exists with the
                // expected CRC-32, skip it (payload bytes are still consumed
                // from the stream to stay aligned, but nothing is written).
                let up_to_date = strict
                    && out_path.exists()
                    && crc32_of_file(&out_path).map_or(false, |crc| crc == stored_crc);
                if up_to_date {
                    stats.skipped_files += 1;
                    let n = usize::try_from(compressed_size)?;
                    read_bytes(r, n)?;
                    offset += compressed_size;
                    if verbose {
                        println!("  [skip] {name} (CRC-32 ok)");
                    }
                    if let Some(cb) = on_checkpoint.as_mut() {
                        cb(offset);
                    }
                    continue;
                }

                if let Some(parent) = out_path.parent() {
                    std::fs::create_dir_all(parent).with_context(|| {
                        format!("failed to create directory {}", parent.display())
                    })?;
                }

                // Tell the caller which file is about to be written (for a
                // live progress message): normalised, no leading slash.
                if let Some(cb) = on_file.as_mut() {
                    let shown = crate::relpath::normalize(&name);
                    cb(shown.trim_start_matches('/'));
                }

                // Open the output (truncates any previous / partial extraction).
                let mut out_file = File::create(&out_path).with_context(|| {
                    format!("failed to create {}", out_path.display())
                })?;
                let decoded = decode_zstd(r, compressed_size, &mut out_file, progress);
                drop(out_file);
                offset += compressed_size;

                match decoded {
                    Ok((written, actual_crc)) => {
                        stats.files += 1;
                        stats.compressed_bytes += compressed_size;
                        stats.uncompressed_bytes += written;

                        if written != uncompressed_size {
                            if strict {
                                let _ = std::fs::remove_file(&out_path);
                                bail!(
                                    "{label}: size mismatch for {:?}: declared \
                                     {uncompressed_size} bytes, got {written}",
                                    name
                                );
                            }
                            eprintln!(
                                "warning: {label}: size mismatch for {:?}: \
                                 declared {uncompressed_size} bytes, got {written}",
                                name
                            );
                            stats.size_mismatches += 1;
                        }

                        if stored_crc != actual_crc {
                            if strict {
                                let _ = std::fs::remove_file(&out_path);
                                bail!(
                                    "{label}: CRC-32 mismatch for {:?}: stored \
                                     {stored_crc:08x}, computed {actual_crc:08x}",
                                    name
                                );
                            }
                            eprintln!(
                                "warning: {label}: CRC-32 mismatch for {:?}: stored \
                                 {stored_crc:08x}, computed {actual_crc:08x}",
                                name
                            );
                            stats.crc_mismatches += 1;
                        }
                        if verbose {
                            println!("  [file] {name} ({compressed_size} -> {written} bytes)");
                        }
                    }
                    Err(e) => {
                        // Never leave a truncated / corrupt file behind.
                        let _ = std::fs::remove_file(&out_path);
                        if strict {
                            bail!("{label}: failed to decompress {name:?}: {e:#}");
                        }
                        eprintln!("warning: {label}: {e:#}");
                        stats.decode_errors += 1;
                    }
                }

                if let Some(cb) = on_checkpoint.as_mut() {
                    cb(offset);
                }
            }
            // Unknown magic → end of the entry stream (as in the reference).
            _ => break,
        }
    }

    Ok(stats)
}

/// Extract a local `.pegNN` package from disk into `output_dir`.
///
/// Lenient: a bad entry is reported and counted, not fatal (mirrors the
/// reference tool).  For a streaming CDN install use [`extract_peg_install`].
#[allow(dead_code)]
pub fn extract_peg(
    peg_path: &Path,
    output_dir: &Path,
    progress: Option<&ProgressBar>,
    verbose: bool,
) -> Result<PegStats> {
    let file = File::open(peg_path)
        .with_context(|| format!("failed to open {}", peg_path.display()))?;
    let mut r = BufReader::new(file);
    extract_reader(
        &mut r,
        output_dir,
        &peg_path.display().to_string(),
        progress,
        verbose,
        false,
        0,
        None,
        None,
    )
}

/// Extract a local `.pegNN` package from disk into `output_dir`, verifying
/// every file's decompressed size and CRC-32 — the same strict rules as a
/// CDN install (see [`extract_peg_install`]).
///
/// A file whose target already exists with the expected CRC-32 is skipped
/// (its payload is still read so the stream stays aligned), so re-running
/// after an interruption only re-extracts what is missing or corrupt.  A
/// decode / size / CRC-32 problem removes the partial target and fails the
/// part with a `bail!` (the caller can report it and let the user re-fetch a
/// corrupt part).
pub fn extract_peg_local(
    peg_path: &Path,
    output_dir: &Path,
    verbose: bool,
) -> Result<PegStats> {
    extract_peg_local_with(peg_path, output_dir, verbose, None, None)
}

/// Like [`extract_peg_local`], but with hooks for a live progress bar.
///
/// `part_progress`, when given, wraps the source file reader so the bar
/// advances with the bytes read from the `.pegNN` part on disk (set its
/// length to the part's file size).  `on_file`, when given, is called with
/// each file's (normalised) name just before it is written so the bar can
/// show which file is being extracted.  The internal decoder does not
/// double-count: it only feeds `on_file`, never `part_progress`.
pub fn extract_peg_local_with(
    peg_path: &Path,
    output_dir: &Path,
    verbose: bool,
    part_progress: Option<&ProgressBar>,
    on_file: Option<&mut dyn FnMut(&str)>,
) -> Result<PegStats> {
    let file = File::open(peg_path)
        .with_context(|| format!("failed to open {}", peg_path.display()))?;
    let reader: Box<dyn Read> = if let Some(pb) = part_progress {
        Box::new(BufReader::new(ProgressRead::new(file, pb)))
    } else {
        Box::new(BufReader::new(file))
    };
    let mut r = reader;
    extract_reader(
        &mut r,
        output_dir,
        &peg_path.display().to_string(),
        None,
        verbose,
        true, // strict
        0,
        None, // a local file can always be restarted from offset 0
        on_file,
    )
}

/// Extract a PEG package straight from a sequential stream (e.g. an HTTP body)
/// into `output_dir`, verifying every file's decompressed size and CRC-32.
///
/// Strict: any per-file decode / size / CRC problem aborts with an error so
/// the caller can retry the part; files already written stay on disk.  The
/// `.peg` bytes themselves are never stored.
///
/// (Used by tests / tools; the install path uses [`extract_peg_install`].)
#[allow(dead_code)]
pub fn extract_peg_stream<R: Read>(
    r: &mut R,
    output_dir: &Path,
) -> Result<PegStats> {
    extract_reader(r, output_dir, "(stream)", None, false, true, 0, None, None)
}

/// Install a PEG package from a sequential stream with resume support.
///
/// This is the strict CDN-install entry point:
/// - A file whose target already exists with the expected CRC-32 is skipped
///   (its payload bytes are still consumed from the stream).
/// - Any decode / size / CRC problem aborts, so the caller can re-open the
///   stream at `start_at` (the byte offset of the next entry to process).
/// - After every handled entry, `on_checkpoint` is called with the byte offset
///   of the *next* entry, so the caller can persist a resume point.
///
/// `start_at` must be `0` for a fresh part, or the byte offset returned by the
/// last `on_checkpoint` call when resuming a part (the stream must be
/// positioned there, e.g. via an HTTP `Range` request).
pub fn extract_peg_install<R: Read, F: FnMut(u64)>(
    r: &mut R,
    output_dir: &Path,
    start_at: u64,
    on_checkpoint: F,
) -> Result<PegStats> {
    let mut on_checkpoint = on_checkpoint;
    extract_reader(
        r,
        output_dir,
        "(stream)",
        None,
        false,
        true,
        start_at,
        Some(&mut on_checkpoint),
        None,
    )
}

/// Metadata from a PEG package header.
#[derive(Debug, Clone)]
pub struct PegHeaderInfo {
    pub total_pegs: u16,
    pub peg_number: u16,
    pub declared_uncompressed: u64,
    pub declared_file_size: u64,
}

/// Metadata of one file entry inside a PEG package (payload not read).
#[derive(Debug, Clone)]
pub struct PegFileInfo {
    /// Path relative to the game root, normalised to `/` separators.
    pub name: String,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    /// CRC-32 of the decompressed content.
    pub crc32: u32,
    /// FILETIME (100 ns since 1601-01-01); 0 when not set.
    pub filetime: u64,
}

/// The structure of one PEG package: header plus its directory / file entries.
///
/// Kept for callers (and tests) that want a full in-memory listing; the live
/// `--check --verbose` path streams via [`walk_entries`] instead.
#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct PegIndex {
    pub header: Option<PegHeaderInfo>,
    pub dirs: u64,
    pub files: Vec<PegFileInfo>,
}

impl PegIndex {
    /// Sum of every file's decompressed size.
    #[allow(dead_code)]
    pub fn total_uncompressed(&self) -> u64 {
        self.files.iter().map(|f| f.uncompressed_size).sum()
    }
}

/// Walk a PEG package's structure without decoding any payload.
///
/// `on_header` is invoked once after the header has been parsed, and `on_file`
/// is invoked for every file entry as soon as its metadata has been read (so
/// callers can stream output immediately).  Payloads are skipped with a seek,
/// so this also works over an HTTP range reader without downloading them.
/// Returns the number of directory entries seen.
pub fn walk_entries<R: Read + Seek>(
    r: &mut R,
    on_header: &mut dyn FnMut(&PegHeaderInfo),
    on_file: &mut dyn FnMut(&PegFileInfo),
) -> Result<u64> {
    // ---- Header ----
    let mut magic = [0u8; 4];
    if !read_exact_or_eof(r, &mut magic)? {
        bail!("empty PEG file");
    }
    if &magic != HEADER_MAGIC {
        bail!(
            "bad PEG magic {:?} (expected \"1984\")",
            String::from_utf8_lossy(&magic)
        );
    }
    let declared_uncompressed = read_u64le(r)?;
    let _unknown_flag = read_u16le(r)?;
    let total_pegs = read_u16le(r)?;
    let peg_number = read_u16le(r)?;
    let declared_file_size = read_u64le(r)?;
    on_header(&PegHeaderInfo {
        total_pegs,
        peg_number,
        declared_uncompressed,
        declared_file_size,
    });

    // ---- Entries ----
    let mut dirs = 0u64;
    loop {
        let mut magic = [0u8; 4];
        if !read_exact_or_eof(r, &mut magic)? {
            break; // clean end of stream
        }
        match &magic {
            DIR_MAGIC => {
                let _name = read_wstring(r)?;
                dirs += 1;
            }
            FILE_MAGIC => {
                let compressed_size = read_u64le(r)?;
                let uncompressed_size = read_u64le(r)?;
                let hash = read_bytes(r, 12)?;
                let name = read_wstring(r)?;
                let crc32 =
                    u32::from_le_bytes(hash[0..4].try_into().expect("hash is 12 bytes"));
                let filetime =
                    u64::from_le_bytes(hash[4..12].try_into().expect("hash is 12 bytes"));
                // Skip the payload — no data transfer needed for a listing.
                let pos = r.stream_position()?;
                r.seek(SeekFrom::Start(pos + compressed_size))?;
                // Normalise separators and drop a leading `/` so names read
                // like `BlackCipher/BlackCall64.aes` rather than `/…`.
                let name = crate::relpath::normalize(&name);
                on_file(&PegFileInfo {
                    name: name.trim_start_matches('/').to_owned(),
                    compressed_size,
                    uncompressed_size,
                    crc32,
                    filetime,
                });
            }
            // Unknown magic → end of the entry stream (as in the reference).
            _ => break,
        }
    }

    Ok(dirs)
}

/// Walk a PEG package and collect its whole structure into a [`PegIndex`].
///
/// Convenience wrapper around [`walk_entries`] for callers that want the full
/// listing in memory.
#[allow(dead_code)]
pub fn list_package<R: Read + Seek>(r: &mut R) -> Result<PegIndex> {
    let mut index = PegIndex::default();
    let mut header: Option<PegHeaderInfo> = None;
    let mut files: Vec<PegFileInfo> = Vec::new();
    let dirs = walk_entries(
        r,
        &mut |h| header = Some(h.clone()),
        &mut |f| files.push(f.clone()),
    )?;
    index.header = header;
    index.dirs = dirs;
    index.files = files;
    Ok(index)
}

// ---------------------------------------------------------------------------
// Manual extraction (`nxdl peg --extract`) — for `.pegNN` parts the user has
// already downloaded, outside of the NGM installer.
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

/// True when a file *name* looks like a PEG part: `<anything>.peg` or
/// `<anything>.pegNN` where NN is decimal digits (e.g.
/// `MapleStoryM_2.430.6284_Live_1717.peg00`).  This deliberately excludes
/// temp / partial downloads such as `…peg00.part` or `…peg00.crdownload`.
fn is_peg_part(file_name: &str) -> bool {
    match file_name.find(".peg") {
        Some(idx) => {
            let suffix = &file_name[idx + 4..];
            suffix.is_empty() || suffix.chars().all(|c| c.is_ascii_digit())
        }
        None => false,
    }
}

/// Natural sort key for PEG part names: the numeric `.pegNN` suffix sorts
/// numerically (`peg02` before `peg10`); a bare `.peg` with no numeric suffix
/// sorts first (by name).
fn peg_part_sort_key(name: &str) -> (u64, &str) {
    let num = name
        .find(".peg")
        .and_then(|idx| name[idx + 4..].parse::<u64>().ok())
        .unwrap_or(0);
    (num, name)
}

/// Clip a (possibly long) message to `max` characters, keeping the tail so a
/// deep path still ends in the file name.  ASCII-only (no ellipsis glyph, to
/// stay legible on legacy code-page consoles).
fn clip_msg(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_owned();
    }
    let keep = max.saturating_sub(3);
    let tail: String = s.chars().rev().take(keep).collect::<Vec<char>>()
        .into_iter().rev().collect();
    format!("...{tail}")
}

/// Build the small progress bar shown while extracting one part in
/// non-verbose mode.  `len` is the part's file size on disk; the bar counts
/// the bytes read from it and its message names the current file.
fn part_progress_bar(len: u64) -> ProgressBar {
    let pb = ProgressBar::new(len);
    pb.set_style(
        ProgressStyle::with_template(
            "  {msg} [{bar:24.cyan/blue}] {bytes}/{total_bytes} ({binary_bytes_per_sec})",
        )
        .unwrap()
        .progress_chars("=>-"),
    );
    pb.enable_steady_tick(Duration::from_millis(120));
    pb
}

/// `nxdl peg --extract`: extract one `.pegNN` file, or every `*.peg*` file
/// directly inside a source directory (top level only, not recursive), into
/// `output_dir`.
///
/// Extraction is strict (each file's decompressed size and CRC-32 are
/// verified) and resumable: a target file that already exists with the
/// expected CRC-32 is skipped, so an interrupted run (or one with a corrupt
/// part) finishes quickly on re-run.  When several parts are given, a part
/// that fails does not stop the remaining parts; all failures are reported
/// together at the end.
pub fn manual_extract(source: &Path, output_dir: &Path, verbose: bool) -> Result<()> {
    // ---- Resolve the list of parts to extract ----
    let parts: Vec<PathBuf> = if source.is_dir() {
        let mut found: Vec<(u64, String, PathBuf)> = Vec::new();
        for entry in std::fs::read_dir(source)
            .with_context(|| format!("failed to read directory {}", source.display()))?
        {
            let entry = entry.with_context(|| {
                format!("failed to read an entry of {}", source.display())
            })?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if is_peg_part(&name) {
                found.push((peg_part_sort_key(&name).0, name, path));
            }
        }
        if found.is_empty() {
            bail!(
                "no .peg files (e.g. *.peg, *.peg00) found in {} - only the \
                 top level is scanned, not sub-directories",
                source.display()
            );
        }
        found.sort();
        found.into_iter().map(|(_, _, path)| path).collect()
    } else {
        if !source.exists() {
            bail!("no such file or directory: {}", source.display());
        }
        if !source.is_file() {
            bail!("not a file or directory: {}", source.display());
        }
        vec![source.to_path_buf()]
    };

    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("failed to create {}", output_dir.display()))?;

    let count = parts.len();
    println!();
    if count == 1 {
        println!(
            "Extracting {} into {} ...",
            parts[0].display(),
            output_dir.display()
        );
    } else {
        println!(
            "Extracting {count} .peg part(s) from {} into {} ...",
            source.display(),
            output_dir.display()
        );
    }

    let mut total_files = 0u64;
    let mut total_skipped = 0u64;
    let mut total_dirs = 0u64;
    let mut total_bytes = 0u64;
    let mut failures: Vec<String> = Vec::new();

    for (idx, part) in parts.iter().enumerate() {
        let display = part.display().to_string();

        // Non-verbose: a small live bar shows how much of the part has been
        // parsed and which file is currently being written (skipped files are
        // consumed almost instantly, so on a resume the bar races to the
        // end).  Verbose mode prints per-file lines instead.
        let part_len = std::fs::metadata(part).map(|m| m.len()).ok();
        let bar = if !verbose {
            Some(part_progress_bar(part_len.unwrap_or(0)))
        } else {
            None
        };

        let result = match &bar {
            Some(pb) => {
                pb.set_message(clip_msg(&display, 56));
                let mut on_file = |name: &str| pb.set_message(clip_msg(name, 56));
                extract_peg_local_with(part, output_dir, false, Some(pb), Some(&mut on_file))
            }
            None => extract_peg_local(part, output_dir, true),
        };

        if let Some(pb) = &bar {
            pb.finish_and_clear();
        }

        match result {
            Ok(stats) => {
                total_files += stats.files;
                total_skipped += stats.skipped_files;
                total_dirs += stats.dirs;
                total_bytes += stats.uncompressed_bytes;
                let skipped = if stats.skipped_files > 0 {
                    format!(", {} skipped (CRC ok)", stats.skipped_files)
                } else {
                    String::new()
                };
                println!(
                    "  [peg {}/{count}] {}: {} file(s){}, {} dir(s), {} decompressed",
                    idx + 1,
                    display,
                    stats.files,
                    skipped,
                    stats.dirs,
                    human_size(stats.uncompressed_bytes),
                );
            }
            Err(e) => failures.push(format!("{display}: {e:#}")),
        }
    }

    println!();
    if !failures.is_empty() {
        println!("Failed parts:");
        for f in &failures {
            println!("  {f}");
        }
        println!(
            "Note: extracted files were kept; re-run to finish.  Each part \
             resumes automatically (a file whose CRC-32 already matches is \
             skipped), so a fixed or re-downloaded part is only re-extracted \
             where needed."
        );
        bail!("{} part(s) failed to extract", failures.len());
    }
    let skipped_note = if total_skipped > 0 {
        format!(", {} skipped (already present)", total_skipped)
    } else {
        String::new()
    };
    println!(
        "Extracted {total_files} file(s){skipped_note} in {total_dirs} dir(s) \
         ({total_bytes} bytes decompressed) into {}",
        output_dir.display()
    );
    println!("All file CRC-32 checks passed.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruzstd::encoding::{compress_to_vec, CompressionLevel};
    use std::io::Cursor;
    fn wstring(s: &str) -> Vec<u8> {
        let mut v = Vec::new();
        let units: Vec<u16> = s.encode_utf16().collect();
        v.extend_from_slice(&(units.len() as u16).to_le_bytes());
        for u in units {
            v.extend_from_slice(&u.to_le_bytes());
        }
        v
    }

    fn header() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(HEADER_MAGIC);
        v.extend_from_slice(&0u64.to_le_bytes()); // declared total
        v.extend_from_slice(&1u16.to_le_bytes()); // unknown flag
        v.extend_from_slice(&1u16.to_le_bytes()); // total pegs
        v.extend_from_slice(&0u16.to_le_bytes()); // peg number
        v.extend_from_slice(&0u64.to_le_bytes()); // declared file size
        v
    }

    /// A single-directory, single-file PEG for `data` compressed into
    /// `payload` (or `data` empty with `payload` empty for an empty file).
    fn build_peg(payload: &[u8], data: &[u8]) -> Vec<u8> {
        let mut v = header();
        v.extend_from_slice(DIR_MAGIC);
        v.extend_from_slice(&wstring(r"\sub\dir"));
        v.extend_from_slice(FILE_MAGIC);
        v.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        v.extend_from_slice(&(data.len() as u64).to_le_bytes());
        v.extend_from_slice(&crc32fast::hash(data).to_le_bytes());
        v.extend_from_slice(&0u64.to_le_bytes()); // filetime
        v.extend_from_slice(&wstring(r"\sub\dir\hello.txt"));
        v.extend_from_slice(payload);
        v
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("nxdl-peg-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn extracts_zstd_file_entry() {
        let data = b"hello world";
        let payload = compress_to_vec(Cursor::new(&data[..]), CompressionLevel::Fastest);
        let root = temp_dir("file");
        let peg = root.join("game.peg00");
        std::fs::write(&peg, build_peg(&payload, data)).unwrap();

        let out = root.join("out");
        let stats = extract_peg(&peg, &out, None, false).unwrap();
        assert_eq!(stats.dirs, 1);
        assert_eq!(stats.files, 1);
        assert_eq!(stats.decode_errors, 0);
        assert_eq!(stats.size_mismatches, 0);
        assert_eq!(stats.crc_mismatches, 0);
        assert_eq!(stats.compressed_bytes, payload.len() as u64);
        assert_eq!(stats.uncompressed_bytes, data.len() as u64);

        let got = std::fs::read(out.join("sub").join("dir").join("hello.txt")).unwrap();
        assert_eq!(&got, data);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn extracts_concatenated_zstd_frames() {
        // Real PEG payloads are a run of concatenated zstd frames (~128 KiB of
        // output each); make sure every frame is decoded, not just the first.
        let part1 = b"hello ";
        let part2 = b"world, this spans two zstd frames!";
        let data: Vec<u8> = part1.iter().chain(part2.iter()).copied().collect();
        let mut payload = compress_to_vec(Cursor::new(&part1[..]), CompressionLevel::Fastest);
        payload.extend(compress_to_vec(
            Cursor::new(&part2[..]),
            CompressionLevel::Fastest,
        ));

        let root = temp_dir("concat");
        let peg = root.join("game.peg00");
        std::fs::write(&peg, build_peg(&payload, &data)).unwrap();

        let out = root.join("out");
        let stats = extract_peg(&peg, &out, None, false).unwrap();
        assert_eq!(stats.files, 1);
        assert_eq!(stats.decode_errors, 0);
        assert_eq!(stats.size_mismatches, 0);
        assert_eq!(stats.crc_mismatches, 0);
        let got = std::fs::read(out.join("sub").join("dir").join("hello.txt")).unwrap();
        assert_eq!(&got, &data);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// End-to-end check against the real reference PEG
    /// (`reference/MapleStoryM_2.430.6284_Live_1717.peg00`).  It decompresses
    /// ~1.8 GiB, so it only runs when `NXDL_PEG_REFERENCE=1` is set.
    #[test]
    fn extracts_real_reference_peg_cleanly() {
        if std::env::var("NXDL_PEG_REFERENCE").as_deref() != Ok("1") {
            return;
        }
        let peg = Path::new("reference").join("MapleStoryM_2.430.6284_Live_1717.peg00");
        if !peg.exists() {
            return;
        }
        let root = temp_dir("reference");
        let out = root.join("out");
        let stats = extract_peg(&peg, &out, None, false).unwrap();
        assert!(stats.files > 0, "no files were extracted: {stats:?}");
        assert_eq!(stats.decode_errors, 0, "decode errors: {stats:?}");
        assert_eq!(stats.size_mismatches, 0, "size mismatches: {stats:?}");
        assert_eq!(stats.crc_mismatches, 0, "crc mismatches: {stats:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Strict (streaming-install) path against the real reference PEG.
    /// Reads from a plain reader rather than a file path.  Opt-in via
    /// `NXDL_PEG_REFERENCE=1`.
    #[test]
    fn stream_extracts_reference_peg_strictly() {
        if std::env::var("NXDL_PEG_REFERENCE").as_deref() != Ok("1") {
            return;
        }
        let peg = Path::new("reference").join("MapleStoryM_2.430.6284_Live_1717.peg00");
        if !peg.exists() {
            return;
        }
        let root = temp_dir("stream-ref");
        let out = root.join("out");
        let file = File::open(&peg).unwrap();
        let mut r = std::io::BufReader::new(file);
        let stats = extract_peg_stream(&mut r, &out).unwrap();
        assert!(stats.files > 0, "no files were extracted: {stats:?}");
        assert_eq!(stats.decode_errors, 0, "decode errors: {stats:?}");
        assert_eq!(stats.size_mismatches, 0, "size mismatches: {stats:?}");
        assert_eq!(stats.crc_mismatches, 0, "crc mismatches: {stats:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn extracts_empty_file_without_a_payload() {
        let root = temp_dir("empty");
        let peg = root.join("game.peg00");
        // data = "", payload = "".
        std::fs::write(&peg, build_peg(b"", b"")).unwrap();

        let out = root.join("out");
        let stats = extract_peg(&peg, &out, None, false).unwrap();
        assert_eq!(stats.files, 1);
        assert_eq!(stats.decode_errors, 0);
        assert_eq!(stats.size_mismatches, 0);
        assert_eq!(stats.crc_mismatches, 0);
        let got = std::fs::read(out.join("sub").join("dir").join("hello.txt")).unwrap();
        assert!(got.is_empty());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stops_cleanly_at_unknown_magic() {
        let data = b"abc";
        let payload = compress_to_vec(Cursor::new(&data[..]), CompressionLevel::Fastest);
        let mut blob = build_peg(&payload, data);
        // Trailing junk that is not a known entry magic must not error.
        blob.extend_from_slice(b"\x00\x00\x00\x00trailing-junk");
        let root = temp_dir("junk");
        let peg = root.join("game.peg00");
        std::fs::write(&peg, &blob).unwrap();

        let out = root.join("out");
        let stats = extract_peg(&peg, &out, None, false).unwrap();
        assert_eq!(stats.files, 1);
        let got = std::fs::read(out.join("sub").join("dir").join("hello.txt")).unwrap();
        assert_eq!(&got, data);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn rejects_bad_header_magic() {
        let root = temp_dir("badmagic");
        let peg = root.join("bad.peg");
        std::fs::write(&peg, b"NOPE.....................").unwrap();
        let err = extract_peg(&peg, &root, None, false).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("magic"), "got: {msg}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn install_resumes_and_skips_complete_files() {
        // Build a PEG with two files so we can exercise the resume rules:
        //   - existing target with matching CRC-32  -> skipped
        //   - missing / corrupt target              -> (re)installed
        //   - resuming mid-part from a byte offset  -> continues there
        let a = b"content of file A";
        let b = b"content of file B";
        let pa = compress_to_vec(Cursor::new(&a[..]), CompressionLevel::Fastest);
        let pb = compress_to_vec(Cursor::new(&b[..]), CompressionLevel::Fastest);

        let entry = |name: &str, payload: &[u8], data: &[u8]| {
            let mut e = Vec::new();
            e.extend_from_slice(FILE_MAGIC);
            e.extend_from_slice(&(payload.len() as u64).to_le_bytes());
            e.extend_from_slice(&(data.len() as u64).to_le_bytes());
            e.extend_from_slice(&crc32fast::hash(data).to_le_bytes());
            e.extend_from_slice(&0u64.to_le_bytes()); // filetime
            e.extend_from_slice(&wstring(name));
            e.extend_from_slice(payload);
            e
        };

        let mut blob = header();
        let ea = entry(r"\alpha.txt", &pa, a);
        let eb = entry(r"\beta.txt", &pb, b);
        let off_b = (26 + ea.len()) as u64;
        blob.extend_from_slice(&ea);
        blob.extend_from_slice(&eb);

        let root = temp_dir("install");
        let out = root.join("out");
        std::fs::create_dir_all(&out).unwrap();

        // 1) Fresh install from the beginning installs both files.
        {
            let mut cur = Cursor::new(&blob[..]);
            let stats = extract_peg_install(&mut cur, &out, 0, |_| {}).unwrap();
            assert_eq!(stats.files, 2);
            assert_eq!(stats.skipped_files, 0);
        }
        assert_eq!(std::fs::read(out.join("alpha.txt")).unwrap(), a);
        assert_eq!(std::fs::read(out.join("beta.txt")).unwrap(), b);

        // 2) Re-running from the start skips both (target CRC-32 already ok)
        //    and still parses the whole stream cleanly.
        {
            let mut cur = Cursor::new(&blob[..]);
            let stats = extract_peg_install(&mut cur, &out, 0, |_| {}).unwrap();
            assert_eq!(stats.files, 0);
            assert_eq!(stats.skipped_files, 2);
        }

        // 3) Resume mid-part at beta's entry: alpha is left alone, and the
        //    corrupt beta is reinstalled (its CRC-32 did not match).
        {
            std::fs::write(out.join("beta.txt"), b"corrupt").unwrap();
            let mut cur = Cursor::new(&blob[off_b as usize..]);
            let stats = extract_peg_install(&mut cur, &out, off_b, |_| {}).unwrap();
            assert_eq!(stats.files, 1, "beta should be reinstalled: {stats:?}");
            assert_eq!(std::fs::read(out.join("beta.txt")).unwrap(), b);
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn lists_package_structure_without_decoding() {
        let data = b"hello world";
        let payload = compress_to_vec(Cursor::new(&data[..]), CompressionLevel::Fastest);
        let root = temp_dir("list");
        let peg = root.join("game.peg00");
        std::fs::write(&peg, build_peg(&payload, data)).unwrap();

        let file = File::open(&peg).unwrap();
        let mut r = BufReader::new(file);
        let index = list_package(&mut r).unwrap();

        let h = index.header.as_ref().expect("header present");
        assert_eq!(h.total_pegs, 1);
        assert_eq!(h.peg_number, 0);
        assert_eq!(h.declared_file_size, 0);
        assert_eq!(index.dirs, 1);
        assert_eq!(index.files.len(), 1);

        let f = &index.files[0];
        assert_eq!(f.name, "sub/dir/hello.txt");
        assert_eq!(f.compressed_size, payload.len() as u64);
        assert_eq!(f.uncompressed_size, data.len() as u64);
        assert_eq!(f.crc32, crc32fast::hash(data));
        assert_eq!(f.filetime, 0);
        assert_eq!(index.total_uncompressed(), data.len() as u64);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Structure listing against the real reference PEG (no payload decode).
    /// Runs whenever the fixture is present — it is cheap (headers only).
    #[test]
    fn lists_real_reference_peg_structure() {
        let peg = Path::new("reference").join("MapleStoryM_2.430.6284_Live_1717.peg00");
        if !peg.exists() {
            return;
        }
        let file = File::open(&peg).unwrap();
        let mut r = BufReader::new(file);
        let index = list_package(&mut r).unwrap();

        let h = index.header.as_ref().expect("header present");
        assert_eq!(h.total_pegs, 1);
        assert_eq!(h.peg_number, 0);
        assert_eq!(h.declared_file_size, 445_793_771);

        // Known counts from the reference / python tool.
        assert_eq!(index.dirs, 11);
        assert_eq!(index.files.len(), 177);

        // Spot-check a known entry's metadata (matches the earlier probe).
        let f = index
            .files
            .iter()
            .find(|f| f.name == "BlackCipher/BlackCall64.aes")
            .expect("BlackCall64.aes present");
        assert_eq!(f.compressed_size, 30_925_229);
        assert_eq!(f.uncompressed_size, 47_024_416);
        assert_eq!(f.crc32, 0x32613137);
    }

    /// Build one FILE entry (used to assemble multi-file PEG fixtures).
    fn file_entry(name: &str, payload: &[u8], data: &[u8]) -> Vec<u8> {
        let mut e = Vec::new();
        e.extend_from_slice(FILE_MAGIC);
        e.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        e.extend_from_slice(&(data.len() as u64).to_le_bytes());
        e.extend_from_slice(&crc32fast::hash(data).to_le_bytes());
        e.extend_from_slice(&0u64.to_le_bytes()); // filetime
        e.extend_from_slice(&wstring(name));
        e.extend_from_slice(payload);
        e
    }

    #[test]
    fn local_extract_is_strict_and_resumes() {
        let a = b"content of file A";
        let b = b"content of file B";
        let pa = compress_to_vec(Cursor::new(&a[..]), CompressionLevel::Fastest);
        let pb = compress_to_vec(Cursor::new(&b[..]), CompressionLevel::Fastest);
        let mut blob = header();
        blob.extend(file_entry(r"\alpha.txt", &pa, a));
        blob.extend(file_entry(r"\beta.txt", &pb, b));

        let root = temp_dir("local");
        let peg = root.join("game.peg00");
        std::fs::write(&peg, &blob).unwrap();
        let out = root.join("out");

        // Fresh extract writes both files.
        let stats = extract_peg_local(&peg, &out, false).unwrap();
        assert_eq!(stats.files, 2);
        assert_eq!(stats.skipped_files, 0);
        assert_eq!(std::fs::read(out.join("alpha.txt")).unwrap(), a);
        assert_eq!(std::fs::read(out.join("beta.txt")).unwrap(), b);

        // Re-run: both targets already exist with the right CRC-32 → skipped.
        let stats = extract_peg_local(&peg, &out, false).unwrap();
        assert_eq!(stats.files, 0);
        assert_eq!(stats.skipped_files, 2);

        // Corrupt beta on disk: only it is re-extracted.
        std::fs::write(out.join("beta.txt"), b"wrong").unwrap();
        let stats = extract_peg_local(&peg, &out, false).unwrap();
        assert_eq!(stats.files, 1);
        assert_eq!(stats.skipped_files, 1);
        assert_eq!(std::fs::read(out.join("beta.txt")).unwrap(), b);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn local_extract_rejects_corrupt_payload_without_leftovers() {
        let a = b"good file";
        let pa = compress_to_vec(Cursor::new(&a[..]), CompressionLevel::Fastest);
        let mut blob = header();
        blob.extend(file_entry(r"\alpha.txt", &pa, a));
        // A second entry whose payload is not zstd at all.
        blob.extend(file_entry(r"\gamma.txt", b"this is not zstd!", b"whatever"));

        let root = temp_dir("corrupt");
        let peg = root.join("game.peg00");
        std::fs::write(&peg, &blob).unwrap();
        let out = root.join("out");

        // The good file is written, then the corrupt entry fails the part and
        // leaves no partial/truncated file behind.
        let err = extract_peg_local(&peg, &out, false).unwrap_err();
        assert!(format!("{err:#}").contains("zstd"), "got: {err:#}");
        assert_eq!(std::fs::read(out.join("alpha.txt")).unwrap(), a);
        assert!(!out.join("gamma.txt").exists());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn local_extract_with_progress_reports_file_names() {
        let a = b"file A payload";
        let b = b"file B payload";
        let pa = compress_to_vec(Cursor::new(&a[..]), CompressionLevel::Fastest);
        let pbz = compress_to_vec(Cursor::new(&b[..]), CompressionLevel::Fastest);
        let mut blob = header();
        blob.extend(file_entry(r"\alpha.txt", &pa, a));
        blob.extend(file_entry(r"\sub\beta.txt", &pbz, b));

        let root = temp_dir("progress");
        let peg = root.join("game.peg00");
        std::fs::write(&peg, &blob).unwrap();
        let out = root.join("out");

        // The on_file hook sees each normalised file name just before it is
        // written; the byte-counting reader advances the bar.
        let bar = ProgressBar::new(blob.len() as u64);
        let mut seen: Vec<String> = Vec::new();
        let mut hook = |name: &str| seen.push(name.to_owned());
        let stats =
            extract_peg_local_with(&peg, &out, false, Some(&bar), Some(&mut hook)).unwrap();
        bar.finish_and_clear();
        assert_eq!(stats.files, 2);
        assert_eq!(stats.dirs, 0);
        assert_eq!(seen, ["alpha.txt", "sub/beta.txt"]);
        assert!(
            bar.position() >= 26,
            "bar never advanced past the header: {}",
            bar.position()
        );
        assert_eq!(std::fs::read(out.join("alpha.txt")).unwrap(), a);
        assert_eq!(std::fs::read(out.join("sub").join("beta.txt")).unwrap(), b);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn peg_part_matcher_and_numeric_order() {
        assert!(is_peg_part("maplestory.peg00"));
        assert!(is_peg_part("maplestory.peg"));
        assert!(is_peg_part("MapleStoryM_2.430.6284_Live_1717.peg00"));
        assert!(!is_peg_part("maplestory.peg00.part"));
        assert!(!is_peg_part("maplestory.peg00.crdownload"));
        assert!(!is_peg_part("maplestory.pegnote"));
        assert!(!is_peg_part("maplestory.peg0x"));
        assert!(!is_peg_part("readme.txt"));

        // peg02 sorts before peg10 (numeric); a bare .peg sorts first.
        let mut names = ["maplestory.peg10", "maplestory.peg02", "maplestory.peg"];
        names.sort_by(|a, b| peg_part_sort_key(a).cmp(&peg_part_sort_key(b)));
        assert_eq!(
            names,
            ["maplestory.peg", "maplestory.peg02", "maplestory.peg10"]
        );
    }

    #[test]
    fn manual_extract_single_file() {
        let data = b"single part content";
        let payload = compress_to_vec(Cursor::new(&data[..]), CompressionLevel::Fastest);
        let root = temp_dir("manual-one");
        let src = root.join("only.peg03");
        let mut blob = header();
        blob.extend(file_entry(r"\dir\only.txt", &payload, data));
        std::fs::write(&src, blob).unwrap();

        let out = root.join("out");
        manual_extract(&src, &out, false).unwrap();
        assert_eq!(std::fs::read(out.join("dir").join("only.txt")).unwrap(), data);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn manual_extract_directory_scans_peg_parts() {
        let data_a = b"alpha data";
        let data_b = b"beta data";
        let pa = compress_to_vec(Cursor::new(&data_a[..]), CompressionLevel::Fastest);
        let pb = compress_to_vec(Cursor::new(&data_b[..]), CompressionLevel::Fastest);
        let make = |name: &str, payload: &[u8], data: &[u8]| {
            let mut blob = header();
            blob.extend(file_entry(name, payload, data));
            blob
        };

        let root = temp_dir("manual-dir");
        let src = root.join("parts");
        std::fs::create_dir_all(src.join("nested")).unwrap();
        std::fs::write(src.join("game.peg00"), make(r"\alpha.txt", &pa, data_a)).unwrap();
        std::fs::write(src.join("game.peg01"), make(r"\beta.txt", &pb, data_b)).unwrap();
        // Inside a sub-directory → must NOT be picked up (non-recursive).
        std::fs::write(
            src.join("nested").join("game.peg00"),
            make(r"\gamma.txt", &pa, data_a),
        )
        .unwrap();
        std::fs::write(src.join("readme.txt"), b"not a peg").unwrap();

        let out = root.join("out");
        manual_extract(&src, &out, false).unwrap();

        assert_eq!(std::fs::read(out.join("alpha.txt")).unwrap(), data_a);
        assert_eq!(std::fs::read(out.join("beta.txt")).unwrap(), data_b);
        assert!(!out.join("gamma.txt").exists(), "nested part must be ignored");

        // Re-run is idempotent (files are skipped, not rewritten).
        manual_extract(&src, &out, false).unwrap();
        assert_eq!(std::fs::read(out.join("alpha.txt")).unwrap(), data_a);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn manual_extract_directory_with_no_pegs_errors() {
        let root = temp_dir("manual-none");
        let src = root.join("empty");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("notes.txt"), b"x").unwrap();

        let out = root.join("out");
        let err = manual_extract(&src, &out, false).unwrap_err();
        assert!(format!("{err:#}").contains("no .peg files"), "got: {err:#}");

        let _ = std::fs::remove_dir_all(&root);
    }
}
