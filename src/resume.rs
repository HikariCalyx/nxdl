//! Resume support for NXL and NGM object-based downloads.
//!
//! Each download sidecar file records which object blocks have been
//! successfully written to disk.  On interruption, the next run detects the
//! sidecar and skips already-completed objects.
//!
//! Two sidecar formats are supported:
//! - `.nxldl` (NXL) — magic `NXLDL`, extension `.nxldl`
//! - `.ngmdl` (NGM) — magic `NGMDL`, extension `.ngmdl`
//!
//! # Binary layout
//!
//! ```text
//! 0x00-0x04  ASCII magic (e.g. "NXLDL" or "NGMDL")
//! 0x05       version (1)
//! 0x06-0x07  reserved (zeroed)
//! 0x08-0x0B  number of objects (u32 LE)
//! 0x0C-0x13  total file size (u64 LE)
//! 0x14+      completion bitmap: 1 bit per object, LSB of each byte first,
//!            padded to whole bytes (0 = not done, 1 = done)
//! ```
//!
//! A sidecar only ever describes an *unfinished* download: it is deleted once
//! the file is complete.  [`CompletedLog`] therefore records finished files (in
//! a per-app log file next to the manifest hash) so that a later run can skip
//! them instead of downloading them again.

use std::collections::HashMap;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use sha1::{Digest, Sha1};

// ---------------------------------------------------------------------------
// Sidecar kind
// ---------------------------------------------------------------------------

/// Describes the magic bytes and file extension for a sidecar format.
#[derive(Clone, Copy)]
pub struct SidecarKind {
    pub magic: [u8; 5],
    pub ext: &'static str,
}

/// NXL sidecar format (`.nxldl`, magic `NXLDL`).
pub const SIDECAR_NXL: SidecarKind = SidecarKind {
    magic: *b"NXLDL",
    ext: ".nxldl",
};

/// NGM sidecar format (`.ngmdl`, magic `NGMDL`).
pub const SIDECAR_NGM: SidecarKind = SidecarKind {
    magic: *b"NGMDL",
    ext: ".ngmdl",
};

/// PEG setup-part segment sidecar (`.nxdlseg`, magic `NXPEG`).
///
/// Used while a `.pegNN` part is downloaded in parallel byte-range segments
/// (default non-streamed mode): one "object" per segment, so the bitmap says
/// which of the part's byte ranges are already on disk.  Lives next to the
/// staging file (e.g. `maplestory.peg00.part.nxdlseg`) and is deleted once
/// the part is complete.
pub const SIDECAR_PEG: SidecarKind = SidecarKind {
    magic: *b"NXPEG",
    ext: ".nxdlseg",
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const VERSION: u8 = 1;
const HEADER_SIZE: usize = 0x14; // 20 bytes

/// Serializes sidecar updates.
///
/// The objects of one file are downloaded by several worker threads, all of
/// which report completion into the same sidecar, and updating a sidecar is a
/// read-modify-write cycle.  Serializing it is required for two reasons:
/// without it concurrent updates lose each other's bits, and — because writing
/// truncates the file first — a concurrent reader can observe a zero-length
/// sidecar, which previously panicked while parsing the header and aborted the
/// whole download (releases are built with `panic = 'abort'`).
static SIDECAR_LOCK: Mutex<()> = Mutex::new(());

/// Lock the sidecar mutex, ignoring poisoning: every operation either fully
/// applies or leaves the sidecar untouched, so a panic inside a critical
/// section cannot leave the file in a half-updated state.
fn lock_sidecars() -> std::sync::MutexGuard<'static, ()> {
    SIDECAR_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Returns the path of the sidecar file for `dest`.
pub fn progress_path(dest: &Path, kind: &SidecarKind) -> PathBuf {
    let mut s = dest.as_os_str().to_owned();
    s.push(kind.ext);
    PathBuf::from(s)
}

/// Read a sidecar file and return the completion bitmap, or `None` if the
/// sidecar is absent, invalid, or inconsistent.
///
/// Returns `(completed_bitmap, num_objects, total_size)` on success.
/// Each byte in the returned bitmap is `1` if the object is done, `0`
/// otherwise (unpacked representation, one byte per object for easy indexing).
pub fn read_progress(path: &Path, kind: &SidecarKind) -> Option<(Vec<u8>, u32, u64)> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.len() < HEADER_SIZE {
        return None;
    }
    if bytes[0..5] != kind.magic {
        return None;
    }
    if bytes[5] != VERSION {
        return None;
    }
    let num_objects = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
    let total_size = u64::from_le_bytes(bytes[12..20].try_into().ok()?);

    let packed_len = (num_objects as usize + 7) / 8;
    if bytes.len() < HEADER_SIZE + packed_len {
        return None;
    }

    // Unpack bits into one byte per object.
    let mut bitmap = vec![0u8; num_objects as usize];
    for (i, b) in bitmap.iter_mut().enumerate() {
        let byte = bytes[HEADER_SIZE + i / 8];
        *b = (byte >> (i % 8)) & 1;
    }
    Some((bitmap, num_objects, total_size))
}

/// Create a new sidecar file for a download with the given parameters.
pub fn create_progress(
    dest: &Path,
    num_objects: u32,
    total_size: u64,
    kind: &SidecarKind,
) -> io::Result<()> {
    let path = progress_path(dest, kind);
    let packed_len = (num_objects as usize + 7) / 8;
    let file_size = HEADER_SIZE + packed_len;
    let mut data = vec![0u8; file_size];

    data[0..5].copy_from_slice(&kind.magic);
    data[5] = VERSION;
    // bytes 6-7 are reserved (already zero)
    data[8..12].copy_from_slice(&num_objects.to_le_bytes());
    data[12..20].copy_from_slice(&total_size.to_le_bytes());
    // bitmap starts as all zeros (nothing done yet)

    let _guard = lock_sidecars();
    std::fs::write(&path, &data)?;
    Ok(())
}

/// Mark an object as completed in the sidecar file.
///
/// Returns an error if `index` is out of bounds or the sidecar is missing,
/// truncated, or not of `kind`.
pub fn mark_done(dest: &Path, index: u32, kind: &SidecarKind) -> io::Result<()> {
    let path = progress_path(dest, kind);
    let _guard = lock_sidecars();

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)?;

    // `read_exact` fails cleanly (instead of panicking) on a short sidecar.
    let mut header = [0u8; HEADER_SIZE];
    file.read_exact(&mut header)?;
    if header[0..5] != kind.magic || header[5] != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("bad sidecar {}", path.display()),
        ));
    }
    let num_objects = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);

    if index >= num_objects {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("object index {index} out of range ({num_objects} objects)"),
        ));
    }

    let needed = HEADER_SIZE as u64 + (num_objects as u64 + 7) / 8;
    if file.metadata()?.len() < needed {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("truncated sidecar {}", path.display()),
        ));
    }

    // Update only the byte holding this object's bit: rewriting the whole file
    // would briefly truncate it, and neighbouring objects share the byte.
    let offset = (HEADER_SIZE + (index as usize) / 8) as u64;
    let mask = 1u8 << (index % 8);
    file.seek(SeekFrom::Start(offset))?;
    let mut byte = [0u8; 1];
    file.read_exact(&mut byte)?;
    if byte[0] & mask == 0 {
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(&[byte[0] | mask])?;
    }
    Ok(())
}

/// Delete the sidecar file (called when the download completes successfully).
pub fn delete_progress(dest: &Path, kind: &SidecarKind) {
    let path = progress_path(dest, kind);
    let _guard = lock_sidecars();
    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// Completed-file log
// ---------------------------------------------------------------------------

/// A stable identifier for a manifest file's object list.
///
/// Two manifest entries with the same path are the same file only if they list
/// the same objects, so this is what a [`CompletedLog`] entry is validated
/// against before the file is skipped.
pub fn objects_id(objects: &[String]) -> String {
    let mut hasher = Sha1::new();
    for id in objects {
        hasher.update(id.as_bytes());
        hasher.update(b"\n");
    }
    hex::encode(hasher.finalize())
}

struct CompletedEntry {
    fsize: u64,
    objects_id: String,
}

/// Record of files that were downloaded completely.
///
/// The sidecar of a finished file is deleted, so without this log a resumed run
/// cannot distinguish a finished file from one that was never started and
/// downloads it again.  It lives next to the manifest hash and looks like:
///
/// ```text
/// <fsize>\t<objects id>\t<relative path>
/// ```
///
/// Only a matching `fsize` *and* object list counts as complete, so a file
/// that changed in a newer manifest is downloaded again.  New completions are
/// appended; entries that no longer match are dropped the next time the log is
/// opened, and malformed lines are ignored.
pub struct CompletedLog {
    path: PathBuf,
    entries: Mutex<HashMap<String, CompletedEntry>>,
}

impl CompletedLog {
    /// Load the log at `path`, or start an empty one if it does not exist yet.
    pub fn open(path: PathBuf) -> Self {
        let mut entries = HashMap::new();
        let mut lines = 0usize;
        if let Ok(text) = std::fs::read_to_string(&path) {
            for line in text.lines() {
                lines += 1;
                let mut fields = line.splitn(3, '\t');
                let (Some(fsize), Some(objects_id), Some(rel_path)) =
                    (fields.next(), fields.next(), fields.next())
                else {
                    continue;
                };
                let Ok(fsize) = fsize.parse::<u64>() else {
                    continue;
                };
                entries.insert(
                    rel_path.to_string(),
                    CompletedEntry {
                        fsize,
                        objects_id: objects_id.to_string(),
                    },
                );
            }
        }
        let log = Self {
            path,
            entries: Mutex::new(entries),
        };
        // Drop entries superseded by a newer manifest (and any malformed or
        // duplicated lines) so the file does not grow with every version.
        let live = log.entries.lock().unwrap_or_else(|e| e.into_inner()).len();
        if lines > live {
            let _ = log.rewrite();
        }
        log
    }

    /// Rewrite the log with exactly one line per known file.
    fn rewrite(&self) -> io::Result<()> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let mut text = String::new();
        for (rel_path, entry) in entries.iter() {
            text.push_str(&format!(
                "{}\t{}\t{}\n",
                entry.fsize, entry.objects_id, rel_path
            ));
        }
        drop(entries);

        // Write-then-rename so an interrupted compaction cannot destroy the log.
        let mut tmp = self.path.clone().into_os_string();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, &self.path)
    }

    /// Whether `rel_path` was already downloaded with this exact manifest entry.
    pub fn is_complete(&self, rel_path: &str, fsize: u64, objects_id: &str) -> bool {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries
            .get(rel_path)
            .map_or(false, |e| e.fsize == fsize && e.objects_id == objects_id)
    }

    /// Record `rel_path` as completely downloaded.
    pub fn record(&self, rel_path: &str, fsize: u64, objects_id: &str) -> io::Result<()> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if entries.get(rel_path).map_or(false, |e| {
            e.fsize == fsize && e.objects_id == objects_id
        }) {
            return Ok(());
        }

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{fsize}\t{objects_id}\t{rel_path}")?;

        entries.insert(
            rel_path.to_string(),
            CompletedEntry {
                fsize,
                objects_id: objects_id.to_string(),
            },
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("nxdl-resume-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn mark_done_reports_an_empty_sidecar_instead_of_panicking() {
        // A sidecar can be observed at zero length (a concurrent rewrite used to
        // truncate it, or a crash left it that way); that must be an error, not
        // an out-of-range slice index.
        let root = temp_dir("empty");
        let dest = root.join("file.bin");
        std::fs::write(progress_path(&dest, &SIDECAR_NXL), b"").unwrap();
        assert!(mark_done(&dest, 0, &SIDECAR_NXL).is_err());
    }

    #[test]
    fn mark_done_rejects_a_truncated_bitmap() {
        let root = temp_dir("truncated");
        let dest = root.join("file.bin");
        create_progress(&dest, 16, 1024, &SIDECAR_NXL).unwrap();
        let path = progress_path(&dest, &SIDECAR_NXL);
        let header = std::fs::read(&path).unwrap();
        std::fs::write(&path, &header[..HEADER_SIZE]).unwrap();
        assert!(mark_done(&dest, 0, &SIDECAR_NXL).is_err());
    }

    #[test]
    fn concurrent_mark_done_keeps_every_bit() {
        let root = temp_dir("concurrent");
        let dest = root.join("file.bin");
        const OBJECTS: u32 = 64;
        create_progress(&dest, OBJECTS, 1024, &SIDECAR_NXL).unwrap();

        std::thread::scope(|scope| {
            for i in 0..OBJECTS {
                let dest = &dest;
                scope.spawn(move || mark_done(dest, i, &SIDECAR_NXL).unwrap());
            }
        });

        let (bitmap, objects, size) =
            read_progress(&progress_path(&dest, &SIDECAR_NXL), &SIDECAR_NXL).unwrap();
        assert_eq!(objects, OBJECTS);
        assert_eq!(size, 1024);
        assert!(bitmap.iter().all(|&b| b == 1), "lost updates: {bitmap:?}");
    }

    #[test]
    fn completed_log_round_trips() {
        let root = temp_dir("log");
        let path = root.join("10100.downloaded");
        let objects = vec!["aa".to_string(), "bb".to_string()];
        let id = objects_id(&objects);

        let log = CompletedLog::open(path.clone());
        assert!(!log.is_complete("Data/Base.wz", 42, &id));
        log.record("Data/Base.wz", 42, &id).unwrap();
        assert!(log.is_complete("Data/Base.wz", 42, &id));

        // A different manifest entry for the same path is not complete.
        assert!(!log.is_complete("Data/Base.wz", 43, &id));
        assert!(!log.is_complete("Data/Base.wz", 42, &objects_id(&["cc".to_string()])));

        // Reloading keeps the record, and re-recording adds no duplicate line.
        let log = CompletedLog::open(path.clone());
        assert!(log.is_complete("Data/Base.wz", 42, &id));
        log.record("Data/Base.wz", 42, &id).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 1);
    }

    #[test]
    fn completed_log_ignores_malformed_lines() {
        let root = temp_dir("log-bad");
        let path = root.join("10100.downloaded");
        std::fs::write(&path, "garbage\n42\tdeadbeef\tData/ok.wz\n\n").unwrap();

        let log = CompletedLog::open(path.clone());
        assert!(log.is_complete("Data/ok.wz", 42, "deadbeef"));
        assert!(!log.is_complete("Data/ok.wz", 42, "other"));

        // Opening compacts the file down to the entries it understood.
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "42\tdeadbeef\tData/ok.wz\n");
    }

    #[test]
    fn completed_log_compaction_keeps_the_newest_entry() {
        let root = temp_dir("log-compact");
        let path = root.join("10100.downloaded");
        std::fs::write(&path, "7\told\tData/a.wz\n7\tnew\tData/a.wz\n").unwrap();

        let log = CompletedLog::open(path.clone());
        assert!(log.is_complete("Data/a.wz", 7, "new"));
        assert!(!log.is_complete("Data/a.wz", 7, "old"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "7\tnew\tData/a.wz\n");
    }
}
