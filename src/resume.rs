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

use std::io;
use std::path::{Path, PathBuf};

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

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const VERSION: u8 = 1;
const HEADER_SIZE: usize = 0x14; // 20 bytes

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

    std::fs::write(&path, &data)?;
    Ok(())
}

/// Mark an object as completed in the sidecar file.
///
/// Returns an error if `index` is out of bounds.
pub fn mark_done(dest: &Path, index: u32, kind: &SidecarKind) -> io::Result<()> {
    let path = progress_path(dest, kind);
    let mut data = std::fs::read(&path)?;
    let num_objects = u32::from_le_bytes(
        data[8..12]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad sidecar"))?,
    );
    if index >= num_objects {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("object index {index} out of range ({num_objects} objects)"),
        ));
    }
    let offset = HEADER_SIZE + (index as usize) / 8;
    let bit = (index % 8) as u8;
    data[offset] |= 1 << bit;
    std::fs::write(&path, &data)?;
    Ok(())
}

/// Delete the sidecar file (called when the download completes successfully).
pub fn delete_progress(dest: &Path, kind: &SidecarKind) {
    let path = progress_path(dest, kind);
    let _ = std::fs::remove_file(&path);
}
