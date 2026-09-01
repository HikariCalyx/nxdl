//! Manifest relative-path handling.
//!
//! Nexon manifests store file paths with Windows-style backslash separators
//! (e.g. `Data\Base\Base.wz`).  On Windows `Path::join` splits on `\`, so
//! joining such a string onto a directory yields the intended nested tree.
//! On macOS and Linux `\` is an ordinary filename character, so the same join
//! used to produce one flat file literally named `Data\Base\Base.wz` instead
//! of the nested directories.
//!
//! Everything here treats both `/` and `\` as separators so a manifest path
//! resolves to the same tree on every platform.

use std::path::{Path, PathBuf};

/// Rewrite a manifest path to use `/` separators.
///
/// This is the canonical in-memory form: it is what gets displayed, matched
/// by [`crate::filter::FileFilter`], and recorded in resume bookkeeping.
pub fn normalize(rel: &str) -> String {
    rel.replace('\\', "/")
}

/// Iterate over the meaningful components of a manifest path.
///
/// Both `/` and `\` separate components.  Empty, `.` and `..` components are
/// dropped so a malformed or hostile manifest entry cannot escape the target
/// directory.
fn components(rel: &str) -> impl Iterator<Item = &str> {
    rel.split(['/', '\\'])
        .filter(|c| !c.is_empty() && *c != "." && *c != "..")
}

/// Join a manifest path onto `root`, one component at a time.
///
/// Use this instead of `root.join(rel)` for any path that came out of a
/// manifest.
pub fn join(root: &Path, rel: &str) -> PathBuf {
    let mut path = root.to_path_buf();
    for component in components(rel) {
        path.push(component);
    }
    path
}

/// Like [`join`], but appends `suffix` to the final component's file name
/// (e.g. `.nxdlpatch`) rather than treating it as a separate component.
pub fn join_with_suffix(root: &Path, rel: &str, suffix: &str) -> PathBuf {
    let mut parts: Vec<&str> = components(rel).collect();
    let last = parts.pop();
    let mut path = root.to_path_buf();
    for component in parts {
        path.push(component);
    }
    match last {
        Some(name) => path.push(format!("{name}{suffix}")),
        None => path.push(suffix),
    }
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_converts_backslashes() {
        assert_eq!(normalize(r"Data\Base\Base.wz"), "Data/Base/Base.wz");
        assert_eq!(normalize("Data/Base/Base.wz"), "Data/Base/Base.wz");
        assert_eq!(normalize("Base.wz"), "Base.wz");
    }

    #[test]
    fn join_nests_windows_separators() {
        let root = Path::new("root");
        let expected: PathBuf = ["root", "Data", "Base", "Base.wz"].iter().collect();
        assert_eq!(join(root, r"Data\Base\Base.wz"), expected);
        assert_eq!(join(root, "Data/Base/Base.wz"), expected);
        assert_eq!(join(root, r"Data/Base\Base.wz"), expected);

        // Guard the actual bug: the result must be a nested tree on *every*
        // platform, not one file whose name contains a separator.  A plain
        // `root.join(rel)` satisfies this on Windows but not on POSIX, so
        // count components explicitly rather than relying on `PathBuf` equality.
        for rel in [r"Data\Base\Base.wz", "Data/Base/Base.wz"] {
            let joined = join(root, rel);
            assert_eq!(joined.components().count(), 4, "{rel} did not nest");
            assert_eq!(
                joined.file_name().unwrap().to_str().unwrap(),
                "Base.wz",
                "{rel} kept a separator in the file name"
            );
        }
    }

    #[test]
    fn join_stays_inside_root() {
        let root = Path::new("root");
        // Leading separators, `.` and `..` must not escape `root`.
        assert_eq!(join(root, r"\Data\x"), Path::new("root").join("Data").join("x"));
        assert_eq!(
            join(root, r"..\..\etc\passwd"),
            Path::new("root").join("etc").join("passwd")
        );
        assert_eq!(join(root, r"Data\.\x"), Path::new("root").join("Data").join("x"));
        assert_eq!(join(root, r"Data\\x"), Path::new("root").join("Data").join("x"));
    }

    #[test]
    fn join_with_suffix_extends_the_file_name() {
        let root = Path::new("patches");
        let expected: PathBuf = ["patches", "Data", "Base", "Base.wz.nxdlpatch"]
            .iter()
            .collect();
        let joined = join_with_suffix(root, r"Data\Base\Base.wz", ".nxdlpatch");
        assert_eq!(joined, expected);
        assert_eq!(joined.components().count(), 4);
        assert_eq!(
            joined.file_name().unwrap().to_str().unwrap(),
            "Base.wz.nxdlpatch"
        );
        assert_eq!(
            join_with_suffix(root, "Base.wz", ".nxdlpatch"),
            Path::new("patches").join("Base.wz.nxdlpatch")
        );
    }
}
