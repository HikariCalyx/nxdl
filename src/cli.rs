use std::path::PathBuf;

use clap::Parser;

/// nxdl - a downloader for NXL games.
#[derive(Parser, Debug)]
#[command(name = "nxdl", version, about, long_about = None)]
pub struct Cli {
    /// The game to download (e.g. "nxl", "gms").
    /// When --appid is not provided, the game name is looked up in the alias table.
    #[arg(value_name = "GAME")]
    pub game: String,

    /// The application ID (a number or an alias).
    /// Overrides the game name for appid lookup.
    #[arg(long, value_name = "APPID")]
    pub appid: Option<String>,

    /// Download the client using the given manifest URL into the target path.
    #[arg(long, value_names = ["MANIFEST_URL", "TARGET_PATH"])]
    pub download: Option<Vec<String>>,

    /// Check the client size and file count from a manifest URL without
    /// downloading anything.
    #[arg(long, value_name = "MANIFEST_URL")]
    pub check: Option<String>,

    /// Enable verbose output.
    ///
    /// With `--check`, lists the files that would be downloaded (filtered
    /// when `--filter` or `--filter-regex` is supplied).
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Keep only files whose path contains one of the given substrings.
    ///
    /// Pass a colon-separated list of conditions, e.g.
    /// `--filter="Base:Character:Etc"`. Backslashes are treated as forward
    /// slashes when matching. Cannot be combined with `--filter-regex`.
    #[arg(long, value_name = "COND1[:COND2...]", require_equals = true)]
    pub filter: Option<String>,

    /// Keep only files whose path matches one of the given regex patterns.
    ///
    /// Pass a colon-separated list of patterns, e.g.
    /// `--filter-regex="^mxd/Base":".wz$"`. Cannot be combined with `--filter`.
    #[arg(long, value_name = "PAT1[:PAT2...]", require_equals = true)]
    pub filter_regex: Option<String>,

    /// Invert the filter: keep only files that do NOT match.
    ///
    /// Can be used together with `--filter` or `--filter-regex`.
    #[arg(long)]
    pub invert_filter: bool,
}

impl Cli {
    /// Convenience: returns `(manifest_url, target_path)` when `--download` is set.
    pub fn download_args(&self) -> Option<(&str, PathBuf)> {
        self.download.as_ref().and_then(|v| {
            if v.len() >= 2 {
                Some((v[0].as_str(), PathBuf::from(&v[1])))
            } else {
                None
            }
        })
    }

    /// Resolve the numeric app ID.
    ///
    /// If `--appid` was provided, it is used (parsed as a number or looked up
    /// as an alias).  Otherwise the `game` positional argument is looked up.
    /// Returns `None` when neither resolves to a known app ID.
    pub fn resolve_appid(&self) -> Option<u32> {
        if let Some(ref raw) = self.appid {
            resolve_appid(raw)
        } else {
            resolve_appid(&self.game)
        }
    }
}

/// Known appid aliases (case-insensitive).
const ALIASES: &[(&str, u32)] = &[
    ("gms", 10100),
    ("gms_pts", 40600),
    ("gms_cw", 59822),
];

/// Resolve a raw appid string (number or alias) to a numeric app ID.
///
/// Case-insensitive for aliases. Returns `None` when the alias is unknown
/// or the number fails to parse.
pub fn resolve_appid(raw: &str) -> Option<u32> {
    // If it's already a number, parse it directly.
    if let Ok(id) = raw.parse::<u32>() {
        return Some(id);
    }
    // Otherwise, try case-insensitive alias lookup.
    let lower = raw.to_lowercase();
    for &(alias, id) in ALIASES {
        if alias == lower {
            return Some(id);
        }
    }
    None
}
