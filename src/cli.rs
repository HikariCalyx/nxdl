use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// nxdl - a downloader for NXL games.
#[derive(Parser, Debug)]
#[command(name = "nxdl", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Target game platform or alias.
    /// When --appid is not provided, the game name is looked up in the alias table.
    /// Applicable aliases: 
    /// gms, gms_pts, gms_cw, gmb, vin_gl,
    /// jms, msn, jmb, kmb, kmbt, tales_jp.
    #[arg(value_name = "GAME")]
    pub game: Option<String>,

    /// The application ID (a number or an alias).
    /// Overrides the game name for appid lookup.
    #[arg(long, value_name = "APPID")]
    pub appid: Option<String>,

    /// Download the client.
    ///
    /// With two values: downloads an NXL client from a manifest URL into
    /// the target path.
    /// With one value (NGM games only): downloads the client into the
    /// target path using the NGM API.
    #[arg(long, value_names = ["MANIFEST_URL", "TARGET_PATH"], num_args = 1..=2)]
    pub download: Option<Vec<String>>,

    /// Patch an NXL client from its current version to a new version.
    ///
    /// Takes two values: `<MANIFEST_URL_OR_HASH>` (the target version's
    /// `.manifest.hash` URL, a 40-character SHA-1 hex hash, or `latest` to
    /// resolve via the branch API using the login session in `nxl.ini`) and
    /// `<TARGET_PATH>` (the root client directory).
    #[arg(long, value_names = ["MANIFEST_URL", "TARGET_PATH"], num_args = 2)]
    pub patch: Option<Vec<String>>,

    /// Check the client size and file count without downloading.
    ///
    /// With a manifest URL: checks an NXL client (existing behaviour).
    /// Without a value (flag only): for NGM games (jms, kms, …) fetches
    /// game info and manifest from the NGM API automatically.
    #[arg(long, value_name = "MANIFEST_URL", num_args = 0..=1)]
    pub check: Option<Option<String>>,

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

    /// Output results as JSON (for `--check`).
    #[arg(long)]
    pub json: bool,

    /// Route all traffic through a proxy.
    ///
    /// With a value: use that proxy URL (e.g. `--proxy=http://127.0.0.1:8080`
    /// or `--proxy=socks5://127.0.0.1:1080`). A missing scheme defaults to
    /// `http://`. With no value (just `--proxy`): use the system-configured
    /// proxy (the `*_PROXY` environment variables, or Windows Internet
    /// Settings).
    #[arg(long, value_name = "PROXY_URL", num_args = 0..=1)]
    pub proxy: Option<Option<String>>,

    /// Skip TLS certificate verification (unsafe).
    ///
    /// Only use this as an escape hatch for environments where the normal
    /// certificate chain cannot be validated.
    #[arg(long)]
    pub allow_insecure: bool,
}

/// Subcommands for different game platform operations.
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// NXL operations (download / check NXL clients, account login).
    Nxl {
        /// Application ID (a number or alias like "gms").
        ///
        /// Required for `--check` and `--download`, but not for `--login`.
        #[arg(long, value_name = "APPID")]
        appid: Option<String>,

        /// Log in to a Nexon account and store the session in `nxl.ini`.
        ///
        /// Opens a WebView dialog pointed at the region's login page. Valid
        /// regions (case-insensitive): `ww`/`gl`/`worldwide`/`global`,
        /// `tw`/`taiwan`, `sea`/`southeastasia`, `th`/`thailand`. When no
        /// region is given, `ww` (global) is used.
        #[arg(long, value_name = "REGION", num_args = 0..=1)]
        login: Option<Option<String>>,

        /// Check the client.
        ///
        /// With a value (a `.manifest.hash` URL or a 40-char SHA-1 hash),
        /// checks that client. With no value, the public manifest is resolved
        /// automatically from the branch API using the login session saved in
        /// `nxl.ini` (run `--login` first).
        #[arg(long, value_name = "MANIFEST_URL", num_args = 0..=1)]
        check: Option<Option<String>>,

        /// Download the client into the target path.
        ///
        /// With two values (`<MANIFEST_URL> <TARGET_PATH>`), downloads that
        /// manifest. With one value (`<TARGET_PATH>`), the public manifest is
        /// resolved automatically from the branch API using the login session
        /// saved in `nxl.ini` (run `--login` first).
        #[arg(long, value_names = ["MANIFEST_URL", "TARGET_PATH"], num_args = 1..=2)]
        download: Option<Vec<String>>,

        /// Patch the client from its current version to a new version.
        ///
        /// Takes two values: `<MANIFEST_URL_OR_HASH>` (the target version's
        /// `.manifest.hash` URL, a 40-character SHA-1 hex hash, or the
        /// special value `latest` to resolve via the branch API using the
        /// login session in `nxl.ini`) and `<TARGET_PATH>` (the root client
        /// directory).
        ///
        /// The current version hash is read from
        /// `<TARGET_PATH>/patchdata/<APPID>.manifest.hash`.  Diff files are
        /// downloaded, applied to the files in `<TARGET_PATH>/appdata/`, and
        /// the patched output is staged in
        /// `<TARGET_PATH>/patchdata/patched/`.  Files that cannot be patched
        /// are re-downloaded from the new manifest.  On success the files are
        /// moved into `<TARGET_PATH>/appdata/` and the hash file is updated.
        #[arg(long, value_names = ["MANIFEST_URL", "TARGET_PATH"], num_args = 2)]
        patch: Option<Vec<String>>,

        /// Enable verbose output (lists files with `--check`).
        #[arg(short, long, action = clap::ArgAction::Count)]
        verbose: u8,

        /// Keep only files whose path contains one of the given substrings.
        ///
        /// Pass a colon-separated list of conditions, e.g.
        /// `--filter="Base:Character:Etc"`. Backslashes are treated as
        /// forward slashes when matching. Cannot be combined with
        /// `--filter-regex`.
        #[arg(long, value_name = "COND1[:COND2...]", require_equals = true)]
        filter: Option<String>,

        /// Keep only files whose path matches one of the given regex patterns.
        #[arg(long, value_name = "PAT1[:PAT2...]", require_equals = true)]
        filter_regex: Option<String>,

        /// Invert the filter: keep only files that do NOT match.
        #[arg(long)]
        invert_filter: bool,

        /// Route all traffic through a proxy (value optional; empty = system
        /// proxy). See the top-level `--proxy` help for details.
        #[arg(long, value_name = "PROXY_URL", num_args = 0..=1)]
        proxy: Option<Option<String>>,

        /// Skip TLS certificate verification (unsafe).
        #[arg(long)]
        allow_insecure: bool,
    },

    /// NGM operations.
    Ngm {
        /// Application ID (a number or alias like "jms", "kms").
        #[arg(long, value_name = "APPID")]
        appid: String,

        /// Check client info via the NGM API (fetches manifest and prints
        /// summary).
        #[arg(long)]
        check: bool,

        /// Download the client into the target path using the NGM API.
        #[arg(long, value_name = "TARGET_PATH")]
        download: Option<PathBuf>,

        /// Enable verbose output (lists files with `--check`).
        #[arg(short, long, action = clap::ArgAction::Count)]
        verbose: u8,

        /// Keep only files whose path contains one of the given substrings.
        ///
        /// Pass a colon-separated list of conditions, e.g.
        /// `--filter="Base:Character:Etc"`. Backslashes are treated as
        /// forward slashes when matching. Cannot be combined with
        /// `--filter-regex`.
        #[arg(long, value_name = "COND1[:COND2...]", require_equals = true)]
        filter: Option<String>,

        /// Keep only files whose path matches one of the given regex patterns.
        #[arg(long, value_name = "PAT1[:PAT2...]", require_equals = true)]
        filter_regex: Option<String>,

        /// Invert the filter: keep only files that do NOT match.
        #[arg(long)]
        invert_filter: bool,

        /// Output results as JSON (for `--check`).
        #[arg(long)]
        json: bool,

        /// Route all traffic through a proxy (value optional; empty = system
        /// proxy). See the top-level `--proxy` help for details.
        #[arg(long, value_name = "PROXY_URL", num_args = 0..=1)]
        proxy: Option<Option<String>>,

        /// Skip TLS certificate verification (unsafe).
        #[arg(long)]
        allow_insecure: bool,
    },
}

impl Cli {
    /// Resolve the app ID string.
    ///
    /// If `--appid` was provided, it is used (parsed as a number or looked up
    /// as an alias).  Otherwise the `game` positional argument is looked up.
    /// Returns `None` when neither resolves to a known app ID.
    pub fn resolve_appid(&self) -> Option<String> {
        if let Some(ref raw) = self.appid {
            resolve_appid(raw)
        } else if let Some(ref game) = self.game {
            resolve_appid(game)
        } else {
            None
        }
    }
}

/// Known appid aliases for NXL games (case-insensitive).
const NXL_ALIASES: &[(&str, &str)] = &[
    ("gms", "10100"),
    ("gmb", "10200"),
    ("vin_gl", "10300"),
    ("gms_pts", "40600"),
    ("gms_cw", "59822"),
];

/// Known appid aliases for NGM games (case-insensitive).
const NGM_ALIASES: &[(&str, &str)] = &[
    ("tales_jp", "2528@c829"),
    ("kmb", "74245@761d"),
    ("kmbt", "106542@b48c"),
    ("kms", "589825"),
    ("kmst", "589826"),
    ("kms_mac", "589825@ce13"),
    ("kmst_mac", "589826@7235"),
    ("jmb", "16785925"),
    ("jms", "16785939@bb01"),
    ("kmsm", "106656"),
    ("msn", "106690@d811"),
];

/// Resolve a raw appid string (number or alias) to an app ID string.
///
/// If the input is already a numeric string, it is returned as-is.
/// Otherwise a case-insensitive alias lookup is performed against both
/// the NXL and NGM alias tables.
/// Returns `None` when the alias is unknown.
pub fn resolve_appid(raw: &str) -> Option<String> {
    // If it's a pure number, return it directly.
    if raw.chars().all(|c| c.is_ascii_digit()) {
        return Some(raw.to_owned());
    }
    // Otherwise, try case-insensitive alias lookup.
    let lower = raw.to_lowercase();
    for &(alias, id) in NXL_ALIASES {
        if alias == lower {
            return Some(id.to_owned());
        }
    }
    for &(alias, id) in NGM_ALIASES {
        if alias == lower {
            return Some(id.to_owned());
        }
    }
    None
}

/// Returns `true` if `raw` refers to an NGM (Nexon Game Manager) game.
///
/// This is true when:
/// - `raw` is an NGM alias (e.g. "jms", "kms")
/// - `raw` already contains `@` (direct NGM appid like "16785939@bb01")
/// - the *resolved* appid contains `@`
pub fn is_ngm(raw: &str) -> bool {
    let lower = raw.to_lowercase();
    for &(alias, _) in NGM_ALIASES {
        if alias == lower {
            return true;
        }
    }
    if let Some(resolved) = resolve_appid(raw) {
        if resolved.contains('@') {
            return true;
        }
    }
    raw.contains('@')
}
