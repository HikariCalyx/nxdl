mod cli;
mod filter;
mod nxl;
mod resume;

use anyhow::{bail, Result};
use clap::Parser;

use cli::Cli;
use filter::FileFilter;

fn main() -> Result<()> {
    let cli = Cli::parse();

    println!("nxdl v{}", env!("CARGO_PKG_VERSION"));

    let raw_appid = cli.appid.as_deref().unwrap_or(&cli.game);
    let appid = match cli.resolve_appid() {
        Some(id) => id,
        None => bail!("unknown appid: '{}' (must be a number or a known alias)", raw_appid),
    };

    // Build the optional file filter (shared by --download and --check).
    let filter = if let Some(ref raw) = cli.filter {
        Some(FileFilter::from_substrings(raw, cli.invert_filter)?)
    } else if let Some(ref raw) = cli.filter_regex {
        Some(FileFilter::from_regexes(raw, cli.invert_filter)?)
    } else {
        None
    };

    if let Some(ref manifest_url) = cli.check {
        // --check: print summary (and file list if --verbose).
        println!("nxdl: appid = {} (raw: {})", appid, raw_appid);
        println!("  --check");
        println!("    manifest_url = {manifest_url}");
        if filter.is_some() {
            println!("    filter        = active");
        }
        println!();
        nxl::check_client(manifest_url, appid, filter.as_ref(), cli.verbose > 0)?;
    } else if let Some((manifest_url, target_path)) = cli.download_args() {
        // --download: fetch and write the client.
        println!("nxdl: appid = {} (raw: {})", appid, raw_appid);
        println!("  --download");
        println!("    manifest_url = {manifest_url}");
        println!("    target_path  = {}", target_path.display());
        if filter.is_some() {
            println!("    filter        = active");
        }
        println!();
        nxl::download_client(manifest_url, appid, &target_path, filter.as_ref())?;
    } else {
        println!("nxdl: appid = {} (raw: {})", appid, raw_appid);
        println!("  (no action specified; use --check <MANIFEST_URL> or --download <MANIFEST_URL> <TARGET_PATH>)");
    }

    Ok(())
}
