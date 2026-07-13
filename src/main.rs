mod cli;
mod filter;
mod ngm;
mod nxl;
mod resume;

use anyhow::{bail, Result};
use clap::Parser;

use cli::{Cli, Commands};
use filter::FileFilter;

fn main() -> Result<()> {
    let cli = Cli::parse();

    println!("nxdl v{}", env!("CARGO_PKG_VERSION"));

    // ---- NGM subcommand ----
    if let Some(ref cmd) = cli.command {
        match cmd {
            Commands::Nxl {
                appid,
                check,
                download,
                verbose,
                filter,
                filter_regex,
                invert_filter,
            } => {
                let resolved = cli::resolve_appid(appid).unwrap_or_else(|| appid.clone());
                println!("nxdl nxl: appid = {} (raw: {appid})", resolved);

                // Build filter if provided.
                let filter = if let Some(ref raw) = filter {
                    Some(FileFilter::from_substrings(raw, *invert_filter)?)
                } else if let Some(ref raw) = filter_regex {
                    Some(FileFilter::from_regexes(raw, *invert_filter)?)
                } else {
                    None
                };

                if let Some(ref manifest_url) = check {
                    println!("  --check");
                    println!("    manifest_url = {manifest_url}");
                    if filter.is_some() {
                        println!("    filter        = active");
                    }
                    println!();
                    nxl::check_client(manifest_url, &resolved, filter.as_ref(), *verbose > 0)?;
                } else if let Some(ref dl) = download {
                    if dl.len() < 2 {
                        bail!("--download requires <MANIFEST_URL> <TARGET_PATH>");
                    }
                    let manifest_url = &dl[0];
                    let target_path = std::path::PathBuf::from(&dl[1]);
                    println!("  --download");
                    println!("    manifest_url = {manifest_url}");
                    println!("    target_path  = {}", target_path.display());
                    if filter.is_some() {
                        println!("    filter        = active");
                    }
                    println!();
                    nxl::download_client(manifest_url, &resolved, &target_path, filter.as_ref())?;
                } else {
                    println!("  (no action specified; use --check <MANIFEST_URL> or --download <MANIFEST_URL> <TARGET_PATH>)");
                }
                return Ok(());
            }
            Commands::Ngm {
                appid,
                check,
                verbose,
                filter,
                filter_regex,
                invert_filter,
            } => {
                // Resolve the appid (alias → real id).
                let resolved = cli::resolve_appid(appid).unwrap_or_else(|| appid.clone());
                println!("nxdl ngm: appid = {} (raw: {appid})", resolved);

                if *check {
                    // Build filter if provided.
                    let filter = if let Some(ref raw) = filter {
                        Some(FileFilter::from_substrings(raw, *invert_filter)?)
                    } else if let Some(ref raw) = filter_regex {
                        Some(FileFilter::from_regexes(raw, *invert_filter)?)
                    } else {
                        None
                    };
                    println!();
                    ngm::check_ngm(&resolved, *verbose > 0, filter.as_ref())?;
                } else {
                    println!("  (no action specified; use --check)");
                }
                return Ok(());
            }
        }
    }

    // ---- Main (non-subcommand) path ----
    let raw_appid = cli
        .appid
        .as_deref()
        .or(cli.game.as_deref())
        .unwrap_or("??");
    let appid = match cli.resolve_appid() {
        Some(id) => id,
        None => bail!("unknown appid: '{}' (must be a number or a known alias)", raw_appid),
    };
    let appid_str = appid.as_str();

    // Build the optional file filter (shared by --download and --check).
    let filter = if let Some(ref raw) = cli.filter {
        Some(FileFilter::from_substrings(raw, cli.invert_filter)?)
    } else if let Some(ref raw) = cli.filter_regex {
        Some(FileFilter::from_regexes(raw, cli.invert_filter)?)
    } else {
        None
    };

    match &cli.check {
        Some(Some(manifest_url)) => {
            // --check <URL>: NXL path (existing behaviour).
            println!("nxdl: appid = {} (raw: {})", appid, raw_appid);
            println!("  --check");
            println!("    manifest_url = {manifest_url}");
            if filter.is_some() {
                println!("    filter        = active");
            }
            println!();
            nxl::check_client(manifest_url, appid_str, filter.as_ref(), cli.verbose > 0)?;
        }
        Some(None) => {
            // --check (flag only): NGM API path.
            if !cli::is_ngm(raw_appid) {
                bail!(
                    "--check requires a manifest URL for NXL games.\n\
                     Usage: nxdl {raw_appid} --check <MANIFEST_URL>"
                );
            }
            println!("nxdl: appid = {} (raw: {})", appid, raw_appid);
            println!("  --check (NGM)");
            if filter.is_some() {
                println!("    filter        = active");
            }
            println!();
            ngm::check_ngm(appid_str, cli.verbose > 0, filter.as_ref())?;
        }
        None => {
            // --check not provided; try --download or no-op.
            if let Some((manifest_url, target_path)) = cli.download_args() {
                println!("nxdl: appid = {} (raw: {})", appid, raw_appid);
                println!("  --download");
                println!("    manifest_url = {manifest_url}");
                println!("    target_path  = {}", target_path.display());
                if filter.is_some() {
                    println!("    filter        = active");
                }
                println!();
                nxl::download_client(
                    manifest_url,
                    appid_str,
                    &target_path,
                    filter.as_ref(),
                )?;
            } else {
                println!("nxdl: appid = {} (raw: {})", appid, raw_appid);
                println!(
                    "  (no action specified; use --check [MANIFEST_URL] or \
                     --download <MANIFEST_URL> <TARGET_PATH>)"
                );
            }
        }
    }

    Ok(())
}
