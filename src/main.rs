mod cli;
mod filter;
mod login;
mod miniwzlib;
mod net;
mod ngm;
mod nxl;
mod resume;
mod taskprogress;

use anyhow::{bail, Result};
use clap::Parser;

use cli::{Cli, Commands};
use filter::FileFilter;

fn main() -> Result<()> {
    let cli = Cli::parse();

    // In JSON mode, suppress the version banner (output is machine-readable).
    let json_mode = cli.json
        || cli.command.as_ref().map_or(false, |c| {
            matches!(c, Commands::Ngm { json: true, .. })
        });
    if !json_mode {
        println!("nxdl v{}", env!("CARGO_PKG_VERSION"));
    }

    // ---- NGM subcommand ----
    if let Some(ref cmd) = cli.command {
        match cmd {
            Commands::Nxl {
                appid,
                login,
                check,
                download,
                verbose,
                filter,
                filter_regex,
                invert_filter,
                proxy,
                allow_insecure,
            } => {
                // ---- Login: interactive WebView, no appid required ----
                if let Some(region_opt) = login {
                    let region_str = region_opt.as_deref().unwrap_or("ww");
                    let region = login::Region::parse(region_str).ok_or_else(|| {
                        anyhow::anyhow!(
                            "unknown region '{region_str}'. Valid values: \
                             ww/gl/worldwide/global, tw/taiwan, sea/southeastasia, \
                             th/thailand"
                        )
                    })?;
                    let proxy = net::resolve_proxy(proxy.as_ref());
                    let proxy = proxy.as_deref();
                    let ini_path = std::path::PathBuf::from("nxl.ini");
                    login::login(region, &ini_path, *allow_insecure, proxy)?;
                    return Ok(());
                }

                let proxy = net::resolve_proxy(proxy.as_ref());
                let proxy = proxy.as_deref();
                let allow_insecure = *allow_insecure;
                let appid = appid.as_ref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "--appid is required for --check and --download\n\
                         Usage: nxdl nxl --appid <APPID> --check <MANIFEST_URL>"
                    )
                })?;
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

                if let Some(check_opt) = check {
                    // Resolve the manifest source: an explicit URL/hash, or the
                    // public branch manifest from the saved login session.
                    let manifest_source = match check_opt {
                        Some(url) => url.clone(),
                        None => {
                            let ini_path = std::path::Path::new("nxl.ini");
                            let session = login::load_session(ini_path)?;
                            println!(
                                "  resolving public manifest via branch API ('{}' region)...",
                                session.region.code()
                            );
                            login::resolve_public_manifest_url(
                                &session,
                                &resolved,
                                allow_insecure,
                                proxy,
                            )?
                        }
                    };
                    println!("  --check");
                    println!("    manifest_url = {manifest_source}");
                    if filter.is_some() {
                        println!("    filter        = active");
                    }
                    println!();
                    nxl::check_client(
                        &manifest_source,
                        &resolved,
                        filter.as_ref(),
                        *verbose > 0,
                        allow_insecure,
                        proxy,
                    )?;
                } else if let Some(ref dl) = download {
                    // Two values: explicit <MANIFEST_URL> <TARGET_PATH>.
                    // One value: <TARGET_PATH>, with the manifest resolved from
                    // the saved login session via the branch API.
                    let (manifest_source, target_path) = match dl.as_slice() {
                        [manifest_url, target] => {
                            (manifest_url.clone(), std::path::PathBuf::from(target))
                        }
                        [target] => {
                            let ini_path = std::path::Path::new("nxl.ini");
                            let session = login::load_session(ini_path)?;
                            println!(
                                "  resolving public manifest via branch API ('{}' region)...",
                                session.region.code()
                            );
                            let url = login::resolve_public_manifest_url(
                                &session,
                                &resolved,
                                allow_insecure,
                                proxy,
                            )?;
                            (url, std::path::PathBuf::from(target))
                        }
                        _ => bail!(
                            "--download takes <TARGET_PATH> or <MANIFEST_URL> <TARGET_PATH>"
                        ),
                    };
                    println!("  --download");
                    println!("    manifest_url = {manifest_source}");
                    println!("    target_path  = {}", target_path.display());
                    if filter.is_some() {
                        println!("    filter        = active");
                    }
                    println!();
                    nxl::download_client(
                        &manifest_source,
                        &resolved,
                        &target_path,
                        filter.as_ref(),
                        allow_insecure,
                        proxy,
                    )?;
                } else {
                    println!("  (no action specified; use --check [MANIFEST_URL], --download <MANIFEST_URL> <TARGET_PATH>, or --login [REGION])");
                }
                return Ok(());
            }
            Commands::Ngm {
                appid,
                check,
                download,
                verbose,
                filter,
                filter_regex,
                invert_filter,
                json,
                proxy,
                allow_insecure,
            } => {
                let proxy = net::resolve_proxy(proxy.as_ref());
                let proxy = proxy.as_deref();
                let allow_insecure = *allow_insecure;
                // Resolve the appid (alias → real id).
                let resolved = cli::resolve_appid(appid).unwrap_or_else(|| appid.clone());
                if !*json {
                    println!("nxdl ngm: appid = {} (raw: {appid})", resolved);
                }

                // Build filter if provided.
                let filter = if let Some(ref raw) = filter {
                    Some(FileFilter::from_substrings(raw, *invert_filter)?)
                } else if let Some(ref raw) = filter_regex {
                    Some(FileFilter::from_regexes(raw, *invert_filter)?)
                } else {
                    None
                };

                if *check {
                    if !*json {
                        println!();
                    }
                    ngm::check_ngm(
                        &resolved,
                        *verbose > 0,
                        *json,
                        filter.as_ref(),
                        allow_insecure,
                        proxy,
                    )?;
                } else if let Some(ref target_path) = download {
                    println!("  --download");
                    println!("    target_path  = {}", target_path.display());
                    if filter.is_some() {
                        println!("    filter        = active");
                    }
                    println!();
                    ngm::download_ngm(
                        &resolved,
                        target_path,
                        filter.as_ref(),
                        allow_insecure,
                        proxy,
                    )?;
                } else {
                    println!("  (no action specified; use --check or --download <TARGET_PATH>)");
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

    // Resolve networking options (shared by --download and --check).
    let allow_insecure = cli.allow_insecure;
    let proxy = net::resolve_proxy(cli.proxy.as_ref());
    let proxy = proxy.as_deref();

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
            nxl::check_client(
                manifest_url,
                appid_str,
                filter.as_ref(),
                cli.verbose > 0,
                allow_insecure,
                proxy,
            )?;
        }
        Some(None) => {
            if cli::is_ngm(raw_appid) {
                // --check (flag only): NGM API path.
                if !cli.json {
                    println!("nxdl: appid = {} (raw: {})", appid, raw_appid);
                    println!("  --check (NGM)");
                    if filter.is_some() {
                        println!("    filter        = active");
                    }
                    println!();
                }
                ngm::check_ngm(
                    appid_str,
                    cli.verbose > 0,
                    cli.json,
                    filter.as_ref(),
                    allow_insecure,
                    proxy,
                )?;
            } else {
                // --check (flag only), NXL game: resolve the public manifest
                // from the saved login session via the branch API.
                let session = login::load_session(std::path::Path::new("nxl.ini"))?;
                println!("nxdl: appid = {} (raw: {})", appid, raw_appid);
                println!("  --check");
                println!(
                    "  resolving public manifest via branch API ('{}' region)...",
                    session.region.code()
                );
                let manifest_url = login::resolve_public_manifest_url(
                    &session,
                    appid_str,
                    allow_insecure,
                    proxy,
                )?;
                println!("    manifest_url = {manifest_url}");
                if filter.is_some() {
                    println!("    filter        = active");
                }
                println!();
                nxl::check_client(
                    &manifest_url,
                    appid_str,
                    filter.as_ref(),
                    cli.verbose > 0,
                    allow_insecure,
                    proxy,
                )?;
            }
        }
        None => {
            // --check not provided; try --download or no-op.
            if let Some(ref dl) = cli.download {
                match dl.len() {
                    2 => {
                        // NXL download: <MANIFEST_URL> <TARGET_PATH>
                        let manifest_url = &dl[0];
                        let target_path = std::path::PathBuf::from(&dl[1]);
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
                            allow_insecure,
                            proxy,
                        )?;
                    }
                    1 => {
                        let target_path = std::path::PathBuf::from(&dl[0]);
                        if cli::is_ngm(raw_appid) {
                            // NGM download: <TARGET_PATH>
                            println!("nxdl: appid = {} (raw: {})", appid, raw_appid);
                            println!("  --download (NGM)");
                            println!("    target_path  = {}", target_path.display());
                            if filter.is_some() {
                                println!("    filter        = active");
                            }
                            println!();
                            ngm::download_ngm(
                                appid_str,
                                &target_path,
                                filter.as_ref(),
                                allow_insecure,
                                proxy,
                            )?;
                        } else {
                            // NXL download: <TARGET_PATH>, manifest resolved
                            // from the saved login session via the branch API.
                            let session =
                                login::load_session(std::path::Path::new("nxl.ini"))?;
                            println!("nxdl: appid = {} (raw: {})", appid, raw_appid);
                            println!("  --download");
                            println!(
                                "  resolving public manifest via branch API ('{}' region)...",
                                session.region.code()
                            );
                            let manifest_url = login::resolve_public_manifest_url(
                                &session,
                                appid_str,
                                allow_insecure,
                                proxy,
                            )?;
                            println!("    manifest_url = {manifest_url}");
                            println!("    target_path  = {}", target_path.display());
                            if filter.is_some() {
                                println!("    filter        = active");
                            }
                            println!();
                            nxl::download_client(
                                &manifest_url,
                                appid_str,
                                &target_path,
                                filter.as_ref(),
                                allow_insecure,
                                proxy,
                            )?;
                        }
                    }
                    _ => unreachable!(),
                }
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
