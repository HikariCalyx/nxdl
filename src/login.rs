//! Interactive NX account login for `nxdl nxl --login <region>`.
//!
//! Opens a WebView dialog (backed by the Tauri `wry`/`tao` stack) pointed at
//! the region-specific NX login page. Once the browser reaches a
//! post-login landing page — either the region portal
//! `<domain>/main/<language>` or the account settings page
//! `.../account/<language>/setting/...` (typically on the central
//! `www.nexon.com` account portal) — the session cookies are captured and,
//! together with the selected region, written to `nxl.ini`.
//!
//! The language segment differs per region: `en` for Global/SEA, `zh` for
//! Taiwan, and `th` for Thailand.

use std::path::Path;

use anyhow::{Context, Result};

// ---------------------------------------------------------------------------
// Region
// ---------------------------------------------------------------------------

/// A NX account region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Region {
    /// Global / worldwide account (`www.nexon.com`).
    Global,
    /// Taiwan account (`tw.nexon.com`).
    Taiwan,
    /// South-East Asia account (`sea.nexon.com`).
    Sea,
    /// Thailand account (`th.nexon.com`).
    Thailand,
}

impl Region {
    /// Parse a region argument (case-insensitive). Returns `None` for unknown
    /// values.
    pub fn parse(raw: &str) -> Option<Region> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "ww" | "gl" | "worldwide" | "global" => Some(Region::Global),
            "tw" | "taiwan" => Some(Region::Taiwan),
            "sea" | "southeastasia" => Some(Region::Sea),
            "th" | "thailand" => Some(Region::Thailand),
            _ => None,
        }
    }

    /// Short canonical code stored in `nxl.ini`.
    pub fn code(self) -> &'static str {
        match self {
            Region::Global => "ww",
            Region::Taiwan => "tw",
            Region::Sea => "sea",
            Region::Thailand => "th",
        }
    }

    /// The NX domain for this region.
    pub fn domain(self) -> &'static str {
        match self {
            Region::Global => "www.nexon.com",
            Region::Taiwan => "tw.nexon.com",
            Region::Sea => "sea.nexon.com",
            Region::Thailand => "th.nexon.com",
        }
    }

    /// The login page URL for this region.
    pub fn login_url(self) -> String {
        format!("https://{}/account/login", self.domain())
    }

    /// The UI language used by this region's NX pages. This is the language
    /// segment that appears in post-login landing URLs.
    pub fn language(self) -> &'static str {
        match self {
            Region::Global => "en",
            Region::Sea => "en",
            Region::Taiwan => "zh",
            Region::Thailand => "th",
        }
    }

    /// URL prefixes that indicate a successful login for this region.
    ///
    /// After authenticating, NX redirects away from `/account/login` to one
    /// of a few landing pages depending on the flow:
    ///
    /// - `https://<domain>/main/<language>` — the game/portal landing page.
    /// - `https://www.nexon.com/account/<language>/setting/...` — the account
    ///   settings area (e.g. `.../setting/account-overview`) on the central
    ///   account portal, used when logging in from the standalone login page.
    /// - `https://<domain>/account/<language>/setting/...` — the same settings
    ///   area, in case a region serves it from its own domain.
    fn completion_prefixes(self) -> Vec<String> {
        let lang = self.language();
        let mut prefixes = vec![
            format!("https://{}/main/{lang}", self.domain()),
            format!("https://www.nexon.com/account/{lang}/setting"),
        ];
        if self.domain() != "www.nexon.com" {
            prefixes.push(format!("https://{}/account/{lang}/setting", self.domain()));
        }
        prefixes
    }
}

/// Returns `true` if `url` (ignoring any query string / fragment) equals
/// `prefix` or is nested beneath it.
fn url_matches_prefix(url: &str, prefix: &str) -> bool {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    let path = path.trim_end_matches('/');
    let prefix = prefix.trim_end_matches('/');
    path == prefix || path.starts_with(&format!("{prefix}/"))
}

/// Guidance shown when this machine cannot open the login WebView (a headless
/// or SSH session with no desktop, or a platform without a supported WebView).
const NO_WEBVIEW_HELP: &str = "\
Interactive login needs a desktop WebView, which isn't available here. \
Run `nxdl nxl --login <region>` on another device that has a GUI (Windows or \
macOS), then copy the generated `nxl.ini` to this machine (into the working \
directory) to reuse the saved session.";

/// Returns `true` if `url` is a post-login landing page for `region`.
fn is_login_complete(url: &str, region: Region) -> bool {
    region
        .completion_prefixes()
        .iter()
        .any(|prefix| url_matches_prefix(url, prefix))
}

// ---------------------------------------------------------------------------
// nxl.ini persistence
// ---------------------------------------------------------------------------

/// A login session persisted in `nxl.ini`.
pub struct SavedSession {
    pub region: Region,
    pub cookies: Vec<(String, String)>,
}

/// Render the selected region and captured cookies as INI text.
fn render_ini(region: Region, cookies: &[(String, String)]) -> String {
    let mut out = String::new();
    out.push_str("[account]\n");
    out.push_str(&format!("region = {}\n", region.code()));
    out.push('\n');
    out.push_str("[cookies]\n");
    for (name, value) in cookies {
        out.push_str(&format!("{name} = {value}\n"));
    }
    out
}

/// Write the selected region and captured cookies to `path` in INI format.
fn save_ini(path: &Path, region: Region, cookies: &[(String, String)]) -> Result<()> {
    std::fs::write(path, render_ini(region, cookies))
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

/// Parse `nxl.ini` text into a [`SavedSession`].
fn parse_session(text: &str) -> Result<SavedSession> {
    let mut section = String::new();
    let mut region: Option<Region> = None;
    let mut cookies: Vec<(String, String)> = Vec::new();

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = name.trim().to_ascii_lowercase();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        match section.as_str() {
            "account" if key.eq_ignore_ascii_case("region") => {
                region = Region::parse(value);
            }
            "cookies" if !key.is_empty() => {
                cookies.push((key.to_owned(), value.to_owned()));
            }
            _ => {}
        }
    }

    let region = region
        .ok_or_else(|| anyhow::anyhow!("nxl.ini is missing a valid [account] region"))?;
    if cookies.is_empty() {
        anyhow::bail!("nxl.ini has no [cookies]; re-run `nxdl nxl --login`");
    }
    Ok(SavedSession { region, cookies })
}

/// Read a saved login session (region + cookies) from `ini_path`.
pub fn load_session(ini_path: &Path) -> Result<SavedSession> {
    let text = std::fs::read_to_string(ini_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            anyhow::anyhow!(
                "no saved login found at {}. Run `nxdl nxl --login <region>` first.",
                ini_path.display()
            )
        } else {
            anyhow::Error::from(e)
                .context(format!("failed to read {}", ini_path.display()))
        }
    })?;
    parse_session(&text)
        .with_context(|| format!("failed to parse {}", ini_path.display()))
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run the interactive login flow for `region` and persist the result to
/// `ini_path`.
pub fn login(
    region: Region,
    ini_path: &Path,
    allow_insecure: bool,
    proxy: Option<&str>,
) -> Result<()> {
    println!(
        "Opening login window for region '{}' ({})...",
        region.code(),
        region.domain(),
    );
    println!("Login URL: {}", region.login_url());

    let cookies = run_login_webview(region)?;

    save_ini(ini_path, region, &cookies)?;
    println!(
        "Login complete: saved region '{}' and {} cookie(s) to {}",
        region.code(),
        cookies.len(),
        ini_path.display(),
    );

    // Best-effort: greet the user by their Nexon tag. A failure here does not
    // invalidate the saved session, so we only warn.
    match fetch_nexon_tag(region, &cookies, allow_insecure, proxy) {
        Ok(Some(tag)) => println!("Logged in as {tag}"),
        Ok(None) => eprintln!("warning: logged in, but the account has no nexonTag"),
        Err(e) => eprintln!("warning: could not fetch account info: {e:#}"),
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Authenticated APIs
// ---------------------------------------------------------------------------

/// Build a `Cookie` request-header value from the stored cookie pairs.
fn cookie_header(cookies: &[(String, String)]) -> String {
    cookies
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ")
}

/// A ready-to-use agent for the short JSON API calls in this module.
fn api_agent(allow_insecure: bool, proxy: Option<&str>) -> ureq::Agent {
    use std::time::Duration;
    crate::net::agent(
        allow_insecure,
        proxy,
        Duration::from_secs(10),
        Duration::from_secs(30),
    )
}

/// Fetch the signed-in user's `nexonTag` from
/// `https://<domain>/api/account/v1/account`, using the captured session
/// cookies. Returns `None` when the response has no `nexonTag` field.
fn fetch_nexon_tag(
    region: Region,
    cookies: &[(String, String)],
    allow_insecure: bool,
    proxy: Option<&str>,
) -> Result<Option<String>> {
    let url = format!("https://{}/api/account/v1/account", region.domain());
    let agent = api_agent(allow_insecure, proxy);

    let body = agent
        .get(&url)
        .set("Cookie", &cookie_header(cookies))
        .set("Accept", "application/json")
        .call()
        .with_context(|| format!("request to {url} failed"))?
        .into_string()
        .context("failed to read account response body")?;

    parse_nexon_tag(&body)
}

/// Resolve the public branch's manifest URL for `appid` via
/// `https://<domain>/api/game-build/v1/branch/games/<appid>/public`, using the
/// saved session cookies.
///
/// The returned URL is a `.manifest.hash` URL suitable for
/// [`crate::nxl::check_client`] / [`crate::nxl::download_client`].
pub fn resolve_public_manifest_url(
    session: &SavedSession,
    appid: &str,
    allow_insecure: bool,
    proxy: Option<&str>,
) -> Result<String> {
    let url = format!(
        "https://{}/api/game-build/v1/branch/games/{appid}/public",
        session.region.domain(),
    );
    let agent = api_agent(allow_insecure, proxy);

    // ureq treats 4xx/5xx as `Err(Status(..))`; capture the body in both cases
    // so we can surface the server's own error message (e.g. "Product cannot be
    // found", "User does not have permission").
    let (status, body) = match agent
        .get(&url)
        .set("Cookie", &cookie_header(&session.cookies))
        .set("Accept", "application/json")
        .call()
    {
        Ok(resp) => (
            resp.status(),
            resp.into_string()
                .context("failed to read branch API response body")?,
        ),
        Err(ureq::Error::Status(code, resp)) => {
            (code, resp.into_string().unwrap_or_default())
        }
        Err(e) => {
            return Err(anyhow::Error::from(e)).with_context(|| {
                format!(
                    "branch API request to {url} failed \
                     (is the saved login still valid? try `nxdl nxl --login`)"
                )
            });
        }
    };

    interpret_branch_response(appid, status, &body)
}

/// Pull a human-readable message out of a JSON error body, trying the field
/// names Nexon APIs commonly use.
fn extract_api_message(json: &serde_json::Value) -> Option<String> {
    for key in ["message", "error", "errorMessage", "msg", "detail"] {
        if let Some(s) = json.get(key).and_then(|v| v.as_str()) {
            let s = s.trim();
            if !s.is_empty() {
                return Some(s.to_owned());
            }
        }
    }
    None
}

/// Interpret a branch API response: return the `manifestUrl` on success, or a
/// descriptive error for the "not found" / "no permission" / other failures.
fn interpret_branch_response(appid: &str, status: u16, body: &str) -> Result<String> {
    let json: Option<serde_json::Value> = serde_json::from_str(body).ok();

    // Success: a non-empty manifestUrl.
    if let Some(url) = json
        .as_ref()
        .and_then(|v| v.get("manifestUrl"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        return Ok(url.to_owned());
    }

    // Otherwise, build the clearest possible error message.
    let message = json
        .as_ref()
        .and_then(extract_api_message)
        .unwrap_or_else(|| body.trim().to_owned());
    let lower = message.to_ascii_lowercase();

    if status == 404 || lower.contains("cannot be found") || lower.contains("not found") {
        anyhow::bail!(
            "product '{appid}' was not found. Double-check the appid — it may be \
             wrong, retired, or not published in this account's region."
        );
    }
    if status == 401
        || status == 403
        || lower.contains("permission")
        || lower.contains("not authorized")
        || lower.contains("unauthorized")
        || lower.contains("forbidden")
    {
        anyhow::bail!(
            "your account does not have permission for product '{appid}'. It may \
             require ownership/entitlement, or a different account region \
             (try `nxdl nxl --login <region>`)."
        );
    }
    if message.is_empty() {
        anyhow::bail!(
            "branch API returned HTTP {status} with no manifestUrl for product '{appid}'."
        );
    }
    anyhow::bail!("branch API error for product '{appid}' (HTTP {status}): {message}");
}

/// Extract the `nexonTag` field from an account API response body.
///
/// Returns `None` when the field is absent or empty. See the module tests for
/// the response shape.
fn parse_nexon_tag(body: &str) -> Result<Option<String>> {
    let json: serde_json::Value =
        serde_json::from_str(body).context("failed to parse account response as JSON")?;

    Ok(json
        .get("nexonTag")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_owned()))
}

// ---------------------------------------------------------------------------
// WebView implementation (Windows / macOS)
// ---------------------------------------------------------------------------

/// Open the WebView dialog and block until login completes (or the window is
/// closed). Returns the captured `(name, value)` cookie pairs for the region
/// domain.
#[cfg(any(target_os = "windows", target_os = "macos"))]
fn run_login_webview(region: Region) -> Result<Vec<(String, String)>> {
    use anyhow::{anyhow, bail};
    use tao::{
        dpi::LogicalSize,
        event::{Event, WindowEvent},
        event_loop::{ControlFlow, EventLoopBuilder},
        platform::run_return::EventLoopExtRunReturn,
        window::WindowBuilder,
    };
    use wry::WebViewBuilder;

    /// Custom event delivered from the WebView callbacks to the event loop.
    enum UserEvent {
        /// The WebView reached the post-login landing page.
        LoginComplete,
    }

    let domain = region.domain().to_owned();
    let login_url = region.login_url();

    let mut event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();

    let window = WindowBuilder::new()
        .with_title(format!("NX Login ({})", region.code()))
        .with_inner_size(LogicalSize::new(480.0, 760.0))
        .build(&event_loop)
        .map_err(|e| anyhow!("failed to create the login window: {e}\n\n{NO_WEBVIEW_HELP}"))?;

    // Fire `LoginComplete` when navigation reaches a post-login landing page.
    let nav_proxy = proxy.clone();
    let load_proxy = proxy.clone();

    let webview = WebViewBuilder::new()
        .with_url(login_url.as_str())
        .with_navigation_handler(move |url| {
            if is_login_complete(&url, region) {
                let _ = nav_proxy.send_event(UserEvent::LoginComplete);
            }
            // Always allow navigation to proceed.
            true
        })
        .with_on_page_load_handler(move |_event, url| {
            // Backup trigger in case the final hop happens without a fresh
            // navigation callback (e.g. a client-side redirect).
            if is_login_complete(&url, region) {
                let _ = load_proxy.send_event(UserEvent::LoginComplete);
            }
        })
        .build(&window)
        .map_err(|e| anyhow!("failed to create the login WebView: {e}\n\n{NO_WEBVIEW_HELP}"))?;

    // Read session cookies from the region domain and the central account
    // portal (`www.nexon.com`). Cookies scoped to the shared `.nexon.com`
    // parent appear under both; host-only cookies are picked up from whichever
    // host set them. Names are de-duplicated (first hit wins).
    let cookie_urls = {
        let mut urls = vec![format!("https://{domain}/")];
        if domain != "www.nexon.com" {
            urls.push("https://www.nexon.com/".to_owned());
        }
        urls
    };
    let mut captured: Option<Vec<(String, String)>> = None;
    let mut capture_err: Option<anyhow::Error> = None;

    event_loop.run_return(|event, _target, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            Event::UserEvent(UserEvent::LoginComplete) => {
                if captured.is_some() || capture_err.is_some() {
                    return;
                }
                let mut pairs: Vec<(String, String)> = Vec::new();
                let mut seen: std::collections::HashSet<String> =
                    std::collections::HashSet::new();
                let mut last_err: Option<anyhow::Error> = None;
                for url in &cookie_urls {
                    match webview.cookies_for_url(url) {
                        Ok(cookies) => {
                            for c in cookies {
                                if seen.insert(c.name().to_string()) {
                                    pairs.push((
                                        c.name().to_string(),
                                        c.value().to_string(),
                                    ));
                                }
                            }
                        }
                        Err(e) => {
                            last_err = Some(anyhow!(
                                "failed to read cookies from WebView for {url}: {e}"
                            ));
                        }
                    }
                }
                if pairs.is_empty() {
                    if let Some(e) = last_err {
                        capture_err = Some(e);
                    } else {
                        capture_err =
                            Some(anyhow!("no cookies were found for the logged-in session"));
                    }
                } else {
                    captured = Some(pairs);
                }
                *control_flow = ControlFlow::Exit;
            }
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                *control_flow = ControlFlow::Exit;
            }
            _ => {}
        }
    });

    if let Some(e) = capture_err {
        return Err(e);
    }
    match captured {
        Some(pairs) => Ok(pairs),
        None => bail!("login window was closed before the login completed"),
    }
}

/// Fallback for platforms without a bundled system WebView we can rely on.
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn run_login_webview(_region: Region) -> Result<Vec<(String, String)>> {
    anyhow::bail!("{NO_WEBVIEW_HELP}")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_region_aliases_case_insensitively() {
        for s in ["ww", "GL", "Worldwide", "GLOBAL"] {
            assert_eq!(Region::parse(s), Some(Region::Global));
        }
        assert_eq!(Region::parse("tw"), Some(Region::Taiwan));
        assert_eq!(Region::parse("Taiwan"), Some(Region::Taiwan));
        assert_eq!(Region::parse("sea"), Some(Region::Sea));
        assert_eq!(Region::parse("SouthEastAsia"), Some(Region::Sea));
        assert_eq!(Region::parse("th"), Some(Region::Thailand));
        assert_eq!(Region::parse("thailand"), Some(Region::Thailand));
        assert_eq!(Region::parse("jp"), None);
    }

    #[test]
    fn builds_login_urls() {
        assert_eq!(Region::Global.login_url(), "https://www.nexon.com/account/login");
        assert_eq!(Region::Taiwan.login_url(), "https://tw.nexon.com/account/login");
        assert_eq!(Region::Sea.login_url(), "https://sea.nexon.com/account/login");
        assert_eq!(Region::Thailand.login_url(), "https://th.nexon.com/account/login");
    }

    #[test]
    fn parses_nexon_tag_from_account_response() {
        // Abridged real response shape from `/api/account/v1/account`.
        let body = r#"{
            "email": "user@example.com",
            "isVerified": true,
            "countryCode": "US",
            "nexonTag": "NxTag#1234",
            "renamesRemaining": 1,
            "name": "",
            "isMinor": false
        }"#;
        assert_eq!(
            parse_nexon_tag(body).unwrap(),
            Some("NxTag#1234".to_owned())
        );

        // Missing / empty tag → None.
        assert_eq!(parse_nexon_tag(r#"{"email":"a@b.c"}"#).unwrap(), None);
        assert_eq!(parse_nexon_tag(r#"{"nexonTag":""}"#).unwrap(), None);

        // Invalid JSON → error.
        assert!(parse_nexon_tag("not json").is_err());
    }

    #[test]
    fn parses_manifest_url_from_branch_response() {
        // Real response shape from `/api/game-build/v1/branch/games/<id>/public`.
        let body = r#"{
            "branchName": "Public",
            "executablePath": null,
            "parameter": null,
            "useBranchDirectory": false,
            "manifestUrl": "http://download2.nexon.net/Game/nxl/games/10100/10100.pub229_3_0_3ed487493a3359742d807712ddb180e9.manifest.hash",
            "releaseDate": "2022-01-20T17:42:33.579z",
            "serviceId": "1049736197",
            "toyServiceId": null
        }"#;
        assert_eq!(
            interpret_branch_response("10100", 200, body).unwrap(),
            "http://download2.nexon.net/Game/nxl/games/10100/10100.pub229_3_0_3ed487493a3359742d807712ddb180e9.manifest.hash"
        );
    }

    #[test]
    fn maps_branch_not_found_error() {
        // As a JSON body with a message field...
        let err = interpret_branch_response("59822", 404, r#"{"message":"Product cannot be found"}"#)
            .unwrap_err()
            .to_string();
        assert!(err.contains("59822"), "got: {err}");
        assert!(err.contains("was not found"), "got: {err}");

        // ...and inferred from a bare message even on a 200.
        let err = interpret_branch_response("59822", 200, r#"{"message":"Product cannot be found"}"#)
            .unwrap_err()
            .to_string();
        assert!(err.contains("was not found"), "got: {err}");
    }

    #[test]
    fn maps_branch_permission_error() {
        let err = interpret_branch_response(
            "59822",
            403,
            r#"{"message":"User does not have permission"}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("59822"), "got: {err}");
        assert!(err.contains("does not have permission"), "got: {err}");
    }

    #[test]
    fn maps_other_branch_errors() {
        // Unknown error with a message → surfaced verbatim with status.
        let err = interpret_branch_response("10100", 500, r#"{"message":"Internal error"}"#)
            .unwrap_err()
            .to_string();
        assert!(err.contains("HTTP 500"), "got: {err}");
        assert!(err.contains("Internal error"), "got: {err}");

        // No manifestUrl and no message.
        assert!(interpret_branch_response("10100", 200, r#"{"branchName":"Public"}"#).is_err());
        assert!(interpret_branch_response("10100", 200, "not json").is_err());
    }

    #[test]
    fn round_trips_saved_session() {
        let cookies = vec![
            ("AToken".to_owned(), "abc.def=ghi".to_owned()),
            ("g_AToken".to_owned(), "xyz".to_owned()),
            ("NxLSession".to_owned(), "s3ss10n".to_owned()),
        ];
        let ini = render_ini(Region::Taiwan, &cookies);
        let session = parse_session(&ini).unwrap();
        assert_eq!(session.region, Region::Taiwan);
        assert_eq!(session.cookies, cookies);
    }

    #[test]
    fn rejects_incomplete_session() {
        // No region.
        assert!(parse_session("[cookies]\nAToken = x\n").is_err());
        // No cookies.
        assert!(parse_session("[account]\nregion = ww\n").is_err());
    }

    #[test]
    fn maps_region_languages() {
        assert_eq!(Region::Global.language(), "en");
        assert_eq!(Region::Sea.language(), "en");
        assert_eq!(Region::Taiwan.language(), "zh");
        assert_eq!(Region::Thailand.language(), "th");
    }

    #[test]
    fn detects_login_completion_global() {
        // `/main/<language>` portal landing.
        assert!(is_login_complete("https://www.nexon.com/main/en", Region::Global));
        assert!(is_login_complete(
            "https://www.nexon.com/main/en/home",
            Region::Global
        ));
        // Account settings landing page (with query string).
        assert!(is_login_complete(
            "https://www.nexon.com/account/en/setting/account-overview?foo=bar&baz=1",
            Region::Global
        ));

        // Still on the login page.
        assert!(!is_login_complete(
            "https://www.nexon.com/account/login",
            Region::Global
        ));
        // `/main/` with no language segment.
        assert!(!is_login_complete("https://www.nexon.com/main/", Region::Global));
    }

    #[test]
    fn detects_login_completion_all_regions() {
        // Portal landing on each region's own domain, in its language.
        assert!(is_login_complete("https://tw.nexon.com/main/zh", Region::Taiwan));
        assert!(is_login_complete("https://sea.nexon.com/main/en", Region::Sea));
        assert!(is_login_complete("https://th.nexon.com/main/th", Region::Thailand));

        // Account overview on the central portal, in the region's language.
        assert!(is_login_complete(
            "https://www.nexon.com/account/zh/setting/account-overview",
            Region::Taiwan
        ));
        assert!(is_login_complete(
            "https://www.nexon.com/account/th/setting/account-overview",
            Region::Thailand
        ));
        assert!(is_login_complete(
            "https://www.nexon.com/account/en/setting/account-overview",
            Region::Sea
        ));

        // Account overview on the region's own domain.
        assert!(is_login_complete(
            "https://tw.nexon.com/account/zh/setting/account-overview",
            Region::Taiwan
        ));

        // Wrong language for the region should not count as complete.
        assert!(!is_login_complete(
            "https://www.nexon.com/account/en/setting/account-overview",
            Region::Taiwan
        ));
        // A different region's portal is not this region's landing page.
        assert!(!is_login_complete("https://www.nexon.com/main/en", Region::Taiwan));
    }
}
