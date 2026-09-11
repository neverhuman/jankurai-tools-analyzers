use jankurai_audit_kernel::audit::helpers::AuditContext;
use jankurai_audit_kernel::audit::language_rules::common::{
    finding, is_docs_reference_tips_or_generated, is_test_fixture_or_example, nearby_allow,
    sort_and_cap_findings, strip_comments_for_line_language,
};
use jankurai_audit_kernel::audit::language_rules::{LanguageFinding, ProofWindow};
use jankurai_audit_kernel::model::FileInfo;
use once_cell::sync::Lazy;
use regex::Regex;

mod storage;
mod storage_tokens;
mod vite;

const HLT_RULE_ID: &str = "HLT-039-WEB-SECURITY-BAD-BEHAVIOR";

static VITE_ENV_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bVITE_[A-Z0-9_]+\b").expect("Vite env regex is valid"));

#[derive(Debug, Clone, Copy, Default)]
pub struct WebSecuritySummary {
    pub hard_findings: usize,
    pub advisory_signals: usize,
}

pub fn summary(ctx: &AuditContext) -> WebSecuritySummary {
    WebSecuritySummary {
        hard_findings: findings(ctx).len(),
        advisory_signals: advisory_signals(ctx).len(),
    }
}

pub fn findings(ctx: &AuditContext) -> Vec<LanguageFinding> {
    sort_and_cap_findings(hard_findings(ctx), 50)
}

pub fn advisory_signals(ctx: &AuditContext) -> Vec<LanguageFinding> {
    sort_and_cap_findings(advisory_hits(ctx), 50)
}

fn hard_findings(ctx: &AuditContext) -> Vec<LanguageFinding> {
    let mut out = Vec::new();
    for file in ctx.all_files.iter().filter(|file| !excluded(file)) {
        if is_vite_config(file) {
            match vite::findings(file) {
                Ok(hits) => out.extend(hits),
                Err(error) => out.push(finding(
                    HLT_RULE_ID,
                    "websec.input.incomplete",
                    file,
                    1,
                    error.to_string(),
                    "Vite configuration could not be completely parsed",
                    "repair the input syntax and rerun the complete audit",
                    ProofWindow::None,
                )),
            }
        }
        if is_env_or_client_source(file) {
            out.extend(vite_env_secret_hits(file));
        }
        if is_browser_source(file) {
            out.extend(storage::findings(file));
        }
        if is_cors_surface(file) {
            out.extend(credentialed_wildcard_cors_hits(file));
        }
    }
    out
}

/// The full audit calls this before scoring; an invalid required configuration
/// cannot become a complete report with an empty set of findings.
pub fn validate_inputs(ctx: &AuditContext) -> anyhow::Result<()> {
    for file in ctx
        .all_files
        .iter()
        .filter(|file| !excluded(file) && is_vite_config(file))
    {
        vite::findings(file)?;
    }
    Ok(())
}

fn advisory_hits(ctx: &AuditContext) -> Vec<LanguageFinding> {
    let mut out = Vec::new();
    for file in ctx.all_files.iter().filter(|file| !excluded(file)) {
        if is_csp_surface(file) {
            out.extend(unsafe_csp_hits(file));
        }
        if is_browser_source(file) || is_api_surface(file) {
            out.extend(unvalidated_redirect_hits(file));
        }
        if is_vite_config(file) {
            out.extend(public_sourcemap_hits(file));
        }
    }
    out
}

fn excluded(file: &FileInfo) -> bool {
    is_docs_reference_tips_or_generated(&file.rel_path)
        || is_test_fixture_or_example(&file.rel_path)
        || file.rel_path.to_ascii_lowercase().contains("/fixtures/")
}

fn is_vite_config(file: &FileInfo) -> bool {
    let lower = file.rel_path.to_ascii_lowercase();
    lower.ends_with("vite.config.ts")
        || lower.ends_with("vite.config.js")
        || lower.ends_with("vite.config.mts")
        || lower.ends_with("vite.config.cts")
        || lower.ends_with("vite.config.mjs")
        || lower.ends_with("vite.config.cjs")
}

fn is_env_or_client_source(file: &FileInfo) -> bool {
    is_env_file(file) || is_browser_source(file) || is_vite_config(file)
}

fn is_env_file(file: &FileInfo) -> bool {
    file.name == ".env"
        || file.name.starts_with(".env.")
        || file.rel_path.contains("/.env")
        || file.rel_path.contains("\\.env")
}

fn is_browser_source(file: &FileInfo) -> bool {
    let lower = file.rel_path.to_ascii_lowercase();
    if !is_script_or_html(&lower) {
        return false;
    }
    lower.starts_with("apps/web/")
        || lower.starts_with("frontend/")
        || lower.starts_with("ui/")
        || lower.starts_with("packages/web/")
        || lower.starts_with("packages/ui/")
        || lower.starts_with("src/")
        || file.text.contains("import.meta.env")
        || file.text.contains("localStorage")
        || file.text.contains("sessionStorage")
        || file.text.contains("window.")
        || file.text.contains("document.")
}

fn is_api_surface(file: &FileInfo) -> bool {
    let lower = file.rel_path.to_ascii_lowercase();
    if !(is_script_or_html(&lower)
        || lower.ends_with(".rs")
        || lower.ends_with(".toml")
        || lower.ends_with(".yaml")
        || lower.ends_with(".yml")
        || lower.ends_with(".json"))
    {
        return false;
    }
    lower.starts_with("apps/api/")
        || lower.starts_with("api/")
        || lower.starts_with("server/")
        || lower.starts_with("backend/")
        || lower.starts_with("crates/adapters/")
        || lower.starts_with("crates/application/")
        || lower.starts_with("src/")
}

fn is_cors_surface(file: &FileInfo) -> bool {
    is_api_surface(file) && {
        let lower = file.text.to_ascii_lowercase();
        lower.contains("cors") || lower.contains("access-control-allow")
    }
}

fn is_csp_surface(file: &FileInfo) -> bool {
    let lower = file.rel_path.to_ascii_lowercase();
    is_script_or_html(&lower)
        || lower.ends_with(".conf")
        || lower.ends_with(".toml")
        || lower.ends_with(".yaml")
        || lower.ends_with(".yml")
        || lower.ends_with(".json")
        || lower.ends_with(".rs")
}

fn is_script_or_html(lower_path: &str) -> bool {
    lower_path.ends_with(".ts")
        || lower_path.ends_with(".tsx")
        || lower_path.ends_with(".mts")
        || lower_path.ends_with(".cts")
        || lower_path.ends_with(".js")
        || lower_path.ends_with(".jsx")
        || lower_path.ends_with(".mjs")
        || lower_path.ends_with(".cjs")
        || lower_path.ends_with(".html")
}

fn vite_env_secret_hits(file: &FileInfo) -> Vec<LanguageFinding> {
    let mut out = Vec::new();
    let kind = if is_env_file(file) { "shell" } else { "ts" };
    for (idx, raw_line) in file.text.lines().enumerate() {
        let line_no = idx + 1;
        let line = strip_comments_for_line_language(raw_line, kind);
        if line.is_empty() || nearby_allow(&file.text, line_no, "websec.env.client-secret") {
            continue;
        }
        for found in VITE_ENV_RE.find_iter(&line) {
            let name = found.as_str();
            if vite_env_name_is_secret(name) {
                out.push(finding(
                    HLT_RULE_ID,
                    "websec.env.client-secret",
                    file,
                    line_no,
                    format!("client-exposed Vite env var `{name}` is named like a secret"),
                    "VITE_* values are embedded into browser code and must be treated as public",
                    "move secret-bearing values behind an API, edge function, or server-only environment variable",
                    ProofWindow::None,
                ));
            }
        }
    }
    out
}

fn vite_env_name_is_secret(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if [
        "secret",
        "password",
        "private",
        "client_secret",
        "database",
        "db_",
        "aws_",
        "stripe_secret",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        return true;
    }
    lower.contains("token")
        && !["public", "publishable", "anon", "mapbox"]
            .iter()
            .any(|needle| lower.contains(needle))
}

fn credentialed_wildcard_cors_hits(file: &FileInfo) -> Vec<LanguageFinding> {
    let mut out = Vec::new();
    for (idx, raw_line) in file.text.lines().enumerate() {
        let line_no = idx + 1;
        if nearby_allow(&file.text, line_no, "websec.cors.credential-wildcard") {
            continue;
        }
        let lower = strip_comments_for_line_language(raw_line, "source").to_ascii_lowercase();
        if lower.is_empty() {
            continue;
        }
        let window = nearby_text(file, line_no, 3);
        if has_wildcard_origin(&window) && has_credentials_enabled(&window) {
            out.push(finding(
                HLT_RULE_ID,
                "websec.cors.credential-wildcard",
                file,
                line_no,
                "CORS allows wildcard or arbitrary origins while credentials are enabled",
                "credentialed wildcard CORS can expose authenticated API responses across origins",
                "use an explicit origin allowlist, set Vary: Origin, and disable credentials unless required",
                ProofWindow::None,
            ));
        }
    }
    out
}

fn unsafe_csp_hits(file: &FileInfo) -> Vec<LanguageFinding> {
    let mut out = Vec::new();
    for (idx, raw_line) in file.text.lines().enumerate() {
        let line_no = idx + 1;
        if nearby_allow(&file.text, line_no, "websec.csp.unsafe-script") {
            continue;
        }
        let lower = raw_line.to_ascii_lowercase();
        if !(lower.contains("content-security-policy") || lower.contains("script-src")) {
            continue;
        }
        let window = nearby_text(file, line_no, 2);
        let unsafe_script = window.contains("script-src")
            && (window.contains("'unsafe-inline'") || window.contains("'unsafe-eval'"));
        let bounded = window.contains("nonce-")
            || window.contains("sha256-")
            || window.contains("sha384-")
            || window.contains("sha512-")
            || window.contains("strict-dynamic");
        if unsafe_script && !bounded {
            out.push(finding(
                HLT_RULE_ID,
                "websec.csp.unsafe-script",
                file,
                line_no,
                "CSP script policy uses unsafe inline or eval execution",
                "unsafe CSP script sources weaken XSS containment",
                "replace unsafe script sources with nonces, hashes, strict-dynamic, or a narrower policy",
                ProofWindow::None,
            ));
        }
    }
    out
}

fn unvalidated_redirect_hits(file: &FileInfo) -> Vec<LanguageFinding> {
    let mut out = Vec::new();
    for (idx, raw_line) in file.text.lines().enumerate() {
        let line_no = idx + 1;
        if nearby_allow(&file.text, line_no, "websec.redirect.unvalidated") {
            continue;
        }
        let lower = strip_comments_for_line_language(raw_line, "ts").to_ascii_lowercase();
        if lower.is_empty() {
            continue;
        }
        let sink = lower.contains("window.location")
            || lower.contains("location.href")
            || lower.contains("location.assign(")
            || lower.contains("window.open(")
            || lower.contains("redirect(")
            || lower.contains("navigate(");
        let source = lower.contains("urlsearchparams")
            || lower.contains("location.search")
            || lower.contains("searchparams")
            || lower.contains("returnto")
            || lower.contains("returnurl")
            || lower.contains("callbackurl")
            || lower.contains("next")
            || lower.contains("redirect");
        let window = nearby_text(file, line_no, 5);
        let bounded = window.contains("new url(")
            || window.contains("allowlist")
            || window.contains("allowed")
            || window.contains("sameorigin")
            || window.contains("same-origin")
            || window.contains("origin ===")
            || window.contains("starts_with(\"/\")")
            || window.contains("startswith(\"/\")");
        if sink && source && !bounded {
            out.push(finding(
                HLT_RULE_ID,
                "websec.redirect.unvalidated",
                file,
                line_no,
                "navigation uses a redirect-like value without local same-origin or allowlist proof",
                "unvalidated redirects can become phishing or token-forwarding helpers",
                "parse redirect targets with URL, enforce same-origin or explicit allowlists, and add negative redirect tests",
                ProofWindow::None,
            ));
        }
    }
    out
}

fn public_sourcemap_hits(file: &FileInfo) -> Vec<LanguageFinding> {
    let mut out = Vec::new();
    for (idx, raw_line) in file.text.lines().enumerate() {
        let line_no = idx + 1;
        if nearby_allow(&file.text, line_no, "websec.build.public-sourcemap") {
            continue;
        }
        let compact = raw_line
            .to_ascii_lowercase()
            .split_whitespace()
            .collect::<String>();
        if !compact.contains("sourcemap:true") {
            continue;
        }
        let window = nearby_text(file, line_no, 4);
        let private_upload = ["sentry", "rollbar", "private", "hidden", "upload"]
            .iter()
            .any(|needle| window.contains(needle));
        if !private_upload {
            out.push(finding(
                HLT_RULE_ID,
                "websec.build.public-sourcemap",
                file,
                line_no,
                "production sourcemaps appear enabled without private upload or retention proof",
                "public sourcemaps can expose source, comments, and build-time constants",
                "disable public sourcemaps or upload them privately to an error-monitoring service",
                ProofWindow::None,
            ));
        }
    }
    out
}

fn nearby_text(file: &FileInfo, line: usize, radius: usize) -> String {
    let lines: Vec<&str> = file.text.lines().collect();
    if lines.is_empty() {
        return String::new();
    }
    let idx = line.saturating_sub(1).min(lines.len() - 1);
    let start = idx.saturating_sub(radius);
    let end = (idx + radius + 1).min(lines.len());
    lines[start..end].join("\n").to_ascii_lowercase()
}

fn has_wildcard_origin(window: &str) -> bool {
    (window.contains("access-control-allow-origin") && window.contains('*'))
        || window.contains("origin: \"*\"")
        || window.contains("origin: '*'")
        || window.contains("allow_origin(any")
        || window.contains("allow_origin: any")
        || window.contains("allow_any_origin")
}

fn has_credentials_enabled(window: &str) -> bool {
    (window.contains("access-control-allow-credentials") && window.contains("true"))
        || window.contains("credentials: true")
        || window.contains("allow_credentials(true")
        || window.contains("supports_credentials")
        || window.contains("allow-credentials: true")
}
