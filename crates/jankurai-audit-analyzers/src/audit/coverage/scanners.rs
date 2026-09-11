//! Validate scanner report structure before using vulnerability or lint counts.
use super::{ContainerLintIssue, ContainerLintReport, SecurityIssue, SecurityReport};
use anyhow::{bail, Context, Result};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TrivyReport {
    results: Vec<TrivyResult>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TrivyResult {
    target: String,
    vulnerabilities: Option<Vec<Vulnerability>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Vulnerability {
    #[serde(rename = "VulnerabilityID")]
    vulnerability_id: String,
    pkg_name: String,
    severity: String,
    title: Option<String>,
    description: Option<String>,
}

#[derive(Deserialize)]
struct LintIssue {
    file: String,
    line: usize,
    code: String,
    level: String,
    message: String,
}

pub(super) fn trivy(text: &str) -> Result<SecurityReport> {
    let input: TrivyReport = serde_json::from_str(text).context("parse Trivy result inventory")?;
    if input.results.is_empty() {
        bail!("Trivy report has no scanned targets");
    }
    let mut report = SecurityReport::default();
    for result in input.results {
        if result.target.trim().is_empty() {
            bail!("Trivy result has no target identity");
        }
        for vuln in result.vulnerabilities.unwrap_or_default() {
            if vuln.vulnerability_id.trim().is_empty() || vuln.pkg_name.trim().is_empty() {
                bail!("Trivy vulnerability has no vulnerability or package identity");
            }
            let severity = vuln.severity.to_ascii_uppercase();
            match severity.as_str() {
                "CRITICAL" => report.critical += 1,
                "HIGH" => report.high += 1,
                "MEDIUM" => report.medium += 1,
                "LOW" => report.low += 1,
                _ => bail!("incomplete Trivy severity assessment: {severity}"),
            }
            report.vulnerabilities.push(SecurityIssue {
                target: result.target.clone(),
                vulnerability_id: vuln.vulnerability_id,
                package_name: vuln.pkg_name,
                severity,
                title: vuln
                    .title
                    .or(vuln.description)
                    .unwrap_or_else(|| "vulnerability reported by Trivy".into()),
            });
        }
    }
    Ok(report)
}

pub(super) fn hadolint(text: &str) -> Result<ContainerLintReport> {
    let input: Vec<LintIssue> = serde_json::from_str(text).context("parse Hadolint diagnostics")?;
    let mut report = ContainerLintReport::default();
    for issue in input {
        let level = issue.level.to_ascii_lowercase();
        if issue.file.trim().is_empty()
            || issue.line == 0
            || issue.code.trim().is_empty()
            || issue.message.trim().is_empty()
            || !matches!(level.as_str(), "error" | "warning" | "info" | "style")
        {
            bail!("incomplete or invalid Hadolint diagnostic");
        }
        report.diagnostics.push(ContainerLintIssue {
            file: issue.file,
            line: Some(issue.line),
            code: issue.code,
            level,
            message: issue.message,
        });
    }
    Ok(report)
}
