//! Structural validation of diagnostic summaries; imported data grants no authority.
use super::{
    confidence_for_severity, is_hard, normalize_rule_id, primary_rule, read_bounded_text,
    CoverageFinding, CoverageMetric, CoverageMode, CoverageSource,
};
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::{collections::BTreeMap, path::Path};

#[derive(Deserialize)]
struct Summary {
    status: String,
    metrics: BTreeMap<String, CoverageMetric>,
    findings: Vec<ImportedFinding>,
}

#[derive(Deserialize)]
struct ImportedFinding {
    #[serde(alias = "fix")]
    repair: String,
    severity: Option<String>,
    rule_id: Option<String>,
    confidence: Option<f64>,
    path: Option<String>,
    line: Option<usize>,
    message: Option<String>,
    #[serde(default)]
    evidence: Vec<String>,
}

pub(super) fn read(
    source: &CoverageSource,
    path: &Path,
    artifact: &str,
    max_bytes: u64,
    strict: bool,
) -> Result<(BTreeMap<String, CoverageMetric>, Vec<CoverageFinding>)> {
    // Decode directly, so duplicate status and finding fields cannot replace failures.
    let summary: Summary = serde_json::from_str(&read_bounded_text(path, max_bytes)?)
        .context("parse generic JSON summary")?;
    let status_severity = match summary.status.as_str() {
        "pass" => None,
        "warn" => Some("medium"),
        "fail" | "error" | "missing" | "cancelled" | "timeout" | "incomplete" => Some("high"),
        _ => bail!("unsupported generic summary status: {}", summary.status),
    };
    let mut findings = summary
        .findings
        .into_iter()
        .map(|finding| finding.normalize(source, artifact, strict))
        .collect::<Result<Vec<_>>>()?;
    if let Some(severity) = status_severity {
        findings.push(
            ImportedFinding {
                repair: "resolve the producer outcome and regenerate the complete report".into(),
                severity: Some(severity.into()),
                rule_id: None,
                confidence: None,
                path: None,
                line: None,
                message: Some(format!("coverage producer reported {}", summary.status)),
                evidence: vec![format!("reported_status={}", summary.status)],
            }
            .normalize(source, artifact, strict)?,
        );
    }
    Ok((summary.metrics, findings))
}

impl ImportedFinding {
    fn normalize(
        self,
        source: &CoverageSource,
        artifact: &str,
        strict: bool,
    ) -> Result<CoverageFinding> {
        if self.repair.trim().is_empty() {
            bail!("generic summary finding requires a nonempty repair");
        }
        let mut severity = self
            .severity
            .unwrap_or_else(|| "medium".into())
            .to_ascii_lowercase();
        if !matches!(
            severity.as_str(),
            "critical" | "high" | "medium" | "low" | "info"
        ) {
            bail!("unsupported generic finding severity: {severity}");
        }
        if self.line == Some(0)
            || self
                .confidence
                .is_some_and(|value| !(0.0..=1.0).contains(&value))
        {
            bail!("generic finding has invalid line or confidence");
        }
        if source.mode != CoverageMode::Required && !strict && is_hard(&severity) {
            severity = "medium".into();
        }
        Ok(CoverageFinding {
            rule_id: normalize_rule_id(
                &self
                    .rule_id
                    .unwrap_or_else(|| primary_rule(source, "HLT-008-FALSE-GREEN-RISK")),
            ),
            confidence: self
                .confidence
                .unwrap_or_else(|| confidence_for_severity(&severity)),
            severity,
            source_id: source.id.clone(),
            kind: source.kind.as_str().into(),
            artifact: artifact.into(),
            path: self.path.unwrap_or_else(|| artifact.into()),
            line: self.line,
            message: self
                .message
                .unwrap_or_else(|| "generic coverage/proof finding".into()),
            evidence: self.evidence,
            repair: self.repair,
            owner: source.owner.clone(),
            lane: source.lane.clone(),
        })
    }
}
