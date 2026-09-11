use jankurai_audit_analyzers::audit::coverage::{self, CoverageAuditOptions};
use serde_json::json;
use std::{fs, path::PathBuf};

fn audit(report: &str, mode: &str, strict: bool, max_findings: usize) -> coverage::CoverageAudit {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("coverage.toml"), format!("version = 1\n[[source]]\nid = 'checks'\nkind = 'property_fuzz'\nformat = 'generic-json-summary'\nmode = '{mode}'\nowner = 'tools'\nlane = 'coverage-audit'\nartifacts = ['report.json']\napplies_to = ['src/**/*.rs']\nrules = ['HLT-008-FALSE-GREEN-RISK']\n")).unwrap();
    fs::write(root.path().join("report.json"), report).unwrap();
    coverage::run_coverage_audit(CoverageAuditOptions {
        repo_root: root.path().into(),
        config_path: PathBuf::from("coverage.toml"),
        changed_from: None,
        strict,
        max_artifact_bytes: 4096,
        max_findings,
    })
    .unwrap()
}

#[test]
fn complete_summary_retains_metrics_findings_and_repair_alias() {
    let report = audit(
        r#"{"status":"pass","metrics":{"tests":7},"findings":[]}"#,
        "required",
        false,
        200,
    );
    assert_eq!(report.summary.status, "pass");
    assert_eq!(report.sources[0].metrics["tests"], 7);
    let report = audit(
        r#"{"status":"warn","metrics":{},"findings":[{"severity":"LOW","fix":"add a case","evidence":["missing edge"]}]}"#,
        "required",
        false,
        200,
    );
    assert_eq!(report.summary.status, "warn");
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.repair == "add a case" && finding.evidence == ["missing edge"]));
}

#[test]
fn failed_or_incomplete_producer_status_cannot_become_an_empty_pass() {
    for status in [
        "fail",
        "error",
        "missing",
        "cancelled",
        "timeout",
        "incomplete",
    ] {
        let input = json!({"status": status, "metrics": {}, "findings": []}).to_string();
        for (mode, strict, expected) in [
            ("required", false, "fail"),
            ("advisory", false, "warn"),
            ("advisory", true, "fail"),
        ] {
            let report = audit(&input, mode, strict, 200);
            assert_eq!(report.summary.status, expected, "{status} {mode} {strict}");
            assert!(report
                .findings
                .iter()
                .any(|finding| finding.evidence == [format!("reported_status={status}")]));
        }
    }
}

#[test]
fn malformed_and_duplicate_summary_fields_cannot_disappear() {
    for input in [
        r#"{}"#,
        r#"{"status":true,"metrics":{},"findings":[]}"#,
        r#"{"status":"unknown","metrics":{},"findings":[]}"#,
        r#"{"status":"fail","status":"pass","metrics":{},"findings":[]}"#,
        r#"{"status":"pass","metrics":{},"findings":[null]}"#,
        r#"{"status":"pass","metrics":{},"findings":[{"severity":"high"}]}"#,
        r#"{"status":"pass","metrics":{},"findings":[{"repair":" "}]}"#,
        r#"{"status":"pass","metrics":{},"findings":[{"repair":"fix","evidence":[42]}]}"#,
        r#"{"status":"pass","metrics":{},"findings":[{"repair":"fix","severity":"unknown"}]}"#,
        r#"{"status":"pass","metrics":{},"findings":[{"repair":"fix","severity":"high","severity":"info"}]}"#,
        r#"{"status":"pass","metrics":{},"findings":[{"repair":"fix","fix":"hide"}]}"#,
        r#"{"status":"pass","metrics":{},"findings":[{"repair":"fix","line":0}]}"#,
        r#"{"status":"pass","metrics":{},"findings":[{"repair":"fix","confidence":2}]}"#,
    ] {
        let report = audit(input, "required", false, 200);
        assert_eq!(report.summary.status, "fail", "{input}");
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.message.contains("could not be parsed")));
    }
}

#[test]
fn duplicate_findings_and_zero_display_budget_retain_blocking_outcomes() {
    let input = json!({"status": "pass", "metrics": {}, "findings": [
        {"repair": "fix", "severity": "info", "message": "same issue"},
        {"repair": "fix", "severity": "high", "message": "same issue"}
    ]})
    .to_string();
    for limit in [0, 1, 200] {
        let report = audit(&input, "required", false, limit);
        assert_eq!(report.summary.status, "fail", "max_findings={limit}");
        assert_eq!(report.summary.hard_findings, 1);
    }
}
