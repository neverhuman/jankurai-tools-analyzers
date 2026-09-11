use jankurai_audit_analyzers::audit::coverage;
use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
};

#[test]
fn late_blocking_diagnostics_survive_display_limits() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("coverage.toml"), "version = 1\n[[source]]\nid = 'docker'\nkind = 'container'\nformat = 'hadolint-json'\nmode = 'required'\nowner = 'tools'\nlane = 'coverage-audit'\nartifacts = ['report.json']\napplies_to = ['**/Dockerfile']\nrules = ['HLT-032-DOCKER-BAD-BEHAVIOR']\n").unwrap();
    let diagnostics: Vec<_> = (1..=51).map(|line| json!({"file": "Dockerfile", "line": line, "code": "DL3008", "level": if line == 51 {"error"} else {"info"}, "message": "Pin package versions"})).collect();
    fs::write(
        root.path().join("report.json"),
        serde_json::to_vec(&diagnostics).unwrap(),
    )
    .unwrap();
    let report = coverage::run_coverage_audit(coverage::CoverageAuditOptions {
        repo_root: root.path().into(),
        config_path: PathBuf::from("coverage.toml"),
        changed_from: None,
        strict: false,
        max_artifact_bytes: 20_000,
        max_findings: 200,
    })
    .unwrap();
    assert_eq!(report.summary.status, "fail");
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.line == Some(51) && finding.severity == "high"));
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.message.contains("omitted by per-source cap")));
    assert_eq!(report.sources[0].metrics["diagnostics"], 51);
}

fn input<T>(text: &str, parse: impl FnOnce(&Path, u64) -> anyhow::Result<T>) -> anyhow::Result<T> {
    let root = tempfile::tempdir()?;
    let path = root.path().join("report.json");
    fs::write(&path, text)?;
    parse(&path, 4096)
}

#[test]
fn trivy_preserves_scanned_clean_targets_and_all_vulnerability_levels() {
    for list in ["null", "[]"] {
        let text = format!(r#"{{"Results":[{{"Target":"Cargo.lock","Vulnerabilities":{list}}}]}}"#);
        assert!(input(&text, coverage::parse_trivy_json)
            .unwrap()
            .vulnerabilities
            .is_empty());
    }
    let text = json!({"Results": [{"Target": "Cargo.lock", "Vulnerabilities": ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(|severity| json!({"VulnerabilityID": "CVE-2099-0001", "PkgName": "example", "Severity": severity}))}]}).to_string();
    let report = input(&text, coverage::parse_trivy_json).unwrap();
    assert_eq!(
        (report.critical, report.high, report.medium, report.low),
        (1, 1, 1, 1)
    );
}

#[test]
fn malformed_trivy_results_cannot_turn_into_zero_vulnerabilities() {
    for text in [
        r#"{}"#,
        r#"{"Results":null}"#,
        r#"{"Results":[]}"#,
        r#"{"Results":[null]}"#,
        r#"{"Results":[{}]}"#,
        r#"{"Results":[{"Target":"","Vulnerabilities":[] }]}"#,
        r#"{"Results":[{"Target":"Cargo.lock","Vulnerabilities":{}}]}"#,
        r#"{"Results":[{"Target":"Cargo.lock","Vulnerabilities":[{}]}]}"#,
        r#"{"Results":[{"Target":"Cargo.lock","Vulnerabilities":[{"VulnerabilityID":"CVE-2099-0001","PkgName":"example","Severity":"UNKNOWN"}]}]}"#,
        r#"{"Results":[{"Target":"Cargo.lock","Vulnerabilities":[{"VulnerabilityID":"CVE-2099-0001","PkgName":"example","Severity":"HIGH","Severity":"LOW"}]}]}"#,
    ] {
        assert!(input(text, coverage::parse_trivy_json).is_err(), "{text}");
    }
}

#[test]
fn hadolint_accepts_clean_lists_and_rejects_invented_or_malformed_diagnostics() {
    assert!(input("[]", coverage::parse_hadolint_json)
        .unwrap()
        .diagnostics
        .is_empty());
    let valid = json!([{"file": "Dockerfile", "line": 3, "code": "DL3008", "level": "warning", "message": "Pin package versions"}]);
    let report = input(&valid.to_string(), coverage::parse_hadolint_json).unwrap();
    assert_eq!(report.diagnostics[0].line, Some(3));
    for field in ["file", "line", "code", "level", "message"] {
        let mut missing = valid.clone();
        missing[0].as_object_mut().unwrap().remove(field);
        assert!(
            input(&missing.to_string(), coverage::parse_hadolint_json).is_err(),
            "{field}"
        );
    }
    for (field, value) in [
        ("line", json!(0)),
        ("code", json!("")),
        ("message", json!("")),
        ("level", json!("success")),
    ] {
        let mut invalid = valid.clone();
        invalid[0][field] = value;
        assert!(
            input(&invalid.to_string(), coverage::parse_hadolint_json).is_err(),
            "{field}"
        );
    }
    for text in ["{}", "[null]", "[{}]"] {
        assert!(input(text, coverage::parse_hadolint_json).is_err());
    }
}

#[test]
fn stryker_validates_every_mutant_and_unique_file_inventory() {
    let valid = json!({"schemaVersion": "1.0", "files": {"src/a.ts": {"mutants": [
        {"id": "1", "status": "Survived", "mutatorName": "ArithmeticOperator", "location": {"start": {"line": 4, "column": 2}, "end": {"line": 4, "column": 3}}}
    ]}}});
    let report = input(&valid.to_string(), coverage::parse_stryker_json).unwrap();
    assert_eq!(report.survived, 1);
    for status in ["Success", "Pending", "Timeout", "RuntimeError", "unknown"] {
        let mut invalid = valid.clone();
        invalid["files"]["src/a.ts"]["mutants"][0]["status"] = json!(status);
        assert!(
            input(&invalid.to_string(), coverage::parse_stryker_json).is_err(),
            "{status}"
        );
    }
    let mut invalid = valid.clone();
    let duplicate = invalid["files"]["src/a.ts"]["mutants"][0].clone();
    invalid["files"]["src/a.ts"]["mutants"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    assert!(input(&invalid.to_string(), coverage::parse_stryker_json).is_err());
    for text in [
        "{}",
        r#"{"schemaVersion":"1","files":{}}"#,
        r#"{"schemaVersion":"1","files":{"a.ts":{"mutants":[]},"a.ts":{"mutants":[]}}}"#,
        r#"{"schemaVersion":"1","files":{"a.ts":{"mutants":[null]}}}"#,
        r#"{"schemaVersion":"1","files":{"a.ts":{}}}"#,
    ] {
        assert!(input(text, coverage::parse_stryker_json).is_err(), "{text}");
    }
}
