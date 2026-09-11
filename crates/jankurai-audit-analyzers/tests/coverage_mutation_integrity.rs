use jankurai_audit_analyzers::audit::coverage;
use serde_json::{json, Value};
use std::fs;

fn parse(text: &str) -> anyhow::Result<coverage::MutationReport> {
    let root = tempfile::tempdir()?;
    let path = root.path().join("outcomes.json");
    fs::write(&path, text)?;
    coverage::parse_cargo_mutants_json(&path, 4096)
}

fn native() -> Value {
    json!({
        "total_mutants": 2, "caught": 1, "missed": 1, "timeout": 0, "unviable": 0, "success": 0,
        "outcomes": [
            {"scenario": "Baseline", "summary": "Success"},
            {"scenario": {"Mutant": {"file": "src/a.rs", "span": {"start": {"line": 2, "column": 1}}}}, "summary": "CaughtMutant"},
            {"scenario": {"Mutant": {"file": "src/a.rs", "span": {"start": {"line": 8, "column": 1}}}}, "summary": "MissedMutant"}
        ]
    })
}

#[test]
fn native_cargo_mutants_outcomes_exclude_baseline_and_retain_survivors() {
    let report = parse(&native().to_string()).unwrap();
    assert_eq!((report.total, report.killed, report.survived), (2, 1, 1));
    assert_eq!(report.mutants[1].path, "src/a.rs");
    assert_eq!(report.mutants[1].line, Some(8));
}

#[test]
fn explicit_legacy_records_remain_readable_without_recursive_guessing() {
    let report = parse(r#"{"outcomes":[{"status":"caught","path":"src/a.rs","line":2},{"summary":"Missed","scenario":{"Mutant":{"file":"src/a.rs","span":{"start":{"line":8}}}}}]}"#).unwrap();
    assert_eq!((report.total, report.killed, report.survived), (2, 1, 1));
}

#[test]
fn missing_failed_unknown_and_duplicate_records_cannot_be_clean_mutation_coverage() {
    for input in [
        r#"{}"#,
        r#"{"outcomes":[]}"#,
        r#"{"outcomes":[{"scenario":"Baseline","summary":"Success"}]}"#,
        r#"{"outcomes":[null]}"#,
        r#"{"outcomes":[{"summary":"caught"}]}"#,
        r#"{"outcomes":[{"summary":"caught","path":""}]}"#,
        r#"{"outcomes":[{"summary":"caught","path":"src/a.rs","line":0}]}"#,
        r#"{"outcomes":[{"summary":"missed","status":"caught","path":"src/a.rs"}]}"#,
        r#"{"outcomes":[{"summary":"Success","path":"src/a.rs"}]}"#,
        r#"{"outcomes":[{"summary":"Timeout","path":"src/a.rs"}]}"#,
        r#"{"outcomes":[{"summary":"Failure","path":"src/a.rs"}]}"#,
        r#"{"outcomes":[{"summary":"unknown","path":"src/a.rs"}]}"#,
        r#"{"outcomes":[{"summary":"caught","path":"src/a.rs","mutant":{"file":"src/b.rs"}}]}"#,
    ] {
        assert!(parse(input).is_err(), "{input}");
    }
}

#[test]
fn failed_baseline_and_inconsistent_or_truncated_native_inventory_fail() {
    for status in ["Failure", "Timeout", "CaughtMutant"] {
        let mut value = native();
        value["outcomes"][0]["summary"] = json!(status);
        assert!(parse(&value.to_string()).is_err());
    }
    for field in [
        "total_mutants",
        "caught",
        "missed",
        "timeout",
        "unviable",
        "success",
    ] {
        let mut value = native();
        value[field] = json!(42);
        assert!(parse(&value.to_string()).is_err(), "{field}");
    }
    let mut value = native();
    value["outcomes"].as_array_mut().unwrap().pop();
    assert!(parse(&value.to_string()).is_err());
    let mut value = native();
    let baseline = value["outcomes"][0].clone();
    value["outcomes"].as_array_mut().unwrap().push(baseline);
    assert!(parse(&value.to_string()).is_err());
}
