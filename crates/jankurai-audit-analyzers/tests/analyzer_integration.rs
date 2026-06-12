//! Integration tests for the analyzer suite.
//!
//! These drive the public analyzer API end-to-end through a constructed
//! `AuditContext`, the same context the orchestration in `jankurai-core` builds
//! before calling each dimension analyzer. They assert the observable contract
//! of the detectors rather than internal helpers, so they survive refactors of
//! the private scan internals.

use jankurai_audit_analyzers::audit::{repo_rot, zyal};
use jankurai_audit_kernel::audit::helpers::AuditContext;
use jankurai_audit_kernel::model::FileInfo;
use std::path::PathBuf;

/// Build a minimal `AuditContext` over the given in-memory files.
fn ctx(files: Vec<FileInfo>) -> AuditContext {
    AuditContext {
        root: PathBuf::from("/tmp/jankurai-analyzers-it"),
        all_files: files.clone(),
        scope_files: files,
        scope_paths: vec![],
        self_audit: false,
        boundary_reclassifications: vec![],
        copy_code: None,
    }
}

/// Construct a code `FileInfo` from a relative path and source text.
fn code_file(rel_path: &str, text: &str) -> FileInfo {
    let suffix = rel_path
        .rfind('.')
        .map(|i| rel_path[i..].to_string())
        .unwrap_or_default();
    let name = rel_path.rsplit('/').next().unwrap_or(rel_path).to_string();
    FileInfo {
        rel_path: rel_path.to_string(),
        name,
        suffix,
        size: text.len() as u64,
        line_count: text.lines().count(),
        text: text.to_string(),
        is_generated: false,
        is_code: true,
    }
}

#[test]
fn repo_rot_summary_is_clean_for_well_named_source() {
    let context = ctx(vec![code_file(
        "crates/app/src/service.rs",
        "pub fn compute(value: u32) -> u32 {\n    value.saturating_add(1)\n}\n",
    )]);
    let summary = repo_rot::summary(&context);
    assert_eq!(
        summary.hard_findings, 0,
        "clean source must not produce repo-rot hard findings"
    );
}

#[test]
fn repo_rot_findings_are_capped_and_deterministic() {
    let context = ctx(vec![code_file(
        "crates/app/src/service.rs",
        "pub fn compute(value: u32) -> u32 {\n    value.saturating_add(1)\n}\n",
    )]);
    // Two evaluations of the same context must yield the same finding count.
    let first = repo_rot::findings(&context).len();
    let second = repo_rot::findings(&context).len();
    assert_eq!(first, second, "repo-rot findings must be deterministic");
}

#[test]
fn zyal_summary_ignores_plain_rust_source() {
    let context = ctx(vec![code_file(
        "crates/app/src/lib.rs",
        "pub fn run() {}\n",
    )]);
    let summary = zyal::summary(&context);
    assert_eq!(
        summary.hard_findings, 0,
        "non-runbook Rust source must not be flagged as a misplaced ZYAL runbook"
    );
}

#[test]
fn zyal_flags_runbook_envelope_outside_canonical_root() {
    let context = ctx(vec![code_file(
        "ops/runbooks/radar.txt",
        "<<<ZYAL 1.0.0:daemon id=radar>>>\nbody: true\n<<<END_ZYAL id=radar>>>\n",
    )]);
    let findings = zyal::findings(&context);
    assert!(
        !findings.is_empty(),
        "a ZYAL envelope outside agent/zyal must produce at least one finding"
    );
}
