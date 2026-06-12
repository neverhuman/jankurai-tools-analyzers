//! Property tests for the analyzer suite.
//!
//! These use `proptest` to assert detector invariants over randomized inputs:
//! clean, well-named source never produces repo-rot hard findings, and the
//! detectors are total (never panic) on arbitrary identifier-shaped input.

use jankurai_audit_analyzers::audit::repo_rot;
use jankurai_audit_kernel::audit::helpers::AuditContext;
use jankurai_audit_kernel::model::FileInfo;
use proptest::prelude::*;
use std::path::PathBuf;

fn ctx(files: Vec<FileInfo>) -> AuditContext {
    AuditContext {
        root: PathBuf::from("/tmp/jankurai-analyzers-prop"),
        all_files: files.clone(),
        scope_files: files,
        scope_paths: vec![],
        self_audit: false,
        boundary_reclassifications: vec![],
        copy_code: None,
    }
}

fn code_file(rel_path: &str, text: &str) -> FileInfo {
    FileInfo {
        rel_path: rel_path.to_string(),
        name: rel_path.rsplit('/').next().unwrap_or(rel_path).to_string(),
        suffix: ".rs".to_string(),
        size: text.len() as u64,
        line_count: text.lines().count(),
        text: text.to_string(),
        is_generated: false,
        is_code: true,
    }
}

proptest! {
    /// A function whose name is a plain lowercase identifier and whose body only
    /// performs arithmetic must never trip the repo-rot dead-language detector.
    #[test]
    fn clean_identifiers_never_flag_repo_rot(ident in "[a-z][a-z_]{2,12}") {
        let source = format!(
            "pub fn {ident}(value: u32) -> u32 {{\n    value.saturating_add(1)\n}}\n"
        );
        let context = ctx(vec![code_file("crates/app/src/clean.rs", &source)]);
        prop_assert_eq!(repo_rot::summary(&context).hard_findings, 0);
    }

    /// The detector is total: arbitrary short ASCII source must not panic and
    /// must return a finding count that equals itself on a second evaluation.
    #[test]
    fn repo_rot_is_total_and_deterministic(body in "[ -~\n]{0,200}") {
        let source = format!("pub fn handler() {{\n{body}\n}}\n");
        let context = ctx(vec![code_file("crates/app/src/handler.rs", &source)]);
        let a = repo_rot::findings(&context).len();
        let b = repo_rot::findings(&context).len();
        prop_assert_eq!(a, b);
    }
}
