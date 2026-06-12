//! Analyzer/scoring modules moved out of `jankurai-core`.
//!
//! These mirror the `crate::audit::*` layout they had in core so that the
//! intra-suite references (`crate::audit::analyzers`, `crate::audit::web_security`,
//! `crate::audit::repo_rot`, `crate::audit::proofbind_artifact`) keep resolving
//! within this crate unchanged. References that pointed at shared substrate were
//! repointed to `jankurai_audit_kernel::audit::*`.

pub mod analyzers;
pub mod boundaries_artifact;
pub mod canonical_standard;
pub mod ci_local_parity;
pub mod coverage;
pub mod proofbind_artifact;
pub mod repo_rot;
pub mod security_artifact;
pub mod unnecessary_variety;
pub mod ux_artifact;
pub mod web_security;
pub mod worktree_sprawl;
pub mod zyal;
