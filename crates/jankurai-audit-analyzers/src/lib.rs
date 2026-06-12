//! Dimension analyzers and scoring suite for the jankurai audit standard.
//!
//! This crate holds the analyzer/scoring tools that were extracted out of
//! `jankurai-core`. The shared substrate (helpers, scan, model, language rules,
//! finding builders) lives in `jankurai-audit-kernel`; this crate depends on it
//! and re-exposes its tools under `crate::audit::*` so core can re-export them
//! at their original paths.
//!
//! The orchestration that *calls* these analyzers (`audit::caps`,
//! `build_findings`/`run_audit`) stays in core; this is the intended dependency
//! direction (core -> analyzers -> kernel).

pub mod audit;
