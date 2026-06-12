# Changelog

All notable changes to jankurai-tools-analyzers are documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). The authoritative
version string lives in [`VERSION`](VERSION).

## [Unreleased]

### Added

- Root `Justfile` command surface with `setup`, `fast`, `check`, `security`, and
  `audit` lanes for one-command setup and validation.
- GitHub Actions CI (`.github/workflows/ci.yml`) with build, security, and
  jankurai audit jobs, all third-party actions pinned to commit SHAs.
- Pinned `ops/ci/*.sh` lane scripts and `scripts/ci-local.sh` so local runs and
  CI execute the exact same commands.
- Agent-readable documentation: `README.md`, `docs/architecture.md`,
  `docs/testing.md`, `docs/boundaries.md`, `docs/release.md`, and
  `docs/exceptions.md`.
- `agent/` control surface: `audit-policy.toml` (with the detector-vocabulary
  `[dead_language] allow_terms` allowlist and scan exclusions), `boundaries.toml`,
  `coverage-sources.toml`, `copy-code-allowlist.toml`, `security-policy.toml`,
  `tool-adoption.toml`, and `proof-lanes.toml`.
- Rust integration and property tests for the analyzer crate under
  `crates/jankurai-audit-analyzers/tests/`.

### Changed

- Re-scoped `agent/owner-map.json`, `agent/test-map.json`, and
  `agent/generated-zones.toml` to the paths that exist in this single-purpose
  analyzer repo.

## [1.7.0-split.0] - 2026-06-12

### Added

- Initial split-family extraction of the jankurai audit analyzer suite out of
  `jankurai-core`.
