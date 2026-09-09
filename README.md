# jankurai-tools-analyzers

<!-- jankurai-badge:start -->
[![Jankurai score: 94/100](agent/jankurai-badge.svg)](agent/jankurai-badge.json)
<!-- jankurai-badge:end -->

[![CI](https://github.com/neverhuman/jankurai-tools-analyzers/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/neverhuman/jankurai-tools-analyzers/actions/workflows/ci.yml)

Dimension analyzers and scoring suite for the **jankurai** audit standard. This
repository is one member of the Jankurai split family; read [`SPLIT.md`](SPLIT.md)
for the family contract and [`AGENTS.md`](AGENTS.md) for agent routing rules.

## Stack

Rust core + TypeScript/React/Vite product surface + PostgreSQL truth + generated
contracts + exception-only Python AI/data service. This repository is the
Rust-first analyzer crate that was extracted from `jankurai-core`; see
[`docs/architecture.md`](docs/architecture.md).

## Quick start

```bash
# One-command setup (toolchain + locked dependencies).
just setup

# Deterministic fast lane (check + tests).
just fast

# Full local check: format, lint, fast, security, and self-audit.
just check
```

The full command surface lives in the root [`Justfile`](Justfile). Continuous
integration runs the same lanes under
[`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## Layout

| Path | Role |
| --- | --- |
| `crates/jankurai-audit-analyzers` | Rust analyzer + scoring crate |
| `agent/` | machine-readable owner, test, boundary, and proof maps |
| `docs/` | architecture, testing, boundaries, release, and exception docs |
| `ops/` | pinned CI script entrypoints |
| `scripts/` | local CI and fusion helpers |
| `schemas/` | JSON Schemas for the auditor's evidence artifacts |

## Documentation

- [Architecture](docs/architecture.md)
- [Testing](docs/testing.md)
- [Boundaries](docs/boundaries.md)
- [Release process](docs/release.md)
- [Agent exceptions and overrides](docs/exceptions.md)

## Versioning

The current version is recorded in [`VERSION`](VERSION) and the change history in
[`CHANGELOG.md`](CHANGELOG.md). Release mechanics are documented in
[`docs/release.md`](docs/release.md).

## License

See [`LICENSE`](LICENSE).
