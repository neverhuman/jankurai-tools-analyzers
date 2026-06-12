# Testing

This document is the testing and verification surface for
jankurai-tools-analyzers. It describes the deterministic proof lanes, the Rust
test strategy for the analyzer crate, and the agent-friendly exception pattern
that governs every audit override.

## Proof lanes

Every change routes to the smallest deterministic lane in
[`agent/proof-lanes.toml`](../agent/proof-lanes.toml). The lanes are exposed both
locally (the root [`Justfile`](../Justfile)) and in CI
([`.github/workflows/ci.yml`](../.github/workflows/ci.yml)) through the shared
`ops/ci/<lane>.sh` scripts, so a green local run means a green CI run.

| Lane | Command | Purpose |
| --- | --- | --- |
| `required` | `bash scripts/ci-local.sh required` | manifest resolves against the locked graph |
| `fast` | `just fast` | `cargo check --workspace --locked` + `cargo nextest run --workspace` |
| `security` | `just security` | `gitleaks detect` + `cargo audit` |
| `audit` | `just audit` | `jankurai audit` writes `.jankurai/repo-score.{json,md}` |

## Rust test strategy

The analyzer crate carries three layers of Rust proof:

- **Unit tests** live next to the analyzers under
  `crates/jankurai/src/audit/**` behind `#[cfg(test)]`, exercising
  each detector against tempfile fixtures.
- **Integration tests** live under
  `crates/jankurai/tests/` and drive the public analyzer API
  (`repo_rot`, `zyal`) end-to-end through a constructed `AuditContext`.
- **Property tests** live under
  `crates/jankurai/tests/` and use `proptest` to assert detector
  invariants over randomized inputs (clean source never flags; the detector
  vocabulary is matched deterministically).

Run the whole suite with `cargo test --workspace --locked` (the route declared in
[`agent/test-map.json`](../agent/test-map.json) for `crates/`).

## Coverage and false-green defense

Coverage and mutation evidence is parsed deterministically from the artifacts
declared in [`agent/coverage-sources.toml`](../agent/coverage-sources.toml). The
HLT-008 false-green check requires both property and integration Rust tests on
the analyzer surface; both are present under the crate's `tests/` directory.

## Agent-friendly exception pattern

Exceptions are the only sanctioned way to deviate from the audit baseline. They
are data, not prose, and every exception entry is reviewed on each audit. An
exception record carries these fields so an agent can act on it without guessing:

- **purpose** — what the exception buys and why the default rule does not fit.
- **reason** — the concrete justification, e.g. "this crate is the dead-language
  detector, so its term lists are load-bearing data, not dead code."
- **owner** — the team or person accountable for removing it.
- **expires** — an ISO date after which the exception is invalid and the audit
  fails again.
- **common fixes** — the repair_hint and docs_url an agent should follow first:
  see [`docs/exceptions.md`](exceptions.md) (`docs_url`) and the `repair_hint`
  recorded next to each override.

The full exception lifecycle is documented in
[`docs/exceptions.md`](exceptions.md).
