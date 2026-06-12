# Agent exceptions and overrides

This document defines the agent-friendly exception pattern for
jankurai-tools-analyzers: how an agent or maintainer requests, records, and
bounds an override of a standard rule. Exceptions are the only sanctioned way to
deviate from the audit baseline.

## Principle

The default answer is "follow the standard." An exception is a dated, owned,
expiring waiver for a specific rule on a specific path. Exceptions are data, not
prose: they live next to the code they govern and are reviewed on every audit.

## How to request an exception

1. Identify the exact `rule_id` and `path` the exception applies to (from the
   audit JSON `findings[]`).
2. Add an entry to the relevant `agent/*.toml` manifest. For boundary
   reclassifications use `agent/boundaries.toml`; for security policy use
   `agent/security-policy.toml`; for the dead-language detector vocabulary use
   the `[dead_language] allow_terms` block in `agent/audit-policy.toml`.
3. Every exception entry MUST carry:
   - **purpose** — what the exception buys.
   - **reason** — the concrete justification.
   - **owner** — the team or person accountable.
   - **expires** — an ISO date after which the exception is invalid and the audit
     fails again.
   - **common fixes** — the `repair_hint` and `docs_url` an agent follows first.

## Standing exception: detector vocabulary (HLT-001)

This crate IS the dead-language / repo-rot detector. Its analyzers enumerate the
exact words they look for — `deprecated`, `fallback`, `stale`, `old`, `unused`,
`obsolete`, `legacy`, `temp`, `stub`, `todo`, `temporary`, `remove later`. Those
terms are load-bearing detection **data**, not dead-code markers left in product
code.

- **purpose**: stop the HLT-001 dead-marker heuristic from flagging the
  detector's own vocabulary while keeping every other check active on the same
  files.
- **reason**: the term lists in `repo_rot.rs`, `shape.rs`, `coverage.rs`, and the
  ZYAL schema are the implementation of the detector; removing or renaming them
  would break detection.
- **owner**: tools.
- **expires**: re-reviewed every release; the allowlist is scoped to exactly the
  words present in the detector source.
- **common fixes** (`repair_hint`): if a NEW dead-marker appears outside the
  detector vocabulary, do not extend the allowlist — implement the behavior or
  model a typed unsupported state. `docs_url`: this file.

The allowlist is declared in
[`agent/audit-policy.toml`](../agent/audit-policy.toml) under
`[dead_language] allow_terms`.

## Override review

- Every exception is re-evaluated on each `just audit` run.
- An expired exception is treated as a hard finding, not a pass.
- Removing an exception requires deleting its entry and proving the underlying
  rule now passes on its own.

## What is never excepted

Secret leakage, destructive migrations without rollback, and hand-edits to
generated zones are never granted exceptions. Fix the underlying cause instead.
