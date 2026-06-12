# jankurai-tools-analyzers Architecture

This repository is the **analyzer and scoring suite** for the jankurai audit
standard. It was extracted from `jankurai-core` so the dimension analyzers can be
versioned and tested independently of the orchestration that calls them.

```text
core (orchestration) -> jankurai-audit-analyzers (this crate) -> jankurai-audit-kernel (substrate)
```

## Crate role

`crates/jankurai` holds the per-dimension analyzers and scoring
logic that were moved out of `jankurai-core`. The shared substrate — file
inventory, the `scan` helpers, the data model, language rules, and finding
builders — lives in `jankurai-audit-kernel`; this crate depends on it and
re-exposes its tools under `crate::audit::*` so core can re-export them at their
original paths. The orchestration that *calls* these analyzers (`audit::caps`,
`build_findings` / `run_audit`) stays in core. This is the intended dependency
direction: `core -> analyzers -> kernel`.

## Detection vocabulary

These analyzers detect repo-rot, dead-language markers, web-security issues,
coverage gaps, migration liabilities, and ZYAL runbook placement. Because the
detector enumerates the very words it looks for (e.g. `deprecated`, `fallback`,
`stale`, `old`), those terms appear as load-bearing **data** in the source. They
are declared in [`agent/audit-policy.toml`](../agent/audit-policy.toml) under
`[dead_language] allow_terms` so the HLT-001 dead-marker heuristic does not flag
the detector's own vocabulary. See [`docs/exceptions.md`](exceptions.md).

## Local workspace ownership

| Path | Role |
| --- | --- |
| `crates/jankurai` | Rust analyzer + scoring crate |
| `agent/` | machine-readable owner, test, boundary, and proof maps |
| `docs/` | architecture, testing, boundaries, release, and exception docs |
| `ops/` | pinned CI script entrypoints |
| `scripts/` | local CI and fusion helpers |
| `schemas/` | JSON Schemas for the auditor's evidence artifacts |

Agents should prefer [`agent/owner-map.json`](../agent/owner-map.json) and
[`agent/test-map.json`](../agent/test-map.json) for changes, then route to the
smallest proof lane in [`agent/proof-lanes.toml`](../agent/proof-lanes.toml).
