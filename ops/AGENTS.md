# ops Agent Instructions

This cell owns the pinned CI script entrypoints and the local-parity runner so
that local runs and GitHub Actions execute the exact same commands.

- Owns: `ops/ci/*.sh` (lane scripts: `fast`, `security`, `audit`,
  `required`, `quality-gates`, `tool-adoption`), `ops/ci/lib.sh` (shared tool
  version pins), and `ops/git-hooks/` (local gates).
- Forbidden: inlining CI commands in `.github/workflows/ci.yml`; every workflow
  job must delegate to `bash ops/ci/<lane>.sh`. Never duplicate tool version
  pins in individual lane scripts — they live only in `ops/ci/lib.sh`.
- Proof lane: security lane / workflow lint — `bash scripts/ci-local.sh gates`
  (`ops/ci/quality-gates.sh`) and `bash scripts/ci-local.sh security`
  (`ops/ci/security.sh`).

Change `ops/ci/lib.sh` to update shared tool version pins; the
`tool-adoption` lane (`ops/ci/tool-adoption.sh`) runs the adopted jankurai tools
and publishes their evidence under `target/jankurai/`.
