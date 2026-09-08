#!/usr/bin/env bash
# Tool-adoption evidence lane.
#
# jankurai replaces a fleet of ad-hoc tools (manual scoring, gitleaks-only
# security, hand-rolled coverage/contract drift checks) with first-class
# subcommands. This lane runs each adopted command in CI and writes its
# evidence artifact under target/jankurai/ so the audit can prove the
# replacement actually executed. The matching artifacts are uploaded by the
# workflow's actions/upload-artifact step.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

mkdir -p target/jankurai target/jankurai/security target/jankurai/coverage \
         target/jankurai/proofbind target/jankurai/proofmark

# audit-ci / proof-routing / contract-drift / authz-matrix / agent-tool-supply
# / release-readiness / cost-budget all adopt the ratchet audit command.
log "tool-adoption: ratchet audit"
jankurai audit . --mode ratchet --baseline target/jankurai/accepted-baseline.json --json target/jankurai/repo-score.json --md target/jankurai/repo-score.md --full
# Adopted artifacts: .jankurai/repo-score.json .jankurai/repo-score.md
# target/jankurai/repair-queue.jsonl

# proofbind: changed-surface proof obligation routing.
log "tool-adoption: proofbind verify"
jankurai proofbind verify . --changed-from origin/main
# Adopted artifacts: target/jankurai/proofbind/surface-witness.json
# target/jankurai/proofbind/obligations.json

# proofmark-rust: in-diff mutation and coverage witness for Rust.
log "tool-adoption: proofmark rust"
jankurai proofmark rust . --obligations target/jankurai/proofbind/obligations.json
# Adopted artifacts: target/jankurai/proofmark/proofmark-receipt.json
# target/jankurai/proofmark/proof-receipt.json

# copy-code: duplication triage replacing ad-hoc copy-code review.
log "tool-adoption: copy-code"
jankurai copy-code . --json target/jankurai/copy-code.json --md target/jankurai/copy-code.md
# Adopted artifacts: target/jankurai/copy-code.json target/jankurai/copy-code.md

# security: secret + dependency + SBOM/provenance evidence in one lane.
log "tool-adoption: security run"
jankurai security run . --out target/jankurai/security/evidence.json --script ops/ci/security-scans.sh
# Adopted artifact: target/jankurai/security/evidence.json

# ci/git/release bad-behavior: language-level workflow safety tests.
log "tool-adoption: language bad-behavior tests"
test -s target/jankurai/language-bad-behavior.log
# Adopted artifact: target/jankurai/language-bad-behavior.log

# contract-drift: boundary manifest schema and public-API drift hooks.
log "tool-adoption: contract drift (ratchet audit)"
jankurai audit . --mode ratchet --baseline target/jankurai/accepted-baseline.json --json target/jankurai/repo-score.json --md target/jankurai/repo-score.md --full

# rust-witness: changed-behavior witness graph for Rust.
log "tool-adoption: rust witness"
jankurai rust witness build .
# Adopted artifact: target/jankurai/rust/witness-graph.json

# coverage-evidence: coverage audit replacing line-only coverage gates.
log "tool-adoption: coverage audit"
jankurai coverage audit . --config agent/coverage-sources.toml --json target/jankurai/coverage/coverage-audit.json --md target/jankurai/coverage/coverage-audit.md
# Adopted artifacts: target/jankurai/coverage/coverage-audit.json
# target/jankurai/coverage/coverage-audit.md
