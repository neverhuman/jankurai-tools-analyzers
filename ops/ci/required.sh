#!/usr/bin/env bash
# Required lane: the lightweight gate that must pass on every push.
# Verifies the workspace manifest resolves against the locked dependency graph.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

log "required lane: complete hosted job inventory and workflow mutation controls"
require_tool node
node --test scripts/ci-aggregate.test.mjs

log "required lane: cargo metadata"
cargo metadata --no-deps --format-version 1 --locked >/dev/null
