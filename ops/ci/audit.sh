#!/usr/bin/env bash
# Jankurai self-audit lane: writes the repo-score artifacts that CI uploads.
# The same lane runs locally via `just audit`.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

readonly audit_json=".jankurai/repo-score.json"
readonly audit_md=".jankurai/repo-score.md"
case "$#" in
  0) ;;
  2)
    if [[ "$1" != "$audit_json" || "$2" != "$audit_md" ]]; then
      printf '[ci] audit lane accepts only the canonical repo-score artifact pair\n' >&2
      exit 2
    fi
    ;;
  *)
    printf '[ci] usage: %s [%s %s]\n' "$0" "$audit_json" "$audit_md" >&2
    exit 2
    ;;
esac

mkdir -p .jankurai
log "audit lane: jankurai audit -> .jankurai/repo-score.{json,md}"
bash ops/ci/governed-jankurai audit . --no-score-history --json "$audit_json" --md "$audit_md" --full

assert_artifact "$audit_json"
assert_artifact "$audit_md"
