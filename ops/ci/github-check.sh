#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
export PATH="$PWD/target/ci-tools/bin:$PATH"
bash ops/ci/prepare-baseline.sh
bash scripts/ci-local.sh required
bash ops/ci/fast.sh
bash ops/ci/security.sh
bash ops/ci/tool-adoption.sh
bash ops/ci/audit.sh
