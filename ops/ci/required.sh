#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

test -d src-snapshot && find src-snapshot -type f | sort | head -n 1 >/dev/null
