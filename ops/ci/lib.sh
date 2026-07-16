#!/usr/bin/env bash
# Shared CI helper module sourced by every ops/ci/<lane>.sh script.
# Single source of truth for tool version pins and artifact assertions so
# local runs and GitHub Actions execute the exact same commands.
set -euo pipefail

if [[ "${JANKURAI_TOOLS_CI_LIB_LOADED:-0}" == "1" ]]; then
  return 0
fi
readonly JANKURAI_TOOLS_CI_LIB_LOADED=1

# Resolve the repository root regardless of where a lane is invoked from.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export REPO_ROOT

# Pinned tool versions. Lanes read these so CI and local environments match.
export RUST_TOOLCHAIN="${RUST_TOOLCHAIN:-stable}"
export GITLEAKS_VERSION="${GITLEAKS_VERSION:-8.18.4}"
export CARGO_AUDIT_VERSION="${CARGO_AUDIT_VERSION:-0.21.0}"
export NEXTEST_VERSION="${NEXTEST_VERSION:-0.9}"

# Governed Jankurai identity. This is deliberately absolute and immutable:
# callers must never select an ambient PATH, Cargo, fusion, or fallback copy.
readonly GOVERNED_JANKURAI_BIN="/home/ubuntu/.jeryu/bin/jankurai"
readonly GOVERNED_JANKURAI_VERSION="jankurai 1.6.11"
readonly GOVERNED_JANKURAI_BINARY_SHA256="fdb42e5fa7d9851c0729e59bf1e582c895aa9cfc03a7175b420c6025d2fd014e"
readonly GOVERNED_JANKURAI_RECEIPT="/home/ubuntu/.jeryu/receipts/jankurai/sha256/494ea02af28e6aa7fb2f817831dc8f00df102398677779f7decfce55b3b20b98.json"
readonly GOVERNED_JANKURAI_RECEIPT_SHA256="494ea02af28e6aa7fb2f817831dc8f00df102398677779f7decfce55b3b20b98"
readonly GOVERNED_JANKURAI_SOURCE_REMOTE="http://127.0.0.1:8787/git/jeryu/jankurai.git"
readonly GOVERNED_JANKURAI_SOURCE_COMMIT="dface7397fe24d46b0b1885ddd5782c34edbff49"
readonly GOVERNED_JANKURAI_SOURCE_TAG="v1.6.11-deadlang-precision-split.1"
readonly GOVERNED_JANKURAI_SOURCE_TREE="34a8a1fb59bc4ebfadf12c45d95f169d06acc781"
readonly GOVERNED_JANKURAI_SOURCE_ARCHIVE_SHA256="2fbca5d04083e3c8d32f383d5b6b4520b8911690b26968c6fbcb210e1202b938"
readonly GOVERNED_JANKURAI_CARGO_LOCK_SHA256="b9acb981c326226a687d0b6703e4f7ee303148e9e1a6dda1aa03d77988820f6a"
readonly GOVERNED_JANKURAI_MANIFEST_REPO="http://127.0.0.1:8787/git/jeryu/jeryu-tool.git"
readonly GOVERNED_JANKURAI_MANIFEST_COMMIT="de80b657e1be5580289dfecdc0cd3c71348261e0"
readonly GOVERNED_JANKURAI_MANIFEST_TREE="8dd6f773dce3ec2e5a82c8f0b606c240760489f9"
readonly GOVERNED_JANKURAI_MANIFEST_SHA256="707f57b7f60b65025303315b050cc1c138c7fb2e2080e775ef97a971f286e9b5"
readonly GOVERNED_JANKURAI_RUSTC="rustc 1.95.0 (59807616e 2026-04-14)"
readonly GOVERNED_JANKURAI_CARGO="cargo 1.95.0 (f2d3ce0bd 2026-03-21)"
readonly GOVERNED_JANKURAI_TARGET="x86_64-unknown-linux-gnu"
readonly GOVERNED_JANKURAI_BUILD_MODE="cargo-install-locked-offline-path-v1"
export JANKURAI_NO_UPDATE_CHECK=1
export GIT_TERMINAL_PROMPT=0

# log <message> -- emit a structured progress line.
log() {
  printf '[ci] %s\n' "$*"
}

# require_tool <binary> -- fail fast with an actionable message when a pinned
# tool is missing from PATH so local parity gaps surface before the lane runs.
require_tool() {
  local tool="$1"
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf '[ci] missing required tool: %s\n' "$tool" >&2
    return 1
  fi
}

# Fail closed before executing Jankurai: both the binary and its production
# installation receipt must match their content addresses and governed source.
require_governed_jankurai() {
  local actual_binary_sha actual_receipt_sha actual_version normalized tool

  for tool in jq realpath sha256sum; do
    require_tool "$tool" || return 1
  done
  if [[ ! -f "$GOVERNED_JANKURAI_BIN" || -L "$GOVERNED_JANKURAI_BIN" || ! -x "$GOVERNED_JANKURAI_BIN" ]]; then
    printf '[ci] governed Jankurai must be an executable regular file: %s\n' "$GOVERNED_JANKURAI_BIN" >&2
    return 1
  fi
  normalized="$(realpath -m "$GOVERNED_JANKURAI_BIN")"
  if [[ "$normalized" != "$GOVERNED_JANKURAI_BIN" ]]; then
    printf '[ci] governed Jankurai path traverses a symlink: %s -> %s\n' "$GOVERNED_JANKURAI_BIN" "$normalized" >&2
    return 1
  fi
  actual_binary_sha="$(sha256sum "$GOVERNED_JANKURAI_BIN" | awk '{print $1}')"
  if [[ "$actual_binary_sha" != "$GOVERNED_JANKURAI_BINARY_SHA256" ]]; then
    printf '[ci] governed Jankurai digest mismatch: expected=%s actual=%s\n' \
      "$GOVERNED_JANKURAI_BINARY_SHA256" "$actual_binary_sha" >&2
    return 1
  fi

  if [[ ! -f "$GOVERNED_JANKURAI_RECEIPT" || -L "$GOVERNED_JANKURAI_RECEIPT" ]]; then
    printf '[ci] governed Jankurai production receipt is unavailable: %s\n' "$GOVERNED_JANKURAI_RECEIPT" >&2
    return 1
  fi
  normalized="$(realpath -m "$GOVERNED_JANKURAI_RECEIPT")"
  if [[ "$normalized" != "$GOVERNED_JANKURAI_RECEIPT" ]]; then
    printf '[ci] governed Jankurai receipt path traverses a symlink: %s -> %s\n' "$GOVERNED_JANKURAI_RECEIPT" "$normalized" >&2
    return 1
  fi
  actual_receipt_sha="$(sha256sum "$GOVERNED_JANKURAI_RECEIPT" | awk '{print $1}')"
  if [[ "$actual_receipt_sha" != "$GOVERNED_JANKURAI_RECEIPT_SHA256" ]]; then
    printf '[ci] governed Jankurai receipt digest mismatch: expected=%s actual=%s\n' \
      "$GOVERNED_JANKURAI_RECEIPT_SHA256" "$actual_receipt_sha" >&2
    return 1
  fi

  jq -e \
    --arg remote "$GOVERNED_JANKURAI_SOURCE_REMOTE" \
    --arg commit "$GOVERNED_JANKURAI_SOURCE_COMMIT" \
    --arg tag "$GOVERNED_JANKURAI_SOURCE_TAG" \
    --arg tree "$GOVERNED_JANKURAI_SOURCE_TREE" \
    --arg archive "$GOVERNED_JANKURAI_SOURCE_ARCHIVE_SHA256" \
    --arg lock "$GOVERNED_JANKURAI_CARGO_LOCK_SHA256" \
    --arg binary "$GOVERNED_JANKURAI_BIN" \
    --arg binary_sha "$GOVERNED_JANKURAI_BINARY_SHA256" \
    --arg version "$GOVERNED_JANKURAI_VERSION" \
    --arg manifest_repo "$GOVERNED_JANKURAI_MANIFEST_REPO" \
    --arg manifest_commit "$GOVERNED_JANKURAI_MANIFEST_COMMIT" \
    --arg manifest_tree "$GOVERNED_JANKURAI_MANIFEST_TREE" \
    --arg manifest_sha "$GOVERNED_JANKURAI_MANIFEST_SHA256" \
    --arg rustc "$GOVERNED_JANKURAI_RUSTC" \
    --arg cargo "$GOVERNED_JANKURAI_CARGO" \
    --arg target "$GOVERNED_JANKURAI_TARGET" \
    --arg mode "$GOVERNED_JANKURAI_BUILD_MODE" \
    '.schema == "jeryu.jankurai-installation/v1" and
     .source.remote == $remote and .source.commit == $commit and .source.tag == $tag and
     .source.tree == $tree and .source.archive_sha256 == $archive and
     .source.cargo_lock_sha256 == $lock and .source.verification == "release-authoritative" and
     .build.rustc == $rustc and .build.cargo == $cargo and .build.target_triple == $target and
     .build.mode == $mode and .build.cargo_net_offline == true and
     .build.dedicated_cargo_home == true and .build.git_global_config_disabled == true and
     .build.git_system_config_disabled == true and .build.git_http_follow_redirects == false and
     .build.git_terminal_prompt == false and .build.jankurai_update_check == false and
     .build.network_scope == "local-forge-source-plus-offline-cargo" and
     .build.no_proxy == "127.0.0.1,localhost,::1" and
     .binary.sha256 == $binary_sha and .binary.version_output == $version and
     .installation.path == $binary and .installation.atomic == true and
     .governance.status == "governed" and .governance.manifest_repo == $manifest_repo and
     .governance.manifest_commit == $manifest_commit and .governance.manifest_tree == $manifest_tree and
     .governance.manifest_sha256 == $manifest_sha and .governance.protected_main == true and
     .governance.protection_policy == "immutable-main-v1" and
     .test_mode == false and .conclusion == "success"' \
    "$GOVERNED_JANKURAI_RECEIPT" >/dev/null || {
      printf '[ci] governed Jankurai production receipt failed semantic validation\n' >&2
      return 1
    }

  actual_version="$("$GOVERNED_JANKURAI_BIN" --version 2>/dev/null || true)"
  if [[ "$actual_version" != "$GOVERNED_JANKURAI_VERSION" ]]; then
    printf '[ci] governed Jankurai version mismatch: expected=%s actual=%s\n' \
      "$GOVERNED_JANKURAI_VERSION" "${actual_version:-missing}" >&2
    return 1
  fi
}

run_governed_jankurai() {
  require_governed_jankurai || return 1
  "$GOVERNED_JANKURAI_BIN" "$@"
}

# assert_artifact <path> -- confirm a lane produced the artifact it promised.
assert_artifact() {
  local artifact="$1"
  if [ ! -e "$REPO_ROOT/$artifact" ]; then
    printf '[ci] expected artifact missing: %s\n' "$artifact" >&2
    return 1
  fi
  log "artifact present: $artifact"
}
