#!/usr/bin/env bash
# Public CI dependency installation; all product inputs are immutable GitHub refs.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
repo_root="$PWD"
mkdir -p target/jankurai
if [[ "${GITHUB_ACTIONS:-}" == true ]]; then
  sudo apt-get update
  sudo apt-get install -y pkg-config libssl-dev libfuse3-dev
  if [[ -f paper/jankurai.tex ]]; then
    sudo apt-get install -y latexmk texlive-latex-extra texlive-fonts-recommended
  fi
  bash ops/ci/install-security-tools.sh
fi
if [[ -f Cargo.toml ]]; then cargo fetch --locked; fi
if [[ -f package-lock.json ]]; then npm ci; fi
if [[ -d packages/ux-qa ]]; then npm exec -- playwright install --with-deps chromium --only-shell; fi
# Build an exact published auditor source in an automatically removed CI sandbox.
source_root="$(mktemp -d "$repo_root/target/ci-auditor.XXXXXX")"
trap 'rm -rf "$source_root"' EXIT
git clone --no-checkout https://github.com/neverhuman/jankurai-core.git "$source_root/core"
git -C "$source_root/core" checkout --detach af340cf595fc4c3e1d822adcddc5092eb5ea3400
[[ "$(git -C "$source_root/core" rev-parse HEAD)" == af340cf595fc4c3e1d822adcddc5092eb5ea3400 ]]
cargo install --path "$source_root/core/crates/jankurai" --locked --root "$repo_root/target/ci-tools"
# Preserve the upstream language adversarial checks as part of independent CI.
cargo test --manifest-path "$source_root/core/Cargo.toml" --locked -p jankurai --test language_bad_behavior \
  2>&1 | tee "$repo_root/target/jankurai/language-bad-behavior.log"
