#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
if [[ "${SKIP_VERIFY:-0}" != "1" ]]; then
  bash scripts/verify.sh
fi
cargo build --workspace --release --locked
printf 'TokenSaver Plugin SDK %s release workspace built\n' "$(tr -d '\r\n' < VERSION)"
