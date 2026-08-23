#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
python_bin="${PYTHON_BIN:-}"
if [[ -z "$python_bin" ]]; then
  if command -v python3 >/dev/null 2>&1; then python_bin=python3; else python_bin=python; fi
fi

"$python_bin" scripts/check-version.py
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
(
  cd sdk/go/tokensaverplugin
  go test -race ./...
  go vet ./...
  test -z "$(gofmt -l .)"
)
(
  cd sdk/python
  "$python_bin" -m unittest discover -s tests -v
)
(
  cd sdk/typescript/tokensaver-plugin
  npm ci --ignore-scripts --no-audit --no-fund
  npm test
  npm run check
)
"$python_bin" -m unittest discover -s scripts -p 'test_*.py' -v
