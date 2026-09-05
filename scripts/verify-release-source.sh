#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
requested=${1:?Release version required}
# Keep the complete multi-language manifest check; never bypass a version mismatch.
python scripts/check-version.py "$requested"
tag_commit=$(git rev-parse --verify "refs/tags/v${requested}^{commit}")
source_commit=$(git rev-parse --verify HEAD)
if [[ "$tag_commit" != "$source_commit" ]]; then
  echo "Release tag v${requested} does not identify the checked-out source." >&2
  exit 1
fi
echo "Release version and source tag verified: v${requested} at ${source_commit}"
