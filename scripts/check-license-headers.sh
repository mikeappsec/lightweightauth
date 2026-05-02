#!/usr/bin/env bash
# Verify all Go source files (excluding generated .pb.go) carry the
# Apache 2.0 SPDX license header. Exits non-zero and lists offending
# files if any are missing it.
set -euo pipefail

MISSING=()

while IFS= read -r -d '' file; do
  if ! head -n 3 "$file" | grep -q 'SPDX-License-Identifier: Apache-2.0'; then
    MISSING+=("$file")
  fi
done < <(find . -name '*.go' ! -name '*.pb.go' ! -path './vendor/*' -print0)

if [ ${#MISSING[@]} -gt 0 ]; then
  echo "ERROR: The following files are missing the Apache 2.0 SPDX header:"
  printf '  %s\n' "${MISSING[@]}"
  echo ""
  echo "Run: bash scripts/add-license-headers.sh"
  exit 1
fi

echo "OK: All Go source files have the Apache 2.0 license header."
