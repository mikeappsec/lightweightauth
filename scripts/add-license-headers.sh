#!/usr/bin/env bash
# Add Apache 2.0 SPDX license header to all Go source files that lack one.
# Skips generated protobuf files (*.pb.go, *_grpc.pb.go).
set -euo pipefail

HEADER="// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0
"

find . -name '*.go' \
  ! -name '*.pb.go' \
  ! -path './vendor/*' \
  -print0 | while IFS= read -r -d '' file; do
  # Skip files that already have the header.
  if head -n 2 "$file" | grep -q 'SPDX-License-Identifier: Apache-2.0'; then
    continue
  fi
  # Prepend header + blank line.
  tmp=$(mktemp)
  printf '%s\n' "$HEADER" | cat - "$file" > "$tmp"
  mv "$tmp" "$file"
done

echo "Done. License headers added to all Go source files."
