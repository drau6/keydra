#!/usr/bin/env sh
# Regenerates the detector tables in README.md from the code (single source of truth).
set -eu
cd "$(dirname "$0")/.."

tmp=$(mktemp)
trap 'rm -f "$tmp" README.md.new' EXIT
go run ./cmd/keydra rules --markdown > "$tmp"

awk -v tablefile="$tmp" '
  /<!-- detectors:start -->/ { print; print ""; while ((getline line < tablefile) > 0) print line; print ""; skip = 1; next }
  /<!-- detectors:end -->/   { skip = 0 }
  !skip { print }
' README.md > README.md.new
mv README.md.new README.md
echo "README.md detector tables updated"
