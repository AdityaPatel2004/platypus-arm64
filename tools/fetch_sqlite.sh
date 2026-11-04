#!/usr/bin/env bash
# fetch_sqlite.sh — fetch and unpack the exact SQLite amalgamation used, so the
# build/correctness/benchmark results are reproducible. Pinned to 3.54.1.
set -euo pipefail
VER=3540100                      # SQLite 3.54.1
URL="https://sqlite.org/2026/sqlite-amalgamation-${VER}.zip"
DEST="${1:-$HOME/e0256/targets/sqlite_src}"
mkdir -p "$DEST"; cd "$DEST"
if [ ! -d "sqlite-amalgamation-${VER}" ]; then
  curl -fsSL -o amalg.zip "$URL"
  python3 -c "import zipfile; zipfile.ZipFile('amalg.zip').extractall()"
fi
ls "sqlite-amalgamation-${VER}"/*.c
echo "SQLite amalgamation ${VER} ready in $DEST"
