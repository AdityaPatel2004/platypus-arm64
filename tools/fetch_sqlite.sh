#!/usr/bin/env bash
# fetch_sqlite.sh — make targets/sqlite_src/sqlite-amalgamation-3540100/ exist.
# Order: (1) the prebuilt archive shipped in targets/dl/sqlite_amalg.tgz;
# (2) sqlite.org's release zip; (3) build the amalgamation from the GitHub tag
# version-3.54.1 (sha256 41bba7dd…e5bf), which needs tclsh. All three give the
# same SQLite 3.54.1 (the battery's md5 afbbd05e… matches on each).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/targets/sqlite_src/sqlite-amalgamation-3540100"
[ -f "$DEST/sqlite3.c" ] && { echo "already present: $DEST"; exit 0; }
cd "$ROOT"
if [ -f targets/dl/sqlite_amalg.tgz ]; then tar xzf targets/dl/sqlite_amalg.tgz; echo "from targets/dl/sqlite_amalg.tgz"; exit 0; fi
mkdir -p "$DEST" targets/dl
if curl -fsSL -o targets/dl/amalg.zip https://sqlite.org/2026/sqlite-amalgamation-3540100.zip; then
  python3 -c "import zipfile; zipfile.ZipFile('targets/dl/amalg.zip').extractall('targets/sqlite_src')"
  echo "from sqlite.org"; exit 0
fi
T=targets/dl/sqlite-3.54.1.tar.gz
[ -f $T ] || curl -fsSL -o $T https://codeload.github.com/sqlite/sqlite/tar.gz/refs/tags/version-3.54.1
echo "41bba7dd1793db5a7c2c24de168226d30c4cc969b3d786c353afe55e49d7e5bf  $T" | sha256sum -c -
mkdir -p targets/src && tar xzf $T -C targets/src
( cd targets/src/sqlite-version-3.54.1 && ./configure --quiet && make sqlite3.c shell.c )
S=targets/src/sqlite-version-3.54.1
cp $S/sqlite3.c $S/sqlite3.h $S/sqlite3ext.h $S/shell.c $S/test/speedtest1.c "$DEST/"
echo "built from the GitHub tag"
