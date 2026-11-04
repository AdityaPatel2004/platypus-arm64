/* sqlite_bench.c — deterministic SQLite workload for measuring jail overhead.
 *
 * Links the SQLite amalgamation (so sqlite3.c is instrumented by the pass when
 * built hardened) and drives the VDBE's hot indirect-call paths: a big
 * transaction of prepared INSERTs, an index build, then many indexed point
 * queries. Prints "<elapsed_seconds> <checksum>". The checksum must match
 * between unhardened and hardened builds (correctness under load).
 *
 * usage: sqlite_bench [N_inserts] [N_queries] [DB]
 *   DB defaults to :memory:. A file path runs the same workload on disk
 *   (WAL journal, synchronous=OFF so fsync latency does not swamp the CPU cost
 *   being measured; the file is deleted first). The on-disk run exercises the
 *   VFS's indirect calls into libc (pread/pwrite/fcntl locks).
 */
#include <unistd.h>
#include "sqlite3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now_s(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}

int main(int argc, char **argv) {
    int N = (argc > 1) ? atoi(argv[1]) : 300000;
    int Q = (argc > 2) ? atoi(argv[2]) : 300000;
    sqlite3 *db;
    const char *path = (argc > 3) ? argv[3] : ":memory:";
    int ondisk = strcmp(path, ":memory:") != 0;
    if (ondisk) {
        char b[4096];
        unlink(path);
        snprintf(b, sizeof b, "%s-wal", path); unlink(b);
        snprintf(b, sizeof b, "%s-shm", path); unlink(b);
    }
    if (sqlite3_open(path, &db)) { fprintf(stderr, "open fail\n"); return 1; }
    if (ondisk) {
        sqlite3_exec(db, "PRAGMA journal_mode=WAL;", 0, 0, 0);
        sqlite3_exec(db, "PRAGMA synchronous=OFF;", 0, 0, 0);
    } else {
        sqlite3_exec(db, "PRAGMA journal_mode=MEMORY;", 0, 0, 0);
    }
    sqlite3_exec(db, "CREATE TABLE t(id INTEGER PRIMARY KEY,a INTEGER,b TEXT,c REAL);", 0, 0, 0);

    double t0 = now_s();
    sqlite3_exec(db, "BEGIN;", 0, 0, 0);
    sqlite3_stmt *ins;
    sqlite3_prepare_v2(db, "INSERT INTO t(a,b,c) VALUES(?,?,?)", -1, &ins, 0);
    for (int i = 0; i < N; i++) {
        char buf[32]; snprintf(buf, sizeof buf, "row%d", i);
        sqlite3_bind_int(ins, 1, (i * 7) % 1000);
        sqlite3_bind_text(ins, 2, buf, -1, SQLITE_TRANSIENT);
        sqlite3_bind_double(ins, 3, i * 1.5);
        sqlite3_step(ins); sqlite3_reset(ins);
    }
    sqlite3_finalize(ins);
    sqlite3_exec(db, "CREATE INDEX i_a ON t(a);", 0, 0, 0);
    sqlite3_exec(db, "COMMIT;", 0, 0, 0);

    sqlite3_stmt *sel;
    sqlite3_prepare_v2(db, "SELECT count(*),sum(c) FROM t WHERE a=?", -1, &sel, 0);
    long long acc = 0;
    for (int q = 0; q < Q; q++) {
        sqlite3_bind_int(sel, 1, q % 1000);
        if (sqlite3_step(sel) == SQLITE_ROW) acc += sqlite3_column_int64(sel, 0);
        sqlite3_reset(sel);
    }
    sqlite3_finalize(sel);
    double t1 = now_s();

    printf("%.6f %lld\n", t1 - t0, acc);
    sqlite3_close(db);
    return 0;
}
