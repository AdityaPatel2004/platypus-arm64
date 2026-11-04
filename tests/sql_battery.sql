-- sql_battery.sql — the correctness workload behind the "identical output"
-- claim. Run against both the unhardened and hardened sqlite3 build; the two
-- outputs must be byte-identical (same md5).
PRAGMA journal_mode=WAL;
CREATE TABLE t(id INTEGER PRIMARY KEY, name TEXT, v REAL);
WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<20000)
  INSERT INTO t(id,name,v) SELECT x, 'n'||x, x*1.5 FROM c;
CREATE INDEX idx_v ON t(v);
CREATE TABLE u(id INTEGER, tag TEXT);
INSERT INTO u SELECT id, CASE WHEN id%3=0 THEN 'a' ELSE 'b' END FROM t;
SELECT count(*), sum(v), avg(v), min(v), max(v) FROM t;
SELECT tag, count(*), round(sum(v),2) FROM t JOIN u USING(id) GROUP BY tag ORDER BY tag;
SELECT name,v FROM t WHERE v BETWEEN 100 AND 110 ORDER BY v;
SELECT count(*) FROM t WHERE name LIKE 'n1%';
