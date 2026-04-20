# pg_roast

A PostgreSQL extension that automatically audits your database and harshly judges everything it finds. Inspired by the book [PostgreSQL Mistakes and How to Avoid Them](https://www.manning.com/books/postgresql-mistakes-and-how-to-avoid-them).

```
CRITICAL | nullable_majority | public.events
  → Table public.events has 68% nullable columns. What does a valid row even look like?

CRITICAL | superuser_app_connection | postgres
  → Superuser postgres is connected from 10.0.0.5 running "myapp". A SQL injection is now a full database takeover.

CRITICAL | fsync_off | fsync
  → fsync is OFF. If the server crashes, you will lose committed data and may end up with a corrupt cluster.

WARNING  | offset_pagination | SELECT * FROM orders ...
  → A high-frequency query uses OFFSET for pagination. OFFSET scans from the beginning every time.

WARNING  | col_float | public.orders.price
  → Column public.orders.price is a floating-point type. If this stores money, you will have rounding errors. Use NUMERIC.
```

### How is this different from pganalyze?

[pganalyze](https://pganalyze.com) is a performance monitoring tool — it watches query latency, index hit rates, autovacuum activity, and helps you tune a running system. It is great at answering "why is this slow right now?"

pg_roast is an opinionated database auditor that lives entirely inside your database. It answers a different question: "what is wrong with this database?" It covers schema design, naming anti-patterns, missing constraints, security misconfigurations, operational health, and query behavior — the kind of things that cause problems months later, not necessarily today.

The other practical difference: pganalyze requires an account, an agent, and your query data leaving your server. pg_roast is a single `CREATE EXTENSION` with no external dependencies.

## Requirements

- PostgreSQL 14+
- C compiler and `pg_config` on `PATH`

## Install

```bash
git clone https://github.com/samirketema/pg_roast
cd pg_roast
make
make install
```

### Configure PostgreSQL

pg_roast needs two things in `postgresql.conf`: to be loaded at startup, and to know which database to audit.

**Find your `postgresql.conf`** by running this in psql:

```sql
SHOW config_file;
```

Common locations:
- **macOS (Homebrew):** `/opt/homebrew/var/postgresql@14/postgresql.conf`
- **Linux (apt):** `/etc/postgresql/14/main/postgresql.conf`
- **Linux (yum):** `/var/lib/pgsql/14/data/postgresql.conf`

Open it and add (or update) these lines:

```
shared_preload_libraries = 'pg_roast'   # if you already have other libraries here,
                                         # add pg_roast to the comma-separated list
pg_roast.database = 'mydb'             # the database you want to audit
pg_roast.interval = 3600               # how often to run, in seconds (3600 = 1 hour)
```

**Restart PostgreSQL** to apply the changes:

```bash
# macOS (Homebrew)
brew services restart postgresql@14

# Linux (systemd)
sudo systemctl restart postgresql
```

### Create the extension

Connect to the database you set in `pg_roast.database` and run:

```sql
CREATE EXTENSION pg_roast;
```

> **No restart?** The background worker (automatic periodic audits) requires `shared_preload_libraries` and a restart. If you skip this, everything still works — you just trigger audits manually with `SELECT * FROM roast.run()`.

## Usage

```sql
-- Run an audit
SELECT * FROM roast.run();

-- View findings from the latest run
SELECT severity, check_name, object_name, roast
FROM roast.latest;

-- Summary by category
SELECT * FROM roast.summary;

-- Check run history
SELECT run_id, started_at, finished_at, triggered_by, finding_count
FROM roast.audit_runs
ORDER BY started_at DESC;

-- Clean up old runs (default: keep last 5)
SELECT roast.clear();
```

## Configuration

| Parameter | Default | Reloadable | Description |
|-----------|---------|------------|-------------|
| `pg_roast.database` | `postgres` | No | Database the background worker audits |
| `pg_roast.interval` | `3600` | Yes | Seconds between automatic runs (60–86400) |
| `pg_roast.auto_audit` | `true` | Yes | Pause automatic background audits without restarting |

**Reloadable** parameters can be changed without a restart — edit `postgresql.conf` then run:

```sql
SELECT pg_reload_conf();
```

`pg_roast.database` always requires a full restart because the background worker connects to it at startup.

## Schema

All objects live in the `roast` schema.

| Object | Description |
|--------|-------------|
| `roast.run()` | Run an audit manually, returns `(run_id, finding_count, duration)` |
| `roast.clear(keep int)` | Delete old findings, keep last N runs (default 5) |
| `roast.findings` | All findings from all runs |
| `roast.audit_runs` | Run history |
| `roast.latest` | Findings from the most recent run, sorted by severity |
| `roast.summary` | Finding counts grouped by severity and category |

See [CHECKS.md](CHECKS.md) for the full list of rules.

## License

[PostgreSQL License](LICENSE)
