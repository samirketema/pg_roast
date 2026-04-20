# Contributing to pg_roast

## Requirements

- PostgreSQL 14+ with development headers
- `pg_config` on your `PATH`
- A C compiler (clang or gcc)

**macOS (Homebrew):**
```bash
brew install postgresql@14
export PATH="/opt/homebrew/opt/postgresql@14/bin:$PATH"
```

**Linux (apt):**
```bash
sudo apt-get install postgresql-14 postgresql-server-dev-14
export PATH="/usr/lib/postgresql/14/bin:$PATH"
```

## Build

```bash
git clone https://github.com/samirketema/pg_roast
cd pg_roast
make
make install
```

## Run locally

Add to `postgresql.conf`:
```
shared_preload_libraries = 'pg_roast'
pg_roast.database = 'postgres'
```

Restart PostgreSQL, then:
```sql
CREATE EXTENSION pg_roast;
SELECT * FROM roast.run();
SELECT severity, check_name, object_name, roast FROM roast.latest;
```

## Adding a check

All audit logic lives in `pg_roast--1.0.sql`. Each category has a dedicated function (`roast._check_col_types`, `roast._check_security`, etc.).

To add a new check:

1. Find the appropriate `_check_*` function for the category, or create a new one.
2. Add an `INSERT INTO roast.findings ...` block with:
   - A unique `check_name`
   - The correct `category` and `severity`
   - A `detail` field with the raw machine-readable fact
   - A `roast` message that is specific, accurate, and a little harsh
3. Call the function from both `roast.run()` and `roast._bgw_run_audit()`.

**Severity guidelines:**
- `CRITICAL` — data loss, security breach, or imminent failure risk
- `WARNING` — real problem that will hurt you, just not today
- `INFO` — questionable practice worth knowing about

The roast message should name the object, state the fact, and explain the consequence. Snarky is good. Vague is not.

## Submitting a PR

- Keep changes focused — try to limit the number of changes in a PR
- Test against at least one PostgreSQL version locally, especially if you added new checks
- Update `CHECKS.md` if you add or change a rule
