# pg_roast — Checks Reference

~100 rules across 13 categories. Severity escalates automatically — see [Escalation](#escalation).

## Column Types

| Rule | Severity |
|------|----------|
| `VARCHAR(255)` — are you thinking of MySQL? | WARNING |
| `VARCHAR(n)` with n < 50 — just use TEXT | INFO |
| `CHAR(n)` — almost never correct | WARNING |
| `JSON` instead of `JSONB` | WARNING |
| `MONEY` type — use `NUMERIC(10,2)` | WARNING |
| `SERIAL`/`BIGSERIAL` — prefer `GENERATED ALWAYS AS IDENTITY` | INFO |
| `FLOAT`/`REAL` — floating point is a disaster for anything exact | WARNING |
| `TIMESTAMP` without time zone — use `TIMESTAMPTZ` | WARNING |
| `OID` as a column type | WARNING |
| `XML` type — really? | INFO |

## Column Naming

| Rule | Severity |
|------|----------|
| Columns named `data`, `info`, `misc`, `stuff`, `meta`, `blob`, `payload` | WARNING |
| Columns with `temp_`, `tmp_`, `_temp`, `_tmp` in their name | WARNING |
| Columns ending in `_old`, `_new`, `_bak`, `_backup`, `_copy` | WARNING |
| Columns ending in `_fix`, `_hack`, `_workaround` | CRITICAL |
| Versioned columns: `_v2`, `_final`, `_final_final` | WARNING |
| `flag`, `flag2`, `is_flag` | INFO |
| `value` or `val` unqualified | INFO |
| `status`, `type`, `state` with no CHECK constraint | WARNING |
| `count` or `date` unqualified | INFO |
| Boolean columns not prefixed with `is_`, `has_`, `can_`, `should_` | INFO |

## Table Naming

| Rule | Severity |
|------|----------|
| Verb table names (`process`, `validate`, `compute`, ...) | WARNING |
| Generic names (`data`, `records`, `entries`, `items`, ...) | WARNING |
| `_tbl` or `_table` suffix — it is already a table | INFO |
| `temp_*` or `tmp_*` permanent tables | WARNING |
| `*_old`, `*_new`, `*_bak`, `*_v2` migration leftovers | WARNING |

## Nullable Columns

| Rule | Severity |
|------|----------|
| > 30% of columns nullable | WARNING |
| > 50% of columns nullable | CRITICAL |
| `NOT NULL` column with empty string default | WARNING |
| Nullable boolean (three-valued logic) | WARNING |

## Primary Keys

| Rule | Severity |
|------|----------|
| No primary key | WARNING / CRITICAL |
| Composite PK with > 3 columns | WARNING |
| PK that is `TEXT` or `VARCHAR` | WARNING |
| UUID PK with no default | WARNING |

## Schema Patterns

| Rule | Severity |
|------|----------|
| Soft delete (`deleted` boolean + `deleted_at`) | INFO |
| `created_at` without `updated_at` on a referenced table | INFO |
| `addr1`, `addr2` — missing address table | WARNING |
| `phone1`, `phone2` — missing phone table | WARNING |
| `tag1`, `tag2` — missing tags junction table | WARNING |
| EAV pattern (`entity_id` + `attribute_name` + `attribute_value`) | WARNING |
| > 2 JSONB columns on one table | WARNING |
| 3+ boolean state flags (`is_active`, `is_deleted`, `is_archived`, ...) | WARNING |
| Table with only 1 non-PK column | INFO |
| Table with 60+ columns | WARNING |
| Self-referencing FK with no depth strategy | INFO |
| `sort_order` / `position` as INTEGER | INFO |

## Indexes

| Rule | Severity |
|------|----------|
| Foreign key with no supporting index | WARNING |
| Unused index (`idx_scan = 0`) | WARNING |
| Duplicate indexes (same table, same columns) | WARNING |
| Index on a boolean column | WARNING |
| No non-PK index on a table over 10k rows | WARNING |
| More than 10 indexes on one table | WARNING |
| UNIQUE constraint duplicating the PK | WARNING |
| Index on `created_at` alone | INFO |

## Constraints

| Rule | Severity |
|------|----------|
| Email column with no CHECK constraint | WARNING |
| Price/quantity/amount column with no `> 0` CHECK | INFO |
| UNIQUE constraint on a nullable column | INFO |
| FK with no `ON DELETE` action | INFO |
| FK with `ON DELETE CASCADE` on a large table | WARNING |

## Relational

| Rule | Severity |
|------|----------|
| Orphan table (no FKs in or out) | INFO |
| Write-only table (many inserts, zero scans) | WARNING |

## Naming Consistency

| Rule | Severity |
|------|----------|
| Mixed `snake_case` and `camelCase` across tables | WARNING |
| FK columns not following `{table}_id` convention | INFO |
| Inconsistent timestamp naming (`date_*` vs `*_at`) | INFO |

## Query Behavior

Requires `pg_stat_statements`. If it is not installed, pg_roast will tell you that too.

| Rule | Severity |
|------|----------|
| `pg_stat_statements` not installed | WARNING |
| Frequent sequential scans on large tables | WARNING |
| `OFFSET` used for pagination | WARNING |
| `SELECT *` in high-frequency queries | INFO |
| Queries running longer than 5 minutes | WARNING / CRITICAL |

## Security

| Rule | Severity |
|------|----------|
| `public` schema has CREATE granted to PUBLIC | CRITICAL |
| Table with SELECT granted to PUBLIC | WARNING |
| Superuser role connected from an application | CRITICAL |
| `password`, `ssn`, `credit_card`, `api_key`, etc. stored as plain text | CRITICAL |
| `SECURITY DEFINER` function owned by a superuser | WARNING |
| Extension installed in the `public` schema | WARNING |

## Operational

| Rule | Severity |
|------|----------|
| Table not vacuumed in 30+ days | WARNING |
| Table bloat > 30% dead tuples | WARNING / CRITICAL |
| Autovacuum explicitly disabled on a table | CRITICAL |
| Table never analyzed | WARNING / CRITICAL |
| Sequence > 75% exhausted | WARNING / CRITICAL |
| `fsync = off` | CRITICAL |
| `full_page_writes = off` | CRITICAL |
| `log_min_duration_statement` disabled | WARNING |
| `work_mem` set very high globally | WARNING |
| `max_connections > 200` with no pooler evidence | WARNING |

## Escalation

Severity automatically escalates when:

- The same offense appears on **3 or more tables** in one run — WARNING → CRITICAL
- The offense is on a **high-traffic table** with > 1000 scans — INFO → WARNING
