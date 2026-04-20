-- pg_roast--1.0.sql
\echo Use "CREATE EXTENSION pg_roast" to load this file. \quit

-- ============================================================
-- CORE TABLES
-- ============================================================

CREATE TABLE roast.findings (
    id            bigserial    PRIMARY KEY,
    run_id        uuid         NOT NULL,
    check_name    text         NOT NULL,
    category      text         NOT NULL,
    severity      text         NOT NULL CHECK (severity IN ('INFO','WARNING','CRITICAL')),
    object_schema text,
    object_name   text,
    object_type   text,
    detail        text         NOT NULL,
    roast         text         NOT NULL,
    detected_at   timestamptz  NOT NULL DEFAULT now(),
    dismissed_at  timestamptz
);

-- Persistent ignore rules: suppress a check globally or for a specific object
CREATE TABLE roast.ignores (
    id            bigserial    PRIMARY KEY,
    check_name    text         NOT NULL,
    object_schema text,
    object_name   text,
    reason        text,
    created_at    timestamptz  NOT NULL DEFAULT now(),
    created_by    text         NOT NULL DEFAULT current_user
);

CREATE TABLE roast.audit_runs (
    run_id        uuid         PRIMARY KEY,
    started_at    timestamptz  NOT NULL DEFAULT now(),
    finished_at   timestamptz,
    triggered_by  text         NOT NULL,
    finding_count int
);

CREATE INDEX findings_run_id_idx   ON roast.findings (run_id);
CREATE INDEX findings_severity_idx ON roast.findings (severity);
CREATE INDEX findings_category_idx ON roast.findings (category);

-- ============================================================
-- HELPER: excluded schemas
-- ============================================================

CREATE OR REPLACE FUNCTION roast._excluded_schemas()
RETURNS text[] LANGUAGE sql IMMUTABLE AS $$
    SELECT ARRAY['pg_catalog','information_schema','roast','pg_toast']
$$;

-- ============================================================
-- CATEGORY 1: COLUMN TYPES
-- ============================================================

CREATE OR REPLACE FUNCTION roast._check_col_types(p_run_id uuid)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN

    -- VARCHAR(255): thinking of MySQL?
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'col_varchar_255','schema','WARNING',
           n.nspname, c.relname||'.'||a.attname, 'column',
           'type=varchar(255)',
           format('Column %I.%I.%I is VARCHAR(255). Why 255? Are you thinking of MySQL? '
                  'This is PostgreSQL. Just use TEXT.',
                  n.nspname,c.relname,a.attname)
    FROM pg_attribute a
    JOIN pg_class c ON c.oid=a.attrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
      AND a.atttypid='varchar'::regtype AND a.atttypmod=259
      AND n.nspname != ALL(roast._excluded_schemas());

    -- VARCHAR(n) where n < 50: arbitrary tiny limit
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'col_varchar_tiny','schema','INFO',
           n.nspname, c.relname||'.'||a.attname, 'column',
           format('type=varchar(%s)',a.atttypmod-4),
           format('Column %I.%I.%I is VARCHAR(%s). An arbitrary limit under 50. '
                  'Just use TEXT and stop pretending you know the max length.',
                  n.nspname,c.relname,a.attname,a.atttypmod-4)
    FROM pg_attribute a
    JOIN pg_class c ON c.oid=a.attrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
      AND a.atttypid='varchar'::regtype
      AND a.atttypmod>4 AND a.atttypmod-4<50 AND a.atttypmod!=259
      AND n.nspname != ALL(roast._excluded_schemas());

    -- CHAR(n): almost never correct
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'col_char','schema','WARNING',
           n.nspname, c.relname||'.'||a.attname, 'column',
           format('type=char(%s)',a.atttypmod-4),
           format('Column %I.%I.%I is CHAR(%s). Fixed-width padding. '
                  'You almost certainly want TEXT.',
                  n.nspname,c.relname,a.attname,a.atttypmod-4)
    FROM pg_attribute a
    JOIN pg_class c ON c.oid=a.attrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
      AND a.atttypid='bpchar'::regtype AND a.atttypmod>4
      AND n.nspname != ALL(roast._excluded_schemas());

    -- JSON instead of JSONB
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'col_json','schema','WARNING',
           n.nspname, c.relname||'.'||a.attname, 'column',
           'type=json',
           format('Column %I.%I.%I is JSON, not JSONB. '
                  'JSON is stored as text and re-parsed on every access. '
                  'There is no reason to use JSON in modern PostgreSQL.',
                  n.nspname,c.relname,a.attname)
    FROM pg_attribute a
    JOIN pg_class c ON c.oid=a.attrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
      AND a.atttypid='json'::regtype
      AND n.nspname != ALL(roast._excluded_schemas());

    -- MONEY type
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'col_money','schema','WARNING',
           n.nspname, c.relname||'.'||a.attname, 'column',
           'type=money',
           format('Column %I.%I.%I uses the MONEY type. '
                  'It is locale-dependent and does not round-trip through text safely. '
                  'Use NUMERIC(10,2) like an adult.',
                  n.nspname,c.relname,a.attname)
    FROM pg_attribute a
    JOIN pg_class c ON c.oid=a.attrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
      AND a.atttypid='money'::regtype
      AND n.nspname != ALL(roast._excluded_schemas());

    -- SERIAL/BIGSERIAL (nextval default, not IDENTITY)
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'col_serial','schema','INFO',
           n.nspname, c.relname||'.'||a.attname, 'column',
           format('type=%s,default=nextval',pg_catalog.format_type(a.atttypid,a.atttypmod)),
           format('Column %I.%I.%I uses SERIAL/BIGSERIAL. '
                  'That is a deprecated shorthand. '
                  'Use GENERATED ALWAYS AS IDENTITY instead.',
                  n.nspname,c.relname,a.attname)
    FROM pg_attribute a
    JOIN pg_class c ON c.oid=a.attrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
    WHERE c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
      AND a.attidentity=''
      AND pg_get_expr(d.adbin,d.adrelid) LIKE 'nextval(%'
      AND n.nspname != ALL(roast._excluded_schemas());

    -- FLOAT/REAL: floating point for financials
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'col_float','schema','WARNING',
           n.nspname, c.relname||'.'||a.attname, 'column',
           format('type=%s',pg_catalog.format_type(a.atttypid,a.atttypmod)),
           format('Column %I.%I.%I is a floating-point type. '
                  'If this stores money or anything that must be exact, '
                  'you will have rounding errors. Use NUMERIC.',
                  n.nspname,c.relname,a.attname)
    FROM pg_attribute a
    JOIN pg_class c ON c.oid=a.attrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
      AND a.atttypid IN ('float4'::regtype,'float8'::regtype)
      AND n.nspname != ALL(roast._excluded_schemas());

    -- TIMESTAMP without time zone
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'col_timestamp_no_tz','schema','WARNING',
           n.nspname, c.relname||'.'||a.attname, 'column',
           'type=timestamp (no timezone)',
           format('Column %I.%I.%I is TIMESTAMP without time zone. '
                  'The moment you deploy across a DST boundary or move servers, '
                  'your timestamps will lie to you. Use TIMESTAMPTZ.',
                  n.nspname,c.relname,a.attname)
    FROM pg_attribute a
    JOIN pg_class c ON c.oid=a.attrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
      AND a.atttypid='timestamp'::regtype
      AND n.nspname != ALL(roast._excluded_schemas());

    -- OID as column type
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'col_oid','schema','WARNING',
           n.nspname, c.relname||'.'||a.attname, 'column',
           'type=oid',
           format('Column %I.%I.%I uses OID as a data type. '
                  'OIDs wrap around. Use BIGINT or UUID.',
                  n.nspname,c.relname,a.attname)
    FROM pg_attribute a
    JOIN pg_class c ON c.oid=a.attrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
      AND a.atttypid='oid'::regtype
      AND n.nspname != ALL(roast._excluded_schemas());

    -- XML type
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'col_xml','schema','INFO',
           n.nspname, c.relname||'.'||a.attname, 'column',
           'type=xml',
           format('Column %I.%I.%I is XML. Really? '
                  'It is 2024. Consider JSONB, or at minimum ask yourself '
                  'why you are storing XML in a relational database.',
                  n.nspname,c.relname,a.attname)
    FROM pg_attribute a
    JOIN pg_class c ON c.oid=a.attrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
      AND a.atttypid='xml'::regtype
      AND n.nspname != ALL(roast._excluded_schemas());

END;
$$;

-- ============================================================
-- CATEGORY 2: COLUMN NAMING SMELLS
-- ============================================================

CREATE OR REPLACE FUNCTION roast._check_col_naming(p_run_id uuid)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN

    -- Generic meaningless names
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'col_name_vague','schema','WARNING',
           n.nspname, c.relname||'.'||a.attname, 'column',
           format('column_name=%I',a.attname),
           format('Column %I.%I.%I is named "%s". '
                  'What is in there? What does it mean? '
                  'Future you will have no idea. Name it something specific.',
                  n.nspname,c.relname,a.attname,a.attname)
    FROM pg_attribute a
    JOIN pg_class c ON c.oid=a.attrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
      AND a.attname = ANY(ARRAY['data','info','misc','stuff','meta','blob','payload'])
      AND n.nspname != ALL(roast._excluded_schemas());

    -- Temp/tmp columns
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'col_name_temp','schema','WARNING',
           n.nspname, c.relname||'.'||a.attname, 'column',
           format('column_name=%I',a.attname),
           format('Column %I.%I.%I sounds temporary. '
                  'Temporary columns have a way of becoming permanent. '
                  'Either commit to it or delete it.',
                  n.nspname,c.relname,a.attname)
    FROM pg_attribute a
    JOIN pg_class c ON c.oid=a.attrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
      AND (a.attname ~ '^(temp_|tmp_)' OR a.attname ~ '(_temp|_tmp)$')
      AND n.nspname != ALL(roast._excluded_schemas());

    -- Old/bak/copy columns
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'col_name_stale','schema','WARNING',
           n.nspname, c.relname||'.'||a.attname, 'column',
           format('column_name=%I',a.attname),
           format('Column %I.%I.%I looks like a leftover from a migration. '
                  'If the old column is still here, what happened to the migration?',
                  n.nspname,c.relname,a.attname)
    FROM pg_attribute a
    JOIN pg_class c ON c.oid=a.attrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
      AND a.attname ~ '(_old|_new|_bak|_backup|_copy)$'
      AND n.nspname != ALL(roast._excluded_schemas());

    -- Hack/fix/workaround columns
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'col_name_hack','schema','CRITICAL',
           n.nspname, c.relname||'.'||a.attname, 'column',
           format('column_name=%I',a.attname),
           format('Column %I.%I.%I has the word "%s" in its name. '
                  'This is now load-bearing technical debt with a name tag. '
                  'Whatever the hack was, it shipped.',
                  n.nspname,c.relname,a.attname,a.attname)
    FROM pg_attribute a
    JOIN pg_class c ON c.oid=a.attrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
      AND a.attname ~ '(_fix|_hack|_workaround|_kludge)$'
      AND n.nspname != ALL(roast._excluded_schemas());

    -- Versioned columns
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'col_name_versioned','schema','WARNING',
           n.nspname, c.relname||'.'||a.attname, 'column',
           format('column_name=%I',a.attname),
           format('Column %I.%I.%I looks versioned. '
                  'If there is a _v2, there is probably a _v1 rotting somewhere nearby. '
                  'Schema migrations exist for a reason.',
                  n.nspname,c.relname,a.attname)
    FROM pg_attribute a
    JOIN pg_class c ON c.oid=a.attrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
      AND (a.attname ~ '_v[0-9]+$' OR a.attname ~ '_(final|final_final|final2)$')
      AND n.nspname != ALL(roast._excluded_schemas());

    -- flag / flag2 / is_flag
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'col_name_flag','schema','INFO',
           n.nspname, c.relname||'.'||a.attname, 'column',
           format('column_name=%I',a.attname),
           format('Column %I.%I.%I is just called "%s". '
                  'Flag of what? Flag for whom? This tells you nothing.',
                  n.nspname,c.relname,a.attname,a.attname)
    FROM pg_attribute a
    JOIN pg_class c ON c.oid=a.attrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
      AND a.attname ~ '^(flag|is_flag|flag[0-9]+)$'
      AND n.nspname != ALL(roast._excluded_schemas());

    -- value / val unqualified
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'col_name_value','schema','INFO',
           n.nspname, c.relname||'.'||a.attname, 'column',
           format('column_name=%I',a.attname),
           format('Column %I.%I.%I is named "%s". Value of what? '
                  'This is the column equivalent of naming your dog "Dog".',
                  n.nspname,c.relname,a.attname,a.attname)
    FROM pg_attribute a
    JOIN pg_class c ON c.oid=a.attrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
      AND a.attname = ANY(ARRAY['value','val'])
      AND n.nspname != ALL(roast._excluded_schemas());

    -- status column with no CHECK constraint
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'col_status_no_check','schema','WARNING',
           n.nspname, c.relname||'.'||a.attname, 'column',
           'column=status, no_check_constraint=true',
           format('Column %I.%I.%I is named "status" but has no CHECK constraint. '
                  'Any string can go in there. What are the valid statuses? '
                  'Nobody knows. Probably not even you.',
                  n.nspname,c.relname,a.attname)
    FROM pg_attribute a
    JOIN pg_class c ON c.oid=a.attrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
      AND a.attname = ANY(ARRAY['status','type','state'])
      AND n.nspname != ALL(roast._excluded_schemas())
      AND NOT EXISTS (
          SELECT 1 FROM pg_constraint co
          WHERE co.conrelid=c.oid AND co.contype='c'
            AND co.conkey @> ARRAY[a.attnum]
      );

    -- count column
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'col_name_count','schema','INFO',
           n.nspname, c.relname||'.'||a.attname, 'column',
           'column_name=count',
           format('Column %I.%I.%I is named "count". Count of what? '
                  'Also, COUNT is a SQL keyword. Just say what you are counting.',
                  n.nspname,c.relname,a.attname)
    FROM pg_attribute a
    JOIN pg_class c ON c.oid=a.attrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
      AND a.attname = 'count'
      AND n.nspname != ALL(roast._excluded_schemas());

    -- date column (unqualified)
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'col_name_date','schema','INFO',
           n.nspname, c.relname||'.'||a.attname, 'column',
           'column_name=date',
           format('Column %I.%I.%I is just called "date". Date of what? '
                  'Created? Modified? Expires? Birth? Apocalypse? Be specific.',
                  n.nspname,c.relname,a.attname)
    FROM pg_attribute a
    JOIN pg_class c ON c.oid=a.attrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
      AND a.attname = 'date'
      AND n.nspname != ALL(roast._excluded_schemas());

    -- Boolean not prefixed with is_/has_/can_/should_
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'col_bool_prefix','schema','INFO',
           n.nspname, c.relname||'.'||a.attname, 'column',
           format('column=%I,type=bool',a.attname),
           format('Boolean column %I.%I.%I is not prefixed with is_, has_, can_, or should_. '
                  'Reading it in a WHERE clause will confuse everyone including you.',
                  n.nspname,c.relname,a.attname)
    FROM pg_attribute a
    JOIN pg_class c ON c.oid=a.attrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
      AND a.atttypid='bool'::regtype
      AND a.attname NOT LIKE 'is_%'
      AND a.attname NOT LIKE 'has_%'
      AND a.attname NOT LIKE 'can_%'
      AND a.attname NOT LIKE 'should_%'
      AND n.nspname != ALL(roast._excluded_schemas());

END;
$$;

-- ============================================================
-- CATEGORY 3: TABLE NAMING SMELLS
-- ============================================================

CREATE OR REPLACE FUNCTION roast._check_table_naming(p_run_id uuid)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN

    -- Verb table names
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'table_name_verb','schema','WARNING',
           n.nspname, c.relname, 'table',
           format('table_name=%I',c.relname),
           format('Table %I.%I has a verb for a name. '
                  'Tables store things, they do not do things. '
                  'Rename it to a noun.',
                  n.nspname,c.relname)
    FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r'
      AND c.relname = ANY(ARRAY['process','validate','compute','transform','update',
                                 'delete','insert','select','execute','handle',
                                 'process_data','sync','migrate'])
      AND n.nspname != ALL(roast._excluded_schemas());

    -- Generic table names
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'table_name_generic','schema','WARNING',
           n.nspname, c.relname, 'table',
           format('table_name=%I',c.relname),
           format('Table %I.%I has a generic name that tells you nothing. '
                  'What is actually in there?',
                  n.nspname,c.relname)
    FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r'
      AND c.relname = ANY(ARRAY['data','records','entries','items','things',
                                 'stuff','misc','info','metadata','objects'])
      AND n.nspname != ALL(roast._excluded_schemas());

    -- _tbl or _table suffix
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'table_name_redundant_suffix','schema','INFO',
           n.nspname, c.relname, 'table',
           format('table_name=%I',c.relname),
           format('Table %I.%I ends with "_tbl" or "_table". '
                  'It is already a table. The suffix is redundant.',
                  n.nspname,c.relname)
    FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r'
      AND (c.relname LIKE '%_tbl' OR c.relname LIKE '%_table')
      AND n.nspname != ALL(roast._excluded_schemas());

    -- temp/tmp table names
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'table_name_temp','schema','WARNING',
           n.nspname, c.relname, 'table',
           format('table_name=%I',c.relname),
           format('Table %I.%I sounds temporary but is a permanent table. '
                  'Temporary things have a way of becoming permanent fixtures. '
                  'Rename or delete it.',
                  n.nspname,c.relname)
    FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r'
      AND (c.relname LIKE 'temp_%' OR c.relname LIKE 'tmp_%'
           OR c.relname LIKE '%_temp' OR c.relname LIKE '%_tmp')
      AND n.nspname != ALL(roast._excluded_schemas());

    -- _old/_new/_bak/_v2 table names
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'table_name_stale','schema','WARNING',
           n.nspname, c.relname, 'table',
           format('table_name=%I',c.relname),
           format('Table %I.%I looks like a migration leftover. '
                  'If the migration is done, drop this. '
                  'If it is not done, finish the migration.',
                  n.nspname,c.relname)
    FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r'
      AND (c.relname ~ '(_old|_new|_bak|_backup|_copy)$'
           OR c.relname ~ '_v[0-9]+$')
      AND n.nspname != ALL(roast._excluded_schemas());

END;
$$;

-- ============================================================
-- CATEGORY 4: NULLABLE COLUMNS
-- ============================================================

CREATE OR REPLACE FUNCTION roast._check_nullable(p_run_id uuid)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN

    -- >50% nullable columns (CRITICAL)
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'nullable_majority_critical','schema','CRITICAL',
           n.nspname, c.relname, 'table',
           format('total_cols=%s, nullable_cols=%s, nullable_pct=%s%%',
                  col_counts.total, col_counts.nullable,
                  round(100.0*col_counts.nullable/col_counts.total)::text),
           format('Table %I.%I has %s%% nullable columns (%s of %s). '
                  'What does a valid row even look like? '
                  'This table has no idea what it is supposed to store.',
                  n.nspname,c.relname,
                  round(100.0*col_counts.nullable/col_counts.total)::text,
                  col_counts.nullable,col_counts.total)
    FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
    JOIN (
        SELECT a.attrelid,
               count(*) AS total,
               count(*) FILTER (WHERE NOT a.attnotnull) AS nullable
        FROM pg_attribute a
        WHERE a.attnum>0 AND NOT a.attisdropped
        GROUP BY a.attrelid
        HAVING count(*)>0
    ) col_counts ON col_counts.attrelid=c.oid
    WHERE c.relkind='r'
      AND col_counts.total>0
      AND col_counts.nullable::float/col_counts.total > 0.5
      AND n.nspname != ALL(roast._excluded_schemas());

    -- 30-50% nullable (WARNING) — separate so we don't double-fire
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'nullable_majority_warning','schema','WARNING',
           n.nspname, c.relname, 'table',
           format('total_cols=%s, nullable_cols=%s, nullable_pct=%s%%',
                  col_counts.total, col_counts.nullable,
                  round(100.0*col_counts.nullable/col_counts.total)::text),
           format('Table %I.%I has %s%% nullable columns (%s of %s). '
                  'More than 30%% nullable is a sign the schema is guessing at structure.',
                  n.nspname,c.relname,
                  round(100.0*col_counts.nullable/col_counts.total)::text,
                  col_counts.nullable,col_counts.total)
    FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
    JOIN (
        SELECT a.attrelid,
               count(*) AS total,
               count(*) FILTER (WHERE NOT a.attnotnull) AS nullable
        FROM pg_attribute a
        WHERE a.attnum>0 AND NOT a.attisdropped
        GROUP BY a.attrelid
        HAVING count(*)>0
    ) col_counts ON col_counts.attrelid=c.oid
    WHERE c.relkind='r'
      AND col_counts.total>0
      AND col_counts.nullable::float/col_counts.total BETWEEN 0.3 AND 0.5
      AND n.nspname != ALL(roast._excluded_schemas());

    -- NOT NULL column with empty string default
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'notnull_empty_default','schema','WARNING',
           n.nspname, c.relname||'.'||a.attname, 'column',
           format('column=%I,default=''''',a.attname),
           format('Column %I.%I.%I is NOT NULL but defaults to empty string. '
                  'You are using '''' as a substitute for NULL. '
                  'That breaks IS NULL checks, aggregates, and human sanity.',
                  n.nspname,c.relname,a.attname)
    FROM pg_attribute a
    JOIN pg_class c ON c.oid=a.attrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
    WHERE c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
      AND a.attnotnull
      AND pg_get_expr(d.adbin,d.adrelid) = ''''''
      AND n.nspname != ALL(roast._excluded_schemas());

    -- Nullable boolean
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'nullable_boolean','schema','WARNING',
           n.nspname, c.relname||'.'||a.attname, 'column',
           format('column=%I,type=bool,nullable=true',a.attname),
           format('Boolean column %I.%I.%I is nullable. '
                  'A nullable boolean has three states: true, false, and NULL. '
                  'Is NULL meaningful here, or is this an accident?',
                  n.nspname,c.relname,a.attname)
    FROM pg_attribute a
    JOIN pg_class c ON c.oid=a.attrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
      AND a.atttypid='bool'::regtype AND NOT a.attnotnull
      AND n.nspname != ALL(roast._excluded_schemas());

END;
$$;

-- ============================================================
-- CATEGORY 5: PRIMARY KEYS
-- ============================================================

CREATE OR REPLACE FUNCTION roast._check_primary_keys(p_run_id uuid)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN

    -- No primary key
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'no_primary_key','schema',
           CASE WHEN coalesce(s.n_live_tup,0)>1000000 THEN 'CRITICAL' ELSE 'WARNING' END,
           n.nspname, c.relname, 'table',
           format('estimated_rows=%s',coalesce(s.n_live_tup,0)),
           format('Table %I.%I has no primary key. '
                  'You have invented a bag of chaos. '
                  'Logical replication, UPDATE, DELETE — all worse without a PK.',
                  n.nspname,c.relname)
    FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
    LEFT JOIN pg_stat_user_tables s ON s.relid=c.oid
    WHERE c.relkind='r'
      AND NOT EXISTS (
          SELECT 1 FROM pg_constraint pk
          WHERE pk.conrelid=c.oid AND pk.contype='p'
      )
      AND n.nspname != ALL(roast._excluded_schemas());

    -- Composite PK with > 3 columns
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'pk_too_many_cols','schema','WARNING',
           n.nspname, c.relname, 'table',
           format('pk_column_count=%s',array_length(pk.conkey,1)),
           format('Table %I.%I has a composite primary key with %s columns. '
                  'That is probably a surrogate key waiting to happen.',
                  n.nspname,c.relname,array_length(pk.conkey,1))
    FROM pg_constraint pk
    JOIN pg_class c ON c.oid=pk.conrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE pk.contype='p' AND array_length(pk.conkey,1)>3
      AND n.nspname != ALL(roast._excluded_schemas());

    -- PK that is TEXT or VARCHAR
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'pk_text_type','schema','WARNING',
           n.nspname, c.relname||'.'||a.attname, 'column',
           format('pk_column=%I,type=%s',a.attname,pg_catalog.format_type(a.atttypid,a.atttypmod)),
           format('Primary key column %I.%I.%I is text-typed. '
                  'String comparisons, storage size, index fragmentation — '
                  'are you sure this is not better as a UUID or BIGINT?',
                  n.nspname,c.relname,a.attname)
    FROM pg_constraint pk
    JOIN pg_class c ON c.oid=pk.conrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=ANY(pk.conkey)
    WHERE pk.contype='p'
      AND a.atttypid IN ('text'::regtype,'varchar'::regtype)
      AND n.nspname != ALL(roast._excluded_schemas());

    -- UUID PK without a default
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'uuid_pk_no_default','schema','WARNING',
           n.nspname, c.relname||'.'||a.attname, 'column',
           format('pk_column=%I,type=uuid,has_default=false',a.attname),
           format('UUID primary key %I.%I.%I has no default. '
                  'Every INSERT must supply a UUID manually. '
                  'Add DEFAULT gen_random_uuid() before someone forgets.',
                  n.nspname,c.relname,a.attname)
    FROM pg_constraint pk
    JOIN pg_class c ON c.oid=pk.conrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=ANY(pk.conkey)
    WHERE pk.contype='p'
      AND a.atttypid='uuid'::regtype
      AND a.attidentity=''
      AND NOT EXISTS (
          SELECT 1 FROM pg_attrdef d
          WHERE d.adrelid=a.attrelid AND d.adnum=a.attnum
      )
      AND n.nspname != ALL(roast._excluded_schemas());

END;
$$;

-- ============================================================
-- CATEGORY 6: SCHEMA PATTERNS
-- ============================================================

CREATE OR REPLACE FUNCTION roast._check_patterns(p_run_id uuid)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN

    -- Soft delete pattern: deleted boolean + deleted_at
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'soft_delete_pattern','schema','INFO',
           n.nspname, c.relname, 'table',
           'pattern=soft_delete(deleted+deleted_at)',
           format('Table %I.%I implements soft delete with a boolean + timestamp. '
                  'Have you thought through partial indexes, FK integrity, '
                  'and query complexity with deleted=false on every query?',
                  n.nspname,c.relname)
    FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r'
      AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid
                  AND a.attnum>0 AND NOT a.attisdropped
                  AND a.attname='deleted' AND a.atttypid='bool'::regtype)
      AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid
                  AND a.attnum>0 AND NOT a.attisdropped
                  AND a.attname='deleted_at')
      AND n.nspname != ALL(roast._excluded_schemas());

    -- created_at without updated_at (or vice versa)
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'timestamps_asymmetric','schema','INFO',
           n.nspname, c.relname, 'table',
           'pattern=created_at_without_updated_at',
           format('Table %I.%I has created_at but no updated_at. '
                  'How will you know when a row changed?',
                  n.nspname,c.relname)
    FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r'
      AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid
                  AND a.attnum>0 AND NOT a.attisdropped AND a.attname='created_at')
      AND NOT EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid
                      AND a.attnum>0 AND NOT a.attisdropped AND a.attname='updated_at')
      AND EXISTS (SELECT 1 FROM pg_constraint fk
                  WHERE fk.confrelid=c.oid AND fk.contype='f')
      AND n.nspname != ALL(roast._excluded_schemas());

    -- addr1/addr2/addr3 pattern
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'denorm_address','schema','WARNING',
           n.nspname, c.relname, 'table',
           'pattern=addr1_addr2_addr3',
           format('Table %I.%I has addr1, addr2, addr3 columns. '
                  'You are storing a structured address in numbered columns. '
                  'This is what address tables are for.',
                  n.nspname,c.relname)
    FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r'
      AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid
                  AND a.attnum>0 AND NOT a.attisdropped AND a.attname='addr1')
      AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid
                  AND a.attnum>0 AND NOT a.attisdropped AND a.attname='addr2')
      AND n.nspname != ALL(roast._excluded_schemas());

    -- phone1/phone2 pattern
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'denorm_phone','schema','WARNING',
           n.nspname, c.relname, 'table',
           'pattern=phone1_phone2',
           format('Table %I.%I has phone1, phone2 columns. '
                  'You are storing multiple phones in numbered columns. '
                  'There is a better way and it is called a junction table.',
                  n.nspname,c.relname)
    FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r'
      AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid
                  AND a.attnum>0 AND NOT a.attisdropped AND a.attname ~ '^phone[0-9]$')
      AND n.nspname != ALL(roast._excluded_schemas());

    -- tag1/tag2/tag3 pattern
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'denorm_tags','schema','WARNING',
           n.nspname, c.relname, 'table',
           'pattern=tag1_tag2_tag3',
           format('Table %I.%I has tag columns like tag1, tag2. '
                  'Use a tags junction table. '
                  'This design caps you at a fixed number of tags per row forever.',
                  n.nspname,c.relname)
    FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r'
      AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid
                  AND a.attnum>0 AND NOT a.attisdropped AND a.attname ~ '^tag[0-9]$')
      AND n.nspname != ALL(roast._excluded_schemas());

    -- EAV pattern: entity_id + attribute_name + attribute_value
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'eav_pattern','schema','WARNING',
           n.nspname, c.relname, 'table',
           'pattern=EAV(entity_id,attribute_name,attribute_value)',
           format('Table %I.%I looks like an Entity-Attribute-Value table. '
                  'EAV is almost never the right answer. '
                  'It sacrifices type safety, constraints, and query performance '
                  'for schema flexibility you probably do not need.',
                  n.nspname,c.relname)
    FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r'
      AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid
                  AND a.attnum>0 AND NOT a.attisdropped AND a.attname='entity_id')
      AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid
                  AND a.attnum>0 AND NOT a.attisdropped
                  AND a.attname IN ('attribute_name','attr_name','key'))
      AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid
                  AND a.attnum>0 AND NOT a.attisdropped
                  AND a.attname IN ('attribute_value','attr_value','value'))
      AND n.nspname != ALL(roast._excluded_schemas());

    -- More than 2 JSONB columns
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'many_jsonb_cols','schema','WARNING',
           n.nspname, c.relname, 'table',
           format('jsonb_column_count=%s', jsonb_counts.cnt),
           format('Table %I.%I has %s JSONB columns. '
                  'Two might be acceptable. More than two means your schema '
                  'has given up on having a schema.',
                  n.nspname,c.relname,jsonb_counts.cnt)
    FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
    JOIN (
        SELECT a.attrelid, count(*) AS cnt
        FROM pg_attribute a
        WHERE a.attnum>0 AND NOT a.attisdropped
          AND a.atttypid='jsonb'::regtype
        GROUP BY a.attrelid
        HAVING count(*)>2
    ) jsonb_counts ON jsonb_counts.attrelid=c.oid
    WHERE c.relkind='r'
      AND n.nspname != ALL(roast._excluded_schemas());

    -- Multiple boolean state flags (is_active + is_deleted + is_archived + is_suspended)
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'state_flag_explosion','schema','WARNING',
           n.nspname, c.relname, 'table',
           format('state_flag_count=%s',flag_counts.cnt),
           format('Table %I.%I has %s boolean state flags. '
                  'You are building a state machine with boolean columns. '
                  'What happens when is_active=true AND is_deleted=true? '
                  'Use a status column with a CHECK constraint.',
                  n.nspname,c.relname,flag_counts.cnt)
    FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
    JOIN (
        SELECT a.attrelid, count(*) AS cnt
        FROM pg_attribute a
        WHERE a.attnum>0 AND NOT a.attisdropped
          AND a.atttypid='bool'::regtype
          AND a.attname = ANY(ARRAY['is_active','is_deleted','is_archived',
                                    'is_suspended','is_enabled','is_blocked',
                                    'is_disabled','is_hidden','is_locked'])
        GROUP BY a.attrelid
        HAVING count(*)>=3
    ) flag_counts ON flag_counts.attrelid=c.oid
    WHERE c.relkind='r'
      AND n.nspname != ALL(roast._excluded_schemas());

    -- Table with only 1 non-PK column
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'single_column_table','schema','INFO',
           n.nspname, c.relname, 'table',
           'non_pk_column_count=1',
           format('Table %I.%I has only one non-PK column. '
                  'Should this be an enum or a lookup table?',
                  n.nspname,c.relname)
    FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r'
      AND n.nspname != ALL(roast._excluded_schemas())
      AND (
          SELECT count(*) FROM pg_attribute a
          WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
            AND NOT EXISTS (
                SELECT 1 FROM pg_constraint pk
                WHERE pk.conrelid=c.oid AND pk.contype='p'
                  AND a.attnum = ANY(pk.conkey)
            )
      ) = 1;

    -- Table with 60+ columns
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'wide_table','schema','WARNING',
           n.nspname, c.relname, 'table',
           format('column_count=%s',col_counts.cnt),
           format('Table %I.%I has %s columns. '
                  'This table is doing too much. '
                  'Consider breaking it into related tables.',
                  n.nspname,c.relname,col_counts.cnt)
    FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
    JOIN (
        SELECT a.attrelid, count(*) AS cnt
        FROM pg_attribute a
        WHERE a.attnum>0 AND NOT a.attisdropped
        GROUP BY a.attrelid
        HAVING count(*)>=60
    ) col_counts ON col_counts.attrelid=c.oid
    WHERE c.relkind='r'
      AND n.nspname != ALL(roast._excluded_schemas());

    -- parent_id self-referencing FK
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'self_ref_fk','schema','INFO',
           n.nspname, c.relname, 'table',
           format('self_ref_column=%I',a.attname),
           format('Table %I.%I has a self-referencing foreign key via %I. '
                  'Tree structures in SQL are fine, but do you have a plan '
                  'for recursive queries and depth limits?',
                  n.nspname,c.relname,a.attname)
    FROM pg_constraint fk
    JOIN pg_class c ON c.oid=fk.conrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=ANY(fk.conkey)
    WHERE fk.contype='f' AND fk.confrelid=fk.conrelid
      AND n.nspname != ALL(roast._excluded_schemas());

    -- sort_order / position as INTEGER
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'sort_order_integer','schema','INFO',
           n.nspname, c.relname||'.'||a.attname, 'column',
           format('column=%I,type=integer',a.attname),
           format('Column %I.%I.%I is an integer sort order. '
                  'Integer gaps will haunt you when you try to insert between rows. '
                  'Consider float8 or a resequencing strategy.',
                  n.nspname,c.relname,a.attname)
    FROM pg_attribute a
    JOIN pg_class c ON c.oid=a.attrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
      AND a.attname IN ('sort_order','position','rank','display_order','list_order')
      AND a.atttypid IN ('int4'::regtype,'int8'::regtype,'int2'::regtype)
      AND n.nspname != ALL(roast._excluded_schemas());

END;
$$;

-- ============================================================
-- CATEGORY 7: INDEXES
-- ============================================================

CREATE OR REPLACE FUNCTION roast._check_indexes(p_run_id uuid)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN

    -- FK without supporting index
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'fk_no_index','index','WARNING',
           n.nspname, c.relname, 'table',
           format('fk_constraint=%I,fk_columns=%s',
                  fk.conname,
                  (SELECT string_agg(a.attname,', ' ORDER BY a.attnum)
                   FROM pg_attribute a
                   WHERE a.attrelid=c.oid AND a.attnum=ANY(fk.conkey))),
           format('Foreign key %I on %I.%I has no supporting index. '
                  'Every FK lookup is a sequential scan. '
                  'Your DBA ancestors are weeping.',
                  fk.conname,n.nspname,c.relname)
    FROM pg_constraint fk
    JOIN pg_class c ON c.oid=fk.conrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE fk.contype='f'
      AND n.nspname != ALL(roast._excluded_schemas())
      AND NOT EXISTS (
          SELECT 1 FROM pg_index idx
          WHERE idx.indrelid=fk.conrelid
            AND (idx.indkey::smallint[])[0:array_length(fk.conkey,1)-1]
                @> fk.conkey::smallint[]
      );

    -- Unused indexes
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'unused_index','index','WARNING',
           s.schemaname, s.indexrelname, 'index',
           format('idx_scan=0,table=%I,size=%s',s.relname,pg_size_pretty(pg_relation_size(s.indexrelid))),
           format('Index %I on %I.%I has never been used (idx_scan=0) '
                  'but weighs %s. It is purely decorative at this point.',
                  s.indexrelname,s.schemaname,s.relname,
                  pg_size_pretty(pg_relation_size(s.indexrelid)))
    FROM pg_stat_user_indexes s
    JOIN pg_index i ON i.indexrelid=s.indexrelid
    JOIN pg_stat_user_tables t ON t.relid=s.relid
    WHERE s.idx_scan=0
      AND NOT i.indisprimary AND NOT i.indisunique
      AND coalesce(t.n_live_tup,0)>1000
      AND s.schemaname != ALL(roast._excluded_schemas());

    -- Duplicate indexes
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    WITH idx_sig AS (
        SELECT idx.indrelid,
               idx.indexrelid,
               n.nspname,
               tc.relname AS tbl,
               ic.relname AS idx_name,
               am.amname,
               (SELECT string_agg(pg_get_indexdef(idx.indexrelid,k+1,true),','
                                  ORDER BY k)
                FROM generate_subscripts(idx.indkey,1) AS k) AS cols
        FROM pg_index idx
        JOIN pg_class tc ON tc.oid=idx.indrelid
        JOIN pg_class ic ON ic.oid=idx.indexrelid
        JOIN pg_namespace n ON n.oid=tc.relnamespace
        JOIN pg_am am ON am.oid=ic.relam
        WHERE n.nspname != ALL(roast._excluded_schemas())
    )
    SELECT p_run_id,'duplicate_index','index','WARNING',
           a.nspname, a.idx_name, 'index',
           format('table=%I,duplicate_of=%I,columns=%s',a.tbl,b.idx_name,a.cols),
           format('Index %I on %I is an exact duplicate of %I. '
                  'You are paying write overhead twice for nothing. '
                  'Pick one and drop the other.',
                  a.idx_name,a.tbl,b.idx_name)
    FROM idx_sig a
    JOIN idx_sig b ON a.indrelid=b.indrelid
                  AND a.cols=b.cols
                  AND a.amname=b.amname
                  AND a.indexrelid<b.indexrelid;

    -- Index on boolean column
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'index_on_boolean','index','WARNING',
           n.nspname, ic.relname, 'index',
           format('table=%I,column=%I',tc.relname,a.attname),
           format('Index %I on %I.%I(%I) is on a boolean column. '
                  'With only two distinct values, this index will almost never be chosen. '
                  'You are paying write overhead for decoration.',
                  ic.relname,n.nspname,tc.relname,a.attname)
    FROM pg_index idx
    JOIN pg_class tc ON tc.oid=idx.indrelid
    JOIN pg_class ic ON ic.oid=idx.indexrelid
    JOIN pg_namespace n ON n.oid=tc.relnamespace
    JOIN pg_attribute a ON a.attrelid=tc.oid AND a.attnum=idx.indkey[0]
    WHERE NOT idx.indisprimary AND NOT idx.indisunique
      AND a.atttypid='bool'::regtype
      AND idx.indnatts=1
      AND n.nspname != ALL(roast._excluded_schemas());

    -- No index on table over 10k rows
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'no_index_large_table','index','WARNING',
           n.nspname, c.relname, 'table',
           format('estimated_rows=%s',c.reltuples::bigint),
           format('Table %I.%I has ~%s rows and no non-PK indexes. '
                  'Every non-PK lookup is a sequential scan.',
                  n.nspname,c.relname,c.reltuples::bigint)
    FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r' AND c.reltuples>10000
      AND n.nspname != ALL(roast._excluded_schemas())
      AND NOT EXISTS (
          SELECT 1 FROM pg_index idx
          WHERE idx.indrelid=c.oid AND NOT idx.indisprimary
      );

    -- More than 10 indexes on a table
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'too_many_indexes','index','WARNING',
           n.nspname, c.relname, 'table',
           format('index_count=%s',idx_counts.cnt),
           format('Table %I.%I has %s indexes. '
                  'Every INSERT and UPDATE must maintain all of them. '
                  'Your write performance is suffering for this.',
                  n.nspname,c.relname,idx_counts.cnt)
    FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
    JOIN (
        SELECT indrelid, count(*) AS cnt
        FROM pg_index GROUP BY indrelid HAVING count(*)>10
    ) idx_counts ON idx_counts.indrelid=c.oid
    WHERE c.relkind='r'
      AND n.nspname != ALL(roast._excluded_schemas());

    -- Unique constraint duplicating PK
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'unique_duplicates_pk','index','WARNING',
           n.nspname, c.relname, 'table',
           format('constraint=%I',uc.conname),
           format('Table %I.%I has a UNIQUE constraint %I on the same columns as the primary key. '
                  'That is redundant. Drop the UNIQUE constraint.',
                  n.nspname,c.relname,uc.conname)
    FROM pg_constraint uc
    JOIN pg_class c ON c.oid=uc.conrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    JOIN pg_constraint pk ON pk.conrelid=c.oid AND pk.contype='p'
    WHERE uc.contype='u'
      AND uc.conkey::smallint[] = pk.conkey::smallint[]
      AND n.nspname != ALL(roast._excluded_schemas());

    -- Index on created_at alone
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'index_created_at_alone','index','INFO',
           n.nspname, ic.relname, 'index',
           format('table=%I,column=created_at',tc.relname),
           format('Index %I on %I.%I(created_at) indexes only created_at. '
                  'If queries always filter on other columns too, '
                  'this should be a composite index.',
                  ic.relname,n.nspname,tc.relname)
    FROM pg_index idx
    JOIN pg_class tc ON tc.oid=idx.indrelid
    JOIN pg_class ic ON ic.oid=idx.indexrelid
    JOIN pg_namespace n ON n.oid=tc.relnamespace
    JOIN pg_attribute a ON a.attrelid=tc.oid AND a.attnum=idx.indkey[0]
    WHERE NOT idx.indisprimary
      AND idx.indnatts=1
      AND a.attname='created_at'
      AND n.nspname != ALL(roast._excluded_schemas());

END;
$$;

-- ============================================================
-- CATEGORY 8: CONSTRAINTS
-- ============================================================

CREATE OR REPLACE FUNCTION roast._check_constraints(p_run_id uuid)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN

    -- Email column without CHECK constraint
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'email_no_check','constraints','WARNING',
           n.nspname, c.relname||'.'||a.attname, 'column',
           format('column=%I,type=%s',a.attname,pg_catalog.format_type(a.atttypid,a.atttypmod)),
           format('Column %I.%I.%I looks like it stores email addresses '
                  'but has no CHECK constraint. Any garbage can go in there.',
                  n.nspname,c.relname,a.attname)
    FROM pg_attribute a
    JOIN pg_class c ON c.oid=a.attrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
      AND a.attname IN ('email','email_address','user_email','contact_email')
      AND a.atttypid IN ('text'::regtype,'varchar'::regtype)
      AND n.nspname != ALL(roast._excluded_schemas())
      AND NOT EXISTS (
          SELECT 1 FROM pg_constraint co
          WHERE co.conrelid=c.oid AND co.contype='c'
            AND co.conkey @> ARRAY[a.attnum]
      );

    -- Positive-only numerics without CHECK
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'positive_no_check','constraints','INFO',
           n.nspname, c.relname||'.'||a.attname, 'column',
           format('column=%I,type=%s',a.attname,pg_catalog.format_type(a.atttypid,a.atttypmod)),
           format('Column %I.%I.%I looks like it should always be positive '
                  'but has no CHECK (value > 0) constraint. '
                  'A negative price or quantity is waiting to happen.',
                  n.nspname,c.relname,a.attname)
    FROM pg_attribute a
    JOIN pg_class c ON c.oid=a.attrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
      AND a.attname IN ('price','amount','quantity','qty','cost','balance',
                        'total','subtotal','weight','age','duration','count')
      AND a.atttypid IN ('int4'::regtype,'int8'::regtype,'numeric'::regtype,
                         'float8'::regtype,'float4'::regtype)
      AND n.nspname != ALL(roast._excluded_schemas())
      AND NOT EXISTS (
          SELECT 1 FROM pg_constraint co
          WHERE co.conrelid=c.oid AND co.contype='c'
            AND co.conkey @> ARRAY[a.attnum]
      );

    -- UNIQUE on nullable column
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'unique_on_nullable','constraints','INFO',
           n.nspname, c.relname||'.'||a.attname, 'column',
           format('constraint=%I,column=%I,nullable=true',uc.conname,a.attname),
           format('UNIQUE constraint %I on %I.%I.%I is on a nullable column. '
                  'NULLs are not equal in SQL, so multiple NULLs are allowed. '
                  'Is that intentional?',
                  uc.conname,n.nspname,c.relname,a.attname)
    FROM pg_constraint uc
    JOIN pg_class c ON c.oid=uc.conrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=ANY(uc.conkey)
    WHERE uc.contype='u' AND NOT a.attnotnull
      AND array_length(uc.conkey,1)=1
      AND n.nspname != ALL(roast._excluded_schemas());

    -- FK without ON DELETE specified
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'fk_no_on_delete','constraints','INFO',
           n.nspname, c.relname, 'table',
           format('fk_constraint=%I,references=%I',fk.conname,rc.relname),
           format('Foreign key %I on %I.%I has no ON DELETE action. '
                  'When the parent row is deleted, PostgreSQL will ERROR. '
                  'Is that what you want? Say so explicitly.',
                  fk.conname,n.nspname,c.relname)
    FROM pg_constraint fk
    JOIN pg_class c ON c.oid=fk.conrelid
    JOIN pg_class rc ON rc.oid=fk.confrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE fk.contype='f' AND fk.confdeltype='a'  -- 'a' = no action (default)
      AND n.nspname != ALL(roast._excluded_schemas());

    -- FK with ON DELETE CASCADE on large table
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'cascade_delete_large','constraints','WARNING',
           n.nspname, c.relname, 'table',
           format('fk_constraint=%I,references=%I,estimated_rows=%s',
                  fk.conname,rc.relname,coalesce(s.n_live_tup,0)),
           format('Foreign key %I on %I.%I uses ON DELETE CASCADE '
                  'and the table has ~%s rows. '
                  'A single parent delete could cascade to thousands of rows '
                  'and hold locks for a long time.',
                  fk.conname,n.nspname,c.relname,coalesce(s.n_live_tup,0))
    FROM pg_constraint fk
    JOIN pg_class c ON c.oid=fk.conrelid
    JOIN pg_class rc ON rc.oid=fk.confrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    LEFT JOIN pg_stat_user_tables s ON s.relid=c.oid
    WHERE fk.contype='f' AND fk.confdeltype='c'  -- 'c' = cascade
      AND coalesce(s.n_live_tup,0)>100000
      AND n.nspname != ALL(roast._excluded_schemas());

END;
$$;

-- ============================================================
-- CATEGORY 9: RELATIONAL
-- ============================================================

CREATE OR REPLACE FUNCTION roast._check_relational(p_run_id uuid)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN

    -- Orphan table (no FKs to or from anything)
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'orphan_table','relational','INFO',
           n.nspname, c.relname, 'table',
           'no_foreign_keys_in_or_out',
           format('Table %I.%I has no foreign keys in either direction. '
                  'It is an island. Does it belong to this schema, '
                  'or is it a forgotten table from a feature nobody finished?',
                  n.nspname,c.relname)
    FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r'
      AND n.nspname != ALL(roast._excluded_schemas())
      AND NOT EXISTS (
          SELECT 1 FROM pg_constraint fk
          WHERE (fk.conrelid=c.oid OR fk.confrelid=c.oid)
            AND fk.contype='f'
      );

    -- Write-only table (high n_tup_ins, zero seq_scan + idx_scan)
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'write_only_table','relational','WARNING',
           s.schemaname, s.relname, 'table',
           format('n_tup_ins=%s,seq_scan=%s,idx_scan=%s',
                  s.n_tup_ins,s.seq_scan,coalesce(si.idx_scan,0)),
           format('Table %I.%I has %s inserts but zero scans. '
                  'Nobody is reading it. Is this a dead table? '
                  'Or is something querying it through a view nobody knows about?',
                  s.schemaname,s.relname,s.n_tup_ins)
    FROM pg_stat_user_tables s
    LEFT JOIN (
        SELECT relid, sum(idx_scan) AS idx_scan
        FROM pg_stat_user_indexes GROUP BY relid
    ) si ON si.relid=s.relid
    WHERE s.n_tup_ins>10000
      AND s.seq_scan=0
      AND coalesce(si.idx_scan,0)=0
      AND s.schemaname != ALL(roast._excluded_schemas());

END;
$$;

-- ============================================================
-- CATEGORY 10: NAMING CONSISTENCY
-- ============================================================

CREATE OR REPLACE FUNCTION roast._check_naming_consistency(p_run_id uuid)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_snake int;
    v_camel int;
BEGIN

    -- Mixed snake_case and camelCase table names across user schemas
    SELECT count(*) FILTER (WHERE relname ~ '^[a-z][a-z0-9_]*$' AND relname ~ '_'),
           count(*) FILTER (WHERE relname ~ '[A-Z]')
    INTO v_snake, v_camel
    FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r'
      AND n.nspname != ALL(roast._excluded_schemas());

    IF v_snake>0 AND v_camel>0 THEN
        INSERT INTO roast.findings
            (run_id,check_name,category,severity,object_name,object_type,detail,roast)
        VALUES (p_run_id,'mixed_naming_convention','naming','WARNING',
                'schema tables','schema',
                format('snake_case_tables=%s,camelCase_tables=%s',v_snake,v_camel),
                format('Your schema has %s snake_case tables and %s camelCase tables. '
                       'Pick one convention and stick with it. '
                       'Mixed conventions mean every query requires a memory lookup.',
                       v_snake,v_camel));
    END IF;

    -- FK columns not following {table}_id convention
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'fk_col_naming','naming','INFO',
           n.nspname, c.relname||'.'||a.attname, 'column',
           format('fk_column=%I,references=%I',a.attname,rc.relname),
           format('Foreign key column %I.%I.%I does not follow the {table}_id convention '
                  '(expected something like %s_id). '
                  'Inconsistent FK naming makes joins harder to read.',
                  n.nspname,c.relname,a.attname,rc.relname)
    FROM pg_constraint fk
    JOIN pg_class c ON c.oid=fk.conrelid
    JOIN pg_class rc ON rc.oid=fk.confrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=fk.conkey[1]
    WHERE fk.contype='f'
      AND array_length(fk.conkey,1)=1
      AND a.attname != (rc.relname||'_id')
      AND a.attname != 'id'
      AND n.nspname != ALL(roast._excluded_schemas());

    -- Timestamp naming inconsistency (created_at vs created_on vs date_created)
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'timestamp_naming_inconsistent','naming','INFO',
           n.nspname, c.relname||'.'||a.attname, 'column',
           format('column=%I,type=timestamptz',a.attname),
           format('Column %I.%I.%I uses a non-standard timestamp name. '
                  'The convention in this schema appears to be *_at. '
                  'Inconsistency makes tooling and muscle-memory unreliable.',
                  n.nspname,c.relname,a.attname)
    FROM pg_attribute a
    JOIN pg_class c ON c.oid=a.attrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
      AND a.atttypid IN ('timestamptz'::regtype,'timestamp'::regtype)
      AND a.attname ~ '^(date_|on_|time_|dt_)'
      AND n.nspname != ALL(roast._excluded_schemas())
      AND EXISTS (
          SELECT 1 FROM pg_attribute b
          JOIN pg_class bc ON bc.oid=b.attrelid
          JOIN pg_namespace bn ON bn.oid=bc.relnamespace
          WHERE b.attnum>0 AND NOT b.attisdropped
            AND b.atttypid IN ('timestamptz'::regtype,'timestamp'::regtype)
            AND b.attname LIKE '%_at'
            AND bn.nspname != ALL(roast._excluded_schemas())
      );

END;
$$;

-- ============================================================
-- CATEGORY 11: QUERY BEHAVIOR (pg_stat_statements)
-- ============================================================

CREATE OR REPLACE FUNCTION roast._check_query_behavior(p_run_id uuid)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN

    -- Skip entirely if pg_stat_statements is not available
    IF NOT EXISTS (
        SELECT 1 FROM pg_extension WHERE extname='pg_stat_statements'
    ) THEN
        INSERT INTO roast.findings
            (run_id,check_name,category,severity,object_name,object_type,detail,roast)
        VALUES (p_run_id,'pg_stat_statements_missing','query','WARNING',
                'pg_stat_statements','extension',
                'pg_stat_statements=not_installed',
                'pg_stat_statements is not installed. '
                'You are flying completely blind on query performance. '
                'Add pg_stat_statements to shared_preload_libraries now.');
        RETURN;
    END IF;

    -- Sequential scans on large tables in frequent queries
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'frequent_seqscan','query','WARNING',
           s.schemaname, s.relname, 'table',
           format('seq_scan=%s,n_live_tup=%s',s.seq_scan,s.n_live_tup),
           format('Table %I.%I has had %s sequential scans and ~%s rows. '
                  'Either add an index or accept that someone is always reading the whole table.',
                  s.schemaname,s.relname,s.seq_scan,s.n_live_tup)
    FROM pg_stat_user_tables s
    WHERE s.seq_scan>100
      AND s.n_live_tup>10000
      AND s.schemaname != ALL(roast._excluded_schemas());

    -- Queries using OFFSET on large result sets
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_name,object_type,detail,roast)
    SELECT p_run_id,'offset_pagination','query','WARNING',
           left(pss.query,100), 'query',
           format('calls=%s,mean_exec_time_ms=%s',pss.calls,round(pss.mean_exec_time::numeric,1)::text),
           format('A high-frequency query uses OFFSET for pagination. '
                  'OFFSET scans from the beginning every time. '
                  'Use keyset pagination (WHERE id > $last_id) instead. '
                  'Query: %s',left(pss.query,120))
    FROM pg_stat_statements pss
    WHERE pss.query ILIKE '%OFFSET%'
      AND pss.calls>50
      AND pss.query NOT ILIKE '%pg_roast%'
    ORDER BY pss.calls DESC
    LIMIT 5;

    -- Queries using SELECT * frequently
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_name,object_type,detail,roast)
    SELECT p_run_id,'select_star','query','INFO',
           left(pss.query,100), 'query',
           format('calls=%s',pss.calls),
           format('A high-frequency query uses SELECT *. '
                  'You are fetching columns you almost certainly do not need. '
                  'Query: %s',left(pss.query,120))
    FROM pg_stat_statements pss
    WHERE pss.query ILIKE '%SELECT *%'
      AND pss.calls>100
      AND pss.query NOT ILIKE '%pg_roast%'
    ORDER BY pss.calls DESC
    LIMIT 5;

    -- Long-running queries
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_name,object_type,detail,roast)
    SELECT p_run_id,'long_running_query','query',
           CASE WHEN extract(epoch FROM (now()-query_start))>3600
                THEN 'CRITICAL' ELSE 'WARNING' END,
           usename, 'query',
           format('pid=%s,duration=%s,state=%s,wait_event=%s',
                  pid,age(now(),query_start),state,wait_event),
           format('Query by %I has been running for %s (pid %s). '
                  'Either it is doing something incredible or it is stuck. '
                  'First 80 chars: "%s"',
                  usename,age(now(),query_start),pid,
                  left(regexp_replace(query,'\s+',' ','g'),80))
    FROM pg_stat_activity
    WHERE state='active'
      AND query_start < now()-interval '5 minutes'
      AND backend_type='client backend'
      AND pid<>pg_backend_pid();

END;
$$;

-- ============================================================
-- CATEGORY 12: SECURITY
-- ============================================================

CREATE OR REPLACE FUNCTION roast._check_security(p_run_id uuid)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN

    -- PUBLIC schema permissions not revoked (default PG config is insecure)
    IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname='public' AND ARRAY(SELECT r::text FROM unnest(nspacl) r WHERE r::text LIKE '=C/%') <> '{}') THEN
        INSERT INTO roast.findings
            (run_id,check_name,category,severity,object_name,object_type,detail,roast)
        VALUES (p_run_id,'public_schema_create','security','CRITICAL',
                'public','schema',
                'public_schema_create_privilege=granted_to_PUBLIC',
                'The public schema grants CREATE to PUBLIC. '
                'Any connected user can create tables in it. '
                'Run: REVOKE CREATE ON SCHEMA public FROM PUBLIC;');
    END IF;

    -- Tables granted to PUBLIC
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'table_public_grant','security','WARNING',
           n.nspname, c.relname, 'table',
           'select_granted_to_PUBLIC',
           format('Table %I.%I has SELECT granted to PUBLIC. '
                  'Every user who can connect — including the one your contractor '
                  'forgot to revoke — can read this table.',
                  n.nspname,c.relname)
    FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r'
      AND n.nspname != ALL(roast._excluded_schemas())
      AND c.relacl IS NOT NULL AND EXISTS (SELECT 1 FROM unnest(c.relacl) a WHERE a::text ~ '^\=[^/]*r');

    -- Superuser app connections
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_name,object_type,detail,roast)
    SELECT p_run_id,'superuser_app_connection','security','CRITICAL',
           a.usename, 'role',
           format('pid=%s,app=%s,client=%s',a.pid,a.application_name,a.client_addr),
           format('Superuser %I is connected from %s running "%s". '
                  'If your application runs as a superuser, '
                  'a SQL injection is a full database takeover. '
                  'Use least-privilege roles.',
                  a.usename,a.client_addr,a.application_name)
    FROM pg_stat_activity a
    JOIN pg_roles r ON r.rolname=a.usename
    WHERE r.rolsuper
      AND a.state IS NOT NULL
      AND a.application_name NOT IN ('pg_roast','psql','','pg_dump','pg_restore')
      AND a.backend_type='client backend';

    -- Password / PII columns stored as plain text
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'sensitive_plaintext_col','security','CRITICAL',
           n.nspname, c.relname||'.'||a.attname, 'column',
           format('column=%I,type=%s',a.attname,pg_catalog.format_type(a.atttypid,a.atttypmod)),
           format('Column %I.%I.%I sounds like it stores sensitive data as plain text. '
                  'If this is not hashed or encrypted, you are one breach away from a headline.',
                  n.nspname,c.relname,a.attname)
    FROM pg_attribute a
    JOIN pg_class c ON c.oid=a.attrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
      AND a.attname IN ('password','passwd','pwd','secret','ssn','social_security',
                        'credit_card','card_number','cvv','cvv2','pin',
                        'api_key','api_secret','access_token','private_key')
      AND a.atttypid IN ('text'::regtype,'varchar'::regtype)
      AND n.nspname != ALL(roast._excluded_schemas());

    -- SECURITY DEFINER functions owned by a superuser
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'security_definer_superuser','security','WARNING',
           n.nspname, p.proname, 'function',
           format('owner=%I,security=SECURITY DEFINER',r.rolname),
           format('Function %I.%I is SECURITY DEFINER and owned by superuser %I. '
                  'Callers temporarily acquire superuser privileges. '
                  'Own it with a less-privileged role.',
                  n.nspname,p.proname,r.rolname)
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid=p.pronamespace
    JOIN pg_roles r ON r.oid=p.proowner
    WHERE p.prosecdef AND r.rolsuper
      AND n.nspname != ALL(roast._excluded_schemas());

    -- Extensions installed in public schema
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_name,object_type,detail,roast)
    SELECT p_run_id,'extension_in_public','security','WARNING',
           e.extname, 'extension',
           format('extension=%I,schema=public',e.extname),
           format('Extension %I is installed in the public schema. '
                  'Install extensions in a dedicated schema '
                  '(e.g. CREATE SCHEMA extensions) to keep public clean.',
                  e.extname)
    FROM pg_extension e
    JOIN pg_namespace n ON n.oid=e.extnamespace
    WHERE n.nspname='public'
      AND e.extname!='pg_roast';

END;
$$;

-- ============================================================
-- CATEGORY 13: OPERATIONAL / HEALTH
-- ============================================================

CREATE OR REPLACE FUNCTION roast._check_operational(p_run_id uuid)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_work_mem       text;
    v_work_mem_kb    bigint;
    v_max_conn       int;
    v_fsync          text;
    v_fpw            text;
    v_log_min_dur    text;
BEGIN

    -- Tables with no VACUUM in over 30 days
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'no_vacuum_30d','operational','WARNING',
           s.schemaname, s.relname, 'table',
           format('last_vacuum=%s,last_autovacuum=%s,dead_tuples=%s',
                  s.last_vacuum,s.last_autovacuum,s.n_dead_tup),
           format('Table %I.%I has not been vacuumed in over 30 days. '
                  'Dead tuple bloat is accumulating. '
                  'Check your autovacuum settings.',
                  s.schemaname,s.relname)
    FROM pg_stat_user_tables s
    WHERE greatest(s.last_vacuum,s.last_autovacuum) < now()-interval '30 days'
      OR (s.last_vacuum IS NULL AND s.last_autovacuum IS NULL AND s.n_live_tup>0)
      AND s.schemaname != ALL(roast._excluded_schemas());

    -- Table bloat > 50% dead tuples
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'dead_tuple_bloat','operational',
           CASE WHEN (s.n_dead_tup::float/NULLIF(s.n_live_tup+s.n_dead_tup,0))>0.5
                THEN 'CRITICAL' ELSE 'WARNING' END,
           s.schemaname, s.relname, 'table',
           format('live=%s,dead=%s,dead_pct=%s%%',
                  s.n_live_tup,s.n_dead_tup,
                  round(100.0*s.n_dead_tup/NULLIF(s.n_live_tup+s.n_dead_tup,0),1)::text),
           format('Table %I.%I is %s%% dead tuples (%s dead rows). '
                  'Run VACUUM before this becomes an incident.',
                  s.schemaname,s.relname,
                  round(100.0*s.n_dead_tup/NULLIF(s.n_live_tup+s.n_dead_tup,0),1)::text,
                  s.n_dead_tup)
    FROM pg_stat_user_tables s
    WHERE s.n_live_tup+s.n_dead_tup>1000
      AND (s.n_dead_tup::float/NULLIF(s.n_live_tup+s.n_dead_tup,0))>0.3
      AND s.schemaname != ALL(roast._excluded_schemas());

    -- Autovacuum disabled on a table
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'autovacuum_disabled','operational','CRITICAL',
           n.nspname, c.relname, 'table',
           'autovacuum_enabled=false',
           format('Autovacuum is explicitly disabled on %I.%I. '
                  'Dead tuples will accumulate indefinitely. '
                  'Transaction ID wraparound is not a theoretical risk.',
                  n.nspname,c.relname)
    FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r'
      AND c.reloptions IS NOT NULL
      AND 'autovacuum_enabled=false' = ANY(c.reloptions::text[])
      AND n.nspname != ALL(roast._excluded_schemas());

    -- Tables with no statistics
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'never_analyzed','operational',
           CASE WHEN coalesce(s.n_live_tup,0)>10000 THEN 'CRITICAL' ELSE 'WARNING' END,
           s.schemaname, s.relname, 'table',
           format('live_rows=%s,last_analyze=never',coalesce(s.n_live_tup,0)),
           format('Table %I.%I has never been analyzed. '
                  'The query planner is guessing at row counts. '
                  'Every query plan is pure fiction.',
                  s.schemaname,s.relname)
    FROM pg_stat_user_tables s
    WHERE s.last_analyze IS NULL AND s.last_autoanalyze IS NULL
      AND coalesce(s.n_live_tup,0)>0
      AND s.schemaname != ALL(roast._excluded_schemas());

    -- Sequences over 75% exhausted
    INSERT INTO roast.findings
        (run_id,check_name,category,severity,object_schema,object_name,object_type,detail,roast)
    SELECT p_run_id,'sequence_near_exhaustion','operational',
           CASE WHEN (last_value-start_value)::float/(max_value-start_value)>0.9
                THEN 'CRITICAL' ELSE 'WARNING' END,
           n.nspname, c.relname, 'sequence',
           format('current=%s,max=%s,pct_used=%s%%',
                  seq.last_value,seq.max_value,
                  round(100.0*(seq.last_value-seq.start_value)/
                        NULLIF(seq.max_value-seq.start_value,0),1)::text),
           format('Sequence %I.%I is %s%% exhausted (current=%s, max=%s). '
                  'When it wraps, every INSERT will fail.',
                  n.nspname,c.relname,
                  round(100.0*(seq.last_value-seq.start_value)/
                        NULLIF(seq.max_value-seq.start_value,0),1)::text,
                  seq.last_value,seq.max_value)
    FROM pg_sequences seq
    JOIN pg_class c ON c.relname=seq.sequencename
    JOIN pg_namespace n ON n.nspname=seq.schemaname AND n.oid=c.relnamespace
    WHERE seq.max_value>0
      AND (seq.last_value-seq.start_value)::float/
          NULLIF(seq.max_value-seq.start_value,0) > 0.75
      AND seq.schemaname != ALL(roast._excluded_schemas());

    -- GUC checks
    SELECT current_setting('fsync') INTO v_fsync;
    SELECT current_setting('full_page_writes') INTO v_fpw;
    SELECT current_setting('log_min_duration_statement') INTO v_log_min_dur;
    SELECT current_setting('work_mem') INTO v_work_mem;
    SELECT current_setting('max_connections') INTO v_max_conn;

    IF v_fsync='off' THEN
        INSERT INTO roast.findings
            (run_id,check_name,category,severity,object_name,object_type,detail,roast)
        VALUES (p_run_id,'fsync_off','operational','CRITICAL',
                'fsync','config_param','fsync=off',
                'fsync is OFF. If the server crashes, you will lose committed data '
                'and may end up with a corrupt cluster. '
                'This is not a quirk. This is a disaster.');
    END IF;

    IF v_fpw='off' THEN
        INSERT INTO roast.findings
            (run_id,check_name,category,severity,object_name,object_type,detail,roast)
        VALUES (p_run_id,'full_page_writes_off','operational','CRITICAL',
                'full_page_writes','config_param','full_page_writes=off',
                'full_page_writes is OFF. After a partial-page crash, '
                'data corruption will be silent. '
                'You have opted out of one of PostgreSQL''s core safety mechanisms.');
    END IF;

    IF v_log_min_dur='-1' THEN
        INSERT INTO roast.findings
            (run_id,check_name,category,severity,object_name,object_type,detail,roast)
        VALUES (p_run_id,'no_slow_query_log','operational','WARNING',
                'log_min_duration_statement','config_param',
                'log_min_duration_statement=-1',
                'log_min_duration_statement is disabled. '
                'Slow queries are invisible. '
                'You are debugging production performance with no data.');
    END IF;

    -- work_mem: parse value and check if > 256MB globally
    SELECT (regexp_replace(v_work_mem,'[^0-9]','','g'))::bigint *
           CASE
               WHEN v_work_mem ~ 'GB' THEN 1048576
               WHEN v_work_mem ~ 'MB' THEN 1024
               ELSE 1
           END INTO v_work_mem_kb;

    IF v_work_mem_kb > 262144 THEN
        INSERT INTO roast.findings
            (run_id,check_name,category,severity,object_name,object_type,detail,roast)
        VALUES (p_run_id,'high_work_mem','operational','WARNING',
                'work_mem','config_param',
                format('work_mem=%s',v_work_mem),
                format('work_mem is %s globally. Each sort or hash per connection can use this. '
                       'With %s connections that is potentially %s of RAM just for sorts.',
                       v_work_mem, v_max_conn,
                       pg_size_pretty(v_work_mem_kb * v_max_conn * 1024)));
    END IF;

    -- High max_connections (> 200) with no evidence of a pooler
    IF v_max_conn > 200 THEN
        INSERT INTO roast.findings
            (run_id,check_name,category,severity,object_name,object_type,detail,roast)
        VALUES (p_run_id,'high_max_connections','operational','WARNING',
                'max_connections','config_param',
                format('max_connections=%s',v_max_conn),
                format('max_connections is %s. Each idle connection consumes ~5-10MB. '
                       'At full capacity that is %sMB of RAM just for connection overhead. '
                       'Consider PgBouncer.',
                       v_max_conn, v_max_conn * 8));
    END IF;

END;
$$;

-- ============================================================
-- ESCALATION: bump severity when offense appears on multiple
-- tables, or on high-traffic tables
-- ============================================================

CREATE OR REPLACE FUNCTION roast._apply_escalation(p_run_id uuid)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN

    -- High-traffic table (many scans) → escalate INFO to WARNING
    UPDATE roast.findings f
    SET severity='WARNING',
        roast = roast || E'\n[ESCALATED: this table is frequently scanned]'
    FROM pg_stat_user_tables s
    WHERE f.run_id=p_run_id
      AND f.severity='INFO'
      AND f.object_type='table'
      AND f.object_name=s.relname
      AND f.object_schema=s.schemaname
      AND (s.seq_scan + coalesce(0,0)) > 1000;

END;
$$;

-- ============================================================
-- MASTER AUDIT FUNCTIONS
-- ============================================================

CREATE OR REPLACE FUNCTION roast._bgw_run_audit()
RETURNS void LANGUAGE plpgsql AS $$
DECLARE v_run_id uuid := gen_random_uuid(); v_count bigint;
BEGIN
    INSERT INTO roast.audit_runs(run_id,triggered_by) VALUES(v_run_id,'bgw');
    PERFORM roast._check_col_types(v_run_id);
    PERFORM roast._check_col_naming(v_run_id);
    PERFORM roast._check_table_naming(v_run_id);
    PERFORM roast._check_nullable(v_run_id);
    PERFORM roast._check_primary_keys(v_run_id);
    PERFORM roast._check_patterns(v_run_id);
    PERFORM roast._check_indexes(v_run_id);
    PERFORM roast._check_constraints(v_run_id);
    PERFORM roast._check_relational(v_run_id);
    PERFORM roast._check_naming_consistency(v_run_id);
    PERFORM roast._check_query_behavior(v_run_id);
    PERFORM roast._check_security(v_run_id);
    PERFORM roast._check_operational(v_run_id);
    PERFORM roast._apply_escalation(v_run_id);
    PERFORM roast._apply_ignores(v_run_id);
    SELECT count(*) INTO v_count FROM roast.findings WHERE run_id=v_run_id;
    UPDATE roast.audit_runs SET finished_at=now(), finding_count=v_count WHERE run_id=v_run_id;
END;
$$;

CREATE OR REPLACE FUNCTION roast.run()
RETURNS TABLE(run_id uuid, finding_count bigint, duration interval)
LANGUAGE plpgsql AS $$
DECLARE
    v_run_id    uuid := gen_random_uuid();
    v_count     bigint;
    v_start     timestamptz := now();
BEGIN
    INSERT INTO roast.audit_runs(run_id,triggered_by) VALUES(v_run_id,'manual');
    PERFORM roast._check_col_types(v_run_id);
    PERFORM roast._check_col_naming(v_run_id);
    PERFORM roast._check_table_naming(v_run_id);
    PERFORM roast._check_nullable(v_run_id);
    PERFORM roast._check_primary_keys(v_run_id);
    PERFORM roast._check_patterns(v_run_id);
    PERFORM roast._check_indexes(v_run_id);
    PERFORM roast._check_constraints(v_run_id);
    PERFORM roast._check_relational(v_run_id);
    PERFORM roast._check_naming_consistency(v_run_id);
    PERFORM roast._check_query_behavior(v_run_id);
    PERFORM roast._check_security(v_run_id);
    PERFORM roast._check_operational(v_run_id);
    PERFORM roast._apply_escalation(v_run_id);
    PERFORM roast._apply_ignores(v_run_id);
    SELECT count(*) INTO v_count FROM roast.findings WHERE findings.run_id=v_run_id;
    UPDATE roast.audit_runs
    SET finished_at=now(), finding_count=v_count
    WHERE audit_runs.run_id=v_run_id;
    RETURN QUERY SELECT v_run_id, v_count, now()-v_start;
END;
$$;

-- Convenience: clear old findings (keep last N runs)
CREATE OR REPLACE FUNCTION roast.clear(keep_runs int DEFAULT 5)
RETURNS int LANGUAGE plpgsql AS $$
DECLARE v_deleted int;
BEGIN
    DELETE FROM roast.findings
    WHERE run_id NOT IN (
        SELECT run_id FROM roast.audit_runs
        ORDER BY started_at DESC LIMIT keep_runs
    );
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    DELETE FROM roast.audit_runs
    WHERE run_id NOT IN (
        SELECT run_id FROM roast.audit_runs
        ORDER BY started_at DESC LIMIT keep_runs
    );
    RETURN v_deleted;
END;
$$;

-- ============================================================
-- IGNORE / DISMISS
-- ============================================================

-- Delete findings from a run that match any ignore rule
CREATE OR REPLACE FUNCTION roast._apply_ignores(p_run_id uuid)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM roast.findings f
    USING roast.ignores i
    WHERE f.run_id = p_run_id
      AND f.check_name = i.check_name
      AND (i.object_schema IS NULL OR i.object_schema = f.object_schema)
      AND (i.object_name  IS NULL OR i.object_name  = f.object_name);
END;
$$;

-- Dismiss a specific finding by id (hides it from roast.latest)
CREATE OR REPLACE FUNCTION roast.dismiss(p_id bigint)
RETURNS void LANGUAGE sql AS $$
    UPDATE roast.findings SET dismissed_at = now() WHERE id = p_id;
$$;

-- Ignore a check permanently, optionally scoped to a specific object
-- Examples:
--   SELECT roast.ignore('col_serial');                             -- ignore everywhere
--   SELECT roast.ignore('col_serial', 'public.users.id');         -- ignore for one column
--   SELECT roast.ignore('unused_index', NULL, 'legacy index');    -- with a reason
CREATE OR REPLACE FUNCTION roast.ignore(
    p_check_name    text,
    p_object_name   text DEFAULT NULL,
    p_reason        text DEFAULT NULL
) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_schema text := NULL;
    v_object text := NULL;
BEGIN
    -- If object_name contains a dot, split into schema + object
    IF p_object_name IS NOT NULL AND p_object_name LIKE '%.%' THEN
        v_schema := split_part(p_object_name, '.', 1);
        v_object := substr(p_object_name, length(v_schema) + 2);
    ELSE
        v_object := p_object_name;
    END IF;

    INSERT INTO roast.ignores (check_name, object_schema, object_name, reason)
    VALUES (p_check_name, v_schema, v_object, p_reason);
END;
$$;

-- Remove an ignore rule
CREATE OR REPLACE FUNCTION roast.unignore(
    p_check_name  text,
    p_object_name text DEFAULT NULL
) RETURNS int LANGUAGE plpgsql AS $$
DECLARE
    v_schema text := NULL;
    v_object text := NULL;
    v_deleted int;
BEGIN
    IF p_object_name IS NOT NULL AND p_object_name LIKE '%.%' THEN
        v_schema := split_part(p_object_name, '.', 1);
        v_object := substr(p_object_name, length(v_schema) + 2);
    ELSE
        v_object := p_object_name;
    END IF;

    DELETE FROM roast.ignores
    WHERE check_name = p_check_name
      AND (v_schema IS NULL OR object_schema = v_schema)
      AND (v_object IS NULL OR object_name  = v_object);
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
END;
$$;

-- ============================================================
-- VIEWS
-- ============================================================

CREATE OR REPLACE VIEW roast.latest AS
    SELECT f.*
    FROM roast.findings f
    WHERE f.run_id = (
        SELECT run_id FROM roast.audit_runs
        ORDER BY started_at DESC LIMIT 1
    )
    AND f.dismissed_at IS NULL
    ORDER BY
        CASE f.severity WHEN 'CRITICAL' THEN 1 WHEN 'WARNING' THEN 2 ELSE 3 END,
        f.category,
        f.object_schema,
        f.object_name;

CREATE OR REPLACE VIEW roast.summary AS
    SELECT
        f.severity,
        f.category,
        count(*) AS finding_count
    FROM roast.findings f
    WHERE f.run_id = (
        SELECT run_id FROM roast.audit_runs
        ORDER BY started_at DESC LIMIT 1
    )
    AND f.dismissed_at IS NULL
    GROUP BY f.severity, f.category
    ORDER BY
        CASE f.severity WHEN 'CRITICAL' THEN 1 WHEN 'WARNING' THEN 2 ELSE 3 END,
        f.category;

-- ============================================================
-- PERMISSIONS
-- ============================================================

REVOKE ALL ON ALL TABLES IN SCHEMA roast FROM PUBLIC;
GRANT SELECT ON roast.findings    TO PUBLIC;
GRANT SELECT ON roast.audit_runs  TO PUBLIC;
GRANT SELECT ON roast.ignores     TO PUBLIC;
GRANT SELECT ON roast.latest      TO PUBLIC;
GRANT SELECT ON roast.summary     TO PUBLIC;
GRANT EXECUTE ON FUNCTION roast.run()                          TO PUBLIC;
GRANT EXECUTE ON FUNCTION roast.clear(int)                     TO PUBLIC;
GRANT EXECUTE ON FUNCTION roast.dismiss(bigint)                TO PUBLIC;
GRANT EXECUTE ON FUNCTION roast.ignore(text, text, text)       TO PUBLIC;
GRANT EXECUTE ON FUNCTION roast.unignore(text, text)           TO PUBLIC;

-- ============================================================
-- INSTALL-TIME NOTICE: warn if BGW won't start
-- ============================================================

DO $$
BEGIN
    IF current_setting('shared_preload_libraries') NOT LIKE '%pg_roast%' THEN
        RAISE NOTICE
            E'pg_roast: background worker is INACTIVE.\n'
            'Add pg_roast to shared_preload_libraries in postgresql.conf '
            'and restart PostgreSQL to enable automatic audits.\n'
            'Manual audits via SELECT * FROM roast.run() still work.';
    END IF;
END;
$$;
