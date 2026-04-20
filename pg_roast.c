#include "postgres.h"
#include "fmgr.h"
#include "utils/guc.h"
#include "postmaster/bgworker.h"
#include "miscadmin.h"
#include "pg_roast.h"

PG_MODULE_MAGIC;

int   pg_roast_interval_seconds = 3600;
bool  pg_roast_auto_audit       = true;
char *pg_roast_database         = NULL;

void _PG_init(void);

void
_PG_init(void)
{
    DefineCustomIntVariable(
        "pg_roast.interval",
        "Seconds between automatic audit runs (60–86400).",
        NULL,
        &pg_roast_interval_seconds,
        3600,   /* default: 1 hour */
        60,     /* min: 1 minute */
        86400,  /* max: 1 day */
        PGC_SIGHUP,
        0, NULL, NULL, NULL
    );

    DefineCustomBoolVariable(
        "pg_roast.auto_audit",
        "Enable or disable automatic background audits.",
        NULL,
        &pg_roast_auto_audit,
        true,
        PGC_SIGHUP,
        0, NULL, NULL, NULL
    );

    DefineCustomStringVariable(
        "pg_roast.database",
        "Database the background worker connects to for auditing.",
        "Must match the database where CREATE EXTENSION pg_roast was run.",
        &pg_roast_database,
        "postgres",
        PGC_POSTMASTER,
        0, NULL, NULL, NULL
    );

#if PG_VERSION_NUM >= 150000
    MarkGUCPrefixReserved("pg_roast");
#else
    EmitWarningsOnPlaceholders("pg_roast");
#endif

    if (process_shared_preload_libraries_in_progress)
    {
        BackgroundWorker worker;
        memset(&worker, 0, sizeof(worker));

        worker.bgw_flags       = BGWORKER_SHMEM_ACCESS |
                                  BGWORKER_BACKEND_DATABASE_CONNECTION;
        worker.bgw_start_time  = BgWorkerStart_RecoveryFinished;
        worker.bgw_restart_time = 10;

        snprintf(worker.bgw_name,          BGW_MAXLEN, "pg_roast auditor");
        snprintf(worker.bgw_type,          BGW_MAXLEN, "pg_roast auditor");
        snprintf(worker.bgw_library_name,  BGW_MAXLEN, "pg_roast");
        snprintf(worker.bgw_function_name, BGW_MAXLEN, "pg_roast_bgw_main");

        worker.bgw_main_arg    = (Datum) 0;
        worker.bgw_notify_pid  = 0;

        RegisterBackgroundWorker(&worker);
    }
}
