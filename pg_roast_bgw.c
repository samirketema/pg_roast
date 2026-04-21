#include "postgres.h"
#include "fmgr.h"
#include "postmaster/bgworker.h"
#include "postmaster/interrupt.h"
#include "storage/ipc.h"
#include "storage/latch.h"
#include "access/xact.h"
#include "executor/spi.h"
#include "utils/guc.h"
#include "utils/snapmgr.h"
#include "tcop/utility.h"
#include "miscadmin.h"
#include "pg_roast.h"

PGDLLEXPORT void
pg_roast_bgw_main(Datum main_arg)
{
    pqsignal(SIGTERM, SignalHandlerForShutdownRequest);
    pqsignal(SIGHUP,  SignalHandlerForConfigReload);
    BackgroundWorkerUnblockSignals();

    BackgroundWorkerInitializeConnection(pg_roast_database, NULL, 0);

    elog(LOG, "pg_roast: auditor started (database=%s, interval=%ds)",
         pg_roast_database, pg_roast_interval_seconds);

    for (;;)
    {
        int rc;

        if (ShutdownRequestPending)
            break;

        if (ConfigReloadPending)
        {
            ConfigReloadPending = false;
            ProcessConfigFile(PGC_SIGHUP);
            elog(LOG, "pg_roast: config reloaded (interval=%ds)", pg_roast_interval_seconds);
        }

        if (pg_roast_auto_audit)
        {
            PG_TRY();
            {
                SetCurrentStatementStartTimestamp();
                StartTransactionCommand();
                SPI_connect();
                PushActiveSnapshot(GetTransactionSnapshot());

                SPI_execute("SELECT roast._bgw_run_audit()", false, 0);

                PopActiveSnapshot();
                SPI_finish();
                CommitTransactionCommand();

                elog(LOG, "pg_roast: audit completed");
            }
            PG_CATCH();
            {
                EmitErrorReport();
                AbortCurrentTransaction();
                SPI_finish();
                FlushErrorState();
                elog(WARNING, "pg_roast: audit failed, will retry next interval");
            }
            PG_END_TRY();
        }

        ResetLatch(MyLatch);
        rc = WaitLatch(MyLatch,
                       WL_LATCH_SET | WL_TIMEOUT | WL_EXIT_ON_PM_DEATH,
                       (long) pg_roast_interval_seconds * 1000L,
                       0);
        (void) rc;
    }

    elog(LOG, "pg_roast: auditor shutting down");
    proc_exit(0);
}
