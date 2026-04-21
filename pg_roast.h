#ifndef PG_ROAST_H
#define PG_ROAST_H

#include "postgres.h"
#include "fmgr.h"

extern int   pg_roast_interval_seconds;
extern bool  pg_roast_auto_audit;
extern char *pg_roast_database;

extern PGDLLEXPORT void pg_roast_bgw_main(Datum main_arg);

#endif /* PG_ROAST_H */
