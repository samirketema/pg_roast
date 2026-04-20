MODULE_big  = pg_roast
OBJS        = pg_roast.o pg_roast_bgw.o

EXTENSION   = pg_roast
DATA        = pg_roast--1.0.sql

REGRESS     = pg_roast

PG_CONFIG   ?= pg_config
PGXS        := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
