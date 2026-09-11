SHELL := /bin/bash

GO        ?= go
BIN       := bin/collab-server
MIGRATE   := bin/collab-migrate
PKG       := ./...
LDFLAGS   ?= -ldflags="-s -w -X github.com/spirefyio/collab/server/internal/config.Version=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev)"

# Database URL for every db-* target. Honours COLLAB_DATABASE_URL when set so
# the same targets work against a staging or production database; otherwise it
# points at the compose Postgres from docker-compose.yml.
POSTGRES_HOST_PORT ?= 5432
DB_URL ?= $(if $(COLLAB_DATABASE_URL),$(COLLAB_DATABASE_URL),postgres://collab:collab@localhost:$(POSTGRES_HOST_PORT)/collab?sslmode=disable)
COMPOSE ?= docker compose

# DB_URL with credentials stripped, for display only.
#
# Every destructive refusal prints this, because CONFIRM=yes answers "be
# destructive" and never answers "against WHICH database" -- and DB_URL
# silently inherits COLLAB_DATABASE_URL, so an operator with production
# exported in the same shell gets no tell from the command they typed. It is
# redacted rather than raw so a refusal cannot drop a password into terminal
# scrollback or a CI log.
REDACT = sed -E 's,://[^@/]*@,://***@,'

.PHONY: all build test test-race test-integration fmt vet lint clean run tidy \
        db-start db-stop db-destroy db-psql \
        db-up db-down db-down-all db-goto db-force db-version db-new db-reset

all: fmt vet test build

build:
	@mkdir -p bin
	$(GO) build $(LDFLAGS) -o $(BIN) ./cmd/relay
	$(GO) build $(LDFLAGS) -o $(MIGRATE) ./cmd/collab-migrate

run: build
	./$(BIN)

test:
	$(GO) test -count=1 $(PKG)

test-race:
	$(GO) test -race -count=1 $(PKG)

# The migration round-trip tests need a real Postgres; without
# COLLAB_TEST_DATABASE_URL they skip, so `make test` alone never exercises the
# SQL. This target starts the compose Postgres and runs the full suite with
# the URL set, so nothing skips. Each test creates and drops its own
# throwaway database — it never touches the dev database at $(DB_URL).
test-integration: db-start
	COLLAB_TEST_DATABASE_URL='$(DB_URL)' $(GO) test -count=1 $(PKG)

fmt:
	$(GO) fmt $(PKG)

vet:
	$(GO) vet $(PKG)

lint:
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not installed; skipping"; exit 0; }
	golangci-lint run $(PKG)

tidy:
	$(GO) mod tidy

clean:
	rm -rf bin/

# ----- database lifecycle (docker compose) ---------------------------

# Brings up ONLY Postgres (not the server) and blocks until it answers
# pg_isready, so a following db-* target cannot race the container.
db-start:
	$(COMPOSE) up -d postgres
	@echo -n "waiting for postgres"; \
	for i in $$(seq 1 60); do \
	  if $(COMPOSE) exec -T postgres pg_isready -U collab -d collab >/dev/null 2>&1; then echo " ready"; exit 0; fi; \
	  echo -n "."; sleep 1; \
	done; \
	echo " TIMEOUT"; $(COMPOSE) logs --tail=30 postgres; \
	echo "postgres never became ready; the container is still running. 'make db-stop' to stop it, 'make db-destroy CONFIRM=yes' to also drop its volume."; \
	exit 1

db-stop:
	$(COMPOSE) stop postgres

# Tears down the whole compose project INCLUDING the postgres-data volume:
# every row is gone and the next db-start bootstraps an empty cluster. Uses
# compose's own verb rather than deriving the volume name, so it cannot
# silently half-succeed.
db-destroy:
	@[ "$(CONFIRM)" = "yes" ] || { echo "refusing: removes the postgres-data volume and all data"; \
	  echo "  re-run as: make db-destroy CONFIRM=yes"; exit 1; }
	$(COMPOSE) down --volumes

# Local dev only, and it says so rather than silently doing the wrong thing.
# This target execs the compose container; it cannot reach a managed database,
# so when DB_URL has been overridden it refuses and names the command that
# does work. The dirty-schema runbook sends operators here, and inspecting the
# wrong database while recovering a broken one is the worst time for it.
db-psql:
	@[ -z "$(COLLAB_DATABASE_URL)" ] || { \
	  echo "refusing: db-psql execs the compose container and cannot reach"; \
	  echo "  $$(printf '%s' '$(DB_URL)' | $(REDACT))"; \
	  echo "run this instead:  psql \"\$$COLLAB_DATABASE_URL\""; exit 1; }
	$(COMPOSE) exec postgres psql -U collab -d collab

# ----- schema migrations (cmd/collab-migrate) ------------------------
#
# The server applies pending migrations itself at boot, so db-up is only for
# migrating ahead of a deploy. Everything else here is what the boot path
# deliberately cannot do.

# The URL goes through the ENVIRONMENT, not `-url`, because argv is
# world-readable via ps on POSIX and DB_URL may carry a production password.
# The CLI already defaults -url from COLLAB_DATABASE_URL, so this needs no
# code change. (Make still substitutes it into the recipe's own `sh -c`
# argv for an instant; the env form keeps it out of the long-lived
# collab-migrate process's argv, which is where the actual work happens.)
MIGRATE_ENV := COLLAB_DATABASE_URL='$(DB_URL)'

db-version: build
	@$(MIGRATE_ENV) $(MIGRATE) version

db-up: build
	@$(MIGRATE_ENV) $(MIGRATE) up

# make db-down N=1 CONFIRM=yes
# Destructive: every rollback runs a .down.sql and drops what it created. With
# a single-migration set, `down 1` empties the whole schema — same blast radius
# as db-down-all, so it carries the same two gates.
db-down: build
	@[ -n "$(N)" ] || { echo "usage: make db-down N=<steps> CONFIRM=yes"; exit 1; }
	@[ "$(CONFIRM)" = "yes" ] || { echo "refusing: rolling back $(N) migration(s) drops what they created"; \
	  echo "  target: $$(printf '%s' '$(DB_URL)' | $(REDACT))"; \
	  echo "  re-run as: make db-down N=$(N) CONFIRM=yes"; exit 1; }
	@$(MIGRATE_ENV) $(MIGRATE) -yes down $(N)

db-down-all: build
	@[ "$(CONFIRM)" = "yes" ] || { echo "refusing: rolls back every migration and drops all data"; \
	  echo "  target: $$(printf '%s' '$(DB_URL)' | $(REDACT))"; \
	  echo "  re-run as: make db-down-all CONFIRM=yes"; exit 1; }
	@$(MIGRATE_ENV) $(MIGRATE) -yes down-all

# make db-goto V=2            (migrating forward needs no confirmation)
# make db-goto V=1 CONFIRM=yes (descending is a rollback, and V=0 empties it)
#
# CONFIRM forwards -yes; without it the CLI compares V against the applied
# version and refuses only when the move is a rollback. Passing -yes
# unconditionally here would have silently disarmed that check, and omitting
# it entirely made `make db-goto V=0` a target that could never succeed.
db-goto: build
	@[ -n "$(V)" ] || { echo "usage: make db-goto V=<version> [CONFIRM=yes]"; exit 1; }
	@$(MIGRATE_ENV) $(MIGRATE) $(if $(filter yes,$(CONFIRM)),-yes,) goto $(V)

# make db-force V=1 CONFIRM=yes  — recovery verb for a dirty schema.
db-force: build
	@[ -n "$(V)" ] || { echo "usage: make db-force V=<version> CONFIRM=yes"; exit 1; }
	@[ "$(CONFIRM)" = "yes" ] || { echo "refusing: force rewrites schema bookkeeping without running SQL."; \
	  echo "  Only correct if you have confirmed the schema matches version $(V)."; \
	  echo "  target: $$(printf '%s' '$(DB_URL)' | $(REDACT))"; \
	  echo "  re-run as: make db-force V=$(V) CONFIRM=yes"; exit 1; }
	@$(MIGRATE_ENV) $(MIGRATE) -yes force $(V)

# make db-new NAME=add_sessions_table
db-new: build
	@[ -n "$(NAME)" ] || { echo "usage: make db-new NAME=<lower_snake_case>"; exit 1; }
	$(MIGRATE) create $(NAME)

# Full schema rebuild against the dev database: down to empty, back up to head.
db-reset: build
	@[ "$(CONFIRM)" = "yes" ] || { echo "refusing: drops every table in the target database then re-migrates"; \
	  echo "  target: $$(printf '%s' '$(DB_URL)' | $(REDACT))"; \
	  echo "  re-run as: make db-reset CONFIRM=yes"; exit 1; }
	@$(MIGRATE_ENV) $(MIGRATE) -yes down-all
	@$(MIGRATE_ENV) $(MIGRATE) up
