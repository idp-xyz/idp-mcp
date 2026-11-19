# idp-mcp build and test entry points.
PG_IMAGE ?= public.ecr.aws/docker/library/postgres:17-alpine
PG_NAME  ?= idp-mcp-test-pg

.PHONY: build test vet test-integration pg-up pg-down

build:
	go build -o bin/ ./cmd/...

vet:
	gofmt -l . | (! grep .) && go vet ./...

test: vet
	go test -race ./...

# Starts a throwaway PostgreSQL on a random loopback port, runs the integration tests against it and
# removes it again.
test-integration: pg-up
	@PORT=$$(docker port $(PG_NAME) 5432/tcp | head -1 | sed 's/.*://'); \
	IDP_TEST_PG_OWNER_URL="postgres://postgres:test@127.0.0.1:$$PORT/postgres?sslmode=disable" \
	go test -count=1 -race -v ./tests/integration/ ; status=$$?; \
	$(MAKE) --no-print-directory pg-down; exit $$status

pg-up:
	@docker rm -f $(PG_NAME) >/dev/null 2>&1 || true
	@docker run -d --name $(PG_NAME) -e POSTGRES_PASSWORD=test -p 127.0.0.1::5432 $(PG_IMAGE) >/dev/null
	@for i in $$(seq 1 60); do docker exec $(PG_NAME) pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1 && break; sleep 0.5; done

pg-down:
	@docker rm -f $(PG_NAME) >/dev/null 2>&1 || true

# Official MCP conformance suite (2026-07-28, 37 scored server scenarios) through the gateway, against the
# pinned runner and reference server that tests/conformance/fetch.sh installs (npm ci from a lockfile; the
# Python SDK at a commit with its own uv.lock). CI runs exactly this target. Point CONFORMANCE_ROOT (a runner
# checkout with dist/index.js and requirements/) and REFERENCE_SERVER (an mcp-everything-server executable) at
# your own builds to run against those instead; the fetch of that part is then skipped.
CONFORMANCE_DEPS ?= $(CURDIR)/build/conformance-deps
CONFORMANCE_ROOT ?= $(CURDIR)/tests/conformance/runner/node_modules/@modelcontextprotocol/conformance
REFERENCE_SERVER ?= $(CONFORMANCE_DEPS)/python-sdk/.venv/bin/mcp-everything-server
.PHONY: conformance conformance-deps
conformance-deps:
	@CONFORMANCE_DEPS=$(CONFORMANCE_DEPS) \
	FETCH_RUNNER=$(if $(filter command line environment,$(origin CONFORMANCE_ROOT)),0,1) \
	FETCH_REFERENCE=$(if $(filter command line environment,$(origin REFERENCE_SERVER)),0,1) \
	bash tests/conformance/fetch.sh

conformance: conformance-deps
	IDP_CONFORMANCE_ROOT=$(CONFORMANCE_ROOT) IDP_REFERENCE_SERVER=$(REFERENCE_SERVER) \
	go test -count=1 -v -timeout 20m ./tests/conformance/
