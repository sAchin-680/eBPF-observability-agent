SHELL := /bin/bash
.DEFAULT_GOAL := help

CERT_DIR := certs
# Logs live beside the services rather than in /tmp: the demo runs the agent as
# root while the services may be started as either user, and a log file left in
# a shared directory by one owner cannot be written by the other.
LOG_DIR  := logs
GO       ?= go
CURL     := curl -sk --http1.1

# Every client negotiates HTTP/2 over ALPN by default. HTTP/2 is out of scope,
# so traffic generation forces HTTP/1.1 rather than producing payloads the
# agent is not designed to parse.

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_%.-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

$(CERT_DIR)/cert.pem:
	@mkdir -p $(CERT_DIR)
	@openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
	  -keyout $(CERT_DIR)/key.pem -out $(CERT_DIR)/cert.pem \
	  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
	@echo ">> generated self-signed certificate in $(CERT_DIR)/"

.PHONY: certs
certs: $(CERT_DIR)/cert.pem ## Generate self-signed certificates

.PHONY: deps
deps: ## Install Python and Node dependencies
	@cd python-flask && python3 -m venv .venv >/dev/null 2>&1 || true
	@cd python-flask && .venv/bin/pip install -q flask
	@cd node-express && npm install --silent --no-fund --no-audit express

.PHONY: build
build: ## Build the Go service
	@cd go-api && $(GO) mod tidy >/dev/null 2>&1 && $(GO) build -o go-api .

.PHONY: run
run: certs build ## Start all three services in the background
	@mkdir -p $(LOG_DIR)
	@cd go-api       && setsid ./go-api                > ../$(LOG_DIR)/go-api.log       2>&1 < /dev/null &
	@cd python-flask && setsid .venv/bin/python app.py > ../$(LOG_DIR)/python-flask.log 2>&1 < /dev/null &
	@cd node-express && setsid node server.js          > ../$(LOG_DIR)/node-express.log 2>&1 < /dev/null &
	@sleep 3
	@$(MAKE) --no-print-directory status

.PHONY: status
status: ## Report which services are responding
	@for p in 8443:go-api 8444:python-flask 8445:node-express; do \
	  port=$${p%%:*}; name=$${p##*:}; \
	  if $(CURL) --max-time 2 https://localhost:$$port/health >/dev/null 2>&1; \
	    then echo "  up    $$name (:$$port)"; \
	    else echo "  DOWN  $$name (:$$port) — see samples/$(LOG_DIR)/$$name.log"; fi; \
	done

.PHONY: traffic
traffic: ## Generate a mixed request load against all three services
	@for port in 8443 8444 8445; do \
	  for path in /health /users /users/1 /users/999 /slow /error; do \
	    $(CURL) --max-time 5 https://localhost:$$port$$path >/dev/null 2>&1; \
	  done; \
	  $(CURL) --max-time 5 -X POST -H 'Content-Type: application/json' \
	    -d '{"name":"new"}' https://localhost:$$port/users >/dev/null 2>&1; \
	done
	@echo ">> 21 requests sent across three services"

.PHONY: load
load: ## Sustained load for benchmarking (N=requests per endpoint)
	@N=$${N:-50}; \
	for i in $$(seq 1 $$N); do \
	  for port in 8443 8444 8445; do \
	    $(CURL) --max-time 5 https://localhost:$$port/users >/dev/null 2>&1 & \
	  done; \
	done; wait; \
	echo ">> $$(( $${N:-50} * 3 )) requests sent"

.PHONY: stop
stop: ## Stop all services
	@# Matched on process name rather than command line: the services are
	@# started from their own directories, so the command line is a bare
	@# relative path that no directory-qualified pattern matches.
	@pkill -x go-api 2>/dev/null || true
	@pkill -f 'python.*app\.py' 2>/dev/null || true
	@pkill -f 'node.*server\.js' 2>/dev/null || true
	@sleep 1
	@echo ">> stopped"

.PHONY: clean
clean: stop ## Stop services and remove build artifacts
	@rm -rf $(CERT_DIR) $(LOG_DIR) go-api/go-api python-flask/.venv node-express/node_modules
