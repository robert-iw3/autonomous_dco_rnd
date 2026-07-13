# ==============================================================================
# Sentinel Nexus -- Operations Automation
# Run `make help` for available targets.
# ==============================================================================

SHELL := /bin/bash
.DEFAULT_GOAL := help

# Load central config
include nexus.conf
export

# -- Directories --
SCRIPTS_DIR := scripts
INFRA_DIR   := infra
N8N_DIR     := n8n
WEBUI_DIR   := webui

# -- Colors --
CYAN  := \033[36m
GREEN := \033[32m
YELLOW := \033[33m
RESET := \033[0m

# ==============================================================================
# Lifecycle
# ==============================================================================

.PHONY: init
init: ## Generate secrets, TLS certs, and create the bridge network
	@echo -e "$(CYAN)[*] Initializing Sentinel Nexus operations stack...$(RESET)"
	@chmod +x $(SCRIPTS_DIR)/*.sh
	@$(SCRIPTS_DIR)/env-gen.sh
	@$(SCRIPTS_DIR)/cert-gen.sh
	@echo -e "$(GREEN)[+] Initialization complete.$(RESET)"

.PHONY: deploy
deploy: ## Deploy the full stack for an incident. Usage: make deploy EVENT_ID=<id>
	@test -n "$(EVENT_ID)" || (echo "Usage: make deploy EVENT_ID=<incident_id>"; exit 1)
	@$(SCRIPTS_DIR)/trigger-incident.sh $(EVENT_ID)

.PHONY: teardown
teardown: ## Tear down the stack. Usage: make teardown EVENT_ID=<id> [DEEP=1]
	@test -n "$(EVENT_ID)" || (echo "Usage: make teardown EVENT_ID=<incident_id>"; exit 1)
	@$(SCRIPTS_DIR)/teardown-incident.sh $(EVENT_ID) $(if $(DEEP),--deep)

.PHONY: redeploy
redeploy: teardown deploy ## Teardown and redeploy. Usage: make redeploy EVENT_ID=<id>

# ==============================================================================
# Testing
# ==============================================================================

.PHONY: test
test: test-lint test-containment ## Run all tests

.PHONY: test-lint
test-lint: ## Validate all configuration files
	@echo -e "$(CYAN)[*] Validating configurations...$(RESET)"
	@# Validate YAML files
	@for f in $(INFRA_DIR)/traefik/*.yaml $(INFRA_DIR)/authentik-blueprint.yaml \
	          $(N8N_DIR)/docker-compose.yml $(WEBUI_DIR)/docker-compose.yml \
	          $(WEBUI_DIR)/config/config.yml $(INFRA_DIR)/docker-compose.yml; do \
	    python3 -c "import yaml; yaml.safe_load(open('$$f'))" 2>/dev/null && \
	        echo -e "  $(GREEN)✓$(RESET) $$f" || \
	        (echo -e "  \033[31m✗\033[0m $$f"; exit 1); \
	done
	@# Validate TOML
	@python3 -c "import tomllib; tomllib.load(open('$(INFRA_DIR)/containment.toml','rb'))" 2>/dev/null && \
	    echo -e "  $(GREEN)✓$(RESET) $(INFRA_DIR)/containment.toml" || \
	    (python3 -c "import toml; toml.load('$(INFRA_DIR)/containment.toml')" 2>/dev/null && \
	        echo -e "  $(GREEN)✓$(RESET) $(INFRA_DIR)/containment.toml" || \
	        (echo -e "  \033[31m✗\033[0m $(INFRA_DIR)/containment.toml"; exit 1))
	@# Validate JSON workflows
	@python3 -c "import json; json.load(open('$(N8N_DIR)/workflows/Master_Containment.json'))" && \
	    echo -e "  $(GREEN)✓$(RESET) $(N8N_DIR)/workflows/Master_Containment.json" || \
	    (echo -e "  \033[31m✗\033[0m $(N8N_DIR)/workflows/Master_Containment.json"; exit 1)
	@echo -e "$(GREEN)[+] All configs valid.$(RESET)"

.PHONY: test-containment
test-containment: ## Test EDR/FW containment pipeline against mock API
	@echo -e "$(CYAN)[*] Starting Mock EDR & Firewall on port $(NEXUS_MOCK_API_PORT)...$(RESET)"
	@python3 $(SCRIPTS_DIR)/mock_containment_api.py --port $(NEXUS_MOCK_API_PORT) &
	@MOCK_PID=$$!; \
	cleanup() { kill $$MOCK_PID 2>/dev/null; wait $$MOCK_PID 2>/dev/null; rm -f mock_audit.log; }; \
	trap cleanup EXIT; \
	sleep 2; \
	echo -e "$(CYAN)[*] Verifying mock API health...$(RESET)"; \
	curl -sf http://localhost:$(NEXUS_MOCK_API_PORT)/health > /dev/null || \
	    (echo -e "\033[31m[✗] Mock API failed to start\033[0m"; exit 1); \
	echo -e "$(CYAN)[*] Executing multi-stage containment plan...$(RESET)"; \
	HTTP_CODE=$$(curl -s -o /dev/null -w '%{http_code}' -X POST \
	    http://localhost:$(NEXUS_MOCK_API_PORT)/v2/devices/isolate \
	    -H "Authorization: Bearer TEST_EDR_KEY" \
	    -H "Content-Type: application/json" \
	    -d '{"target_ip":"10.0.0.99","isolation_mode":"strict","audit_comment":"QA-TEST-001"}'); \
	test "$$HTTP_CODE" = "200" && echo -e "  $(GREEN)✓$(RESET) EDR isolate_host (HTTP $$HTTP_CODE)" || \
	    (echo -e "  \033[31m✗\033[0m EDR isolate_host (HTTP $$HTTP_CODE)"; exit 1); \
	HTTP_CODE=$$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
	    http://localhost:$(NEXUS_MOCK_API_PORT)/api/v1/objects/address/10.0.0.99 \
	    -H "X-API-Key: TEST_FW_KEY" \
	    -H "Content-Type: application/json" \
	    -d '{"name":"NEXUS_BLOCK_10.0.0.99","ip_netmask":"10.0.0.99/32","description":"QA test"}'); \
	test "$$HTTP_CODE" = "200" && echo -e "  $(GREEN)✓$(RESET) FW block_ip (HTTP $$HTTP_CODE)" || \
	    (echo -e "  \033[31m✗\033[0m FW block_ip (HTTP $$HTTP_CODE)"; exit 1); \
	echo -e "$(CYAN)[*] Testing auth rejection (no credentials)...$(RESET)"; \
	HTTP_CODE=$$(curl -s -o /dev/null -w '%{http_code}' -X POST \
	    http://localhost:$(NEXUS_MOCK_API_PORT)/v2/devices/isolate \
	    -H "Content-Type: application/json" \
	    -d '{"target_ip":"10.0.0.99","isolation_mode":"strict"}'); \
	test "$$HTTP_CODE" = "401" && echo -e "  $(GREEN)✓$(RESET) EDR rejects unauthenticated (HTTP $$HTTP_CODE)" || \
	    (echo -e "  \033[31m✗\033[0m EDR should reject unauthenticated (HTTP $$HTTP_CODE)"; exit 1); \
	echo -e "$(CYAN)[*] Testing validation rejection (bad payload)...$(RESET)"; \
	HTTP_CODE=$$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
	    http://localhost:$(NEXUS_MOCK_API_PORT)/api/v1/objects/address/10.0.0.99 \
	    -H "X-API-Key: TEST_FW_KEY" \
	    -H "Content-Type: application/json" \
	    -d '{"name":"BAD","ip_netmask":"10.0.0.99/24"}'); \
	test "$$HTTP_CODE" = "400" && echo -e "  $(GREEN)✓$(RESET) FW rejects bad netmask (HTTP $$HTTP_CODE)" || \
	    (echo -e "  \033[31m✗\033[0m FW should reject /24 mask (HTTP $$HTTP_CODE)"; exit 1); \
	echo -e "$(CYAN)[*] Verifying audit trail...$(RESET)"; \
	AUDIT_COUNT=$$(curl -s http://localhost:$(NEXUS_MOCK_API_PORT)/audit | python3 -c "import sys,json; print(json.load(sys.stdin)['total'])"); \
	test "$$AUDIT_COUNT" -ge 4 && echo -e "  $(GREEN)✓$(RESET) Audit trail: $$AUDIT_COUNT entries logged" || \
	    (echo -e "  \033[31m✗\033[0m Audit trail incomplete ($$AUDIT_COUNT entries)"; exit 1); \
	echo -e "$(GREEN)[+] Containment pipeline verified (4/4 tests passed).$(RESET)"

.PHONY: test-env
test-env: ## Validate that .env has all required secrets
	@echo -e "$(CYAN)[*] Validating .env file...$(RESET)"
	@source $(SCRIPTS_DIR)/lib.sh && validate_env_file

.PHONY: test-tls
test-tls: ## Validate TLS certificate chain
	@echo -e "$(CYAN)[*] Validating TLS certificates...$(RESET)"
	@source $(SCRIPTS_DIR)/lib.sh && validate_tls
	@for domain in $(NEXUS_DOMAIN_N8N) $(NEXUS_DOMAIN_WEBUI); do \
	    BASENAME=$${domain%%.*}; \
	    openssl verify -CAfile $(NEXUS_TLS_DIR)/nexus-ca.crt $(NEXUS_TLS_DIR)/$$BASENAME.crt 2>/dev/null && \
	        echo -e "  $(GREEN)✓$(RESET) $$domain cert chain valid" || \
	        (echo -e "  \033[31m✗\033[0m $$domain cert chain INVALID"; exit 1); \
	done
	@echo -e "$(GREEN)[+] TLS chain validated.$(RESET)"

.PHONY: status
status: ## Show status of all nexus containers
	@echo -e "$(CYAN)[*] Container Status:$(RESET)"
	@podman ps -a --filter "name=$(NEXUS_STACK_PREFIX)" \
	    --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || \
	    echo "  No nexus containers found."

# ==============================================================================
# Maintenance
# ==============================================================================

.PHONY: clean
clean: ## Remove test artifacts
	@rm -f mock_api.log mock_audit.log
	@echo -e "$(GREEN)[+] Test artifacts cleaned.$(RESET)"

.PHONY: logs
logs: ## Tail logs from all nexus containers
	@podman ps --filter "name=$(NEXUS_STACK_PREFIX)" --format "{{.Names}}" | \
	    xargs -I{} podman logs -f --tail 50 {} 2>&1

.PHONY: help
help: ## Show this help
	@echo ""
	@echo -e "$(CYAN)Sentinel Nexus -- Operations Commands$(RESET)"
	@echo -e "$(CYAN)════════════════════════════════════$(RESET)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
	    awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-18s$(RESET) %s\n", $$1, $$2}'
	@echo ""
