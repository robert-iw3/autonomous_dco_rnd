# ==============================================================================
# Sentinel Nexus -- Eval MiniLab
# ==============================================================================

.PHONY: help up down build logs status report clean

EVAL_MODEL ?= llama3.2:3b
COMPOSE    := $(shell command -v podman-compose 2>/dev/null || echo docker-compose)

help:
	@echo ""
	@echo "Sentinel Nexus -- MLOps Pre-Production Corpus Gate"
	@echo ""
	@echo "  USAGE:"
	@echo "    make up              Run the full end-to-end eval (main command)"
	@echo "    make build           Rebuild the eval-runner container image"
	@echo "    make logs            Follow eval-runner logs during a run"
	@echo "    make status          Show status of all containers"
	@echo "    make report          Print last report from reports/"
	@echo "    make down            Stop all containers"
	@echo "    make clean           Stop + remove volumes (fresh start)"
	@echo ""
	@echo "  CORPUS:"
	@echo "    Place new corpus JSONL in:  corpus_testing/<TTP>/name.jsonl"
	@echo "    Simulation Parquet goes to: simulation_data/<TTP>/name_sim.parquet (auto)"
	@echo ""
	@echo "  MODEL SELECTION (edit .env or pass env var):"
	@echo "    EVAL_MODEL=llama3.2:1b   make up    # fast, CPU-only"
	@echo "    EVAL_MODEL=llama3.2:3b   make up    # recommended default"
	@echo "    EVAL_MODEL=phi3:mini     make up    # strong reasoning"
	@echo ""

# Run the full eval end-to-end
up:
	@echo "[*] Starting Sentinel Nexus Eval MiniLab..."
	@echo "[*] Model: $(EVAL_MODEL)"
	@echo "[*] Compose: $(COMPOSE)"
	@echo ""
	EVAL_MODEL=$(EVAL_MODEL) $(COMPOSE) up --build --abort-on-container-exit --exit-code-from eval-runner
	@echo ""
	@$(MAKE) --no-print-directory report

# Rebuild container without running
build:
	$(COMPOSE) build eval-runner

# Follow eval-runner logs
logs:
	$(COMPOSE) logs -f eval-runner

# Container status
status:
	$(COMPOSE) ps

# Show last report
report:
	@LATEST=$$(ls -t reports/corpus_gate_*.json 2>/dev/null | head -1); \
	if [ -z "$$LATEST" ]; then \
	  echo "No reports found in reports/"; \
	else \
	  echo "=== Latest Report: $$LATEST ==="; \
	  python3 -c " \
import json, sys; \
d = json.load(open('$$LATEST')); \
print(f'Time:    {d[\"generated_at\"]}'); \
print(f'Model:   {d[\"model\"]}'); \
print(f'Elapsed: {d[\"elapsed_s\"]}s'); \
print(f'Verdict: {d[\"verdict\"]}'); \
print('Gates:'); \
[print(f'  {g}: pass={v[\"pass\"]} fail={v[\"fail\"]}') for g,v in d['gates'].items()]; \
" 2>/dev/null || cat "$$LATEST"; \
	fi

# Stop without removing volumes
down:
	$(COMPOSE) down

# Stop and wipe all eval state (model cache + Qdrant data)
clean:
	$(COMPOSE) down -v
	rm -f simulation_data/**/*_sim.parquet 2>/dev/null || true
	@echo "[+] Cleaned. Run 'make up' to start fresh."
