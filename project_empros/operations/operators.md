### Sentinel Nexus: End-to-End Command & Control (C&C) Architecture

This technical roadmap establishes the operational stack as a fluid, event-driven extension of the Agentic Swarm. Moving beyond static configurations, this architecture utilizes a fully ephemeral, closed-loop eradication framework that provides operators with a multi-model cross-examination interface, deterministic autonomous containment, and continuous reinforcement learning from operator feedback.

**Nexus Lifecycle**:

<p align="center">
  <img src="img/nexus_operations_lifecycle.svg" alt="Flow" width="100%" />
</p>

---

### 1. The Sovereign Inference Matrix & Air-Gapped Context

The architecture splits inference duties between specialized endpoints to optimize throughput and capability for the human operator, while strictly maintaining data sovereignty.

* **The Interrogator (Open WebUI):** Acts as the Tier-3 operator's unified intelligence terminal, configured via environment variables to multiplex connections.
  * *Local Sovereign (vLLM):* Connects to the high-throughput endpoint serving the fine-tuned Llama-3 model for localized spatial telemetry analysis.
  * *Frontier Models (Anthropic/Azure):* Exposed for complex, generalized tasks (e.g., reverse-engineering obfuscated payloads) without copying sensitive data outside the enclave.

* **Ephemeral Context Injection (The "Air-Gapped Brain"):** To prevent exposing the entire S3 Data Lake to an internet-facing UI, the orchestrator utilizes DuckDB upon boot to safely extract only the specific incident's network flows and ETW process trees from the Parquet archives. This highly scoped subset is injected directly into the Open WebUI volume (`workspace_context.json`), ensuring immediate, air-gapped contextual awareness. **The trigger script validates extraction success and deploys with an explicit empty-context marker on failure, preventing silent data gaps.**

### 2. Deterministic Capability Routing (`worker_soar` & n8n)

To prevent AI hallucination during critical containment actions, the architecture employs a deterministic, capability-based routing engine rather than relying on generative agents to format enterprise API requests.

* **The Capability Schema (`containment.toml`):** A master configuration file defines the exact HTTP contracts (endpoints, methods, headers, and Jinja templates) required for specific EDR and Firewall providers. **Each action includes validation rules, timeout configuration, retry policies (exponential backoff), and explicit success code whitelists.**
* **The Translation Engine (`worker_soar`):** The Rust-based worker subscribes to the `nexus.soar.execute` NATS topic. It evaluates the Swarm's verdict, looks up the active provider in `containment.toml`, validates required fields against the action schema, interpolates the threat telemetry into the template, and synthesizes a universal JSON `ExecutionPlan`.
* **Universal Execution (n8n):** `worker_soar` POSTs the pre-formatted `ExecutionPlan` to the n8n webhook. The n8n `Master_Containment` workflow operates as a resilient state machine with:
  * **Execution tracking:** An initialization node counts total steps and tracks success/failure counts.
  * **Error branching:** The HTTP execution node uses `continueErrorOutput` -- failed API calls route to a failure tracker instead of silently proceeding.
  * **Aggregate reporting:** A results aggregator computes a final status: `CONTAINED` (all pass), `PARTIAL_FAILURE` (mixed), or `FAILED` (all fail). The orchestrator callback includes the full error manifest.

### 3. Zero-Touch Ephemeral Identity (Traefik + Authentik)

Security operates on a Zero-Trust architecture. The Gateway and Identity Provider are completely ephemeral, spinning up from zero alongside the operational tools.

* **Infrastructure Bootstrap:** The edge proxy (Traefik) and the IdP (Authentik) are booted via `infra/docker-compose.yml` into the isolated `deepnet` network. Authentik's PostgreSQL and Redis databases are mapped to volatile `tmpfs` RAM mounts for speed and ephemerality. **All services include health checks, resource limits, restart policies, and dependency ordering (`depends_on: condition: service_healthy`).**
* **Declarative Provisioning:** Authentik utilizes a `nexus.yaml` Blueprint on boot to automatically provision the OAuth2 application, OIDC providers, Traefik ForwardAuth outpost, and cryptographic keys without human intervention. **Domain references in the blueprint are parameterized via environment variables, eliminating hardcoded URLs.**
* **Edge Interception & RBAC:** Traefik dynamically loads a **consolidated `middlewares.yaml`** defining ForwardAuth, security headers, IP allowlisting, rate limiting, and a `secured` middleware chain. Ephemeral UI containers reference the chain via labels (`secured@file`), immediately halting unauthenticated traffic, enforcing SSO, rate limits, and mapping identity headers to application roles.
* **TLS Hardening:** The `tls.yaml` configuration enforces TLS 1.2 minimum with an explicit cipher suite whitelist and strict SNI checking.

### 4. RLHF Feedback & Closed-Loop Teardown

The infrastructure enforces continuous learning and self-terminates to minimize the operational attack surface.

* **The RLHF Feedback Loop:** When an operator manually confirms or dismisses a Swarm verdict in Open WebUI, n8n routes the decision matrix to a dedicated webhook. The standalone `worker_rlhf` Rust microservice consumes this from NATS and spools a "Gold Label" Parquet dataset to continuously fine-tune the PPO Reward Model (Model D).
* **The Capstone Node:** The n8n Master workflow concludes with a callback node that POSTs the final status (`CONTAINED`, `PARTIAL_FAILURE`, or `FAILED`) along with the full execution report back to the orchestrator.
* **Scorched-Earth Purge:** Upon state resolution, the orchestrator executes `teardown-incident.sh`. The script:
  1. Tears down stacks in reverse dependency order (webui → n8n → infra).
  2. Verifies all nexus containers are stopped, force-removing stragglers.
  3. Purges ephemeral context files and n8n execution logs.
  4. Optionally performs a **deep clean** (`--deep`): secure-wipes the `.env` secrets file, removes all TLS material, and destroys the bridge network.

---

### 5. Centralized Configuration & Automation

All operational parameters flow from a **single `nexus.conf` file** at the repository root, eliminating multi-file hunts when changing domains, subnets, or resource limits.

* **`nexus.conf`:** Defines domains, network CIDR, TLS paths, S3 endpoints, container memory limits, health check timeouts, and the mock API port. Every script and Makefile target sources this file.
* **`scripts/lib.sh`:** A shared shell library providing colored logging, dependency checks, network bootstrap, health polling (both HTTP and container-level), compose lifecycle helpers, `.env` validation, TLS validation, and error trap handlers. All lifecycle scripts source this library.
* **`scripts/env-gen.sh`:** Generates **all** required secrets in one pass: interface keys, database passwords, OAUTH client credentials, EDR/FW API keys, and S3 credentials. Supports `--force` for regeneration with automatic backup of the existing file.

### 6. System Data Flow: Nexus to Operations

The lifecycle of an incident traces a strict, linear path from detection to infrastructure teardown, protected by distributed concurrency locks.

1. **Detection & Concurrency Lock:** The Swarm validates a critical threat. The orchestrator checks a Redis distributed lock (`nexus:active_operations_stacks`) to prevent a "boot storm" during massive lateral movement events.
2. **Pre-flight Validation:** The trigger script validates all prerequisites: required CLI tools, `.env` completeness (no placeholder values), and TLS certificate chain integrity. **Failures abort before any containers are created.**
3. **Contextual Bootstrap:** The script creates the bridge network (idempotent), extracts S3 Parquet context via DuckDB with explicit error handling, and deploys the Ingress/Identity stack.
4. **Health-Gated Deployment:** The script waits for Postgres and Redis health checks before polling Authentik readiness. Only after the IdP is confirmed healthy does it deploy n8n and WebUI. **Each container is verified healthy via its Docker health check before proceeding.**
5. **Playbook Drafting & Execution:** `worker_soar` validates the execution plan against `containment.toml` schemas, templates it, and transmits to n8n. The workflow executes each step with error branching and reports the aggregate result.
6. **Human-in-the-Loop Feedback:** Operator manual overrides are captured via webhook and forwarded to `worker_rlhf` for continuous model tuning.
7. **Teardown:** The orchestrator receives the containment confirmation, releases the Redis concurrency lock, logs the finalized report, and executes the teardown script with verified cleanup.

---

### 7. Operations Directory Architecture

The `/operations/` structure is strictly declarative, isolating the volatile interface layer from the durable forensic engine, with comprehensive automation and testing.

```text
/operations/
├── nexus.conf                         # Central config: domains, subnets, limits, timeouts
├── Makefile                           # Full lifecycle: init, deploy, teardown, test, status, logs
├── infra/                             # Core infrastructure definitions
│   ├── docker-compose.yml             # Traefik + Authentik (health checks, resource limits, depends_on)
│   ├── authentik-blueprint.yaml       # Zero-touch IdP provisioning (parameterized domains)
│   ├── containment.toml               # Capability schema with retry policies & validation rules
│   └── traefik/                       # Edge ingress (consolidated)
│       ├── traefik.yaml               # Static config: entrypoints, providers, access logging
│       ├── tls.yaml                   # Certificates, TLS 1.2+ enforcement, cipher suites
│       └── middlewares.yaml           # ForwardAuth, headers, IP allowlist, rate limit, chain
├── n8n/                               # Ephemeral SOAR engine
│   ├── docker-compose.yml             # Health check, resource limits, execution pruning
│   └── workflows/
│       └── Master_Containment.json    # Error branching, failure tracking, aggregate reporting
├── webui/                             # Sovereign chat interface
│   ├── docker-compose.yml             # Health check, resource limits, SSO-only auth
│   ├── config/
│   │   └── config.yml                 # Multi-model routing, OIDC, role management
│   └── data/                          # Persistent workspace + injected incident context
├── sso/                               # SSO provider definitions (legacy/client reference)
│   └── authentik-provider.yaml
└── scripts/                           # Lifecycle automation & testing
    ├── lib.sh                         # Shared library: logging, health, validation, cleanup
    ├── env-gen.sh                     # Complete secrets generation (all keys, --force support)
    ├── cert-gen.sh                    # Configurable TLS CA + per-domain certs (--force support)
    ├── mock_containment_api.py        # Mock EDR/FW with health endpoint, audit trail, latency sim
    ├── trigger-incident.sh            # Pre-flight → context → infra → health gate → interfaces
    └── teardown-incident.sh           # Reverse teardown → verify → purge → optional deep clean
```

### 8. Make Targets

| Target | Description |
|---|---|
| `make init` | Generate secrets, TLS certs, and bridge network |
| `make deploy EVENT_ID=<id>` | Full stack deployment for an incident |
| `make teardown EVENT_ID=<id>` | Graceful teardown with verification |
| `make teardown EVENT_ID=<id> DEEP=1` | Deep clean: wipe secrets, certs, network |
| `make redeploy EVENT_ID=<id>` | Teardown + deploy in one command |
| `make test` | Run all tests (lint + containment) |
| `make test-lint` | Validate all YAML, TOML, and JSON configs |
| `make test-containment` | EDR/FW pipeline: happy path, auth rejection, validation, audit |
| `make test-env` | Validate `.env` completeness |
| `make test-tls` | Validate TLS certificate chain |
| `make status` | Show all nexus container statuses |
| `make logs` | Tail logs from all running containers |
| `make clean` | Remove test artifacts |

**State Persistence Rules:** The infrastructure and interface containers are entirely ephemeral; only forensic artifacts persist. n8n workflows are mounted as read-only volumes. Open WebUI chat history and RAG preferences are mapped to a persistent host volume that survives the teardown sequence.