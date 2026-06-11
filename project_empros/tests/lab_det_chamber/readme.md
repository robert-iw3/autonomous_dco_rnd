# Lab: Det Chamber — live acquisition & detonation lifecycle

Dockerized test environment that mocks the real det_chamber deployment and proves
the full **acquire → deliver → detonate → enrich → verdict** lifecycle. Built
test-first (TDD) and cumulatively: every phase adds tests + the deployment service
it needs, and the whole suite must stay green before the next phase lands.

See the build plan and per-phase contracts in
`project_empros/planning_docs/DET_CHAMBER_INTEGRATION_PLAN.md`.

## Run

Fast (host pytest, Phase 1 contract tests only — no containers):
```bash
cd project_empros
pytest tests/lab_det_chamber/ -v
```

Dockerized (mocks the deployment; the way CI runs it):
```bash
cd project_empros/tests/lab_det_chamber
docker compose up --build --abort-on-container-exit lab-runner
# or via the section runner:
cd project_empros/tests && ./run_tests.sh --section detchamber
```

## Mocked deployment topology (grows per phase)

| Service | Phase | Role |
|---|---|---|
| `lab-runner` | 1 | Deployable engine image (Linux stand-in); runs the cumulative pytest suite |
| `nats` | 2 | Message bus: `nexus.acquire.request` / `nexus.detonation.intake` / `nexus.alerts.detonation` |
| `minio` | 2 | Quarantine bucket substrate (`s3://nexus-quarantine/<incident>/`) |
| `intake` | 2 | `intake_service` — pulls artifact, verifies `sha256==manifest`, runs engine |
| `linux-sandbox` | 3 | ELF dynamic analyzer; proves `os_family` routing |
| `mock-endpoint` | 4 | SSH/WinRM target the acquisition agent deploys to (holds a benign fixture) |
| `swarm-stub` | 5 | Consumes detonation results, returns a verdict |

Windows-only engine pieces (pywin32 / Procmon / Magnet / Volatility) are imported
lazily and stubbed in tests (`DETCHAMBER_ENGINE_MOCK=1`), so the lifecycle runs on
Linux CI without live malware — fixtures are benign EICAR-style PE / ELF samples.

## Test files

| File | Phase | Proves |
|---|---|---|
| `test_engine_singlefile.py` | 1 | Config-driven paths (defaults<toml<env), `--malware` single-file selection, engine is Linux-importable with no hard-coded paths / import-time side effects |
| `test_repo_layout.py` | 1 (refactor) | Single canonical engine (no PS clone), no orphan CI, compose uses only defined engine flags, IaC relocated to `infrastructure/`, Windows engine image ships the config modules |
| `test_iac_isolation.py` | 1 (refactor) | **Network isolation**: compose `internal:true`, k8s default-deny NetworkPolicy + no host network, terraform private switch / isolated port group (never internet-connected). **Deployability**: terraform fmt, yamllint, ansible-lint, multi-doc YAML parse (real validators run in the dockerized lab) |
| `test_intake_custody.py` | 2 | Intake **chain of custody**: detonate only byte-identical manifested artifacts (sha256+size); custody failure ⇒ no detonation + `custody_failed`; os_family routing; `nexus.detonation.intake`→`nexus.alerts.detonation` envelope |
| `test_quarantine_bucket.py` | 2 | Quarantine bucket is KMS-encrypted, versioned, auto-expiring, non-public, TLS-only |
| `test_linux_analyzer.py` | 3 | ELF static parse (no execution) + dynamic sections; uniform file-record envelope |
| `test_os_routing.py` | 3 | `engine_runner` dispatch: linux→ELF analyzer, windows→PE engine; both emit the shared envelope; end-to-end via `handle_intake` |
| `test_linux_sandbox_isolation.py` | 3 | KVM/libvirt detonation network is isolated (`mode=none`, no NAT/route egress) |
| `test_acquire_core.py` | 4 | Acquisition path-safety (deny-list/traversal/wildcard/size) + manifest + zip; never executes; intake-consumable |
| `test_acquire_worker.py` | 4 | Worker vet→dispatch→upload→emit intake; denied path never dispatches; seam into intake+detonation |
| `test_acquire_agents.py` | 4 | On-endpoint agents (bash/PS) hash+zip+manifest, never execute; `acquire_artifact` provider action |
| `test_restore_playbooks.py` | 4+ | FP restore: eradication journals quarantines; `06_restore` reverses isolation + sha-verified file restore |
| `test_phase6_deploy.py` | 6 | DC-N4 renames (det-chamber) + intake `/metrics` (DC-F5) |
| `test_acquire_detonate_lifecycle.py` | 7 | **Capstone**: full lifecycle end to end (trigger→acquire→custody→detonate→verdict) + safety negatives |

Swarm-side Phase 5 (schemas, acquire tool, enrichment) is tested in `tests/lab_agentic_swarm/
test_acquire_detonate_integration.py`; the capstone re-exercises those real modules in-container.

The IaC validators (`terraform`, `yamllint`, `ansible-lint`, `PyYAML`) are installed in
`Dockerfile.detchamber` and run for real in the dockerized lab; on a bare host that lacks them
they skip, so `pytest tests/lab_det_chamber/` still passes the structural subset.
