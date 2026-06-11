# Det Chamber

The detonation chamber for the Sentinel Nexus platform. When the agentic swarm
confirms, **during an investigation**, that a file on a Linux/Windows host is a true
positive, an acquisition agent grabs that file, ships it to the Det Chamber, and the
chamber detonates it in an isolated VM and returns a verdict the swarm uses to harden
its conclusion and (if warranted) drive evidence-backed containment.

This component owns the **engine** (analysis), the **intake service** (the bridge from
an acquired artifact to a detonation), and its **deploy manifests**. VM provisioning
and IaC live under `infrastructure/`; the live-acquisition flow and operator surface are
wired through `analytics/llm_hunter`, `services/`, and `operations/`.

> Full design, phase status, and findings ledger:
> [`planning_docs/DET_CHAMBER_INTEGRATION_PLAN.md`](../planning_docs/DET_CHAMBER_INTEGRATION_PLAN.md).

## Where it sits in the pipeline

```
host_expert (file = TP) → nexus.acquire.request → worker_acquire → acquisition agent (SSH/WinRM)
   → artifact + manifest → s3://nexus-quarantine/<incident>/
   → nexus.detonation.intake → intake_service (THIS) → engine_runner
        → windows_engine (Windows VM pool)  |  linux_sandbox (KVM micro-VM)
   → nexus.alerts.detonation → swarm enrichment → verdict / containment
```

## Layout

```
det_chamber/
├─ engine/    detonation engine (analysis only; runs on the isolated analysis VMs)
│   ├─ malware_sandbox.py   Windows engine entrypoint (static PE/CAPA/YARA + dynamic Procmon/Magnet|Cuckoo/Vol)
│   ├─ linux_analyzer.py    Linux ELF analyzer (static ELF/CAPA/YARA + dynamic strace/net/Vol3)
│   ├─ engine_runner.py     os_family → analyzer dispatch (writes bytes, never executes here)
│   ├─ summary_schema.py    the shared result envelope both platforms emit
│   ├─ sandbox_config.py    config resolution (defaults < detchamber.toml < DETCHAMBER_* env)
│   ├─ targets.py           single-file (--malware) vs whole-dir selection
│   └─ compile_yara_rules.py / filter_yara_rules.ps1 / download_tools.ps1   (image-build assets)
├─ intake/    intake_service.py (NATS in/out, chain-of-custody verify), manifest.py
├─ config/    detchamber.toml
└─ deploy/    Dockerfile.windows-engine, Dockerfile.intake, docker-compose.yml, kubernetes-deployment.yaml
```

Provisioning / IaC (not here — owned by the platform):
- `infrastructure/terraform/det_chamber/` — Windows VM (Hyper-V/VMware, private switch) + Linux KVM
  sandbox (isolated libvirt net) + the `nexus-quarantine` S3 bucket.
- `infrastructure/ansible/roles/det_chamber_sandbox/` (Windows) and `det_chamber_linux/` (Linux).

## Configuration

Everything is config-driven — no hard-coded paths. Resolution order is
**built-in defaults < `config/detchamber.toml` < `DETCHAMBER_*` env** (env wins so container/
orchestration deploys override without a rebuild). See `engine/sandbox_config.py`.

| Setting | TOML key (`[detchamber]`) | Env | Default |
|---|---|---|---|
| Sample intake dir | `malware_dir` | `DETCHAMBER_MALWARE_DIR` | `C:\Malware` |
| Output dir | `collection_dir` | `DETCHAMBER_COLLECTION_DIR` | `C:\Collections` |
| Tools dir | `tools_dir` | `DETCHAMBER_TOOLS_DIR` | `E:\Tools\Windows` |
| Detonation window (s) | `pcap_time` | `DETCHAMBER_PCAP_TIME` | `180` |
| Evidence tool | `evidence_tool` | `DETCHAMBER_EVIDENCE_TOOL` | `magnet` |
| Network simulation | `simulate_network` | `DETCHAMBER_SIMULATE_NETWORK` | `false` |

## Running the engine

```bash
# Detonate ONE acquired artifact (what the intake service invokes):
python engine/malware_sandbox.py --config config/detchamber.toml --malware evil.exe

# Whole-directory batch (omit --malware):
python engine/malware_sandbox.py --config config/detchamber.toml --parallel 4 --simulate-network
```
Both Windows and Linux analyzers emit the same envelope
(`summary_schema`: `{timestamp, host_ip, files:[{file, static, dynamic}]}`).

## Security & isolation

A detonation host must never let malware propagate. Enforced across every IaC layer and
asserted by the tests:
- **No network egress** — Windows VM on a PRIVATE Hyper-V switch / isolated VMware port group;
  Linux VM on an isolated libvirt network (`mode="none"`); k8s default-deny `NetworkPolicy`;
  compose `internal: true`. The terraform variable validations *refuse* the internet-connected
  `"Default Switch"` / `"VM Network"`.
- **Chain of custody** — the intake service detonates only bytes whose `sha256`+size match the
  acquisition manifest; a mismatch yields `custody_failed` and **no detonation** (the engine is
  never called). See `intake/manifest.py`, `intake/intake_service.py`.
- **Quarantine bucket** — own KMS key, versioned, auto-expiring, public-access-blocked, TLS-only.
- **Never executed off the sandbox** — acquisition copies bytes only; `engine_runner` writes the
  sample to disk but never runs it; the sample executes solely inside the isolated VM.

## Testing

Test-first (TDD). The dockerized lab mocks the real deployment and runs real IaC validators
(terraform/yamllint/ansible-lint) so the infrastructure is proven valid + isolated.

```bash
# Fast host run (structural subset):
cd project_empros && pytest tests/lab_det_chamber/ -v

# Dockerized (the way CI runs it):
cd project_empros/tests && ./run_tests.sh --section detchamber
```
Lab details + per-file coverage: [`tests/lab_det_chamber/readme.md`](../tests/lab_det_chamber/readme.md).
