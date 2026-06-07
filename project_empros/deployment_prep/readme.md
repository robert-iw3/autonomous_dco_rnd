# Sentinel Nexus -- Pre-Deployment Bundle Preparation

Produces a fully self-contained, integrity-verified archive for deploying the
entire Sentinel Nexus stack into an air-gapped (internet-isolated) environment.

**Supports Docker and Podman.** The runtime is auto-detected. Override with:
```bash
export NEXUS_CONTAINER_RUNTIME=podman   # or docker
```

---

## Two-Phase Workflow

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  PHASE A -- ONLINE (internet-connected preparation machine)                   │
│                                                                              │
│  make prep                                                                   │
│  ├── 01 pull_and_save_images.sh   -- pull 34 base/runtime → images/*.tar.gz   │
│  ├── 02 build_custom_images.sh    -- load bases, build 14 final images:       │
│  │       Rust services (6): nexus-ingress, worker-qdrant, worker-rules,      │
│  │                          worker-s3-archive, worker-soar, worker-rlhf      │
│  │       Python/Node  (4): nexus-hunter (model baked), nexus-n8n (CLIs),     │
│  │                         nexus-looking-glass (npm built), nexus-mlops      │
│  │       Infrastructure (4): nexus-nats, nexus-qdrant, nexus-haproxy,        │
│  │                            nexus-redis  → custom-images/*.tar.gz          │
│  ├── 03 download_python_deps.sh   -- pip download → wheels/                   │
│  ├── 04 download_ansible_deps.sh  -- ansible-galaxy → collections/            │
│  ├── 05 download_terraform_deps.sh-- tf providers → providers/                │
│  ├── 06 scan_all_images.sh        -- syft + grype on all 48 images            │
│  │                                  → scan/reports/                          │
│  ├── 07 hash_and_manifest.sh      -- sha256sums.txt + manifest.json           │
│  └── 08 package_bundle.sh         → nexus_bundle_<ts>.tar.gz                 │
│                                     + nexus_bundle_<ts>.tar.gz.sha256        │
└──────────────────────────────────────────────────────────────────────────────┘
                          │  (physical transport)
                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE B -- OFFLINE (air-gapped target machine)                      │
│                                                                     │
│  sha256sum -c nexus_bundle_<ts>.tar.gz.sha256                       │
│  tar -xzf nexus_bundle_<ts>.tar.gz                                  │
│  cd deployment_prep                                                 │
│                                                                     │
│  make deploy-offline                                                │
│  ├── 09 verify_bundle.sh    -- verify all SHA-256 hashes             │
│  ├── 10 load_images.sh      -- docker/podman load *.tar.gz           │
│  ├── install-deps           -- pip + ansible-galaxy offline          │
│  └── ../deploy.sh --offline -- full stack deployment                 │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Directory Layout

```
deployment_prep/
├── Makefile                    Phase orchestrator
├── README.md                   This file
├── .gitignore                  Excludes all downloaded artifacts
├── image_manifest.json         Canonical image registry (source of truth)
├── python_requirements.txt     Aggregated Python deps for offline install
├── ansible_requirements.yml    Ansible Galaxy collections
│
├── scripts/
│   ├── lib_container.sh        Docker/podman abstraction (sourced by all scripts)
│   ├── 01_pull_and_save_images.sh
│   ├── 02_build_custom_images.sh
│   ├── 03_download_python_deps.sh
│   ├── 04_download_ansible_deps.sh
│   ├── 05_download_terraform_deps.sh
│   ├── 06_scan_all_images.sh
│   ├── 07_hash_and_manifest.sh
│   ├── 08_package_bundle.sh
│   ├── 09_verify_bundle.sh     (run on target)
│   └── 10_load_images.sh       (run on target)
│
├── scan/
│   ├── Dockerfile              Anchore scanner build (syft 1.45.0 + grype 0.112.0)
│   ├── scan_config.json        Image list for scanning (32 images)
│   ├── deploy_anchore.py       Scan orchestrator (docker or podman)
│   ├── requirements.txt        tqdm, pyyaml, requests
│   └── reports/                Scan output (gitignored -- populated by script 06)
│
├── images/                     Runtime + build-base image archives (gitignored)
├── custom-images/              Custom Nexus image archives (gitignored)
├── wheels/                     Python wheel cache (gitignored)
├── collections/                Ansible collection archives (gitignored)
├── providers/                  Terraform provider mirror (gitignored)
└── manifests/
    ├── sha256sums.txt          SHA-256 of every bundle file (gitignored)
    └── deployment_manifest.json Full inventory with sizes + hashes (gitignored)
```

---

## Quick Start -- Online Phase

```bash
cd project_empros/deployment_prep

# Full end-to-end preparation (30–90 min depending on image sizes)
make prep

# Or run individual phases:
make pull          # Images only
make build         # Custom images only
make scan          # SBOM + vuln reports only (requires images pulled)
make hash          # Regenerate hashes only
make package       # Package existing artifacts into bundle
```

**Status check at any time:**
```bash
make status
```

---

## Quick Start -- Offline Phase (Air-Gapped Target)

```bash
# 1. Verify bundle before touching anything
sha256sum -c nexus_bundle_<timestamp>.tar.gz.sha256

# 2. Unpack
tar -xzf nexus_bundle_<timestamp>.tar.gz

# 3. Verify all internal artifacts
cd deployment_prep
make verify         # Checks every sha256sum inside the bundle

# 4. Load images + install deps + deploy
make deploy-offline

# Or step by step:
make load           # Load images into docker/podman
make install-deps   # Install Python wheels + Ansible collections
cd ..
bash deploy.sh --offline
```

---

## Scan Reports

All reports land in `deployment_prep/scan/reports/` after `make scan`:

| File pattern | Tool | Format |
|---|---|---|
| `<image>_SBOM.json` | syft | SPDX/CycloneDX SBOM |
| `<image>_SBOM.csv` | syft | Tabular component list |
| `<image>_vulnerabilities.json` | grype | CVE findings (JSON) |
| `<image>_vulnerabilities.csv` | grype | CVE findings (table) |
| `scan_summary.json` | deploy_anchore.py | Scan metadata |

Run scanner directly against a specific image:
```bash
cd scan/
# Docker
docker build -t nexus-anchore:latest .
docker run --rm -d --name nexus-anchore nexus-anchore:latest sleep infinity
docker exec nexus-anchore syft docker.io/opencti/platform:6.8.10 \
    --scope all-layers -o syft-json=reports/opencti_SBOM.json
docker rm -f nexus-anchore

# Podman (same commands, replace docker with podman)
```

---

## Integrity Model

Every artifact is hashed at preparation time (`make hash`):

```
deployment_prep/manifests/sha256sums.txt   -- one hash per file, relative paths
deployment_prep/manifests/deployment_manifest.json -- full inventory with sizes
nexus_bundle_<ts>.tar.gz.sha256            -- hash of the complete bundle archive
```

On the target, `make verify` (script 09) re-hashes every file and fails loudly
if anything mismatches. **Do not proceed with deployment if verification fails.**

---

## Runtime Override

All scripts and the Makefile respect `NEXUS_CONTAINER_RUNTIME`:

```bash
# Force docker
NEXUS_CONTAINER_RUNTIME=docker make prep

# Force podman
NEXUS_CONTAINER_RUNTIME=podman make deploy-offline
```

The lib_container.sh abstraction ensures identical behavior between runtimes.
Compose commands use `docker compose` (plugin), `docker-compose` (legacy),
`podman compose`, or `podman-compose` -- whichever is present.

---

## Build Context Rules

All internet downloads (cargo crates, pip packages, npm modules, apt packages,
CLI tools, HuggingFace model weights) happen during Phase A (`make build`).
The resulting images are fully self-contained -- no network calls at runtime.

### Rust services -- `build_context: "."`
Rust service Dockerfiles do `COPY . .` then `cargo build -p <service>`. Every
service Cargo.toml uses `{ workspace = true }`, meaning the workspace-root
`Cargo.toml` and `Cargo.lock` must be present in the build context. If
`build_context` were set to `services/core_ingress/` alone, cargo cannot resolve
workspace dependencies and the build fails.

**Rule:** All Rust services use `"build_context": "."` (repo root) with a
`"dockerfile": "services/<name>/Dockerfile"` pointer.

### Python / Node services -- service subdirectory
`nexus-hunter`, `nexus-n8n`, `nexus-looking-glass`, `nexus-mlops` each have a
self-contained `requirements.txt` or `package.json`. Build context is the service
directory. All deps (pip, npm, AWS/Azure/GCP CLIs, HuggingFace model weights)
are baked at build time; no internet access at runtime.

### Infrastructure images -- their own subdirectory
`nexus-nats`, `nexus-qdrant`, `nexus-haproxy`, `nexus-redis` build hardened
distroless variants from `infrastructure/<service>/Dockerfile`. The `build_args`
field pins versions (e.g., `QDRANT_VERSION=v1.13.6`) for reproducibility.

**Qdrant version pin:** `QDRANT_VERSION` must satisfy the qdrant-client
compatibility rule: `|client_minor - server_minor| ≤ 1`.
Check: `grep 'qdrant-client' Cargo.lock | head -1`

---

## Adding a New Image

1. Add an entry to `image_manifest.json` under `runtime_images`, `build_base_images`, or `custom_images`
   - Rust services: `"build_context": "."` + `"dockerfile": "services/<name>/Dockerfile"`
   - Python/Node/infra: `"build_context": "<dir>"` with `"dockerfile": "Dockerfile"`
   - Images with internet content baked in: use `custom_images` (not `runtime_images`)
   - Optional: `"build_args": {"KEY": "value"}` for ARG values
2. Add a corresponding entry to `scan/scan_config.json`
   - Local (Phase 2 built) images: add `"local": true`
3. Re-run `make pull` (or `make build`) + `make scan` + `make hash` + `make package`
