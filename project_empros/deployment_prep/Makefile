# ==============================================================================
# deployment_prep/Makefile
# Orchestrates online (preparation) and offline (target) phases.
#
# ONLINE (internet-connected prep machine):
#   make prep              -- full end-to-end: pull → build → deps → cargo-audit →
#                             supply-chain → scan → hash → package
#   make pull              -- pull and save all runtime + build-base images
#   make build             -- build and save all custom Nexus images
#   make deps              -- download Python wheels, Ansible collections, Terraform providers
#   make cargo-audit       -- run cargo audit on all Rust workspaces (Phase 5b)
#   make supply-chain      -- run GuardDog Python supply-chain scan (Phase 5c)
#   make scan              -- run syft + grype on all images
#   make hash              -- generate sha256sums.txt + deployment_manifest.json
#   make package           -- tar all artifacts into nexus_bundle_<timestamp>.tar.gz
#
# OFFLINE (air-gapped target machine):
#   make verify            -- verify bundle SHA-256 integrity before deployment
#   make load              -- load all image tarballs into docker/podman
#   make install-deps      -- install Python wheels + Ansible collections offline
#   make deploy-offline    -- verify + load + then call ../deploy.sh --offline
#
# Environment variables:
#   NEXUS_CONTAINER_RUNTIME=docker|podman   override auto-detection
#   SCAN_WORKERS=N                          concurrent scan workers (default: 4)
#   CARGO_AUDIT_DENY=critical|high|all|none deny threshold for Rust audits (default: critical)
#   GUARDDOG_DENY=true|false                block on Python supply-chain findings (default: false)
# ==============================================================================

SHELL := /usr/bin/env bash
.ONESHELL:

SCRIPTS_DIR := scripts
SCAN_WORKERS ?= 4

# -- Online phase --------------------------------------------------------------

.PHONY: prep pull build deps deps-python deps-ansible deps-terraform \
        cargo-audit supply-chain scan hash package

prep: pull build deps cargo-audit supply-chain scan hash package
	@echo ""
	@echo "[+] prep complete -- bundle ready for transport."

pull:
	@echo "[*] Phase 1: Pull + save runtime and build-base images..."
	bash $(SCRIPTS_DIR)/01_pull_and_save_images.sh

build:
	@echo "[*] Phase 2: Build + save custom Nexus images..."
	bash $(SCRIPTS_DIR)/02_build_custom_images.sh

deps: deps-python deps-ansible deps-terraform

deps-python:
	@echo "[*] Phase 3: Download Python wheels..."
	bash $(SCRIPTS_DIR)/03_download_python_deps.sh

deps-ansible:
	@echo "[*] Phase 4: Download Ansible collections..."
	bash $(SCRIPTS_DIR)/04_download_ansible_deps.sh

deps-terraform:
	@echo "[*] Phase 5: Mirror Terraform providers..."
	bash $(SCRIPTS_DIR)/05_download_terraform_deps.sh

cargo-audit:
	@echo "[*] Phase 5b: Cargo audit + lockfile verification (all Rust workspaces)..."
	bash $(SCRIPTS_DIR)/05b_cargo_audit.sh

supply-chain:
	@echo "[*] Phase 5c: Python supply-chain scan (GuardDog)..."
	bash $(SCRIPTS_DIR)/05c_scan_python_supply_chain.sh

scan:
	@echo "[*] Phase 6: Syft + Grype image scans..."
	bash $(SCRIPTS_DIR)/06_scan_all_images.sh --workers $(SCAN_WORKERS)

hash:
	@echo "[*] Phase 7: Generate SHA-256 manifest..."
	bash $(SCRIPTS_DIR)/07_hash_and_manifest.sh

package:
	@echo "[*] Phase 8: Package air-gap bundle..."
	bash $(SCRIPTS_DIR)/08_package_bundle.sh

# -- Offline phase (run on air-gapped target) ----------------------------------

.PHONY: verify load install-deps deploy-offline

verify:
	@echo "[*] Verifying bundle integrity..."
	bash $(SCRIPTS_DIR)/09_verify_bundle.sh

load:
	@echo "[*] Loading images into container runtime..."
	bash $(SCRIPTS_DIR)/10_load_images.sh

install-deps:
	@echo "[*] Installing Python wheels offline..."
	pip install --no-index --find-links wheels/ -r python_requirements.txt
	@echo "[*] Installing Ansible collections offline..."
	ansible-galaxy collection install --offline -r ansible_requirements.yml -p collections/ 2>/dev/null || true

deploy-offline: verify load install-deps
	@echo "[*] Launching offline deployment..."
	cd .. && bash deploy.sh --offline

# -- Helpers -------------------------------------------------------------------

.PHONY: status clean-artifacts validate

status:
	@echo "=== deployment_prep/ Status ==="
	@echo "Runtime images:   $$(ls images/*.tar.gz 2>/dev/null | wc -l) archives"
	@echo "Custom images:    $$(ls custom-images/*.tar.gz 2>/dev/null | wc -l) archives"
	@echo "Python wheels:    $$(ls wheels/*.whl 2>/dev/null | wc -l) wheels"
	@echo "Ansible colls:    $$(ls collections/*.tar.gz 2>/dev/null | wc -l) archives"
	@echo "Scan reports:     $$(ls scan/reports/*.json 2>/dev/null | wc -l) reports"
	@echo "Supply chain:     $$(ls supply_chain/reports/*.json supply_chain/reports/*.txt 2>/dev/null | wc -l) reports"
	@echo "Bundles:          $$(ls nexus_bundle_*.tar.gz 2>/dev/null | wc -l) bundles"

validate:
	@echo "[*] Running deployment prep validation..."
	python3 $(SCRIPTS_DIR)/validate_deployment.py

clean-artifacts:
	@echo "[!] Removing all downloaded artifacts (keeps scripts, manifests, configs)..."
	rm -rf images/ custom-images/ wheels/ collections/ providers/
	rm -rf scan/reports/
	rm -rf supply_chain/reports/
	rm -f nexus_bundle_*.tar.gz nexus_bundle_*.tar.gz.sha256
	@echo "[+] Clean complete."
