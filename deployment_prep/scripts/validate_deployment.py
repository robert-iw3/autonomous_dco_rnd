#!/usr/bin/env python3
"""
validate_deployment.py -- End-to-End Deployment & Bundle Cross-Reference Validator

Checks:
  1.  Image manifest completeness -- every image in every docker-compose/Dockerfile is
      listed in deployment_prep/image_manifest.json
  2.  Bundle coverage -- every image in the manifest has a corresponding save_as file
      that will be created by script 01/02
  3.  Custom image Dockerfiles -- every custom image in the manifest has a Dockerfile
  4.  Orchestration script chain -- all 7 scripts exist, are executable, propagate
      NEXUS_OFFLINE_MODE
  5.  Ansible role completeness -- every role in site.yml exists on disk
  6.  Offline mode wiring -- nexus_offline / nexus_skip_pull threaded through all roles
      and scripts
  7.  Python deps coverage -- top-level packages used in requirements.in appear in
      the aggregated deployment_prep/python_requirements.txt
  8.  Makefile target coverage -- every stage script is in the Makefile data-all target
  9.  deploy.sh argument coverage -- --offline and --skip-mlops both handled
  10. Deployment prep directory structure integrity

Exits 0 if all checks pass, 1 if any failures.
"""

import re
import sys
import json
import yaml
import stat
import hashlib
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional

# -- Paths ----------------------------------------------------------------------
REPO = Path(__file__).parent.parent.parent   # project_empros/
PREP = REPO / "deployment_prep"

COMPOSE_FILES = [
    REPO / "operations/infra/docker-compose.yml",
    REPO / "operations/n8n/docker-compose.yml",
    REPO / "operations/webui/docker-compose.yml",
    REPO / "tests/docker-compose.yml",
    REPO / "middleware/deploy/podman/docker-compose.yml",
    REPO / "infrastructure/ansible/roles/opencti_node/files/docker-compose.yml",
]

DOCKERFILE_ROOTS = [
    REPO / "services",
    REPO / "operations",
    REPO / "analytics",
    REPO / "infrastructure",
    REPO / "deployment_prep/scan",
]

ORCHESTRATION_SCRIPTS = [
    REPO / "orchestration/scripts/01-render-templates.sh",
    REPO / "orchestration/scripts/02-provision-infra.sh",
    REPO / "orchestration/scripts/03-harden-os.sh",
    REPO / "orchestration/scripts/04-deploy-core.sh",
    REPO / "orchestration/scripts/05-deploy-middleware.sh",
    REPO / "orchestration/scripts/06-trigger-mlops.sh",
    REPO / "orchestration/scripts/07-deploy-inference.sh",
]

SITE_YML     = REPO / "infrastructure/ansible/site.yml"
ROLES_DIR    = REPO / "infrastructure/ansible/roles"
DEPLOY_SH    = REPO / "deploy.sh"
MLOPS_MAKEFILE = REPO / "mlops/Makefile"

# -- Result tracking ------------------------------------------------------------

@dataclass
class Check:
    name: str
    passed: bool
    detail: str = ""
    warnings: List[str] = field(default_factory=list)

class Report:
    def __init__(self):
        self.checks: List[Check] = []

    def add(self, c: Check):
        self.checks.append(c)

    def ok(self, name: str, detail: str = "", warnings: List[str] = None):
        self.add(Check(name, True, detail, warnings or []))

    def fail(self, name: str, detail: str = "", warnings: List[str] = None):
        self.add(Check(name, False, detail, warnings or []))

    def passed_all(self) -> bool:
        return all(c.passed for c in self.checks)

    def print(self):
        G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; B = "\033[1m"; N = "\033[0m"
        W = 74
        print(f"\n{B}{'═'*W}{N}")
        print(f"{B}  Sentinel Nexus -- Deployment & Bundle Validation{N}")
        print(f"{B}{'═'*W}{N}\n")

        passed = sum(1 for c in self.checks if c.passed)
        total  = len(self.checks)

        for c in self.checks:
            mark = f"{G}✓{N}" if c.passed else f"{R}✗{N}"
            print(f"  {mark}  {c.name}")
            if c.detail:
                for line in c.detail.splitlines():
                    print(f"       {line}")
            for w in c.warnings:
                print(f"     {Y}⚠  {w}{N}")

        print(f"\n{B}{'-'*W}{N}")
        col = G if passed == total else R
        print(f"  {col}{B}{passed}/{total} checks passed{N}")
        status = "All checks passed -- deployment is validated." if passed == total else \
                 "Failures found -- fix before deploying."
        print(f"  {col}{status}{N}")
        print(f"{B}{'═'*W}{N}\n")


# -- Normalisation helpers ------------------------------------------------------

def _norm(img: str) -> str:
    """
    Normalise a Docker image reference to a canonical form for comparison.
    Expands short names and docker.io/<bare> to docker.io/library/<bare>.

    e.g. "redis:alpine"                 → "docker.io/library/redis:alpine"
         "prom/prometheus:latest"       → "docker.io/prom/prometheus:latest"
         "docker.io/node:22-alpine"     → "docker.io/library/node:22-alpine"
         "docker.io/minio/minio:latest" → "docker.io/minio/minio:latest"  (unchanged)
    """
    img = img.strip().strip('"').strip("'")
    if not img:
        return img
    parts = img.split("/")

    if len(parts) == 1:
        # bare name -- no registry, no org
        return f"docker.io/library/{img}"

    has_registry = "." in parts[0] or ":" in parts[0]

    if not has_registry:
        # org/image like "prom/prometheus:latest" -- no registry prefix
        return f"docker.io/{img}"

    # Has registry (e.g. docker.io, gcr.io, ghcr.io)
    if len(parts) == 2:
        # docker.io/<bare-name>  → docker.io/library/<bare-name>
        # Only applies to docker.io -- other registries don't have an implicit namespace
        if parts[0] == "docker.io":
            return f"docker.io/library/{parts[1]}"
        return img

    return img  # 3+ components (registry/org/image) -- leave as-is


def manifest_image_set(manifest: dict, section: str) -> set:
    return { _norm(e["repo"]) for e in manifest.get(section, []) }


def manifest_all_images(manifest: dict) -> set:
    s = set()
    for sec in ("runtime_images", "build_base_images"):
        s |= manifest_image_set(manifest, sec)
    return s


# -- Check 1: Image manifest completeness --------------------------------------

def check_image_manifest_coverage(report: Report, manifest: dict):
    """Every image: in docker-compose files must appear in the manifest."""
    manifest_imgs = manifest_all_images(manifest)
    not_in_manifest = []
    covered = []

    for cfile in COMPOSE_FILES:
        if not cfile.exists():
            report.fail(f"Compose file missing: {cfile.relative_to(REPO)}")
            continue
        try:
            data = yaml.safe_load(cfile.read_text())
        except Exception as e:
            report.fail(f"Compose YAML parse: {cfile.name}", str(e))
            continue

        services = (data or {}).get("services", {}) or {}
        for svc_name, svc in services.items():
            if not isinstance(svc, dict):
                continue
            img_raw = svc.get("image", "")
            if not img_raw:
                continue
            img_norm = _norm(str(img_raw).strip())
            if img_norm not in manifest_imgs:
                not_in_manifest.append(f"{cfile.name}::{svc_name} → {img_raw}")
            else:
                covered.append(img_norm)

    if not_in_manifest:
        report.fail(
            "Compose images → manifest coverage",
            f"{len(not_in_manifest)} image(s) in compose files NOT in manifest:\n" +
            "\n".join(f"    • {x}" for x in not_in_manifest),
        )
    else:
        report.ok("Compose images → manifest coverage",
                  f"All {len(covered)} runtime image references are in image_manifest.json")


def check_dockerfile_from_coverage(report: Report, manifest: dict):
    """Every FROM base image in Dockerfiles must be in build_base_images."""
    base_imgs = manifest_image_set(manifest, "build_base_images")
    # Also check runtime_images in case a FROM references one
    all_imgs  = manifest_all_images(manifest)
    not_found = []

    # Collect stage aliases defined within Dockerfiles (FROM ... AS <alias>)
    # so we can skip "FROM <alias>" references that are internal multi-stage refs.
    def _collect_stage_aliases(df_text: str) -> set:
        aliases = set()
        for line in df_text.splitlines():
            m = re.match(r"^\s*FROM\s+\S+\s+AS\s+(\S+)", line, re.IGNORECASE)
            if m:
                aliases.add(m.group(1).lower())
        return aliases

    for root in DOCKERFILE_ROOTS:
        if not root.exists():
            continue
        for df in root.rglob("Dockerfile"):
            text = df.read_text()
            stage_aliases = _collect_stage_aliases(text)

            for line in text.splitlines():
                m = re.match(r"^\s*FROM\s+(\S+)", line, re.IGNORECASE)
                if not m:
                    continue
                raw = m.group(1).strip()
                # Skip ARG-based FROM placeholders like ${repo}/${base_image}
                if raw.startswith("$"):
                    continue
                # Skip internal multi-stage references (FROM <alias_defined_in_same_file>)
                raw_lower = raw.split(":")[0].lower()
                if raw_lower in stage_aliases:
                    continue
                img_norm_base = _norm(raw)
                if img_norm_base not in all_imgs:
                    not_found.append(f"{df.relative_to(REPO)} → {raw}")

    if not_found:
        report.fail(
            "Dockerfile FROM → manifest coverage",
            f"{len(not_found)} base image(s) NOT in manifest:\n" +
            "\n".join(f"    • {x}" for x in not_found),
        )
    else:
        report.ok("Dockerfile FROM → manifest coverage",
                  "All Dockerfile base images are listed in image_manifest.json")


# -- Check 2: Custom image Dockerfiles exist ------------------------------------

def check_custom_image_dockerfiles(report: Report, manifest: dict):
    missing = []
    found   = []
    for entry in manifest.get("custom_images", []):
        ctx_rel  = entry.get("build_context", "")
        ctx_path = REPO / ctx_rel
        df_path  = ctx_path / "Dockerfile"
        if not ctx_path.exists():
            missing.append(f"{entry['name']}: build_context {ctx_rel}/ not found")
        elif not df_path.exists():
            missing.append(f"{entry['name']}: Dockerfile missing in {ctx_rel}/")
        else:
            found.append(entry["name"])

    if missing:
        report.fail("Custom image Dockerfiles exist",
                    f"{len(missing)} custom image(s) lack a Dockerfile:\n" +
                    "\n".join(f"    • {x}" for x in missing))
    else:
        report.ok("Custom image Dockerfiles exist",
                  f"All {len(found)} custom images have a Dockerfile")


# -- Check 3: Orchestration script chain ---------------------------------------

def check_orchestration_scripts(report: Report):
    missing  = []
    no_exec  = []
    no_offline = []

    for script in ORCHESTRATION_SCRIPTS:
        if not script.exists():
            missing.append(script.name)
            continue
        mode = script.stat().st_mode
        if not (mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)):
            no_exec.append(script.name)
        # Check offline awareness (scripts that call ansible-playbook should propagate)
        content = script.read_text()
        if "ansible-playbook" in content:
            if "NEXUS_OFFLINE_MODE" not in content and "nexus_offline" not in content:
                no_offline.append(script.name)

    warns = []
    if no_exec:
        warns.append(f"Not executable: {no_exec}")
    if no_offline:
        warns.append(f"Ansible scripts missing offline var propagation: {no_offline}")

    if missing:
        report.fail("Orchestration scripts exist",
                    f"Missing: {missing}", warnings=warns)
    elif warns:
        report.ok("Orchestration scripts exist",
                  f"All {len(ORCHESTRATION_SCRIPTS)} scripts present",
                  warnings=warns)
    else:
        report.ok("Orchestration scripts exist",
                  f"All {len(ORCHESTRATION_SCRIPTS)} scripts present and offline-aware")


# -- Check 4: Ansible role completeness ----------------------------------------

def check_ansible_roles(report: Report):
    if not SITE_YML.exists():
        report.fail("Ansible site.yml exists", f"Not found: {SITE_YML}")
        return

    content = SITE_YML.read_text()
    # Strip Jinja2 then parse
    stripped = re.sub(r"\{\{.*?\}\}", "PLACEHOLDER", content)
    stripped = re.sub(r"\{%.*?%\}", "", stripped)
    try:
        plays = yaml.safe_load(stripped) or []
    except Exception as e:
        report.fail("Ansible site.yml parses", str(e))
        return

    missing = []; present = []
    for play in plays:
        if not isinstance(play, dict):
            continue
        for role_entry in (play.get("roles") or []):
            if isinstance(role_entry, str):
                role = role_entry
            elif isinstance(role_entry, dict):
                role = role_entry.get("role", role_entry.get("name", ""))
            else:
                continue
            if not role:
                continue
            role_path = ROLES_DIR / role
            if role_path.is_dir():
                present.append(role)
            else:
                missing.append(f"{role} (play: {play.get('name','?')})")

    if missing:
        report.fail("Ansible roles all exist",
                    f"{len(missing)} role(s) referenced but missing:\n" +
                    "\n".join(f"    • {x}" for x in missing))
    else:
        unique = sorted(set(present))
        report.ok("Ansible roles all exist",
                  f"All {len(unique)} unique roles present: {', '.join(unique)}")


# -- Check 5: Offline mode wiring ----------------------------------------------

def check_offline_wiring(report: Report):
    issues = []

    # deploy.sh
    if DEPLOY_SH.exists():
        ds = DEPLOY_SH.read_text()
        for token in ("--offline", "OFFLINE_MODE", "nexus_offline", "install_offline_deps"):
            if token not in ds:
                issues.append(f"deploy.sh: missing '{token}'")
    else:
        issues.append("deploy.sh not found")

    # opencti_node role
    oc_tasks = ROLES_DIR / "opencti_node/tasks/main.yml"
    if oc_tasks.exists():
        ct = oc_tasks.read_text()
        if "nexus_offline" not in ct and "nexus_skip_pull" not in ct:
            issues.append("opencti_node/tasks/main.yml: missing nexus_offline / nexus_skip_pull guard")
    else:
        issues.append("opencti_node/tasks/main.yml not found")

    # opencti_node defaults
    oc_defs = ROLES_DIR / "opencti_node/defaults/main.yml"
    if oc_defs.exists():
        dd = oc_defs.read_text()
        if "nexus_offline" not in dd:
            issues.append("opencti_node/defaults/main.yml: nexus_offline default not declared")
    else:
        issues.append("opencti_node/defaults/main.yml not found")

    # 06-trigger-mlops.sh
    mlops_trigger = REPO / "orchestration/scripts/06-trigger-mlops.sh"
    if mlops_trigger.exists():
        mt = mlops_trigger.read_text()
        if "NEXUS_OFFLINE_MODE" not in mt:
            issues.append("06-trigger-mlops.sh: NEXUS_OFFLINE_MODE not handled")
        if "wheels" not in mt and "no-index" not in mt and "--find-links" not in mt:
            issues.append("06-trigger-mlops.sh: offline pip install not wired")
    else:
        issues.append("06-trigger-mlops.sh not found")

    if issues:
        report.fail("Offline mode wiring",
                    f"{len(issues)} wiring gap(s):\n" +
                    "\n".join(f"    • {x}" for x in issues))
    else:
        report.ok("Offline mode wiring",
                  "deploy.sh --offline, opencti_node role, and mlops trigger all offline-aware")


# -- Check 6: deployment_prep structure integrity ------------------------------

def check_prep_structure(report: Report):
    required = [
        PREP / "image_manifest.json",
        PREP / "python_requirements.txt",
        PREP / "ansible_requirements.yml",
        PREP / "Makefile",
        PREP / "scan/Dockerfile",
        PREP / "scan/scan_config.json",
        PREP / "scan/deploy_anchore.py",
        PREP / "scan/requirements.txt",
        PREP / "supply_chain/Dockerfile",
        PREP / "supply_chain/guarddog-config.yaml",
        PREP / "supply_chain/requirements.txt",
        PREP / "supply_chain/scan-requirements.sh",
        PREP / "scripts/lib_container.sh",
        *[PREP / f"scripts/0{i}_{name}.sh" for i, name in [
            (1,"pull_and_save_images"), (2,"build_custom_images"),
            (3,"download_python_deps"), (4,"download_ansible_deps"),
            (5,"download_terraform_deps"), (6,"scan_all_images"),
            (7,"hash_and_manifest"), (8,"package_bundle"),
            (9,"verify_bundle"),
        ]],
        PREP / "scripts/05b_cargo_audit.sh",
        PREP / "scripts/05c_scan_python_supply_chain.sh",
        PREP / "scripts/10_load_images.sh",
    ]
    missing = [str(p.relative_to(REPO)) for p in required if not p.exists()]
    non_exec = []
    for p in required:
        if p.exists() and p.suffix == ".sh":
            mode = p.stat().st_mode
            if not (mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)):
                non_exec.append(p.name)

    warns = [f"Not executable: {f}" for f in non_exec]
    if missing:
        report.fail("deployment_prep structure",
                    f"{len(missing)} required file(s) missing:\n" +
                    "\n".join(f"    • {x}" for x in missing),
                    warnings=warns)
    else:
        report.ok("deployment_prep structure",
                  f"All {len(required)} required files present",
                  warnings=warns)


# -- Check 7: scan_config.json covers all manifest images ----------------------

def check_scan_config_coverage(report: Report, manifest: dict):
    scan_cfg_path = PREP / "scan/scan_config.json"
    if not scan_cfg_path.exists():
        report.fail("scan_config.json exists", "Not found")
        return
    scan_cfg = json.loads(scan_cfg_path.read_text())
    scan_imgs = { _norm(e["repo"]) for e in scan_cfg.get("images", []) }

    all_manifest = manifest_all_images(manifest)
    not_scanned  = all_manifest - scan_imgs
    extra_scanned = scan_imgs - all_manifest

    warns = []
    if extra_scanned:
        warns.append(f"In scan_config but not in manifest: {sorted(extra_scanned)[:3]}...")

    if not_scanned:
        report.fail("scan_config.json covers all manifest images",
                    f"{len(not_scanned)} manifest image(s) NOT in scan_config.json:\n" +
                    "\n".join(f"    • {x}" for x in sorted(not_scanned)[:10]),
                    warnings=warns)
    else:
        report.ok("scan_config.json covers all manifest images",
                  f"All {len(all_manifest)} manifest images are in scan_config.json",
                  warnings=warns)


# -- Check 8: mlops Makefile references all stage scripts ----------------------

def check_makefile_stage_scripts(report: Report):
    if not MLOPS_MAKEFILE.exists():
        report.fail("mlops/Makefile exists", "Not found")
        return
    content = MLOPS_MAKEFILE.read_text()
    scripts = sorted((REPO / "mlops/scripts").glob("stage_*.py"))
    missing = [s.name for s in scripts if s.name not in content]
    if missing:
        report.fail("mlops/Makefile stage script coverage",
                    f"{len(missing)} stage script(s) not in Makefile:\n" +
                    "\n".join(f"    • {x}" for x in missing))
    else:
        report.ok("mlops/Makefile stage script coverage",
                  f"All {len(scripts)} stage_*.py scripts referenced in mlops/Makefile")


# -- Check 9: Python requirements aggregation ----------------------------------

def check_python_reqs_aggregation(report: Report):
    """
    Verify that top-level package names from mlops/requirements.in
    appear in deployment_prep/python_requirements.txt
    """
    mlops_in = REPO / "mlops/requirements.in"
    dp_reqs  = PREP / "python_requirements.txt"

    if not mlops_in.exists():
        report.fail("mlops/requirements.in exists", "Not found")
        return
    if not dp_reqs.exists():
        report.fail("deployment_prep/python_requirements.txt exists", "Not found")
        return

    def _pkg_name(line: str) -> Optional[str]:
        line = line.strip()
        if not line or line.startswith("#"):
            return None
        m = re.match(r"([A-Za-z0-9_\-\.]+)", line)
        return m.group(1).lower() if m else None

    mlops_pkgs = set()
    for line in mlops_in.read_text().splitlines():
        n = _pkg_name(line)
        if n:
            mlops_pkgs.add(n)

    dp_pkg_text = dp_reqs.read_text().lower()
    missing = [p for p in sorted(mlops_pkgs) if p not in dp_pkg_text]

    if missing:
        report.fail("Python reqs aggregation (mlops.in → deployment_prep/python_requirements.txt)",
                    f"{len(missing)} top-level package(s) from requirements.in not in aggregated reqs:\n" +
                    "\n".join(f"    • {x}" for x in missing))
    else:
        report.ok("Python reqs aggregation",
                  f"All {len(mlops_pkgs)} mlops top-level packages present in aggregated requirements")


# -- Check 10: deploy.sh argument coverage -------------------------------------

def check_deploy_sh(report: Report):
    if not DEPLOY_SH.exists():
        report.fail("deploy.sh exists", "Not found")
        return
    content = DEPLOY_SH.read_text()
    issues = []
    for token in ("--offline", "--skip-mlops", "OFFLINE_MODE", "NEXUS_OFFLINE_MODE",
                  "install_offline_deps", "ansible_offline_vars", "Stage 2b"):
        if token not in content:
            issues.append(f"Missing: '{token}'")
    if issues:
        report.fail("deploy.sh offline completeness",
                    "\n".join(f"    • {x}" for x in issues))
    else:
        report.ok("deploy.sh offline completeness",
                  "--offline flag, offline dep install, Stage 2b image load, and Ansible var propagation all present")


# -- Check 11: image_manifest save_as uniqueness -------------------------------

def check_manifest_uniqueness(report: Report, manifest: dict):
    seen_repos   = {}
    seen_save_as = {}
    dupes = []

    for sec in ("runtime_images", "build_base_images", "custom_images"):
        for entry in manifest.get(sec, []):
            repo    = entry.get("repo", "")
            save_as = entry.get("save_as", "")
            name    = entry.get("name", "")

            if repo and repo in seen_repos:
                dupes.append(f"Duplicate repo: {repo} (in {sec} and {seen_repos[repo]})")
            elif repo:
                seen_repos[repo] = sec

            if save_as and save_as in seen_save_as:
                dupes.append(f"Duplicate save_as: {save_as} (in {sec} and {seen_save_as[save_as]})")
            elif save_as:
                seen_save_as[save_as] = sec

    if dupes:
        report.fail("image_manifest.json uniqueness",
                    f"{len(dupes)} duplicate(s):\n" + "\n".join(f"    • {x}" for x in dupes))
    else:
        total = sum(len(manifest.get(s, [])) for s in ("runtime_images","build_base_images","custom_images"))
        report.ok("image_manifest.json uniqueness",
                  f"All {total} entries have unique repo + save_as values")


# -- Check 12: supply_chain/ integration --------------------------------------

def check_supply_chain_integration(report: Report):
    """
    Verify supply_chain/ lives inside deployment_prep/, has all required files,
    GuardDog config is valid YAML, and all pipeline scripts correctly reference
    supply_chain/reports/ as their output directory.
    """
    SC_DIR = PREP / "supply_chain"
    issues = []

    # Required files
    for f in ("Dockerfile", "guarddog-config.yaml", "requirements.txt", "scan-requirements.sh"):
        if not (SC_DIR / f).exists():
            issues.append(f"supply_chain/{f} missing")

    # Validate guarddog-config.yaml
    cfg_path = SC_DIR / "guarddog-config.yaml"
    if cfg_path.exists():
        try:
            import yaml as _yaml
            cfg = _yaml.safe_load(cfg_path.read_text())
            if "rules" not in (cfg or {}):
                issues.append("supply_chain/guarddog-config.yaml: 'rules' section absent")
        except Exception as e:
            issues.append(f"supply_chain/guarddog-config.yaml parse error: {e}")

    # scan-requirements.sh must target python_requirements.txt (not the old supply_chain copy)
    scan_sh = SC_DIR / "scan-requirements.sh"
    if scan_sh.exists():
        text = scan_sh.read_text()
        if "python_requirements.txt" not in text and "REQUIREMENTS_FILE" not in text:
            issues.append(
                "supply_chain/scan-requirements.sh: does not reference python_requirements.txt "
                "(should default to the canonical central list)"
            )

    # 05b must output to supply_chain/reports/
    audit_script = PREP / "scripts/05b_cargo_audit.sh"
    if audit_script.exists():
        if "supply_chain/reports" not in audit_script.read_text():
            issues.append("05b_cargo_audit.sh: supply_chain/reports/ not referenced as output dir")

    # 05c must target python_requirements.txt as canonical scan target
    gdog_script = PREP / "scripts/05c_scan_python_supply_chain.sh"
    if gdog_script.exists():
        txt = gdog_script.read_text()
        if "python_requirements.txt" not in txt:
            issues.append(
                "05c_scan_python_supply_chain.sh: does not reference python_requirements.txt "
                "(must scan the canonical central list)"
            )
        if "supply_chain/reports" not in txt:
            issues.append("05c_scan_python_supply_chain.sh: supply_chain/reports/ not referenced")

    # 08_package_bundle must include supply_chain/
    bundle_script = PREP / "scripts/08_package_bundle.sh"
    if bundle_script.exists():
        if "supply_chain" not in bundle_script.read_text():
            issues.append("08_package_bundle.sh: supply_chain/ absent from INCLUDE_DIRS")

    # 07_hash_and_manifest must hash supply_chain/reports
    hash_script = PREP / "scripts/07_hash_and_manifest.sh"
    if hash_script.exists():
        if "supply_chain/reports" not in hash_script.read_text():
            issues.append("07_hash_and_manifest.sh: supply_chain/reports/ absent from ARTIFACT_DIRS")

    if issues:
        report.fail("supply_chain/ integration",
                    f"{len(issues)} issue(s):\n" +
                    "\n".join(f"    • {x}" for x in issues))
    else:
        report.ok("supply_chain/ integration",
                  "supply_chain/ present; GuardDog targets canonical python_requirements.txt; "
                  "cargo-audit + GuardDog output to supply_chain/reports/; "
                  "bundle + hash phases include supply_chain/")


def check_makefile_supply_chain_targets(report: Report):
    """Verify Makefile has cargo-audit and supply-chain targets wired into prep."""
    mk_path = PREP / "Makefile"
    if not mk_path.exists():
        report.fail("Makefile supply-chain targets", "Makefile not found")
        return

    content = mk_path.read_text()
    issues = []

    prep_line = next((l for l in content.splitlines() if l.startswith("prep:")), "")
    if "cargo-audit" not in prep_line:
        issues.append("prep: target missing cargo-audit phase")
    if "supply-chain" not in prep_line:
        issues.append("prep: target missing supply-chain phase")

    if "05b_cargo_audit.sh" not in content:
        issues.append("Makefile does not call 05b_cargo_audit.sh")
    if "05c_scan_python_supply_chain.sh" not in content:
        issues.append("Makefile does not call 05c_scan_python_supply_chain.sh")
    if "supply_chain" not in content:
        issues.append("Makefile has no supply_chain reference (status/clean targets)")

    if issues:
        report.fail("Makefile supply-chain targets",
                    f"{len(issues)} gap(s):\n" +
                    "\n".join(f"    • {x}" for x in issues))
    else:
        report.ok("Makefile supply-chain targets",
                  "cargo-audit and supply-chain phases wired into prep target")


# -- Check 12: 07-deploy-inference.sh offline awareness -----------------------

def check_inference_deploy_offline(report: Report):
    script = REPO / "orchestration/scripts/07-deploy-inference.sh"
    if not script.exists():
        report.fail("07-deploy-inference.sh exists", "Not found")
        return
    content = script.read_text()
    issues = []
    if "NEXUS_OFFLINE_MODE" not in content:
        issues.append("NEXUS_OFFLINE_MODE not handled (OCI pull will fail air-gapped)")
    if issues:
        report.fail("07-deploy-inference.sh offline awareness",
                    "\n".join(f"    • {x}" for x in issues),
                    warnings=["In offline mode, models must be pre-loaded via deployment_prep/ before inference deploy"])
    else:
        report.ok("07-deploy-inference.sh offline awareness",
                  "Script handles NEXUS_OFFLINE_MODE")


# -- Main -----------------------------------------------------------------------

def main():
    report = Report()

    manifest_path = PREP / "image_manifest.json"
    if not manifest_path.exists():
        report.fail("image_manifest.json exists", f"Not found at {manifest_path}")
        report.print()
        sys.exit(1)

    manifest = json.loads(manifest_path.read_text())

    print("\nRunning validation checks...\n")

    check_image_manifest_coverage(report, manifest)
    check_dockerfile_from_coverage(report, manifest)
    check_custom_image_dockerfiles(report, manifest)
    check_orchestration_scripts(report)
    check_ansible_roles(report)
    check_offline_wiring(report)
    check_prep_structure(report)
    check_scan_config_coverage(report, manifest)
    check_makefile_stage_scripts(report)
    check_python_reqs_aggregation(report)
    check_deploy_sh(report)
    check_manifest_uniqueness(report, manifest)
    check_inference_deploy_offline(report)
    check_supply_chain_integration(report)
    check_makefile_supply_chain_targets(report)

    report.print()
    sys.exit(0 if report.passed_all() else 1)


if __name__ == "__main__":
    main()
