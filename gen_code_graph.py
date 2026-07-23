#!/usr/bin/env python3
"""gen_code_graph.py - generate the codebase dependency/link graph.

Scans autonomous_dco_rnd and emits, from source (so it never drifts):
  * code_graph.json  - machine-readable nodes + edges (fast lookup / jq)
  * CODE_GRAPH.md    - human guide: the NATS subject bus (the system's nervous
                       system, cross-language), a component index, and Python imports.

The rad view here is the NATS subject graph: who PUBLISHES and who CONSUMES each
subject across Python + Rust services - the fastest way to trace a logic flow.
Constants (e.g. `ei.INTAKE_SUBJECT`) are resolved; config/default-driven subjects
that aren't pub/sub literals are still captured as `mentioned_by` so no edge is lost.

Usage:  gen_code_graph.py            # (re)write code_graph.json + CODE_GRAPH.md
        gen_code_graph.py --check    # exit 1 if either is stale (CI drift guard)
"""
from __future__ import annotations

import ast
import json
import re
import sys
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parent
GRAPH_JSON = ROOT / "code_graph.json"
GRAPH_MD = ROOT / "CODE_GRAPH.md"

# path-prefix -> (component, language). Most specific first.
_COMPONENTS = [
    ("analytics/llm_hunter", "llm_hunter_swarm", "python"),
    ("services/core_ingress", "core_ingress", "rust"),
    ("services/worker_soar", "worker_soar", "rust"),
    ("services/worker_memory", "worker_memory", "python"),
    ("services/worker_qdrant", "worker_qdrant", "rust"),
    ("services/worker_rules", "worker_rules", "rust"),
    ("services/worker_s3_archive", "worker_s3_archive", "rust"),
    ("services/worker_rlhf", "worker_rlhf", "rust"),
    ("services/worker_ti_ingest", "worker_ti_ingest", "python"),
    ("services/model_steward", "model_steward", "python"),
    ("services/looking_glass", "looking_glass", "svelte-ts"),
    ("libs/lib_siem_core", "lib_siem_core", "rust"),
    ("middleware/src/worker_splunk", "worker_splunk", "rust"),
    ("middleware/src/worker_elastic", "worker_elastic", "rust"),
    ("middleware/src/worker_nexus", "worker_nexus", "rust"),
    ("middleware/src/worker_sql", "worker_sql", "rust"),
    ("middleware/src", "middleware", "rust"),
    ("operations/agent", "on_host_agent", "python"),
    ("operations/playbooks", "ir_playbooks", "mixed"),
    ("mlops/scripts", "mlops_pipeline", "python"),
    ("det_chamber", "det_chamber", "python"),
    ("infrastructure/nats", "nats_streams", "shell"),
]
_SCAN_EXT = {".py", ".rs", ".sh", ".ts", ".svelte"}
_SKIP = {"tests", "target", "data", "__pycache__", "node_modules", ".git", "img", "archive",
         # data_ops/ is a conceptual draft (see data_ops/README.md) — not real
         # wired-in code yet, so keep it out of the generated graph for now.
         "data_ops"}
# Vendored third-party distributions: present in the tree but not our source.
_SKIP_PREFIXES = ("operations/playbooks/tools/",)
_SKIP_SUBPATHS = ("threat_hunting/egress_monitor/tools/",)


def _skipped(rel_path) -> bool:
    rel = rel_path.as_posix() if hasattr(rel_path, "as_posix") else str(rel_path)
    if rel.startswith(_SKIP_PREFIXES):
        return True
    if any(sub in rel for sub in _SKIP_SUBPATHS):
        return True
    return any(part in _SKIP for part in rel.split("/"))

_SUBJECT = re.compile(r'"((?:nexus|middleware)\.[a-zA-Z0-9_.*>]+)"')
_CONST_DEF = re.compile(
    r'(?:const\s+)?([A-Z][A-Z0-9_]+)\s*(?::\s*&?str\s*)?=\s*"((?:nexus|middleware)\.[a-zA-Z0-9_.*>]+)"')
_PUBSUB = re.compile(r'\b(publish|publish_with_headers|pull_subscribe|subscribe)\s*\(\s*([^,)\s]+)')
_PY_LOCAL_TOP = {"agents", "tools", "state", "orchestrator", "detonation_enrichment",
                 "investigation_metrics", "playbook_planner", "lateral_movement",
                 "memory_analysis", "evidence_intake", "corpus_utils", "model_config"}


def component_of(rel_path: str):
    for prefix, name, lang in _COMPONENTS:
        if rel_path.startswith(prefix):
            return name, lang
    return None, None


def subject_constants(text: str) -> dict:
    """{CONST_NAME: subject} for module-level subject string constants (py + rust)."""
    return {m.group(1): m.group(2) for m in _CONST_DEF.finditer(text)}


def _clean_arg(arg: str) -> str:
    return arg.strip().strip('"').split('"')[0].strip()


def subject_edges(text: str, consts: dict()) -> list:
    """(subject, role) for explicit pub/sub calls; role in {publish, subscribe}.
    Resolves a constant arg (bare or module-qualified) via `consts`."""
    edges = []
    for m in _PUBSUB.finditer(text):
        verb, raw = m.group(1), m.group(2).strip()
        role = "publish" if verb.startswith("publish") else "subscribe"
        if raw.startswith('"'):
            lit = _clean_arg(raw)
            if lit.startswith(("nexus.", "middleware.")):
                edges.append((lit, role))
        else:
            bare = raw.split(".")[-1].strip().rstrip(")")
            if bare in consts:
                edges.append((consts[bare], role))
    return edges


def stream_defs(text: str) -> list:
    """(stream_name, subject) from streams_init.sh create_stream calls."""
    out = []
    for blk in re.split(r'\bcreate_stream\b', text)[1:]:
        quoted = re.findall(r'"([^"]+)"', blk[:200])
        if len(quoted) >= 2:
            out.append((quoted[0], quoted[1]))
    return out


# Named single-purpose Ansible roles -> the runtime component they deploy.
_ROLE_COMPONENT = {
    "memory_worker": "worker_memory", "ti_ingest_worker": "worker_ti_ingest",
    "nexus_hunter": "llm_hunter_swarm", "rust_ingress": "core_ingress",
}
# Stores (S3 buckets / Qdrant collections) -> tokens that mark a component touching them.
_STORES = {
    "s3_cold_archive":     ("s3", ["nexus-cold-archive", "S3_BUCKET_NAME", '"telemetry/']),
    "s3_quarantine":       ("s3", ["nexus-quarantine"]),
    "s3_memory_evidence":  ("s3", ["nexus-ir-memory-archive", "NEXUS_MEMORY_ARCHIVE_BUCKET", "memory/{incident"]),
    "qdrant_swarm_memory": ("qdrant", ["nexus_swarm_memory"]),
    "qdrant_ti_corpus":    ("qdrant", ["nexus_ti_corpus"]),
}
_API = re.compile(r'/api/v[0-9]+/[a-z0-9_/-]+')
_ROUTE = re.compile(r'\.route\(\s*"(/api/[^"]+)"\s*,\s*(get|post|put|delete)\(')


def _array_block(text: str, name: str) -> list:
    """Lines inside a `NAME=( ... )` bash array."""
    out, inside = [], False
    for line in text.splitlines():
        if re.match(rf'\s*{name}=\(', line):
            inside = True
            continue
        if inside and line.strip() == ")":
            break
        if inside:
            out.append(line)
    return out


def parse_sections(run_text: str):
    """({section: dockerfile}, [(path_regex, [sections])]) from run_tests.sh."""
    secs = {}
    for line in _array_block(run_text, "SECTIONS"):
        m = re.search(r'"([a-z]+)\|([^|]+)\|', line)
        if m:
            secs[m.group(1)] = m.group(2)
    trigs = []
    for line in _array_block(run_text, "TRIGGERS"):
        m = re.search(r'"([^"]+):([a-z ]+)"\s*$', line)
        if m:
            trigs.append((m.group(1), m.group(2).split()))
    return secs, trigs


def section_for(rel: str, triggers) -> str:
    """First trigger section whose path pattern matches this file path."""
    for pattern, sections in triggers:
        if any(alt and alt in rel for alt in pattern.split("|")):
            return sections[0]
    return ""


def ansible_deploy(site_text: str) -> dict:
    """component -> {role, host} from site.yml (worker fleet worker_name + named roles)."""
    out, host = {}, ""
    for line in site_text.splitlines():
        h = re.match(r'\s*hosts:\s*([^\s#]+)', line)
        if h:
            host = h.group(1)
        w = re.search(r'worker_name:\s*"([^"]+)"', line)
        if w:
            out[w.group(1)] = {"role": "rust_podman_worker", "host": host}
        r = re.match(r'\s*-\s*([a-z_]+)\s*$', line)
        if r and r.group(1) in _ROLE_COMPONENT:
            out[_ROLE_COMPONENT[r.group(1)]] = {"role": r.group(1), "host": host}
    return out


def http_routes(text: str) -> list:
    """(method, path) HTTP routes a service exposes."""
    return [(m.group(2), m.group(1)) for m in _ROUTE.finditer(text)]


def http_calls(text: str) -> set:
    """/api/* paths a component references (caller side)."""
    return {p.rstrip('.,)"') for p in _API.findall(text)}


def _first_purpose(text: str) -> str:
    """First comment / docstring line - a numbered script's one-line purpose."""
    in_doc = False
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith(("#!", "import ", "from ", "set() -", "export ", "source ")):
            continue
        if in_doc:
            return s.strip('"\' ')[:90]
        if s.startswith("#"):
            return s.lstrip("# ").strip()[:90]
        if s[:3] in ('"""', "'''"):
            body = s[3:].strip('"\' ')
            if body:
                return body[:90]
            in_doc = True            # docstring opened on its own line
            continue
        return ""                    # first real code line, no purpose comment
    return ""


def pipeline_stages(entries) -> list:
    """entries: [(rel, text)] of a numbered-script dir -> ordered [id, name, purpose]."""
    out = []
    for rel, text in entries:
        m = re.match(r'(\d+[a-z]?)[_-]([a-z0-9_-]+)\.(?:sh|py)$', rel.rsplit("/", 1)[-1])
        if m:
            out.append([m.group(1), m.group(2), _first_purpose(text)])
    return sorted(out, key=lambda s: (int(re.match(r'\d+', s[0]).group()), s[0]))


# -- CG-2: Rust crate deps, GRC controls, infra inventory, config-driven subjects --
_CONFIG_SUBJECT = re.compile(r'\bsubject:\s*"((?:nexus|middleware)\.[a-zA-Z0-9_.*>]+)"')
_TF_RESOURCE = re.compile(r'resource\s+"([a-z_]+)"\s+"([a-z0-9_]+)"')


def workspace_members(cargo_text: str) -> list:
    """Internal crate paths from a workspace Cargo.toml `members = [...]`."""
    m = re.search(r'members\s*=\s*\[(.*?)\]', cargo_text, re.S)
    return re.findall(r'"([^"]+)"', m.group(1)) if m else []


def cargo_deps(cargo_text: str) -> list:
    """Dependency crate names from a crate Cargo.toml `[dependencies]` table."""
    deps, inside = [], False
    for line in cargo_text.splitlines():
        s = line.strip()
        if s.startswith("["):
            inside = s.startswith("[dependencies]")
            continue
        if inside:
            d = re.match(r'([a-zA-Z0-9_-]+)\s*=', s)
            if d:
                deps.append(d.group(1))
    return deps


def config_subjects(text: str) -> list:
    """Subjects consumed via a durable-worker config field `subject: "nexus..."`."""
    return _CONFIG_SUBJECT.findall(text)


def tf_resources(text: str) -> list:
    """(type, name) Terraform resources declared in a .tf file."""
    return _TF_RESOURCE.findall(text)


def load_controls(manifest_text: str, evidence_text: str) -> dict:
    """control_id -> {status, category, components, tests, evidence_files} (GRC join)."""
    import yaml
    man = yaml.safe_load(manifest_text) or {}
    evi = (yaml.safe_load(evidence_text) or {}).get("evidence", {}) or {}
    out = {}
    for c in man.get("controls", []):
        impl = c.get("implementation") or []
        impl = [impl] if isinstance(impl, str) else impl
        ev_files = [e["file"] for e in (evi.get(c["id"]) or [])
                    if isinstance(e, dict) and e.get("file")]
        comps = sorted({component_of(f)[0] for f in (impl + ev_files)
                        if f and component_of(f)[0]})
        tests = c.get("tests") or []
        tests = [tests] if isinstance(tests, str) else tests
        out[c["id"]] = {"status": c.get("status", ""), "category": c.get("category", ""),
                        "components": comps, "tests": list(tests),
                        "evidence_files": sorted(set(ev_files))}
    return out


def python_local_imports(src: str) -> set:
    """Intra-repo top-level modules imported by a Python file."""
    found = set()
    try:
        with warnings.catch_warnings():   # scanning is not linting - stay quiet
            warnings.simplefilter("ignore")
            tree = ast.parse(src)
    except SyntaxError:
        return found
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            top = node.module.split(".")[0]
            if top in _PY_LOCAL_TOP:
                found.add(node.module)
        elif isinstance(node, ast.Import):
            for a in node.names:
                top = a.name.split(".")[0]
                if top in _PY_LOCAL_TOP:
                    found.add(a.name)
    return found


def _iter_source_files():
    for p in sorted(ROOT.rglob("*")):
        if p.suffix not in _SCAN_EXT or not p.is_file():
            continue
        rel = p.relative_to(ROOT).as_posix()
        if _skipped(p.relative_to(ROOT)):
            continue
        yield rel, p


def build_graph() -> dict:
    components: dict() = {}
    subjects: dict() = {}
    imports: dict() = {}
    streams: dict() = {}

    comp_text: dict() = {}
    http_endpoints: dict() = {}

    def comp(name, lang):
        return components.setdefault(name, {
            "language": lang, "paths": [], "publishes": set(), "subscribes": set(),
            "mentions": set(), "serves": set(), "calls": set(), "rust_deps": set(),
            "controls": set(), "deploy": {}, "dockerfile": "", "test_section": ""})

    def subj(s):
        return subjects.setdefault(s, {"producers": set(), "consumers": set(),
                                       "mentioned_by": set(), "streams": set()})

    # Pass 1: read every file once; build a global subject-constant map so a
    # cross-module ref (e.g. `ei.INTAKE_SUBJECT`) resolves to a real edge.
    files = [(rel, path, path.read_text(errors="replace")) for rel, path in _iter_source_files()]
    global_consts: dict() = {}
    for _rel, _p, text in files:
        global_consts.update(subject_constants(text))

    for rel, path, text in files:
        name, lang = component_of(rel)
        if rel.endswith("streams_init.sh"):
            for sname, s in stream_defs(text):
                subj(s)["streams"].add(sname)
                if name:
                    comp(name, lang)
        if name is None:
            continue
        c = comp(name, lang)
        c["paths"].append(rel)
        consts = {**global_consts, **subject_constants(text)}
        for s, role in subject_edges(text, consts):
            node = subj(s)
            if role == "publish":
                c["publishes"].add(s); node["producers"].add(name)
            else:
                c["subscribes"].add(s); node["consumers"].add(name)
        for s in config_subjects(text):          # durable-worker config `subject: "..."`
            c["subscribes"].add(s); subj(s)["consumers"].add(name)
        for s in _SUBJECT.findall(text):
            subj(s)["mentioned_by"].add(name); c["mentions"].add(s)
        comp_text[name] = comp_text.get(name, "") + "\n" + text
        for method, pathname in http_routes(text):
            c["serves"].add(pathname)
            ep = http_endpoints.setdefault(pathname, {"service": name, "methods": set(), "callers": set()})
            ep["service"] = name; ep["methods"].add(method)
        c["calls"].update(http_calls(text))
        if rel.endswith(".py"):
            imp = python_local_imports(text)
            if imp:
                imports.setdefault(rel, sorted(imp))

    # -- deploy / build / test wiring per component ---------------------------
    site = ROOT / "infrastructure/ansible/site.yml"
    deploy = ansible_deploy(site.read_text(errors="replace")) if site.exists else {}
    rt = ROOT / "tests/run_tests.sh"
    _secs, triggers = parse_sections(rt.read_text(errors="replace")) if rt.exists else ({}, [])
    for name, c in components.items():
        c["deploy"] = deploy.get(name, {})
        c["test_section"] = section_for(c["paths"][0], triggers) if c["paths"] else ""
        df = ROOT / (c["paths"][0].split("/", 2)[0] + "/" + c["paths"][0].split("/")[1] + "/Dockerfile") \
            if c["paths"] and "/" in c["paths"][0] else None
        c["dockerfile"] = df.relative_to(ROOT).as_posix() if df and df.exists else ""

    # -- HTTP endpoint callers ------------------------------------------------
    for path_, ep in http_endpoints.items():
        for cname, c in components.items():
            if cname != ep["service"] and any(path_ == call or call.startswith(path_) for call in c["calls"]):
                ep["callers"].add(cname)

    # -- stores (S3 / Qdrant) touched by each component -----------------------
    stores: dict() = {}
    for sid, (kind, tokens) in _STORES.items():
        touched = sorted(n for n, t in comp_text.items() if any(tok in t for tok in tokens))
        stores[sid] = {"kind": kind, "touched_by": touched}

    # -- ordered pipelines (deploy + ML training) -----------------------------
    def _stage_entries(prefix):
        return [(rel, text) for rel, _p, text in files if rel.startswith(prefix)]
    pipelines = {
        "deploy": pipeline_stages(_stage_entries("orchestration/scripts/")),
        "mlops": pipeline_stages(_stage_entries("mlops/scripts/")),
    }

    # -- Rust internal crate-dep edges (CG-2a) --------------------------------
    crate_component = {}    # internal crate name -> component
    for cargo in (ROOT / "Cargo.toml", ROOT / "middleware/Cargo.toml"):
        if cargo.exists:
            for member in workspace_members(cargo.read_text(errors="replace")):
                cname = member.rstrip("/").rsplit("/", 1)[-1]
                comp_name = component_of(member + "/")[0]
                crate_component[cname] = comp_name or cname
    for p in sorted(ROOT.rglob("Cargo.toml")):
        if _skipped(p.relative_to(ROOT)):
            continue
        rel = p.relative_to(ROOT).as_posix()
        cname = component_of(rel)[0] or ("middleware" if rel.startswith("middleware") else None)
        if cname not in components:
            continue
        for dep in cargo_deps(p.read_text(errors="replace")):
            if dep in crate_component and crate_component[dep] != cname:
                components[cname]["rust_deps"].add(crate_component[dep])

    # -- GRC controls join: control -> components + tests (CG-2b) --------------
    man = ROOT / "docs/governance/controls_manifest.yaml"
    evm = ROOT / "docs/governance/evidence_map.yaml"
    controls = load_controls(man.read_text(errors="replace"),
                             evm.read_text(errors="replace")) if man.exists and evm.exists else {}
    for cid, info in controls.items():
        for cn in info["components"]:
            if cn in components:
                components[cn]["controls"].add(cid)

    # -- infrastructure inventory (CG-2c) -------------------------------------
    tf = sorted({(t, n) for p in ROOT.rglob("*.tf")
                 if not _skipped(p.relative_to(ROOT))
                 for t, n in tf_resources(p.read_text(errors="replace"))})
    roles_dir = ROOT / "infrastructure/ansible/roles"
    roles = sorted(d.name for d in roles_dir.iterdir() if d.is_dir()) if roles_dir.exists else []
    cfg_globs = ("*.conf", "*.conf.j2", "*.cfg", "*.cfg.j2")
    configs = sorted({p.relative_to(ROOT).as_posix() for g in cfg_globs
                      for p in (ROOT / "infrastructure").rglob(g)}) if (ROOT / "infrastructure").exists else []
    infrastructure = {
        "terraform_resources": [[t, n] for t, n in tf],
        "ansible_roles": roles,
        "config_files": configs,
    }

    # -- containment capability matrix: tailored actions per target class --
    import tomllib
    cap = ROOT / "operations/infra/capability_matrix.toml"
    containment = sorted(
        [e["target_class"], e["environment"], e["action"], e["executor"]]
        for e in tomllib.loads(cap.read_text()).get("capability", [])
    ) if cap.exists else []

    def _ser(d):
        out = {}
        for k, v in d.items():
            if isinstance(v, set):
                out[k] = sorted(v)
            elif isinstance(v, dict):
                out[k] = {kk: (sorted(vv) if isinstance(vv, set) else vv) for kk, vv in v.items()}
            else:
                out[k] = v
        return out

    return {
        "components": {k: _ser(v) for k, v in sorted(components.items())},
        "subjects": {k: _ser(v) for k, v in sorted(subjects.items())},
        "http_endpoints": {k: _ser(v) for k, v in sorted(http_endpoints.items())},
        "stores": {k: _ser(v) for k, v in sorted(stores.items())},
        "pipelines": pipelines,
        "controls": {k: _ser(v) for k, v in sorted(controls.items())},
        "infrastructure": infrastructure,
        "containment": containment,
        "python_imports": dict(sorted(imports.items())),
    }


def render_md(g: dict()) -> str:
    L = ["# Code Graph - how Sentinel Nexus is wired together", "",
         "> **Generated** from source by `gen_code_graph.py` (do not edit by hand; "
         "`--check` drift-guards it in CI). Machine-readable twin: `code_graph.json`.", "",
         "## How to use this", "",
         "Start a change by finding the **logic flow**, not the file. This repo is "
         "event-driven across Python + Rust, so the fastest trace is the **NATS subject "
         "bus** below: pick the subject your change touches -> see who *publishes* and who "
         "*consumes* it -> that is the call chain across services. Then drill in:", "",
         "- **Subjects** - every event, its producers/consumers/stream.",
         "- **HTTP endpoints** - synchronous service<->caller edges (`/api/*`).",
         "- **Stores** - which components read/write each S3 bucket / Qdrant collection.",
         "- **Component index** - per service: build (Dockerfile), deploy (Ansible role @ "
         "host), test section, Rust crate deps, and how many GRC controls it carries.",
         "- **GRC controls** - control -> implementing components -> the tests that prove it.",
         "- **Infrastructure inventory** - Ansible roles, Terraform resources, config files.",
         "- **Pipelines** - the ordered `deploy` and `mlops` stages.",
         "- **Python imports** - intra-repo call chains in the Python planes.", "",
         "`code_graph.json` is the same data for `jq`/grep.", "",
         "## NATS subject bus (the nervous system)", "",
         "```mermaid", "flowchart LR"]
    # edges producer -->|subject| consumer
    eid = 0
    for s, node in g["subjects"].items():
        producers = node["producers"] or (["?"] if node["consumers"] else [])
        consumers = node["consumers"] or (["?"] if node["producers"] else [])
        for p in producers:
            for c in consumers:
                L.append(f'    {p}(["{p}"]) -->|{s}| {c}(["{c}"])')
                eid += 1
    if eid == 0:
        L.append("    none")
    L += ["```", "", "## Subjects", "",
          "| Subject | Producers | Consumers | Stream | Also mentions |", "|---|---|---|---|---|"]
    for s, n in g["subjects"].items():
        L.append(f"| `{s}` | {', '.join(n['producers']) or '-'} | "
                 f"{', '.join(n['consumers']) or '-'} | {', '.join(n['streams']) or '-'} | "
                 f"{', '.join(sorted(set(n['mentioned_by']) - set(n['producers']) - set(n['consumers']))) or '-'} |")
    L += ["", "## HTTP endpoints (service <-> caller)", "",
          "| Endpoint | Service | Methods | Callers |", "|---|---|---|---|"]
    for path_, ep in g["http_endpoints"].items():
        L.append(f"| `{path_}` | {ep['service']} | {', '.join(ep['methods'])} | "
                 f"{', '.join(ep['callers']) or '-'} |")
    L += ["", "## Stores (who touches each S3 bucket / Qdrant collection)", "",
          "| Store | Kind | Touched by |", "|---|---|---|"]
    for sid, st in g["stores"].items():
        L.append(f"| `{sid}` | {st['kind']} | {', '.join(st['touched_by']) or '-'} |")
    L += ["", "## Component index", "",
          "Each component: language, how it's **built** (Dockerfile), **deployed** (Ansible "
          "role + host group), **tested** (run_tests.sh section), and the subjects it speaks.", "",
          "| Component | Lang | Build | Deploy (role @ host) | Test section | Pub -> Sub | Crate deps | Controls | Files |",
          "|---|---|---|---|---|---|---|---|---|"]
    for name, c in g["components"].items():
        dep = c.get("deploy") or {}
        deploy = f"{dep['role']} @ {dep['host']}" if dep else "-"
        L.append(f"| **{name}** | {c['language']} | {c.get('dockerfile') or '-'} | {deploy} | "
                 f"{c.get('test_section') or '-'} | {len(c['publishes'])}->{len(c['subscribes'])} | "
                 f"{', '.join(c.get('rust_deps') or []) or '-'} | {len(c.get('controls') or [])} | "
                 f"{len(c['paths'])} |")
    L += ["", "## GRC controls -> components + tests", "",
          "Joins the governance dossier into the graph: each control's implementing "
          "components and the tests that prove it.", "",
          "| Control | Status | Components | Tests |", "|---|---|---|---|"]
    for cid, info in g["controls"].items():
        L.append(f"| `{cid}` | {info['status']} | {', '.join(info['components']) or '-'} | "
                 f"{', '.join(info['tests']) or '-'} |")
    inf = g["infrastructure"]
    L += ["", "## Infrastructure inventory", "",
          f"**Ansible roles** ({len(inf['ansible_roles'])}): "
          + ", ".join(f"`{r}`" for r in inf["ansible_roles"]), "",
          f"**Terraform resources** ({len(inf['terraform_resources'])}):", "",
          "| Type | Name |", "|---|---|"]
    for t, n in inf["terraform_resources"]:
        L.append(f"| `{t}` | {n} |")
    L += ["", f"**Config files** ({len(inf['config_files'])}): "
          + ", ".join(f"`{c}`" for c in inf["config_files"])]
    L += ["", "## Containment capability matrix", "",
          "Tailored containment actions the swarm may plan per target class + "
          "environment - the contract that keeps the planner and executors in sync.", "",
          "| Target class | Environment | Action | Executor |", "|---|---|---|---|"]
    for tc_, env, action, executor in g.get("containment", []):
        L.append(f"| {tc_} | {env} | `{action}` | {executor} |")
    L += ["", "## Pipelines (ordered stages)", "",
          "End-to-end flows run as numbered scripts: `deploy` (orchestration) and `mlops` "
          "(train -> eval -> serve -> RSI -> benchmark).", ""]
    for pname, stages in g["pipelines"].items():
        L += [f"### {pname}", "", "| Stage | Script | Purpose |", "|---|---|---|"]
        for sid, sname, purpose in stages:
            L.append(f"| {sid} | `{sname}` | {purpose or '-'} |")
        L.append("")
    L += ["## Python intra-repo imports", "",
          "Module -> local modules it imports (call-chain within the Python planes).", ""]
    for mod, imps in g["python_imports"].items():
        L.append(f"- `{mod}` -> {', '.join(f'`{i}`' for i in imps)}")
    return "\n".join(L).rstrip() + "\n"


def build_outputs() -> dict:
    g = build_graph()
    return {GRAPH_JSON: json.dumps(g, indent=2, sort_keys=True) + "\n",
            GRAPH_MD: render_md(g)}


def main(argv) -> int:
    outputs = build_outputs()
    if "--check" in argv:
        stale = [p.name for p, exp in outputs.items()
                 if (p.read_text() if p.exists else "") != exp]
        if stale:
            print(f"DRIFT: {stale} out of sync - run gen_code_graph.py", file=sys.stderr)
            return 1
        print("code graph in sync.")
        return 0
    for p, exp in outputs.items():
        p.write_text(exp)
    print(f"wrote {GRAPH_JSON.name} + {GRAPH_MD.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
