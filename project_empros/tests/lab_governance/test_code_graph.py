"""
CG-1 — codebase dependency/link graph (gen_code_graph.py).

Unit-tests the pure extractors (subject constants, pub/sub edges incl. constant
resolution + bare `publish(`, stream defs, python imports), then asserts the
real-repo graph carries known-true subject edges, and that the committed
code_graph.json / CODE_GRAPH.md are not stale (drift guard, like gen_evidence).
"""
import importlib.util as ilu
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent          # project_empros/
spec = ilu.spec_from_file_location("gen_code_graph", str(ROOT / "gen_code_graph.py"))
cg = ilu.module_from_spec(spec)
sys.modules["gen_code_graph"] = cg
spec.loader.exec_module(cg)


# ── pure extractors ──────────────────────────────────────────────────────────
class TestExtractors:
    def test_subject_constants_py_and_rust(self):
        c = cg.subject_constants('INTAKE_SUBJECT = "nexus.memory.intake"\n'
                                 'const FOO: &str = "nexus.agent.tasks";')
        assert c["INTAKE_SUBJECT"] == "nexus.memory.intake"
        assert c["FOO"] == "nexus.agent.tasks"

    def test_edges_literal_and_const_and_bare_publish(self):
        consts = {"ENRICHMENT_SUBJECT": "nexus.memory.enrichment"}
        text = ('await js.publish("nexus.soar.execute", body)\n'
                'await publish(ei.ENRICHMENT_SUBJECT, b)\n'
                'js.subscribe(INTAKE_SUBJECT)\n')
        consts["INTAKE_SUBJECT"] = "nexus.memory.intake"
        edges = set(cg.subject_edges(text, consts))
        assert ("nexus.soar.execute", "publish") in edges          # dotted literal
        assert ("nexus.memory.enrichment", "publish") in edges     # bare publish + module const
        assert ("nexus.memory.intake", "subscribe") in edges       # bare const

    def test_stream_defs(self):
        sh = 'create_stream \\\n  "Nexus_Memory_Intake" \\\n  "nexus.memory.intake" \\\n  3 \\\n'
        assert ("Nexus_Memory_Intake", "nexus.memory.intake") in cg.stream_defs(sh)

    def test_python_local_imports_only_repo_modules(self):
        imp = cg.python_local_imports("import os\nfrom agents.controls import x\n"
                                      "import investigation_metrics\nimport numpy\n")
        assert "agents.controls" in imp and "investigation_metrics" in imp
        assert not any(m in imp for m in ("os", "numpy"))

    def test_ansible_deploy_fleet_and_named_roles(self):
        site = ('- name: Workers\n  hosts: workers\n  roles:\n'
                '    - { role: rust_podman_worker, worker_name: "worker_soar" }\n'
                '- name: Analytics\n  hosts: analytics\n  roles:\n    - nexus_hunter\n    - memory_worker\n')
        d = cg.ansible_deploy(site)
        assert d["worker_soar"] == {"role": "rust_podman_worker", "host": "workers"}
        assert d["worker_memory"] == {"role": "memory_worker", "host": "analytics"}
        assert d["llm_hunter_swarm"]["host"] == "analytics"

    def test_parse_sections_and_section_for(self):
        run = ('SECTIONS=(\n    "analytics|Dockerfile.analytics|x"\n    "memory|Dockerfile.memory|y"\n)\n'
               'TRIGGERS=(\n    "services/worker_memory/:memory"\n    "analytics/llm_hunter/:analytics services"\n)\n')
        secs, trigs = cg.parse_sections(run)
        assert secs["memory"] == "Dockerfile.memory"
        assert cg.section_for("services/worker_memory/main.py", trigs) == "memory"
        assert cg.section_for("analytics/llm_hunter/orchestrator.py", trigs) == "analytics"

    def test_http_routes_and_calls(self):
        assert ("post", "/api/v1/evidence") in cg.http_routes('.route("/api/v1/evidence", post(h))')
        assert "/api/v1/tasks" in cg.http_calls('client.get("/api/v1/tasks")')

    def test_workspace_members_and_cargo_deps(self):
        assert "libs/lib_siem_core" in cg.workspace_members('members = [\n  "libs/lib_siem_core",\n  "services/worker_soar",\n]')
        deps = cg.cargo_deps("[package]\nname = \"x\"\n[dependencies]\ntokio = { workspace = true }\n"
                             "lib_siem_core = { path = \"../../libs/lib_siem_core\" }\n[dev-dependencies]\nmockall = \"*\"\n")
        assert "tokio" in deps and "lib_siem_core" in deps and "mockall" not in deps

    def test_config_subjects_and_tf_resources(self):
        assert "nexus.soar.execute" in cg.config_subjects('subject: "nexus.soar.execute".into(),')
        assert ("aws_lambda_function", "aws_isolate") in cg.tf_resources('resource "aws_lambda_function" "aws_isolate" {')

    def test_load_controls_joins_impl_evidence_tests(self):
        man = ('controls:\n  - id: X-1\n    status: implemented\n'
               '    implementation: analytics/llm_hunter/agents/response.py\n'
               '    tests: ["tests/lab_governance/test_x.py"]\n')
        evm = ('evidence:\n  X-1:\n    - file: services/core_ingress/src/main.rs\n      anchor: foo\n')
        ctl = cg.load_controls(man, evm)["X-1"]
        assert ctl["status"] == "implemented"
        assert {"llm_hunter_swarm", "core_ingress"} <= set(ctl["components"])
        assert ctl["tests"] == ["tests/lab_governance/test_x.py"]
        assert "services/core_ingress/src/main.rs" in ctl["evidence_files"]

    def test_pipeline_stages_order_and_purpose(self):
        entries = [("d/03-harden.sh", "#!/bin/bash\n# Stage 3: harden\nset -e\n"),
                   ("d/01-render.sh", "#!/bin/bash\n# Stage 1: render\n"),
                   ("d/02b-build.py", '#!/usr/bin/env python3\n"""\nBuild inventory.\n"""\n')]
        stages = cg.pipeline_stages(entries)
        assert [s[0] for s in stages] == ["01", "02b", "03"]            # numeric order
        assert stages[0] == ["01", "render", "Stage 1: render"]
        assert stages[1][2] == "Build inventory."                       # multi-line docstring


# ── real-repo invariants (the graph must reflect the actual wiring) ─────────
class TestRealGraph:
    G = cg.build_graph()

    def _s(self, subject):
        return self.G["subjects"].get(subject, {})

    def test_memory_evidence_flow(self):
        # gateway streams to WORM + publishes intake; worker_memory consumes it…
        assert "core_ingress" in self._s("nexus.memory.intake")["producers"]
        assert "worker_memory" in self._s("nexus.memory.intake")["consumers"]
        # …and publishes the enrichment back to the swarm
        assert "worker_memory" in self._s("nexus.memory.enrichment")["producers"]

    def test_soar_and_metrics_producers(self):
        assert "llm_hunter_swarm" in self._s("nexus.soar.execute")["producers"]
        assert "llm_hunter_swarm" in self._s("nexus.metrics.investigation")["producers"]

    def test_agent_task_loop(self):
        n = self._s("nexus.agent.tasks")
        assert "worker_soar" in n["producers"] and "core_ingress" in n["consumers"]

    def test_components_present_with_language(self):
        comps = self.G["components"]
        assert comps["core_ingress"]["language"] == "rust"
        assert comps["worker_memory"]["language"] == "python"
        assert comps["llm_hunter_swarm"]["language"] == "python"

    def test_every_subject_has_an_endpoint(self):
        # no dangling subject node: each must have a producer, consumer, stream, or mention
        dangling = [s for s, n in self.G["subjects"].items()
                    if not (n["producers"] or n["consumers"] or n["streams"] or n["mentioned_by"])]
        assert not dangling, f"subjects with no endpoint: {dangling}"


class TestExpandedGraph:
    G = cg.build_graph()

    def test_evidence_endpoint_served_by_gateway(self):
        ep = self.G["http_endpoints"]["/api/v1/evidence"]
        assert ep["service"] == "core_ingress" and "post" in ep["methods"]

    def test_memory_evidence_bucket_writers(self):
        st = self.G["stores"]["s3_memory_evidence"]
        assert st["kind"] == "s3"
        assert {"core_ingress", "worker_memory"} <= set(st["touched_by"])

    def test_swarm_reads_cold_archive_and_qdrant(self):
        assert "worker_s3_archive" in self.G["stores"]["s3_cold_archive"]["touched_by"]
        assert "llm_hunter_swarm" in self.G["stores"]["qdrant_swarm_memory"]["touched_by"]

    def test_component_build_deploy_test_wiring(self):
        wm = self.G["components"]["worker_memory"]
        assert wm["dockerfile"] == "services/worker_memory/Dockerfile"
        assert wm["deploy"] == {"role": "memory_worker", "host": "analytics"}
        assert wm["test_section"] == "memory"
        # the rust worker fleet deploys via the shared role on the workers host
        assert self.G["components"]["worker_soar"]["deploy"]["role"] == "rust_podman_worker"

    def test_pipelines_present(self):
        deploy = {s[1] for s in self.G["pipelines"]["deploy"]}
        mlops = {s[1] for s in self.G["pipelines"]["mlops"]}
        assert "render-templates" in deploy and "deploy-core" in deploy
        assert "benchmark_runner" in mlops and "rsi_loop" in mlops

    def test_config_driven_subject_consumers(self):     # CG-2d
        assert "worker_soar" in self.G["subjects"]["nexus.soar.execute"]["consumers"]
        assert "worker_rlhf" in self.G["subjects"]["nexus.training.rlhf"]["consumers"]

    def test_rust_internal_crate_deps(self):            # CG-2a
        assert "lib_siem_core" in self.G["components"]["worker_soar"]["rust_deps"]

    def test_controls_joined_with_components_and_tests(self):   # CG-2b
        ctl = self.G["controls"]
        assert len(ctl) >= 20
        ai = ctl["AI-GROUNDING"]
        assert "llm_hunter_swarm" in ai["components"] and ai["tests"]
        # reverse index lands on the component
        assert "AI-GROUNDING" in self.G["components"]["llm_hunter_swarm"]["controls"]

    def test_infrastructure_inventory(self):            # CG-2c
        inf = self.G["infrastructure"]
        assert {"rust_ingress", "nexus_hunter", "qdrant_node"} <= set(inf["ansible_roles"])
        assert inf["terraform_resources"] and any(t == "aws_lambda_function" for t, _ in inf["terraform_resources"])
        assert any("haproxy" in c for c in inf["config_files"])

    def test_containment_capability_matrix(self):       # WS-I / TC-4
        rows = self.G["containment"]
        assert ["endpoint", "windows", "isolate_host", "agent_task_v1"] in rows
        assert any(r[0] == "cloud_instance" and r[1] == "aws" for r in rows)


# ── drift guard ──────────────────────────────────────────────────────────────
class TestDrift:
    def test_artifacts_exist_at_root(self):
        assert (ROOT / "code_graph.json").exists() and (ROOT / "CODE_GRAPH.md").exists()

    def test_committed_graph_in_sync(self):
        # regenerate in-memory and compare to the committed files
        assert cg.main(["--check"]) == 0, "code graph stale — run gen_code_graph.py"
