"""
target-class + environment resolver.

Every confirmed-TP entity must resolve to (target_class, environment) so the
containment protocol can pick a tailored, executable action for *that kind of
thing in that environment*. Unknown types resolve to ("unknown", ...) so the
coverage gate escalates rather than silently dropping them.
"""
import importlib
import sys
import types
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
AGENTS = ROOT / "analytics" / "llm_hunter" / "agents"
# lightweight `agents` package (path only) so `from agents.X import` resolves
# without triggering the heavy agents/__init__ (langchain etc.).
_pkg = types.ModuleType("agents")
_pkg.__path__ = [str(AGENTS)]
sys.modules.setdefault("agents", _pkg)

tc = importlib.import_module("agents.target_class")


class TestSourceEnvironment:
    def test_endpoint_os(self):
        assert tc.source_environment("sysmon_sensor") == "windows"
        assert tc.source_environment("windows_c2") == "windows"
        assert tc.source_environment("linux_sentinel") == "linux"

    def test_cloud_providers(self):
        assert tc.source_environment("aws_guardduty") == "aws"
        assert tc.source_environment("azure_entraid") == "azure"
        assert tc.source_environment("gcp_audit") == "gcp"
        assert tc.source_environment("vmware_syslog") == "vmware"

    def test_unknown_is_blank(self):
        assert tc.source_environment("weird_sensor") == ""
        assert tc.source_environment("") == ""


class TestClassifyEntity:
    def _c(self, eid, etype, env):
        return tc.classify_entity(eid, {"type": etype, "status": "malicious"}, env)

    def test_identity_idp_resolution(self):
        assert self._c("alice", "user", "azure") == ("identity", "entra")
        assert self._c("AKIA...", "access_key", "aws") == ("identity", "iam")
        assert self._c("svc", "user", "gcp") == ("identity", "gcp")
        assert self._c("admin", "user", "windows") == ("identity", "local")

    def test_network_domain_and_external_ip(self):
        assert self._c("evil.com", "domain", "linux") == ("network", "onprem")
        assert self._c("evil.com", "domain", "aws") == ("network", "aws")
        # public IP is C2/egress, not an internal host
        assert self._c("203.0.113.10", "ip", "windows") == ("network", "onprem")

    def test_internal_ip_endpoint_vs_cloud_instance(self):
        assert self._c("10.0.0.5", "ip", "windows") == ("endpoint", "windows")
        assert self._c("10.0.0.5", "ip", "aws") == ("cloud_instance", "aws")

    def test_cloud_instance_and_container(self):
        assert self._c("i-0abc", "instance", "aws") == ("cloud_instance", "aws")
        assert self._c("arn:aws:...", "arn", "aws") == ("cloud_instance", "aws")
        assert self._c("pod-x", "pod", "gcp") == ("container", "k8s")

    def test_datastore(self):
        assert self._c("my-bucket", "bucket", "aws") == ("datastore", "aws")

    def test_host_local_artifacts_map_to_endpoint(self):
        for et in ("pid", "hash", "file", "process"):
            assert self._c("x", et, "linux") == ("endpoint", "linux")

    def test_unknown_type_escalates(self):
        cls, env = self._c("???", "wormhole", "linux")
        assert cls == "unknown" and env == "linux"
