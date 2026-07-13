"""
Lab det_chamber -- Phase 3: Linux detonation sandbox is network-isolated.

The Linux dynamic analyzer detonates ELF samples in a KVM/libvirt micro-VM. Like
the Windows pool, that VM must have NO route off-box so malware cannot propagate.
A libvirt network with no <forward> is isolated (guest-to-guest only, no NAT/route
to the host or internet).
"""

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TF = REPO / "infrastructure" / "terraform" / "det_chamber" / "linux_sandbox.tf"
ROLE = REPO / "infrastructure" / "ansible" / "roles" / "det_chamber_linux"


def _tf():
    assert TF.exists(), "infrastructure/terraform/det_chamber/linux_sandbox.tf must exist"
    return TF.read_text()


def _tf_code():
    """HCL with comments stripped -- so 'never add mode=nat' notes don't false-positive."""
    lines = []
    for ln in TF.read_text().splitlines():
        code = ln.split("#", 1)[0]   # drop trailing/full-line comments (no # in our strings)
        lines.append(code)
    return "\n".join(lines)


def test_libvirt_network_defined():
    assert 'resource "libvirt_network"' in _tf(), "Linux sandbox needs a dedicated libvirt network"


def test_libvirt_network_is_isolated_no_egress():
    code = _tf_code()
    # Isolated = no NAT/route forwarding. Refuse any forward mode that grants egress.
    assert '"nat"' not in code and '"route"' not in code, \
        "Linux sandbox network must not forward (NAT/route) -- malware would get egress"
    assert '"none"' in code, "the libvirt network must be explicitly isolated (mode none)"


def test_linux_sandbox_vm_attached_to_isolated_net():
    t = _tf()
    assert 'resource "libvirt_domain"' in t, "the detonation VM (libvirt_domain) must be defined"
    assert "libvirt_network" in t


def test_det_chamber_linux_role_exists():
    assert (ROLE / "tasks" / "main.yml").exists(), \
        "infrastructure/ansible/roles/det_chamber_linux/tasks/main.yml must exist"
