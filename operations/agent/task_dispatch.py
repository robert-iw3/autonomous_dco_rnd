"""
Task dispatch -- how Nexus tasks an OUTBOUND-ONLY endpoint (shared, Phase A).

The platform can't reach into endpoints, so both acquisition (worker_acquire) and
SOAR response (worker_soar, for non-EDR hosts) work by ENQUEUEING a signed task
keyed by host. The on-host agent polls `core_ingress GET /api/v1/tasks`, verifies
the signature, and acts. This module is the canonical, tested shape of that task +
its store; worker_acquire (Python) uses it directly, worker_soar (Rust) + ingress
(Rust) mirror it.

Signing reuses response_executor.sign_task (same HMAC the agent verifies with), so
a host can never be made to run a task that didn't come from Nexus.
"""

import time
from typing import Dict, List, Optional

from response_executor import sign_task, ALLOWED_PLAYBOOKS, select_playbook  # noqa: F401

# Task kinds the agent understands (each maps to a fixed playbook via the executor).
RESPONSE_ACTIONS = ("isolate_host", "block_ip", "eradicate_process",
                    "eradicate_persistence", "restore", "collect_forensics")


def _finalize(task: dict, secret: bytes) -> dict:
    task["created_at"] = task.get("created_at", int(time.time()))
    task["signature"] = sign_task(task, secret)
    return task


def build_response_task(*, incident_id: str, host: str, os_family: str,
                        action_type: str, secret: bytes,
                        targets: Optional[list] = None, **params) -> dict:
    """Build a signed SOAR response task (the agent runs the matching playbook)."""
    if action_type not in RESPONSE_ACTIONS:
        raise ValueError(f"not a host response action: {action_type!r}")
    task = {"kind": "response", "incident_id": incident_id, "host": host,
            "os_family": os_family, "action_type": action_type,
            "targets": list(targets or [])}
    task.update({k: v for k, v in params.items() if v is not None})
    return _finalize(task, secret)


def build_acquisition_task(*, incident_id: str, host: str, os_family: str,
                           file_path: str, secret: bytes) -> dict:
    """Build a signed acquisition task (the agent runs 05_acquire_artifact)."""
    task = {"kind": "response", "incident_id": incident_id, "host": host,
            "os_family": os_family, "action_type": "acquire_artifact",
            "file_path": file_path, "targets": []}
    return _finalize(task, secret)


class TaskStore:
    """Per-host task queue. Production = Redis (worker enqueues; the ingress
    GET /api/v1/tasks handler drains for the polling sensor). At-least-once: the
    agent confirms completion out of band via nexus.soar.callback."""

    def __init__(self):
        self._by_host: Dict[str, List[dict]] = {}

    def enqueue(self, host: str, task: dict) -> None:
        self._by_host.setdefault(host, []).append(task)

    def poll(self, host: str) -> List[dict]:
        tasks = self._by_host.get(host, [])
        self._by_host[host] = []
        return tasks

    def pending(self, host: str) -> int:
        return len(self._by_host.get(host, []))
