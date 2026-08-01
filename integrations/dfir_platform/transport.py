"""
Where projections come from — and, just as importantly, which way the connection goes.

This stack **pulls**. The platform's enclave has no egress and accepts no inbound
connection; it writes projections outward to its DMZ edge, and a consumer collects them
from there. So every source below is client-side and short-lived: connect, take what is
held, acknowledge, disconnect. Nothing here listens, and nothing here holds a credential
for anything inside the platform.

Two sources, one interface:

  `DispatcherSource`   polls the platform's DMZ projection endpoint over TLS with its
                       certificate pinned. The endpoint shape mirrors the platform's own
                       receiver (`/pending`, `/fetch/<id>`, `DELETE /fetch/<id>`) because
                       that is the code the platform side already runs in that tier.

  `DirectorySource`    reads sealed bundles dropped into a directory. This is the
                       air-gapped case — a projection carried across on removable media —
                       and it is also what makes the consumer testable and useful before
                       the network path exists.

Both yield `(bundle_id, raw_bytes)` and take an explicit `ack`, so a bundle is only
released once the enrichment it produced is on the bus. A source that dropped its input
on read would lose a run to a restart.

Stdlib only.
"""
from __future__ import annotations

import json
import os
import shutil
import ssl
import urllib.error
import urllib.request

# A projection is findings and run context — kilobytes, not the megabytes of an evidence
# bundle. Anything past this is not a projection, and is refused before it is read into
# memory rather than after.
MAX_BUNDLE_BYTES = int(os.environ.get("NEXUS_PROJECTION_MAX_BYTES", str(32 * 1024 * 1024)))
HTTP_TIMEOUT = float(os.environ.get("NEXUS_PROJECTION_HTTP_TIMEOUT", "30"))


class TransportError(RuntimeError):
    """The source could not be reached or answered unusably. Distinct from a bundle being
    invalid — that is contract.ProjectionError, and it means something very different."""


class DispatcherSource:
    """Pulls from the platform's DMZ projection endpoint.

    The CA bundle pins the one server this should ever talk to. Verification is never
    disabled: a consumer that skipped it would accept a projection from anything answering
    on that address and feed it to the swarm as adjudicated ground truth.
    """

    def __init__(self, url: str, ca_bundle: str = "", token: str = ""):
        self.url = (url or "").rstrip("/")
        self.ca_bundle = ca_bundle
        self.token = token
        if self.url.startswith("http://") and not os.environ.get("NEXUS_PROJECTION_ALLOW_PLAINTEXT"):
            raise TransportError(
                "projection dispatcher URL is plaintext; set NEXUS_PROJECTION_ALLOW_PLAINTEXT "
                "to override for a lab run")

    def _tls(self):
        if not self.url.startswith("https://"):
            return None
        if self.ca_bundle:
            return ssl.create_default_context(cafile=self.ca_bundle)
        return ssl.create_default_context()

    def _open(self, path: str, method: str = "GET"):
        req = urllib.request.Request(self.url + path, method=method)
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            return urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=self._tls())
        except (urllib.error.URLError, OSError, ssl.SSLError) as e:
            raise TransportError(f"{method} {path}: {e}") from e

    def pending(self) -> list:
        with self._open("/pending") as resp:
            body = resp.read(MAX_BUNDLE_BYTES + 1)
        try:
            ids = json.loads(body.decode())
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise TransportError(f"/pending is not JSON: {e}") from e
        if not isinstance(ids, list):
            raise TransportError("/pending did not answer with a list")
        return [str(i) for i in ids]

    def fetch(self, bundle_ref: str) -> bytes:
        with self._open(f"/fetch/{bundle_ref}") as resp:
            body = resp.read(MAX_BUNDLE_BYTES + 1)
        if len(body) > MAX_BUNDLE_BYTES:
            raise TransportError(f"projection {bundle_ref} exceeds {MAX_BUNDLE_BYTES} bytes")
        return body

    def ack(self, bundle_ref: str) -> None:
        with self._open(f"/fetch/{bundle_ref}", method="DELETE"):
            pass

    def poll(self):
        """Yield (ref, raw) for everything currently held. A fetch that fails is skipped,
        not fatal: the bundle stays held and the next poll picks it up."""
        for ref in self.pending():
            try:
                yield ref, self.fetch(ref)
            except TransportError:
                continue


class DirectorySource:
    """Reads sealed bundles dropped into a directory (removable media, or a mount).

    Consumed bundles are **moved**, not deleted. The drop is the only record that a
    projection arrived on this path, and an air-gapped transfer that leaves no trace of
    what was carried is not a transfer anyone can reconstruct later.
    """

    def __init__(self, path: str, consumed_dir: str = ""):
        self.path = path
        self.consumed_dir = consumed_dir or os.path.join(path, "consumed")

    def poll(self):
        try:
            names = sorted(n for n in os.listdir(self.path) if n.endswith(".json"))
        except OSError as e:
            raise TransportError(f"projection drop {self.path}: {e}") from e
        for name in names:
            full = os.path.join(self.path, name)
            try:
                if os.path.getsize(full) > MAX_BUNDLE_BYTES:
                    continue
                with open(full, "rb") as fh:
                    yield name, fh.read()
            except OSError:
                continue

    def ack(self, ref: str) -> None:
        os.makedirs(self.consumed_dir, exist_ok=True)
        try:
            shutil.move(os.path.join(self.path, ref), os.path.join(self.consumed_dir, ref))
        except OSError:
            pass


def from_env():
    """Build the configured source. The drop directory wins when both are set — an
    operator who has staged a directory is doing something deliberate."""
    drop = os.environ.get("NEXUS_PROJECTION_DIR", "")
    if drop:
        return DirectorySource(drop, os.environ.get("NEXUS_PROJECTION_CONSUMED_DIR", ""))
    url = os.environ.get("NEXUS_PROJECTION_URL", "")
    if url:
        return DispatcherSource(url,
                                os.environ.get("NEXUS_PROJECTION_CA_BUNDLE", ""),
                                os.environ.get("NEXUS_PROJECTION_TOKEN", ""))
    raise TransportError(
        "no projection source configured: set NEXUS_PROJECTION_DIR or NEXUS_PROJECTION_URL")
