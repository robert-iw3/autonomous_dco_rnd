"""
siem_entity_extractor — CIM/ECS result rows -> the swarm's typed entities.

SIEM result columns carry the same things the entity board tracks (hosts, IPs,
users, processes, domains, files, hashes, cloud resources) under CIM (Splunk),
ECS (Elastic/Sentinel), or common flattened aliases. This maps them onto the
entity dict shape the containment planner consumes ({entity_id: {type, status,
notes}}), so a SIEM-derived finding can target the affected assets exactly like
a telemetry-derived one.

Extraction is not adjudication: entities come out with status "investigating";
`mark_malicious` promotes them once a verdict (swarm or deterministic ladder)
confirms the finding. Hosts are returned separately — the primary host is the
incident epicenter (the seed's sensor_id, contained via the host path), and
additional hosts surface as internal-IP/lateral evidence rather than standalone
board entities. Pure stdlib.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List

# column name (CIM | ECS | common flattened alias) -> entity type
FIELD_ENTITY_TYPES: Dict[str, str] = {
    # IPs
    "src": "ip_or_host", "dest": "ip_or_host",
    "src_ip": "ip", "dest_ip": "ip", "source.ip": "ip", "destination.ip": "ip",
    "host.ip": "ip", "ip_address": "ip",
    # hosts
    "host": "host", "host.name": "host", "host.hostname": "host",
    "dvc": "host", "computer": "host", "observer.name": "host",
    # identities
    "user": "user", "user.name": "user", "user.id": "user",
    "user_principal_name": "user", "subject_user": "user",
    # processes (host-local artifacts)
    "process": "process", "process.name": "process", "process_name": "process",
    "parent_process": "process", "process.parent.name": "process",
    "process.executable": "file", "process.parent.executable": "file",
    # DNS / URLs
    "dns_query": "domain", "dns.question.name": "domain", "query": "domain",
    "url": "url", "url.original": "url", "http_uri": "url",
    # files + hashes
    "file_name": "file", "file.name": "file", "file_path": "file", "file.path": "file",
    "file_hash": "hash", "hash.sha256": "hash", "pe.imphash": "hash",
    # cloud resources
    "cloud_instance": "instance", "instance_id": "instance", "resource_id": "instance",
    "cloud.instance.id": "instance", "arn": "instance",
    "bucket": "bucket", "bucket_name": "bucket",
}

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)[a-z0-9]([a-z0-9\-]*[a-z0-9])?"
                        r"(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$", re.I)

# Values that carry no investigative meaning and would pollute the board.
_NOISE_VALUES = frozenset({"", "-", "n/a", "none", "null", "unknown", "0.0.0.0", "::"})


def _looks_like_ip(value: str) -> bool:
    if not _IP_RE.match(value):
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _resolve_type(field_type: str, value: str) -> str:
    """CIM's src/dest may hold an IP or a hostname — decide from the value."""
    if field_type == "ip_or_host":
        return "ip" if _looks_like_ip(value) else "host"
    if field_type == "domain" and not _DOMAIN_RE.match(value):
        return ""   # a raw lookup string that is not a domain is not an entity
    return field_type


def extract_entities(rows: List[Dict[str, Any]],
                     note_fields: tuple = ("mitre", "rule.name", "signature",
                                           "event_action", "event.action")) -> Dict[str, dict]:
    """Typed entities from result rows, keyed by entity id.

    Every entity is grounded: it is the literal value of a recognized CIM/ECS
    column in a returned row (nothing is inferred), with a note recording the
    detection context it appeared in. Hosts are excluded here — use `hosts_in`.
    """
    entities: Dict[str, dict] = {}
    for row in rows or []:
        note_bits = [str(row.get(f)) for f in note_fields if row.get(f)]
        note = "; ".join(dict.fromkeys(note_bits))
        for field, value in (row or {}).items():
            ftype = FIELD_ENTITY_TYPES.get(str(field))
            if not ftype:
                continue
            sval = str(value).strip()
            if sval.lower() in _NOISE_VALUES:
                continue
            etype = _resolve_type(ftype, sval)
            if not etype or etype == "host":
                continue
            existing = entities.get(sval)
            if existing is None:
                entities[sval] = {"type": etype, "status": "investigating",
                                  "notes": note or f"from SIEM field {field}"}
            elif note and note not in existing["notes"]:
                existing["notes"] += f"; {note}"
    return entities


def hosts_in(rows: List[Dict[str, Any]]) -> List[str]:
    """Hostnames referenced by the rows, first-seen order (the first is the
    natural incident epicenter for the seed's sensor_id)."""
    hosts: Dict[str, None] = {}
    for row in rows or []:
        for field, value in (row or {}).items():
            ftype = FIELD_ENTITY_TYPES.get(str(field))
            sval = str(value).strip()
            if not sval or sval.lower() in _NOISE_VALUES:
                continue
            if ftype == "host" or (ftype == "ip_or_host" and not _looks_like_ip(sval)):
                hosts.setdefault(sval)
    return list(hosts)


TIME_FIELDS = ("_time", "@timestamp", "time", "timestamp")

# semantic role -> the column names (CIM | ECS | flat) that carry it
ROW_ALIASES = {
    "host": ("host", "host.name", "host.hostname", "dvc", "computer"),
    "user": ("user", "user.name", "user.id", "user_principal_name"),
    "process": ("process", "process.name", "process_name"),
    "parent_process": ("parent_process", "process.parent.name", "parent_process_name"),
    "dest_ip": ("dest_ip", "destination.ip", "dest"),
    "src_ip": ("src_ip", "source.ip", "src"),
    "dns_query": ("dns_query", "dns.question.name"),
    "cloud_instance": ("cloud_instance", "cloud.instance.id", "instance_id", "resource_id"),
    "event_action": ("event_action", "event.action", "action"),
    "mitre": ("mitre", "mitre_technique", "threat.technique.id"),
}


def normalize_row(row: Dict[str, Any]) -> Dict[str, str]:
    """One row's semantic roles under flat names, whatever schema it arrived in."""
    out = {}
    for role, names in ROW_ALIASES.items():
        for name in names:
            val = (row or {}).get(name)
            if val not in (None, ""):
                out[role] = str(val)
                break
    for tf in TIME_FIELDS:
        if (row or {}).get(tf) not in (None, ""):
            out["_time"] = str(row[tf])
            break
    return out


def mark_malicious(entities: Dict[str, dict], note: str = "") -> Dict[str, dict]:
    """Promote extracted entities to malicious once a verdict confirms the
    finding — only then does the containment planner action them."""
    out = {}
    for eid, ed in (entities or {}).items():
        ed = dict(ed or {})
        ed["status"] = "malicious"
        if note and note not in ed.get("notes", ""):
            ed["notes"] = f"{ed.get('notes', '')}; {note}".strip("; ")
        out[eid] = ed
    return out
