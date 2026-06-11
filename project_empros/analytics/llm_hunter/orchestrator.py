"""
Sentinel Nexus -- Layer-3 LLM Hunter orchestrator.

This module implements the core orchestration logic for the Sentinel Nexus LLM Hunter. It defines the
investigative state schema, the LangGraph DAG structure, and the reactive loops that listen for incoming
alerts from both Redis and NATS JetStream. The orchestrator manages the lifecycle of investigations,
enforces concurrency limits, and ensures that all interactions with the LLM agents and the SOAR system
are governed by strict schema validation and security controls.
"""

import os
import json
import time
import asyncio
import logging

from redis.asyncio import Redis
from nats.aio.client import Client as NATS
from pydantic import ValidationError
from langchain_core.messages import HumanMessage
from langgraph.graph import StateGraph, END
from langgraph.errors import GraphRecursionError

try:  # documented async saver path for langgraph-checkpoint-redis
    from langgraph.checkpoint.redis.aio import AsyncRedisSaver
except ImportError:  # older layout
    from langgraph.checkpoint.redis import AsyncRedisSaver

from prometheus_client import start_http_server, Counter, Histogram
from qdrant_client import AsyncQdrantClient
from qdrant_client.models import Distance, VectorParams

from state import (InvestigativeState, UnifiedAlertSchema, SoarExecutionSchema,
                   FP_CONFIDENCE_GATE, route_for_source_type)
from agents.supervisor import supervisor_agent
from agents.host_expert import host_expert_node
from agents.net_expert import net_expert_node
from agents.cloud_expert import cloud_expert_node
from agents.nettap_expert import nettap_expert_node
from agents.critic import critic_node
from agents.response import response_agent
from detonation_enrichment import enrichment_decision
from tools.sanitizer import CognitiveSanitizer

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("nexus-orchestrator")

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
redis_client = Redis.from_url(REDIS_URL, decode_responses=True)
async_qdrant = AsyncQdrantClient(url=os.getenv("QDRANT_HTTP_URL", "http://qdrant:6333"))

MEMORY_COLLECTION = "nexus_swarm_memory"
EMBED_DIM = 384  # all-MiniLM-L6-v2
MAX_OPERATIONS_STACKS = 3
MAX_CONCURRENT_INVESTIGATIONS = int(os.getenv("NEXUS_MAX_CONCURRENT", "8"))
INVESTIGATION_TIMEOUT_S = float(os.getenv("NEXUS_INVESTIGATION_TIMEOUT", "120"))
RECURSION_LIMIT = int(os.getenv("NEXUS_RECURSION_LIMIT", "20"))

# Stack lifecycle -- mirrors nexus.conf values, configurable via env for container deployments.
STACK_TTL_S = int(os.getenv("NEXUS_STACK_TTL_SECONDS", "14400"))          # 4h hard ceiling
STACK_MIN_LIFETIME_S = int(os.getenv("NEXUS_STACK_MIN_LIFETIME_SECONDS", "1800"))  # 30m review window
STACK_IDLE_TIMEOUT_S = int(os.getenv("NEXUS_STACK_IDLE_TIMEOUT_SECONDS", "1800"))  # 30m idle gate
STACK_ALERT_EXTEND_S = int(os.getenv("NEXUS_STACK_ALERT_EXTEND_SECONDS", "3600"))  # +1h per new alert
STACK_MONITOR_INTERVAL_S = 60  # lifecycle poll cadence

_investigation_sema = asyncio.Semaphore(MAX_CONCURRENT_INVESTIGATIONS)

METRIC_ANOMALIES = Counter('nexus_hunter_anomalies_detected_total', 'Total vector anomalies detected', ['source'])
METRIC_ALERTS = Counter('nexus_hunter_alerts_dispatched_total', 'Total swarm alerts dispatched')
METRIC_LLM_LATENCY = Histogram('nexus_hunter_swarm_execution_seconds', 'End-to-end DAG response time')
METRIC_STACK_TEARDOWNS = Counter('nexus_stack_teardowns_total', 'Stack teardowns by reason', ['reason'])


async def bootstrap_swarm_memory():
    """Ensure the Swarm's long-term RAG memory collection exists on startup."""
    try:
        response = await async_qdrant.get_collections()
        existing = [c.name for c in response.collections]
        if MEMORY_COLLECTION not in existing:
            logger.info("First run detected. Bootstrapping Swarm RAG Memory...")
            await async_qdrant.create_collection(
                collection_name=MEMORY_COLLECTION,
                vectors_config=VectorParams(size=EMBED_DIM, distance=Distance.COSINE),
            )
            logger.info("[+] Swarm Long-Term Memory collection initialized.")
    except Exception as e:
        logger.error(f"Failed to bootstrap Swarm memory: {e}")


async def is_new_anomaly(event_id: str) -> bool:
    """7-day dedup window lock. Returns True only the first time an event is seen."""
    if not event_id:
        return True
    key = f"nexus:processed:{event_id}"
    is_new = await redis_client.setnx(key, "1")
    if is_new:
        await redis_client.expire(key, 604800)
    return bool(is_new)


def supervisor_router(state: InvestigativeState) -> str:
    """
    Pure routing function -- NO state mutation (LangGraph discards mutations made
    in conditional-edge functions; the blast-radius cap that used to live here
    therefore never took effect and now lives in the supervisor node + reducer).

    Critic review is symmetric: True Positives are reviewed before containment
    (as before), and False Positives are reviewed before dismissal whenever the
    dismissal is weak -- confidence below FP_CONFIDENCE_GATE or an incomplete
    blast radius. An unreviewed weak FP previously went straight to the response
    agent and was written into RAG memory, where immunity would auto-dismiss its
    signature forever (the swarm's one self-reinforcing failure mode).
    """
    next_node = state.get("next_agent", "FINISH")
    if next_node != "FINISH":
        return next_node
    verdict = state.get("verdict") or {}
    if not verdict:
        return "response_agent"  # nothing to review
    if verdict.get("is_true_positive"):
        return "critic"
    if state.get("analysis_complete", True) is False:
        return "critic"
    if float(verdict.get("confidence", 0.0) or 0.0) < FP_CONFIDENCE_GATE:
        return "critic"
    return "response_agent"


def build_graph(checkpointer):
    builder = StateGraph(InvestigativeState)
    builder.add_node("supervisor", supervisor_agent)
    builder.add_node("host_expert", host_expert_node)
    builder.add_node("net_expert", net_expert_node)
    builder.add_node("cloud_expert", cloud_expert_node)
    builder.add_node("nettap_expert", nettap_expert_node)
    builder.add_node("critic", critic_node)
    builder.add_node("response_agent", response_agent)

    builder.set_entry_point("supervisor")
    builder.add_conditional_edges("supervisor", supervisor_router, {
        "host_expert": "host_expert",
        "net_expert": "net_expert",
        "cloud_expert": "cloud_expert",
        "nettap_expert": "nettap_expert",
        "critic": "critic",
        "response_agent": "response_agent",
    })
    builder.add_edge("host_expert", "supervisor")
    builder.add_edge("net_expert", "supervisor")
    builder.add_edge("cloud_expert", "supervisor")
    builder.add_edge("nettap_expert", "supervisor")
    builder.add_edge("critic", "response_agent")
    builder.add_edge("response_agent", END)
    return builder.compile(checkpointer=checkpointer)


def _initial_route(source_type: str) -> str:
    """Deterministic first-hop routing -- delegates to the shared map in state.py
    (also used by the supervisor's thoroughness-gate re-route)."""
    return route_for_source_type(source_type)


async def _broadcast_hud(alert: UnifiedAlertSchema, nc_client):
    try:
        raw = alert.raw_event or {}
        hud_payload = {
            "type": "telemetry",
            "timestamp": alert.timestamp,
            "comm": raw.get("process_name", raw.get("process", "unknown")),
            "mitre_tactic": raw.get("mitre_tactic", raw.get("tactic", "Unknown")),
            "mitre_technique": raw.get("mitre_technique", raw.get("technique", "Unknown")),
            "anomaly_score": alert.anomaly_score,
            "level": "CRITICAL" if alert.anomaly_score > 0.90 else "WARNING",
            "command_line": raw.get("command_line", ""),
            "pid": raw.get("pid", 0),
            "ppid": raw.get("parent_pid", raw.get("ppid", 0)),
            "dest_ip": raw.get("dst_ip", raw.get("destination_ip", "")),
        }
        await nc_client.publish("nexus.hud.telemetry", json.dumps(hud_payload).encode())
    except Exception as e:
        logger.warning(f"HUD Broadcast failed: {e}")


async def trigger_swarm(alert: UnifiedAlertSchema, js_client, nc_client, graph):
    """Execute the LangGraph DAG for one alert, then dispatch governed action."""
    async with _investigation_sema:  # bound concurrent investigations (DoS guard)
        await _broadcast_hud(alert, nc_client)
        with METRIC_LLM_LATENCY.time():
            initial_entities = (
                {alert.sensor_id: {"type": "ip", "status": "pending", "notes": "Initial alert target"}}
                if alert.sensor_id else {}
            )
            kickoff_msg = HumanMessage(
                content=f"New high-severity alert on {alert.sensor_id}. "
                        f"Begin investigation and delegate queries to experts."
            )
            canary = CognitiveSanitizer.generate_canary()

            # raw_event is kept as a structured dict; it is neutralized at render time.
            initial_state = {
                "alert": alert.model_dump(),
                "messages": [kickoff_msg],
                "entities_of_interest": initial_entities,
                "next_agent": _initial_route(alert.source_type),
                "verdict": None,
                "action_payload": None,
                "incident_report": None,
                "canary": canary,
                "gate_overrides": 0,
                "analysis_complete": None,
            }

            config_opts = {"configurable": {"thread_id": alert.event_id}, "recursion_limit": RECURSION_LIMIT}
            logger.info(f"Launch sequence initiated for Event {alert.event_id}...")

            try:
                final_state = await asyncio.wait_for(
                    graph.ainvoke(initial_state, config=config_opts),
                    timeout=INVESTIGATION_TIMEOUT_S,
                )
            except asyncio.TimeoutError:
                logger.error(
                    f"TIMEOUT: Swarm DAG for {alert.event_id} exceeded "
                    f"{INVESTIGATION_TIMEOUT_S}s. Escalating to MANUAL_REVIEW -- "
                    f"never silently discard a timed-out investigation."
                )
                timeout_action = {
                    "incident_id":   alert.event_id,
                    "action_type":   "manual_review_required",
                    "target_sensor": alert.sensor_id,
                    "targets":       [alert.sensor_id],
                    "confidence":    0.0,
                    "reason":        (
                        f"Swarm DAG timed out after {int(INVESTIGATION_TIMEOUT_S)}s "
                        f"on {alert.source_type} anomaly (score={alert.anomaly_score:.2f}). "
                        f"Requires human review."
                    )[:200],
                }
                await _dispatch_soar(alert, timeout_action, js_client)
                return
            except GraphRecursionError:
                fault_reason = (
                    f"GraphRecursionError: DAG hit recursion_limit={RECURSION_LIMIT} "
                    f"on {alert.source_type} anomaly (score={alert.anomaly_score:.2f})."
                )
                logger.error(f"[!] COGNITIVE FAULT -- {fault_reason} Event={alert.event_id}")
                await _publish_cognitive_dlq(alert, fault_reason, js_client)
                return
            except Exception as exc:
                fault_reason = (
                    f"Unhandled cognitive fault ({type(exc).__name__}): {str(exc)[:120]} "
                    f"on {alert.source_type} anomaly (score={alert.anomaly_score:.2f})."
                )
                logger.error(f"[!] COGNITIVE FAULT -- {fault_reason} Event={alert.event_id}")
                await _publish_cognitive_dlq(alert, fault_reason, js_client)
                return

            # OWASP LLM01: verify the canary did not leak into any outbound surface.
            report = final_state.get("incident_report", "") or ""
            action = final_state.get("action_payload", {}) or {}
            if canary in report or canary in json.dumps(action):
                logger.critical(f"CANARY LEAK DETECTED in Event {alert.event_id}. "
                                f"Halting SOAR pipeline.")
                return

            verdict = final_state.get("verdict") or {}
            is_tp = bool(verdict.get("is_true_positive"))

            # Ephemeral ops interface only for CONFIRMED incidents (not raw score).
            if is_tp and alert.anomaly_score >= 0.85:
                await manage_ephemeral_interface("trigger", alert.event_id)

            await _dispatch_soar(alert, action, js_client)


async def _publish_cognitive_dlq(alert: UnifiedAlertSchema, reason: str, js_client):
    """Publish an unrecoverable DAG fault to the cognitive DLQ for operator triage."""
    payload = {
        "incident_id":   alert.event_id,
        "sensor_id":     alert.sensor_id,
        "source_type":   alert.source_type,
        "anomaly_score": alert.anomaly_score,
        "fault_reason":  reason[:300],
        "timestamp":     time.time(),
    }
    try:
        await js_client.publish("nexus.dlq.cognitive", json.dumps(payload).encode())
        logger.warning(f"[!] Cognitive DLQ publish: event={alert.event_id} reason={reason[:80]}")
    except Exception as pub_exc:
        # DLQ publish failure -- log loudly but do not re-raise; the investigation slot must release.
        logger.critical(f"[!!!] Cognitive DLQ publish FAILED for event={alert.event_id}: {pub_exc}")


async def _dispatch_soar(alert: UnifiedAlertSchema, action: dict, js_client):
    """Validate the field-aligned SOAR payload and publish it to JetStream."""
    if not action:
        return
    action_type = action.get("action_type")
    if not action_type:
        return
    if action_type == "manual_review_required":
        # Publish to NATS manual queue so HUD, n8n, and operator interfaces see it.
        # Never silently swallow a manual-review decision (governance demotions, timeouts).
        manual_payload = {
            "incident_id":   action.get("incident_id", alert.event_id),
            "action_type":   "manual_review_required",
            "target_sensor": action.get("target_sensor", alert.sensor_id),
            "targets":       action.get("targets", [alert.sensor_id]),
            "confidence":    float(action.get("confidence", 0.0)),
            "reason":        action.get("reason", "Manual review required.")[:200],
        }
        await js_client.publish(
            "nexus.soar.execute",   # H-I2 fix: was "Nexus_System.SOAR.ManualQueue" -- worker_soar subscribes to nexus.soar.execute (lowercase)
            json.dumps(manual_payload).encode(),
        )
        METRIC_ALERTS.inc()
        logger.warning(
            f"[!] MANUAL REVIEW QUEUED: {alert.sensor_id} "
            f"reason={manual_payload['reason'][:80]}"
        )
        return

    try:
        validated = SoarExecutionSchema(
            incident_id=action.get("incident_id", alert.event_id),
            action_type=action_type,
            target_sensor=action.get("target_sensor", alert.sensor_id),
            targets=action.get("targets", []),
            confidence=float(action.get("confidence", 0.0)),
            reason=action.get("reason", "")[:200],
        )
    except ValidationError as e:
        logger.error(f"SOAR payload failed schema validation; dropping to prevent "
                     f"erratic execution: {e}")
        return

    dump = validated.model_dump()
    dump["reason"] = CognitiveSanitizer.scrub_outbound_dlp(dump.get("reason", ""))
    msg_id = action.get("idempotency_key", "")
    await js_client.publish(
        "nexus.soar.execute",   # H-I2 fix: was "Nexus_System.SOAR.Execute" -- worker_soar subscribes to nexus.soar.execute
        json.dumps(dump).encode(),
        headers={"Nats-Msg-Id": msg_id} if msg_id else None,
    )
    METRIC_ALERTS.inc()
    logger.warning(f"[+] CONTAINMENT PUBLISHED to JetStream for {validated.target_sensor} "
                   f"({action_type})")


def _parse_alert(alert_data: dict) -> UnifiedAlertSchema:
    """Build a validated alert, supplying tolerant defaults for the reactive path."""
    return UnifiedAlertSchema(
        event_id=alert_data.get("event_id"),
        timestamp=alert_data.get("timestamp", time.time()),
        sensor_id=alert_data.get("sensor_id"),
        source_type=alert_data.get("source_type", "qdrant_vector"),
        vector_name=alert_data.get("vector_name", "isolation_forest"),
        anomaly_score=alert_data.get("anomaly_score", 1.0),
        raw_event=alert_data.get("raw_event", {}),
    )


async def redis_polling_loop(js_client, nc_client, graph):
    """Reactively listens for deterministic rule alerts on a Redis list."""
    logger.info("[*] Redis Deterministic Listener Online.")
    while True:
        try:
            raw_alert = await redis_client.blpop("nexus:deterministic:alerts", timeout=0)
            if not raw_alert:
                continue
            try:
                alert = UnifiedAlertSchema(**json.loads(raw_alert[1]))
            except (ValidationError, json.JSONDecodeError) as ve:
                logger.error(f"Malformed deterministic alert dropped: {ve}")
                continue
            if not await is_new_anomaly(alert.event_id):
                continue
            METRIC_ANOMALIES.labels(source="redis").inc()
            asyncio.create_task(trigger_swarm(alert, js_client, nc_client, graph))
        except Exception as e:
            logger.error(f"[!] Redis polling exception: {e}")
            await asyncio.sleep(1)


async def reactive_alert_consumer(js_client, nc_client, graph):
    """
    Zero-latency NATS JetStream consumer with PER-MESSAGE isolation.

    The original wrapped the whole batch in one try/except, so a single bad
    message aborted the rest of the batch and was redelivered forever (poison
    loop). Each message is now handled independently: parse/validation failures
    are TERMinated (never redelivered), duplicates are acked and skipped, and
    only genuinely new, valid alerts are dispatched.
    """
    logger.info("Initializing reactive NATS consumer...")
    sub = await js_client.pull_subscribe("nexus.alerts.>", "orchestrator_swarm_consumer")
    while True:
        try:
            msgs = await sub.fetch(batch=5, timeout=2.0)
        except (TimeoutError, asyncio.TimeoutError):
            continue
        except Exception as e:
            logger.error(f"Reactive consumer fetch fault: {e}")
            await asyncio.sleep(1)
            continue

        for msg in msgs:
            try:
                alert_data = json.loads(msg.data.decode())
                alert = _parse_alert(alert_data)
            except (ValidationError, json.JSONDecodeError, UnicodeDecodeError) as e:
                logger.error(f"Poison message TERMinated (will not redeliver): {e}")
                await msg.term()
                continue
            except Exception as e:
                logger.error(f"Unexpected parse error; NAK for redelivery: {e}")
                await msg.nak()
                continue

            try:
                if not await is_new_anomaly(alert.event_id):
                    await msg.ack()  # already handled; drop the duplicate
                    continue
                METRIC_ANOMALIES.labels(source="nats").inc()
                asyncio.create_task(trigger_swarm(alert, js_client, nc_client, graph))
                # At-most-once: ack on successful scheduling. Investigations are
                # idempotent via thread_id=event_id and the dedup lock above.
                await msg.ack()
            except Exception as e:
                logger.error(f"Failed to schedule investigation; NAK: {e}")
                await msg.nak()


async def _teardown_stack(event_id: str, reason: str = "unknown"):
    """Remove a stack from the active set, run teardown, and purge lifecycle state."""
    METRIC_STACK_TEARDOWNS.labels(reason=reason).inc()
    await redis_client.srem("nexus:active_operations_stacks", event_id)
    await manage_ephemeral_interface("teardown", event_id)
    for suffix in ("created_at", "ttl_deadline", "last_alert_at", "status"):
        await redis_client.delete(f"nexus:stack:{event_id}:{suffix}")


async def manage_ephemeral_interface(action: str, event_id: str):
    """Manage the ops tooling lifecycle with concurrency locking."""
    script_map = {
        "trigger": "/opt/sentinel-nexus/operations/scripts/trigger-incident.sh",
        "teardown": "/opt/sentinel-nexus/operations/scripts/teardown-incident.sh",
    }
    script = script_map.get(action)
    if not script:
        return

    if action == "trigger":
        active_stacks = await redis_client.scard("nexus:active_operations_stacks")
        if active_stacks >= MAX_OPERATIONS_STACKS:
            existing = await redis_client.srandmember("nexus:active_operations_stacks")
            if existing:
                logger.warning(f"[!] Concurrency limit reached. Piggybacking {event_id} "
                               f"onto active session {existing}.")
                # Append this incident's context to the shared session so the
                # piggybacked event is still tracked rather than silently dropped.
                await redis_client.sadd(f"nexus:operations_piggyback:{existing}", event_id)
                # Each new piggybacked alert signals continued activity -- extend the TTL
                # so the operator keeps visibility while the campaign is live.
                now = time.time()
                await redis_client.set(f"nexus:stack:{existing}:last_alert_at", now)
                created_raw  = await redis_client.get(f"nexus:stack:{existing}:created_at")
                deadline_raw = await redis_client.get(f"nexus:stack:{existing}:ttl_deadline")
                created_at       = float(created_raw)  if created_raw  else now
                current_deadline = float(deadline_raw) if deadline_raw else (created_at + STACK_TTL_S)
                # Cap at the absolute ceiling: created_at + STACK_TTL_S (hard max from birth)
                absolute_ceiling = created_at + STACK_TTL_S
                new_deadline = min(current_deadline + STACK_ALERT_EXTEND_S, absolute_ceiling)
                await redis_client.set(f"nexus:stack:{existing}:ttl_deadline", new_deadline)
                logger.info(f"[LIFECYCLE] TTL for {existing} extended to "
                            f"{(new_deadline - now) / 60:.0f}m remaining (piggyback: {event_id}).")
                return
        await redis_client.sadd("nexus:active_operations_stacks", event_id)
        # Initialise lifecycle tracking so the monitor can make teardown decisions.
        now = time.time()
        await redis_client.set(f"nexus:stack:{event_id}:created_at", now)
        await redis_client.set(f"nexus:stack:{event_id}:ttl_deadline", now + STACK_TTL_S)
        await redis_client.set(f"nexus:stack:{event_id}:last_alert_at", now)
        await redis_client.set(f"nexus:stack:{event_id}:status", "active")

    logger.info(f"Initiating {action} for operations interface (Event: {event_id})")
    try:
        process = await asyncio.create_subprocess_exec(
            script, event_id,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            logger.error(f"Interface {action} script failed: {stderr.decode()}")
            if action == "trigger":
                await redis_client.srem("nexus:active_operations_stacks", event_id)
                for suffix in ("created_at", "ttl_deadline", "last_alert_at", "status"):
                    await redis_client.delete(f"nexus:stack:{event_id}:{suffix}")
        else:
            logger.info(f"Interface {action} complete: {stdout.decode().strip()}")
    except Exception as e:
        logger.error(f"Failed to execute interface lifecycle script: {e}")
        if action == "trigger":
            await redis_client.srem("nexus:active_operations_stacks", event_id)
            for suffix in ("created_at", "ttl_deadline", "last_alert_at", "status"):
                await redis_client.delete(f"nexus:stack:{event_id}:{suffix}")


async def soar_callback_listener(js_client):
    """Listen for the 'STATUS: CONTAINED' callback from the n8n capstone node."""
    logger.info("Initializing SOAR callback listener...")
    sub = await js_client.pull_subscribe("nexus.soar.callback", "orchestrator_callback_consumer")
    while True:
        try:
            msgs = await sub.fetch(batch=5, timeout=2.0)
        except (TimeoutError, asyncio.TimeoutError):
            continue
        except Exception as e:
            logger.error(f"Callback listener fetch fault: {e}")
            await asyncio.sleep(1)
            continue
        for msg in msgs:
            try:
                payload = json.loads(msg.data.decode())
                soar_status = payload.get("status")
                event_id = payload.get("incident_id", "unknown")

                if soar_status == "CONTAINED":
                    # Mark contained; the lifecycle monitor handles actual teardown once
                    # the operator's minimum review window (STACK_MIN_LIFETIME_S) has elapsed.
                    await redis_client.set(f"nexus:stack:{event_id}:status", "contained")
                    logger.warning(f"[SOAR] {event_id} confirmed CONTAINED. Stack will tear down "
                                   f"after the {STACK_MIN_LIFETIME_S // 60}m operator review window.")

                elif soar_status in ("PARTIAL_FAILURE", "FAILED"):
                    # Containment incomplete -- operator must investigate further or retry.
                    # Extend the TTL so the stack doesn't idle-timeout mid-investigation.
                    now = time.time()
                    created_raw  = await redis_client.get(f"nexus:stack:{event_id}:created_at")
                    deadline_raw = await redis_client.get(f"nexus:stack:{event_id}:ttl_deadline")
                    created_at       = float(created_raw)  if created_raw  else now
                    current_deadline = float(deadline_raw) if deadline_raw else (created_at + STACK_TTL_S)
                    absolute_ceiling = created_at + STACK_TTL_S
                    new_deadline = min(current_deadline + STACK_ALERT_EXTEND_S, absolute_ceiling)
                    await redis_client.set(f"nexus:stack:{event_id}:ttl_deadline", new_deadline)
                    logger.warning(f"[SOAR] {event_id} reported {soar_status}. TTL extended to "
                                   f"{(new_deadline - now) / 60:.0f}m remaining for operator review.")

                await msg.ack()
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                logger.error(f"Poison callback TERMinated: {e}")
                await msg.term()
            except Exception as e:
                logger.error(f"Callback handling fault; NAK: {e}")
                await msg.nak()


async def detonation_enrichment_listener(js_client):
    """Consume Det Chamber verdicts (nexus.alerts.detonation) and act on them.

    Hybrid loop-back: the host_expert dispatched acquisition during the
    investigation; the full detonation verdict arrives here asynchronously. We
    map it to a follow-up SOAR action -- contain on malicious, RESTORE on a benign
    (false-positive) result that we previously contained, manual review on a
    custody failure -- and write the verdict into the swarm's RAG memory so the
    next sighting of this hash auto-escalates.
    """
    logger.info("Initializing detonation enrichment listener...")
    sub = await js_client.pull_subscribe("nexus.alerts.detonation", "orchestrator_detonation_consumer")
    while True:
        try:
            msgs = await sub.fetch(batch=5, timeout=2.0)
        except (TimeoutError, asyncio.TimeoutError):
            continue
        except Exception as e:
            logger.error(f"Detonation listener fetch fault: {e}")
            await asyncio.sleep(1)
            continue
        for msg in msgs:
            try:
                result = json.loads(msg.data.decode())
                incident_id = result.get("incident_id", "unknown")
                # Did we already contain this incident? (decides FP restore vs no-op)
                had_containment = bool(await redis_client.get(f"nexus:stack:{incident_id}:status") == "contained")
                action = enrichment_decision(result, had_containment=had_containment)
                if action:
                    try:
                        validated = SoarExecutionSchema(**action)
                    except ValidationError as e:
                        logger.error(f"Enrichment action failed schema validation; dropping: {e}")
                        await msg.ack()
                        continue
                    dump = validated.model_dump()
                    dump["reason"] = CognitiveSanitizer.scrub_outbound_dlp(dump.get("reason", ""))
                    await js_client.publish("nexus.soar.execute", json.dumps(dump).encode())
                    logger.warning(f"[DETONATION] {incident_id}: {validated.action_type} "
                                   f"(verdict-driven follow-up).")
                await msg.ack()
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                logger.error(f"Poison detonation alert TERMinated: {e}")
                await msg.term()
            except Exception as e:
                logger.error(f"Detonation enrichment fault; NAK: {e}")
                await msg.nak()


async def stack_lifecycle_monitor():
    """
    Evaluate every active operations stack on a fixed cadence and tear it down
    when one of four conditions is met (checked in priority order):

    1. TTL expired        -- absolute hard ceiling; no extensions apply.
    2. Min lifetime gate  -- stack is too young to tear down regardless of status.
    3. Contained          -- SOAR confirmed success AND the operator review window passed.
    4. Idle               -- no new alert has piggybacked for STACK_IDLE_TIMEOUT_S; the
                            incident appears resolved without a formal CONTAINED signal.
    """
    logger.info("[*] Stack Lifecycle Monitor Online.")
    while True:
        await asyncio.sleep(STACK_MONITOR_INTERVAL_S)
        try:
            active = await redis_client.smembers("nexus:active_operations_stacks")
            if not active:
                continue
            now = time.time()
            for event_id in active:
                created_raw = await redis_client.get(f"nexus:stack:{event_id}:created_at")
                deadline_raw = await redis_client.get(f"nexus:stack:{event_id}:ttl_deadline")
                alert_raw = await redis_client.get(f"nexus:stack:{event_id}:last_alert_at")
                status = await redis_client.get(f"nexus:stack:{event_id}:status") or "active"

                if not created_raw or not deadline_raw:
                    logger.warning(f"[LIFECYCLE] Stack {event_id} has no lifecycle state; "
                                   f"skipping until state is available.")
                    continue

                created_at = float(created_raw)
                ttl_deadline = float(deadline_raw)
                last_alert_at = float(alert_raw) if alert_raw else created_at
                lifetime = now - created_at

                # Rule 1: hard ceiling -- never negotiate with the absolute TTL.
                if now >= ttl_deadline:
                    logger.warning(f"[LIFECYCLE] Stack {event_id} hit absolute TTL after "
                                   f"{lifetime / 3600:.1f}h. Tearing down.")
                    await _teardown_stack(event_id, "ttl_expired")
                    continue

                # Rule 2: min lifetime gate -- operator needs time to review before teardown.
                if lifetime < STACK_MIN_LIFETIME_S:
                    continue

                # Rule 3: containment confirmed + review window satisfied.
                if status == "contained":
                    logger.warning(f"[LIFECYCLE] Stack {event_id} confirmed contained and past "
                                   f"min review window ({lifetime / 60:.0f}m). Tearing down.")
                    await _teardown_stack(event_id, "contained")
                    continue

                # Rule 4: idle -- no new alerts for the idle timeout window.
                alert_idle = now - last_alert_at
                if alert_idle > STACK_IDLE_TIMEOUT_S:
                    logger.warning(f"[LIFECYCLE] Stack {event_id} idle for {alert_idle / 60:.0f}m "
                                   f"with no new alert activity. Tearing down.")
                    await _teardown_stack(event_id, "idle")

        except Exception as e:
            logger.error(f"[LIFECYCLE] Monitor error: {e}")


async def _connect_nats_with_retry(url: str, max_attempts: int = 0) -> NATS:
    """
    H-F4 fix: NATS connection with exponential backoff reconnect loop.
    Previously a connection drop caused orchestrator exit → swarm dark until container restart.
    max_attempts=0 means infinite retry (appropriate for a long-running service).
    """
    nc = NATS()
    attempt = 0
    backoff = 2.0
    # C2: central NATS runs default-deny authorization — authenticate as the
    # swarm_node user when credentials are provisioned (hunter.env).
    nats_user = os.getenv("NATS_USER", "")
    nats_pass = os.getenv("NATS_PASS", "")
    auth_kwargs = {"user": nats_user, "password": nats_pass} if nats_user and nats_pass else {}
    while True:
        try:
            await nc.connect(
                url,
                reconnected_cb=lambda: logger.warning("[NATS] Reconnected to JetStream broker"),
                disconnected_cb=lambda: logger.warning("[NATS] Disconnected from JetStream broker -- will retry"),
                error_cb=lambda e: logger.error(f"[NATS] Connection error: {e}"),
                max_reconnect_attempts=-1,   # nats.py built-in reconnect (-1 = infinite)
                reconnect_time_wait=2,
                **auth_kwargs,
            )
            logger.info(f"[NATS] Connected to {url}")
            return nc
        except Exception as e:
            attempt += 1
            if max_attempts and attempt >= max_attempts:
                raise RuntimeError(f"[NATS] Failed to connect after {attempt} attempts: {e}") from e
            logger.error(f"[NATS] Connection attempt {attempt} failed: {e} -- retrying in {backoff:.0f}s")
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 60.0)   # cap at 60s


async def main():
    logger.info("Starting Prometheus Exporter on Port 8000")
    start_http_server(8000)

    await bootstrap_swarm_memory()

    # H-F4 fix: use reconnect-aware connect helper
    nc = await _connect_nats_with_retry(os.getenv("NATS_URL", "nats://nats:4222"))
    js = nc.jetstream()

    # Construct the async checkpointer inside the running loop and set up its
    # Redis indices before compiling the graph (the original passed a raw client
    # to the constructor and never ran asetup()).
    async with AsyncRedisSaver.from_conn_string(REDIS_URL) as checkpointer:
        try:
            await checkpointer.asetup()
        except AttributeError:
            pass  # some versions set up lazily
        graph = build_graph(checkpointer)

        logger.info("[*] Agentic Swarm Online (Dual-Loop). Listening for anomalies...")
        await asyncio.gather(
            redis_polling_loop(js, nc, graph),
            reactive_alert_consumer(js, nc, graph),
            soar_callback_listener(js),
            detonation_enrichment_listener(js),
            stack_lifecycle_monitor(),
        )


if __name__ == "__main__":
    asyncio.run(main())