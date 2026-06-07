"""
Shared LLM provider plumbing for every node in the swarm.
"""

import os
import logging
import threading
import time
from enum import Enum
from functools import lru_cache

from langchain_anthropic import ChatAnthropic
from langchain_openai import ChatOpenAI

from tools.nexus_config import CONFIG, get_llm_provider_order

logger = logging.getLogger("nexus-llm-providers")


# ── Circuit Breaker ────────────────────────────────────────────────────────────

class CircuitState(str, Enum):
    CLOSED    = "CLOSED"     # Normal: calls pass through
    OPEN      = "OPEN"       # Tripped: fast-fail without calling provider
    HALF_OPEN = "HALF_OPEN"  # Recovery probe: allow exactly one call


class ProviderCircuitBreaker:
    """Open/half-open/closed state machine for a single LLM provider.

    Thresholds are read once at construction from environment variables:
      NEXUS_CB_FAILURE_THRESHOLD  (default 3) -- consecutive failures before OPEN
      NEXUS_CB_RECOVERY_TIMEOUT_SECS (default 60) -- seconds OPEN before HALF_OPEN probe
    """

    def __init__(self, name: str):
        self._name = name
        self._failure_threshold = int(os.getenv("NEXUS_CB_FAILURE_THRESHOLD", "3"))
        self._recovery_timeout = float(os.getenv("NEXUS_CB_RECOVERY_TIMEOUT_SECS", "60"))
        self._state = CircuitState.CLOSED
        self._failures = 0
        self._opened_at = 0.0
        self._lock = threading.Lock()

    @property
    def state(self) -> CircuitState:
        with self._lock:
            if (self._state is CircuitState.OPEN and
                    time.monotonic() - self._opened_at >= self._recovery_timeout):
                self._state = CircuitState.HALF_OPEN
                logger.info("[circuit:%s] OPEN → HALF_OPEN (recovery probe allowed)", self._name)
            return self._state

    def is_callable(self) -> bool:
        return self.state is not CircuitState.OPEN

    def record_success(self) -> None:
        with self._lock:
            if self._state is CircuitState.HALF_OPEN:
                logger.info("[circuit:%s] probe succeeded -- HALF_OPEN → CLOSED", self._name)
            self._state = CircuitState.CLOSED
            self._failures = 0

    def record_failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._state is CircuitState.HALF_OPEN:
                self._opened_at = time.monotonic()
                self._state = CircuitState.OPEN
                logger.warning("[circuit:%s] probe failed -- HALF_OPEN → OPEN", self._name)
            elif self._failures >= self._failure_threshold:
                self._opened_at = time.monotonic()
                self._state = CircuitState.OPEN
                logger.warning(
                    "[circuit:%s] CLOSED → OPEN after %d consecutive failures",
                    self._name, self._failures,
                )


# Module-level per-provider circuit breakers -- shared across all agent instances
_CIRCUIT_BREAKERS: dict[str, ProviderCircuitBreaker] = {}
_CB_LOCK = threading.Lock()


def _get_cb(name: str) -> ProviderCircuitBreaker:
    with _CB_LOCK:
        if name not in _CIRCUIT_BREAKERS:
            _CIRCUIT_BREAKERS[name] = ProviderCircuitBreaker(name)
        return _CIRCUIT_BREAKERS[name]


def circuit_is_callable(provider_name: str) -> bool:
    """Return False when the provider's circuit is OPEN (fast-fail, skip the call)."""
    return _get_cb(provider_name).is_callable()


def record_call_success(provider_name: str) -> None:
    """Record a successful call; resets failure count and closes the circuit."""
    _get_cb(provider_name).record_success()


def record_call_failure(provider_name: str) -> None:
    """Record a failed call; may trip the circuit to OPEN after threshold."""
    _get_cb(provider_name).record_failure()


def get_circuit_state(provider_name: str) -> CircuitState:
    """Return current circuit state for observability / testing."""
    return _get_cb(provider_name).state


def _build_one(name: str, cfg: dict, temperature: float):
    """Instantiate a single chat model from its nexus.toml definition."""
    api_type = cfg.get("api_type", "rest_openai_compatible")
    key_env = cfg.get("api_key_env_var", "")
    api_key = os.environ.get(key_env, "") if key_env else ""
    model = cfg.get("model", "")

    if api_type == "anthropic":
        kwargs = {"model": model, "temperature": temperature}
        if api_key:
            kwargs["anthropic_api_key"] = api_key
        return ChatAnthropic(**kwargs)

    if api_type == "openai":
        kwargs = {"model": model, "temperature": temperature}
        if api_key:
            kwargs["openai_api_key"] = api_key
        return ChatOpenAI(**kwargs)

    # rest_openai_compatible -- internal vLLM / Ollama / Azure-as-REST.
    endpoint = cfg.get("endpoint", "")
    return ChatOpenAI(
        model=model,
        openai_api_base=endpoint,
        openai_api_key=api_key or "not-needed",
        temperature=temperature,
    )


def build_failover_chain(temperature: float = 0.0):
    """
    Ordered list of (provider_name, chat_model) per [hunter].active_provider and
    [hunter].failover_providers. Returns [] if nothing is configured (callers
    already fail conservative on an empty chain).
    """
    llm_cfg = CONFIG.get("llm", {}) or {}
    chain = []
    for name in get_llm_provider_order():
        cfg = llm_cfg.get(name)
        if not cfg:
            continue
        try:
            chain.append((name, _build_one(name, cfg, temperature)))
        except Exception as e:
            logger.error(f"Failed to construct LLM provider '{name}': {e}. Skipping.")
    if not chain:
        logger.warning("LLM failover chain is EMPTY -- check [hunter].active_provider in nexus.toml.")
    return chain


@lru_cache(maxsize=1)
def get_embedder():
    """
    Lazily load ONE shared SentenceTransformer instance, on first use rather than
    at import. The model must be pre-baked into the image for air-gapped runtime
    (HF_HOME set, TRANSFORMERS_OFFLINE=1).
    """
    from sentence_transformers import SentenceTransformer
    model_name = os.getenv("NEXUS_EMBED_MODEL", "all-MiniLM-L6-v2")
    logger.info(f"Loading shared embedder: {model_name}")
    return SentenceTransformer(model_name)