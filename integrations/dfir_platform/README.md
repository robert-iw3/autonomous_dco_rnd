# `dfir_platform` — the integration boundary

The DFIR platform is the system of record for memory evidence: it collects it, seals it,
stores it and adjudicates it. This stack consumes the result and does none of those things.
Everything that crosses that line lives here.

| File | What it is |
|---|---|
| [`PROJECTION-CONTRACT.md`](PROJECTION-CONTRACT.md) | The specification both sides implement. Read this first. |
| [`contract.py`](contract.py) | The executable half: seal verification, the allow-list, and the adapter into the toolkit's finding schema. Pure stdlib. |
| [`transport.py`](transport.py) | Where bundles come from — a pinned-TLS pull from the platform's DMZ dispatcher, or a directory drop. Client-side only; nothing here listens. |
| [`platform_drift.py`](platform_drift.py) | Reads a platform checkout and diffs its contract surface against the pinned baseline. |
| [`platform_baseline.json`](platform_baseline.json) | The pinned surface. Changes by decision, never as a side effect. |

## Tracking the platform

The platform is developed on its own track and is **never modified from this repository** —
it is a source to copy from. Its contract surface is pinned instead, and the drift tracker
parses a checkout with `ast` (no import, no execution, read-only) to tell you when something
that matters has moved:

```bash
python integrations/dfir_platform/platform_drift.py --check
```

Set `DFIR_PLATFORM_PATH` if the checkout is not at `~/Documents/DFIR_PLATFORM_DEV`. With no
checkout present the tool reports and exits clean, so CI runners without one are not blocked;
the contract tests assert against the pinned baseline either way.

Contract-affecting drift — a changed verdict ladder, a mapped field renamed or removed, the
platform's two ladders diverging from each other — fails the check. Revise
`PROJECTION-CONTRACT.md` and `contract.py` together, then re-pin with `--update`.

## Who consumes it

[`services/worker_memory`](../../services/worker_memory) polls the configured source,
validates each bundle, and publishes `nexus.memory.enrichment` in the shape the swarm already
consumes. Configuration is in that service's header.
