# Suricata IDS/IPS -- config-driven, risk-based inline blocking

One image, three run modes, selected entirely by environment variables -- no
rebuild to switch between passive detection and active inline blocking, and
nothing hardcoded to a specific network.

## Modes
| IPS_MODE | INLINE_METHOD     | Behaviour                                        |
|----------|-------------------|--------------------------------------------------|
| `ids`    | (n/a)             | Passive tap. Everything alerts; never drops.     |
| `ips`    | `afpacket_bridge` | Two-NIC inline bridge (eth0↔eth1). Drops inline. |
| `ips`    | `nfqueue`         | NFQUEUE inline via netfilter. Drops inline.      |

## Risk model (what gets blocked)
Controlled by `RULE_ACTION_POLICY` and the rule tiers:

- **Tier 0 `allowlist.rules`** -- `pass`. Evaluated first; wins over any drop. Your escape hatch.
- **Tier 1 `block-known-bad.rules`** -- `drop`. High-confidence IOCs (IP/domain/SNI/JA3/MD5 datasets) + exploit patterns.
- **Tier 2 `suspicious.rules`** -- `alert`, **auto-escalates to `drop`** for repeat offenders via `rate_filter` in `threshold.config`.
- **Tier 3 `policy.rules`** -- `alert`. Visibility/policy only.

Policies: `detect` (all alert) · `balanced` (T1 drop) · `aggressive` (T1+T2 drop) · `paranoid` (all drop).
IDS mode always forces everything to alert regardless of policy.

## The three control surfaces
1. **`rate_filter`** (threshold.config) -- risk-based escalation: alert once, block on sustained bad behaviour (per-source, timed).
2. **`threshold`** (threshold.config) -- alert-volume limiting (anti-flood).
3. **`suppress`** (threshold.config) -- false-positive filtering by SID/host/net without disabling a rule.

## Environment-agnostic IOC feeds
`block-known-bad.rules` matches against datasets, not hardcoded indicators.
Drop entries into the mounted `files/*.lst` and reload -- no rule edits:
- `bad_ips.lst` (IPs) · `bad_domains.lst` · `bad_sni.lst` · `bad_ja3.lst` · `bad_file_md5.lst`
- `.lst` files must contain **only entries -- no comments** (Suricata dataset format).

## Availability vs security
`EXCEPTION_POLICY=auto` fails **closed** (drops on internal limits) in IPS mode.
Set `EXCEPTION_POLICY=ignore` to fail **open**. NFQUEUE adds `NFQ_FAIL_OPEN` /
`--queue-bypass`; bridge mode passes traffic if Suricata stops.

## Quick start
```bash
# Passive IDS
./launch.sh

# Inline bridge IPS, block known-bad only
./launch.sh --mode ips --inline afpacket_bridge --interface eth0 --bridge-iface eth1 --policy balanced

# NFQUEUE IPS, escalate suspicious too, fail open
./launch.sh --mode ips --inline nfqueue --policy aggressive --fail-open
```