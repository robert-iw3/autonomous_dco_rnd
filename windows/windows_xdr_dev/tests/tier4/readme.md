# Tier 4 — Kernel driver contract tests

Two sub-layers covering the ring-0 driver ABI.

- **4a — static contracts** (`test_driver_contracts.py`, Linux, automated): the
  32-bit IOCTL values in `ring0_driver/src/ipc.rs` match `agent/KernelBridge.cs`,
  `EVT_*` codes 0–10 are not reordered, `MONITOR_EVENT` is 682 bytes, fixed-point
  score conversion (900→9.0), KernelBridge hardcoded scores (lsass 9.5, quarantine
  10.0, token 9.0), and ring-buffer ≥ 10× poll batch.
- **4b — live driver** (Windows 11 test VM, manual): actual driver load, IRP flow,
  IOCTL_GET_EVENTS, and quarantine/release. Requires test-signing + Secure Boot off
  + WDK; not automatable in CI (see checklist below).

`ring0_driver` is excluded from the Cargo workspace (needs WDK headers); IOCTL/EVT
codes must change in `ipc.rs` and `KernelBridge.cs` atomically.

Run 4a: `pytest tests/tier4/test_driver_contracts.py -v`
