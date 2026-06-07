# Tier 4 - Kernel Driver Contract Tests

## Overview

Tier 4 has two sub-layers:

| Sub-layer | Platform | What it tests |
|---|---|---|
| **4a** Static contracts | Linux (any) | IOCTL codes, EVT_* ordering, struct sizes |
| **4b** Live driver | Windows 11 test VM | Actual driver load, IRP flow, quarantine |

## Sub-layer 4a - Static contract tests (automated)

`test_driver_contracts.py` runs on Linux as part of the standard Tier 0
pytest suite.  It verifies:

- **IOCTL code cross-verification** - the exact 32-bit IOCTL values from
  `ring0_driver/src/ipc.rs` match the constants in `agent/KernelBridge.cs`
- **EVT_\* ordering** - event type codes 0-10 are not reordered (driver ABI)
- **MONITOR_EVENT struct size** - 682 bytes matches the C struct layout
- **Fixed-point score conversion** - `SCORE_CRITICAL_FP=900 / 100 = 9.0`
- **KernelBridge hardcoded scores** - lsass=9.5, quarantine=10.0, token=9.0
- **IRP inversion model** - ring buffer >= 10x poll batch

Run with:
```bash
pytest tests/tier4/test_driver_contracts.py -v
```

## Sub-layer 4b - Live driver tests (manual / restricted)

Live ring-0 driver testing requires:

1. **Windows 11 test VM** with Hyper-V or VMware (NOT production hardware)
2. **Test signing mode** enabled:
   ```
   bcdedit /set testsigning on
   # Reboot required
   ```
3. **Secure Boot disabled** in UEFI firmware
4. **WDK** (Windows Driver Kit) installed for driver signing
5. **Driver signed** with a test certificate:
   ```powershell
   # Generate test cert (WDK)
   MakeCert -r -pe -ss PrivateCertStore -n "CN=DeepXDR Test" TestSign.cer
   SignTool sign /v /s PrivateCertStore /n "DeepXDR Test" ring0_driver.sys
   ```

### Manual live test checklist

After building and signing `ring0_driver.sys`:

```powershell
# Install driver
sc.exe create DeepXDR_Ring0 type= kernel binPath= "C:\...\ring0_driver.sys"
sc.exe start DeepXDR_Ring0

# Verify driver loaded
Get-WmiObject Win32_SystemDriver | Where-Object Name -eq "DeepXDR_Ring0"

# Test IOCTL_GET_EVENTS via KernelBridge test harness
# (build KernelBridgeTestHarness project from tests/tier4/tools/ when added)

# Trigger quarantine test
# IOCTL_QUARANTINE_PID on a known benign test PID, verify block, then release

# Uninstall
sc.exe stop  DeepXDR_Ring0
sc.exe delete DeepXDR_Ring0
```

### What CANNOT be automated in CI

- **IOCTL_QUARANTINE_PID** - actually suspends a process; needs a controlled test target
- **ETW callback registration** - requires running kernel session
- **IRP completion timing** - depends on scheduler and load
- **BSOD regression testing** - requires VM snapshot/restore infrastructure

## Known constraints

- `ring0_driver` is **excluded from the Cargo workspace** (`Cargo.toml` does not
  list it as a member) because it requires WDK headers that are not in the
  standard Rust toolchain. `cargo check --workspace` will NOT compile the driver.

- The EVT_\* codes in `ipc.rs` **must never be reordered**. Adding a new event
  type must append to the end (value 11+). The static contract test will catch
  any reordering.

- The IOCTL codes follow the WDK `CTL_CODE` macro formula. Do not change the
  device type (0x8000), access level, or method without updating both
  `ipc.rs` and `agent/KernelBridge.cs` atomically and re-running Tier 4a tests.
