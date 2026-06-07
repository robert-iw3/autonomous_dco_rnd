# Tier 3 - Windows Ring-3 Smoke Tests

## Purpose

Tier 3 runs on a physical or virtual **Windows 11 x64** machine. It validates
that the XdrAgent binary compiles, publishes, and starts correctly without
requiring actual ETW/kernel driver privileges.

## Prerequisites

Run `Install-TestEnv.ps1` once as Administrator before executing smoke tests.

### What it installs

| Tool | Version | Purpose |
|---|---|---|
| .NET SDK | 10.0 | `dotnet publish` the agent |
| Rust (nightly) | latest | `cargo build` workspace DLLs |
| Python | 3.12+ | Tier 0 tests on Windows if needed |
| WinGet | any | Dependency installer |

## Running

```powershell
# 1. Setup (once, as Administrator)
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
.\tests\tier3\Install-TestEnv.ps1

# 2. Smoke tests (standard user is sufficient for build-only tests)
.\tests\tier3\Invoke-SmokeTests.ps1

# 3. Live tests (Administrator, starts actual agent process)
.\tests\tier3\Invoke-SmokeTests.ps1 -StartAgent
```

## Tests performed

| # | Test | Requires Admin |
|---|---|---|
| T01 | XdrAgent.csproj present | No |
| T02 | NuGet restore succeeds | No |
| T03 | dotnet publish (self-contained win-x64) | No |
| T04 | Published binary is valid PE64/AMD64 | No |
| T05 | DeepXDR_Config.ini parses correctly | No |
| T06 | Rust DLLs present in DllDirectory | No |
| T07 | Windows service registration (sc.exe) | Yes (`-StartAgent`) |
| T08 | Agent self-start + log file created | Yes (`-StartAgent`) |

## Known issues / expected warnings

- **AppGuard .exe discrepancy**: Tier 3 logs a warning when
  `ShellInterpreters` in the INI lacks `.exe` suffixes. This is a known
  config bug - see `test_config.py:test_known_exe_discrepancy_ini_vs_defaults`.

- **Tier 3 does NOT test ring-0**: The kernel driver requires Secure Boot
  disabled + WHQL/test-signed driver + WDK. See Tier 4 for driver testing.

- **AV interference**: Windows Defender may flag the agent binary during
  `StartAgent` tests. Add `$env:TEMP\DeepXDR_SmokePublish_*` to exclusions.

## Output

All results are written to `%USERPROFILE%\DeepXDR_TestReports\tier3_smoke_<timestamp>.log`.

The script exits with code 0 on all-pass, 1 if any test fails.