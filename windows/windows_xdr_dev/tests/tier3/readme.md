# Tier 3 — Windows Ring-3 smoke tests

Runs on a real/VM **Windows 11 x64** host. Validates that the XdrAgent builds,
publishes, and starts without ETW/kernel privileges.

Tests: csproj present, NuGet restore, `dotnet publish` (self-contained win-x64),
published binary is valid PE64, `DeepXDR_Config.ini` parses, Rust DLLs present,
and (with `-StartAgent`, Admin) Windows service registration + agent self-start +
log creation.

Setup once as Admin: `.\Install-TestEnv.ps1` (installs .NET 10 SDK, Rust, Python).
Run: `.\Invoke-SmokeTests.ps1 [-StartAgent]` → log in `%USERPROFILE%\DeepXDR_TestReports\`.

Does **not** test ring-0 (see Tier 4).
