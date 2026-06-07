#!/usr/bin/env bash
# ================================================================================
# File:        sentinel_tester.sh
# Component:   Linux Sentinel -- APT Behavior Simulator
# Description: A synthetic threat generation script.
# Role:        Simulates isolated Advanced Persistent Threat (APT) behaviors
#              (e.g., T1059 Reverse Shells, T1620 Reflective Memory Allocation,
#              T1571 C2 Probes, T1071 DNS Tunneling) to safely trigger and verify
#              the eBPF kernel hooks and downstream SIEM/Dashboard telemetry.
# ================================================================================

echo "======================================================="
echo "  LINUX SENTINEL - ALERTING PIPELINE VALIDATOR         "
echo "======================================================="
echo "Simulating isolated APT behaviors to verify kernel hooks."

# 1. Credential Access (T1078)
# Triggers EVENT_OPEN_CRIT in eBPF when accessing critical paths
echo "[*] Triggering T1078: Simulating credential dumping (/etc/shadow)..."
sudo touch /etc/shadow
sudo cat /etc/shadow > /dev/null

# 2. Reverse Shell Execution (T1059)
# Triggers EVENT_EXEC matching the "nc" or "/dev/tcp" string rules
echo "[*] Triggering T1059: Spawning synthetic reverse shell..."
nc -z 127.0.0.1 80 2>/dev/null || true
bash -c 'echo "simulated shell" > /dev/tcp/127.0.0.1/4444' 2>/dev/null || true

# 3. Known Malicious C2 Ports (T1571)
# Triggers EVENT_CONNECT matching elite backdoor ports (1337, 4444, 50050)
echo "[*] Triggering T1571: Connecting to default C2/CobaltStrike ports..."
curl -s --connect-timeout 1 http://127.0.0.1:4444 > /dev/null || true
curl -s --connect-timeout 1 http://127.0.0.1:1337 > /dev/null || true
curl -s --connect-timeout 1 http://127.0.0.1:50050 > /dev/null || true

# 4. Fileless Code Execution (T1620)
# Triggers EVENT_MEMFD by allocating an anonymous file in RAM
echo "[*] Triggering T1620: Reflective memory allocation (memfd_create)..."
python3 -c 'import ctypes; libc = ctypes.CDLL(None); libc.syscall(319, b"synthetic_memfd", 0)' 2>/dev/null || true

# 5. DNS Tunneling (T1071.004)
# Triggers EVENT_UDP_SEND with a payload entropy > 4.5
echo "[*] Triggering T1071.004: Simulating high-entropy DNS tunnel..."
head -c 128 /dev/urandom | nc -u -w 1 8.8.8.8 53 2>/dev/null || true

echo "======================================================="
echo "[+] Synthetic behavior generation complete."
echo "    Refresh the Forensic Workbench (https://127.0.0.1:8443)"
echo "======================================================="