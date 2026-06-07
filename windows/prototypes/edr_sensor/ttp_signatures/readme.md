## Executive Summary

While Sigma is great for broad level alerting, 90% of the alerts can be ignored.  The following custom TTP signatures are for hyper focused threat behavioral matching from real world attacks.

This guide outlines the transition from broad-net Sigma rules to **high-fidelity TTP Signatures**. As a detection engineer, your goal is to move away from alerting on "suspicious strings" and toward alerting on **correlated behaviors** that represent a specific adversary’s sequence of actions.

**See the Examples Provided in this Directory**

### The Philosophy of TTP-Signature Design
The core of this model is the **Correlation Trinity**. A signature is only valid if the Tactic, Technique, and Procedure are mathematically and logically coupled. This ensures that we aren't just seeing a "suspicious file," but a "specific actor (Tactic) using a known method (Technique) to drop a unique artifact (Procedure)".

---

### 1. The Metadata Block (The "Why" and "How")
The `meta` block is where you define the threat intel context. This ensures that every alert hitting the SIEM or HUD is actionable.

* **Tactic (The Objective):** Define the high-level goal (e.g., Persistence, Initial Access, Defense Evasion). Use MITRE ATT&CK mapping (e.g., `TA0003`).
* **Technique (The Method):** The intermediate method used to achieve the tactic (e.g., DLL Side-Loading, Registry Run Keys). Use the specific ID (e.g., `T1574.002`).
* **Procedure (The Specifics):** The detailed, tailored activity observed in the wild. This describes the exact malware or exploit behavior (e.g., "Covenant loader sideloading via BeardShell.dll").

---

### 2. The Match Block (The Execution Logic)
This block contains the three-way correlation gate. **All three parameters must return true** for the engine to fire.

#### A. The Actor (The "Who")
The most common cause of false positives is ignoring the process context.
* **Parameter:** `actor`
* **Logic:** Specifies the process name (e.g., `winword.exe`, `sqlservr.exe`) that is expected to trigger the event.
* **Engineering Tip:** If a procedure is globally suspicious (like LSASS dumping), leave the actor as `**`. If it is a targeted APT sideload (like BeardShell), the actor must be the specific host process (e.g., `winword.exe`).

#### B. The Type (The "What")
This maps the signature to the specific ETW kernel hook.
* **Parameter:** `type`
* **Valid Values:** `PROCESS_START`, `MODULE_LOAD`, `FILE_EVENT`, `REGISTRY_EVENT`, `NETWORK_CONNECTION`.

#### C. The Target (The "Specific Artifact")
The target is the **Procedural Indicator**. It is the specific string, path, or registry key the adversary interacts with.
* **Parameter:** `target`
* **Logic:** Uses the same high-performance `trigger_string` logic from our previous Sigma engine.
* **Example:** `BeardShell.dll`, `ctec.dll`, or a specific command-line flag like `--port 27017`.

---

### 3. The Filter Block (The Suppression)

Even high-fidelity rules need safety valves for unique environments.
The `filter` section lets you **suppress** known-good behavior without weakening the core detection.

**Available Parameters:**

| Parameter              | Purpose                                                                 | Example Value                          |
|------------------------|-------------------------------------------------------------------------|----------------------------------------|
| `exclude_path`         | Drop alerts when the path matches this pattern                         | `C:\\Windows\\System32\\*`            |
| `exclude_target`       | Drop alerts when the target (file, DLL, registry key, etc.) matches    | `*.System.dll`                         |
| `exclude_target_value` | Drop alerts when the registry value or command-line value matches      | `*Microsoft\\Teams\\*`                 |
| `exclude_actor_cmd`    | Drop alerts when the full command line contains this string            | `*Set-ExecutionPolicy*`                |
| `exclude_actor`        | Drop alerts when the actor process name matches                        | `services.exe`                         |

---

### Authoring Example: Converting an Expert Rule

**Original "Expert Rule" Logic**
> **Actor:** `winword.exe`
> **Action:** Creating `ctec.dll` in user AppData paths.
> **Context:** Signal-delivered Covenant/BeardShell loader observed in 2025.

**Custom TTP-Signature Syntax**

```yaml
- ttp_signature:
    name: "APT28 Covenant Loader Drop"
    severity: "Critical"
    meta:
      tactic: "Initial Access (TA0001)"
      technique: "Spearphishing Attachment (T1566.001)"
      procedure: "WinWord dropping ctec.dll decryption loader (APT28 2025)"
    match:
      actor: "winword.exe"           # The WHO (Tactical Context)
      type: "FILE_EVENT"             # The WHAT (Technique realization)
      target: "ctec.dll"             # The SPECIFIC (Procedural artifact)
    filter:                          # Optional: Reduce FPs
      exclude_path: "C:\\Program Files\\*"
      exclude_target: "*.System.dll"
      exclude_actor: "winword.exe"
```

---

#### Summary for Detection Engineers

By strictly enforcing the **Actor-Target coupling** and using the full set of exclusion filters, we ensure that only the precise malicious behavior triggers an alert.

If `winword.exe` touches `ctec.dll` **outside** the excluded paths, it is a critical alert.

If a legitimate process, backup tool, or known-good location touches it, the rule stays silent.