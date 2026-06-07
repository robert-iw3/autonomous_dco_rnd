# Deep Visibility Sensor

**DISCLAIMER:**

An exploratory side project investigating Sigma/YARA detection on C# ETW traces and lightweight ML/UEBA augmentation, with an emphasis on minimizing sensor overhead while preserving observability and host stability. Not a full EDR; functions as a companion sensor and a test bench for downstream integration. Eventual target: a drop-in detection-and-alerting sensor for suspected-compromised hosts and Windows-based OT/IoT/SCADA endpoints. Happy hunting.

> [!NOTE]
>
> The following ETW trace sensor is the endpoint detection/response module foundation for integration with a unified .net 10 / rust XDR currently in development, eventually this will be converged into that endpoint agent.  All development has stopped for this pwsh/c#/rust sensor, given the proof of concept has passed all testing.

## Overview
A **high-performance, real-time** Endpoint Detection and Response (EDR) sensor operating natively in-memory for Windows. This project bridges unmanaged C# Event Tracing for Windows (ETW) telemetry with a **Native Rust Machine Learning Engine (DLL)** to autonomously detect and neutralize evasive OS behaviors, zero-day persistence, and memory manipulation.

Designed to operate entirely without third-party agents or restricted Microsoft ELAM/PPL boundaries, the suite relies on mathematical outlier detection, dynamic Sigma threat intelligence, and surgical thread-level containment.

The sensor integrates a **Context-Aware YARA Engine** that provides high-fidelity forensic attribution and memory scanning without the overhead of traditional signature-based AV.

By default, the suite operates in a **Safe Baselining Mode (Dry-Run)** to evaluate telemetry and train the ML models on host-specific behavior without impacting legitimate processes.

Standard EDR handles the broad-spectrum behavioral blocking at the surface level; Deep Sensor can safely focus on:
1. Deep-dive UEBA baselining
2. Surgical forensic extraction & YARA attribution
3. Highly specialized Sigma telemetry

---

## Architectural Highlights
* **High-Performance ETW Engine:** Natively subscribes to `Kernel-Process`, `Kernel-Registry`, `Kernel-Memory`, and `Kernel-FileIO`. Zero-allocation string parsing and an $O(n)$ Aho-Corasick state machine evaluate 10,000+ Sigma rules in sub-millisecond time.
* **Context-Aware YARA Engine:** Implements a RAII-based `YaraContext` using **libyara.NET v3.5.2** to manage native handles for ten unique threat matrices. The engine dynamically maps targets to specific vectors (e.g., *BinaryProxy*, *SystemPersistence*, *LotL*) based on process heuristics to maintain zero-latency performance.
* **Native Rust Behavioral & UEBA Engine:** A deeply integrated math engine (`lib.rs`) operates via a zero-latency Foreign Function Interface (FFI) boundary. Event micro-batching eliminates P/Invoke overhead. It features an **asynchronously trained Isolation Forest** to evaluate execution lineages without blocking the ETW thread, calculates Shannon Entropy (T1027), and tracks high-frequency I/O bursts.
* **High-Speed Relational Baselines:** Integrates a deterministic User and Entity Behavior Analytics (UEBA) SQLite database utilizing Write-Ahead Logging (WAL) and memory-mapped synchronization. It learns host-specific administrative noise and autonomously suppresses false positives over time.
* **Dynamic Threat Intel & BYOVD Eradication:** The orchestrator compiles local YAML Sigma rules and dynamically fetches live BYOVD (Bring Your Own Vulnerable Driver) hashes from LOLDrivers.io to instantly convict malicious .sys loads.
* **Surgical Active Defense:** Utilizes native Win32 P/Invoke to execute QuarantineNativeThread (SuspendThread). This freezes malicious threads for forensic analysis without impacting parent process stability.
* **Automated Forensic Attribution:** Upon interventional detection, the sensor executes `NeuterAndDumpPayload` to extract shellcode, neutralize the thread, and perform a YARA scan. The resulting attribution (e.g., "CobaltStrike_Beacon") is embedded directly into the SIEM audit trail.
* **Active Anti-Tamper & Self-Defense:**
  * The C# engine defends its own PID, immediately killing external threads attempting RWX injections into its memory space.
  * Implements `icacls` lockdown sequences and secures the Windows Service DACL via `sc.exe sdset`.
  * Intercepts rogue `logman` commands attempting to blind the ETW session.

### System Diagram
---

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': { 'fontFamily': 'Fira Code, monospace', 'lineColor': '#06b6d4', 'mainBkg': '#0a0a0a', 'textColor': '#e2e8f0'}}}%%
graph LR
    %% Cyberpunk Style Definitions
    classDef title fill:none,stroke:none,color:#06b6d4,font-size:18px,font-weight:bold;
    classDef external fill:#050505,stroke:#888,stroke-width:1px,color:#888,stroke-dasharray: 3 3;
    classDef core fill:#0a0a0a,stroke:#06b6d4,stroke-width:2px,color:#06b6d4;
    classDef logic fill:#0a0a0a,stroke:#ec4899,stroke-width:2px,color:#ec4899;
    classDef storage fill:#000,stroke:#4ade80,stroke-width:1px,color:#4ade80;
    classDef action fill:#0a0a0a,stroke:#ef4444,stroke-width:2px,color:#ef4444;
    classDef alert fill:#0a0a0a,stroke:#f59e0b,stroke-width:1px,color:#f59e0b;

    TITLE["DEEP VISIBILITY SENSOR v2.1"]:::title

    subgraph StagingSpace [COMPILATION & STAGING]
        RUST_BUILD["Build-RustEngine.ps1<br/>(MSVC/Cargo Compiler)"]:::core
        STAGED_YARA[("yara_rules/<br/>10x Vector Matrix")]:::storage
        STAGED_SIGMA[("sigma/<br/>YAML Rules")]:::storage
    end

    subgraph KernelSpace [KERNEL // ETW INSTRUMENTATION]
        ETW["WINDOWS ETW<br/>Kernel.Memory / Process"]:::external
        SELF_DEF["Anti-Tamper<br/>RWX Injection Guard"]:::action
    end

    subgraph EngineSpace [ENGINE // C# RUNSPACE]
        CSHARP["OsSensor.cs<br/>(RAII YaraContext)"]:::core
        TRIE["Aho-Corasick Trie<br/>(Sigma HQ Matches)"]:::core
        VECTORS{"VECTOR MAPPER<br/>DetermineThreatVector"}:::logic
    end

    subgraph AnalysisSpace [ANALYSIS // NATIVE RUST DLL]
        ML["lib.rs<br/>(Async Isolation Forest)"]:::logic
        ENTROPY["Shannon Entropy<br/>H(x) Calculus"]:::logic
        UEBA[("DeepSensor_UEBA.db<br/>SQLite WAL")]:::storage
    end

    subgraph DefenseSpace [ORCHESTRATION & FORENSICS]
        ORCH["DeepSensor_Launcher.ps1<br/>(Triage Loop)"]:::core
        ACT_DEFENSE["QuarantineNativeThread<br/>(Win32 Suspend)"]:::action
        DUMP["Forensic Memory Dump<br/>(YARA Attribution)"]:::action
        LOGS[("Events.jsonl<br/>Audit Trail")]:::storage
        HUD["ANSI HUD<br/>Live Triage"]:::logic
    end

    %% Initialization Flow
    RUST_BUILD ==>|"Compiles"| ML
    STAGED_YARA -.->|"Sorted into"| VECTORS
    STAGED_SIGMA -.->|"Compiled into"| TRIE

    %% Real-Time Telemetry Flow
    ETW ==>|"Stream"| CSHARP
    CSHARP <-->|"Targeted Eval"| VECTORS
    CSHARP <-->|"O(n) Search"| TRIE
    CSHARP ===>|"FFI Micro-Batch"| ML

    %% ML & UEBA Loop
    ML <--> ENTROPY
    ML <--> UEBA

    %% Bridge to Orchestration
    CSHARP ===>|"Zero-Tolerance Alerts"| ORCH
    ML ===>|"Anomaly & UEBA Alerts"| ORCH
    CSHARP -.->|"Shield Self"| SELF_DEF

    %% Defense & Forensic Cycle
    ORCH ==>|"1. Trigger"| DUMP
    DUMP -.->|"YARA Result"| ORCH
    ORCH ==>|"2. Execute if Armed"| ACT_DEFENSE

    %% Output
    ORCH -.-> HUD
    ORCH -.-> LOGS
    SELF_DEF -.-> ACT_DEFENSE

    %% Title alignment
    TITLE ~~~ StagingSpace
```

---

## Prerequisites
* Windows 10 / Windows 11 / Windows Server 2019+
* PowerShell 5.1+ (Must be run as Administrator)
* *Note: The `Build-RustEngine.ps1` script will automatically handle MSVC C++ Build Tools and Rust Toolchain (Cargo) deployment if absent on the host.*

---

## Quick Start Guide

### 1. Compile the Native Engine
Compiles the Rust Machine Learning engine into a C-compatible DLL for zero-latency FFI injection.
```powershell
.\Build-RustEngine.ps1
```

### 2. Launch the Orchestrator (Safe Baselining Mode)
Bootstraps the environment, fetches YARA/Sigma intelligence, and initializes the HUD in **Dry-Run Mode**.
```powershell
.\DeepSensor_Launcher.ps1
```

### 3. Launch the Orchestrator (Armed Mode)
Enables real-time ETW correlation and autonomous active defense with forensic YARA attribution.
```powershell
.\DeepSensor_Launcher.ps1 -ArmedMode
```

### Optional: Launch the Sensor with a Stealth Footprint
```powershell
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "Deployment halted. Administrator privileges are required to configure Session 0 and Symbolic Links."
    return
}

$UsePwshCore = $true  # Toggle to $false for Windows PowerShell 5.1
$TaskName    = "WinTelemetryCache"
$DeepRoot    = "C:\ProgramData\DeepSensor"
$BinDir      = "$DeepRoot\Bin"
$SensorPath  = "C:\Path\to\DeepSensor_Launcher.ps1" # correct the path
$StealthExe  = "$BinDir\vmmem_svc.exe" # rename here

if (!(Test-Path $BinDir)) { New-Item $BinDir -ItemType Directory -Force | Out-Null }

$rootItem = Get-Item $DeepRoot
$rootItem.Attributes = $rootItem.Attributes -bor [System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System

if ($UsePwshCore) {
    $RealExe = (Get-Command pwsh.exe -ErrorAction SilentlyContinue).Source
    if (!$RealExe) { throw "PowerShell 7+ (pwsh.exe) not found on host." }
} else {
    $RealExe = "$env:Windir\System32\WindowsPowerShell\v1.0\powershell.exe"
}

if (Test-Path $StealthExe) { Remove-Item $StealthExe -Force }
New-Item -ItemType SymbolicLink -Path $StealthExe -Target $RealExe | Out-Null

$Action = New-ScheduledTaskAction -Execute $StealthExe `
    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$SensorPath`" -Background -ArmedMode" # configure runtime param switches

$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings

Write-Host "[+] Deployment Complete: Sensor active in Session 0 as '$TaskName'." -ForegroundColor Green
```

---

## Core File Manifest
* **`DeepSensor_Launcher.ps1`**: Master orchestrator, HUD renderer, environment bootstrapper, high-performance YARA/Sigma RAII, and Active Defense gateway.
* **`OsSensor.cs`**: The unmanaged C# ETW listener. Houses the Aho-Corasick string matching algorithms, native Win32 API containment logic, the micro-batching FFI bridge, and the self-defense thread hijacking watchdog.
* **`lib.rs`**: The native Rust mathematical DLL. Provides asynchronous Isolation Forest execution scoring, Shannon Entropy calculations, stateful Ransomware burst detection, and the autonomous UEBA noise suppression engine.
* **`Build-RustEngine.ps1`**: Automated compiler pipeline that scaffolds the MSVC/Rust environment and builds the native `DeepSensor_ML_v2.1.dll`.

---

## Telemetry and Persistent Storage
The engine operates natively in-memory to prevent disk I/O lag, but preserves critical forensic telemetry and state data for investigation and SIEM ingestion in a locked-down directory structure:

| File/Directory | Description | Purpose |
| :--- | :--- | :--- |
| **`sigma\`** | Directory containing local YAML Sigma rules. | Dynamically parsed to build the Threat Intel Engine. |
| **`yara_rules\`** | Contextual YARA subdirectories. | Segments rules (e.g., `BinaryProxy`, `LotL`) for targeted scanning. |
| **`C:\ProgramData\DeepSensor\Data\Quarantine`** | Forensic shellcode repository. | Securely stores memory dumps extracted during interventional events. |
| **`DeepSensor_Events.jsonl`** | Structured JSON alerts with MITRE ATT&CK mappings. | Primary SIEM ingestion file stored in `C:\ProgramData` (Features 50MB Auto-Rotation). |
| **`DeepSensor_UEBA.db`** | SQLite DB stored in `C:\ProgramData` (WAL mode). | Maintains the learned UEBA baseline for deterministic alert suppression within the secure zone. |
| **`DeepSensor_UEBA_Diagnostic.log`**| Plaintext audit ledger in `C:\ProgramData`. | Traces the exact lifecycle of alerts transitioning from 'Learning' to 'Suppressed'. |
| **`DeepSensor_Diagnostic.log`** | Diagnostic log routing FFI engine states. | Troubleshooting environment boots and unmanaged memory mapping (Stored in `C:\ProgramData`). |
| **`deepsensor_canary.tmp`** | Synthetic 60-second file drop. | Evaluates ETW health and detects sensor blinding attempts. |

---

### How Events Are Evaluated in Batches

The engine optimizes performance and context by analyzing telemetry in **micro-batches** rather than as singular events.

1.  **The C# Aggregator (The Collector):** As raw OS events (FileIO, Registry, ImageLoads) occur, they are caught by the C# ETW listeners (`ProcessEvent`, etc.). Instead of sending every single file read to Rust instantly, C# groups these high-volume, low-fidelity events by `ProcessID` into a temporary `UebaAggregator` bucket.
2.  **The 5-Second Flush:** A background watchdog task continuously monitors these buckets. Every 5 seconds, or if a bucket hits 100 events, the aggregator packages the raw events into a compressed JSON array.
3.  **The Rust Multi-Dimensional Vector:** This batched JSON payload is fired across the FFI bridge into Rust. The Rust engine (`BehavioralEngine`) doesn't evaluate individual file reads; it evaluates the *behavior of the batch*. It calculates multi-dimensional features across the batch: [X1: Shannon Entropy, X2: Tuple Rarity, X3: Path Depth, X4: Execution Velocity, X5: Max Velocity].
4.  **High-Fidelity Bypass:** Crucially, if C# detects a Critical `TTP_Match` or `Sigma_Match`, it completely bypasses the aggregator. These events are fired directly to the `_mlWorkQueue` for immediate evaluation.

#### The Detection to UEBA Lifecycle Diagram

```mermaid
graph TD
    subgraph OS["Windows OS Layer"]
        ETW[Windows Kernel ETW<br/>Process/Module/File/Registry]
        Diag[Application Diagnostic ETW<br/>PowerShell/WMI]
    end

    subgraph CSharp["C# ETW Telemetry Engine (OsSensor.cs)"]
        Listener[ETW Session Listener]
        Gatekeeper{Diagnostic Gatekeeper}
        ScriptBlock[ParsePowerShellScriptBlock]

        subgraph Matrices["Threat Intel Matrices"]
            TTP[High-Fidelity TTP Array]
            Sigma[Sigma Rules Array]
        end

        Aggregator[UEBA Aggregator<br/>Batches by PID]
        Watchdog((5-Second Flush))
    end

    subgraph Rust["Rust Behavioral ML Engine (lib.rs)"]
        FFI[Native FFI Memory Bridge]

        subgraph LogicGates["Decision Gates"]
            IsTTP{Is TTP?}
            IsSigma{Is Sigma?}
            NoiseGate{Global Process Count < 5?}
            AlreadyAlerted{Already Alerted?}
        end

        subgraph Scoring["Math Engines"]
            IsolationForest[Isolation Forest<br/>Early UEBA Risk]
            ZScore[LotL Z-Score]
            Welford[Welford's Online Baseline<br/>Mean / StdDev]
        end
    end

    subgraph PowerShell["PowerShell Orchestrator (DeepSensor_Launcher.ps1)"]
        MeatExtractor[Optimize-Cmdline<br/>Regex Stripping]

        subgraph Routing["SIEM Routing & HUD"]
            HotIndex[Main SIEM / Hot Index<br/>Score >= 0.8]
            ColdIndex[UEBA SIEM / Cold Index<br/>Score < 0.0]
        end

        StateLearning[Type: 'Learning'<br/>Score: -4.0]
        StateSecured[Type: 'Secured'<br/>Score: -1.0]
        StateSuppressed[Type: 'Suppressed'<br/>Score: -2.0]
        StateRollup[Type: 'Rollup'<br/>Score: -3.0]
    end

    %% Data Flow - Ingestion & Gating
    ETW --> Listener
    Diag --> Listener
    Listener --> Gatekeeper

    Gatekeeper -->|EventID 4104| ScriptBlock
    Gatekeeper -->|Kernel/WMI Events| Matrices

    ScriptBlock -->|Category: ScriptBlock| FFI

    %% C# Matching Logic
    Matrices --> TTP
    TTP -->|Match Found| Sigma
    TTP -.->|EnqueTtpAlert<br/>Bypasses Aggregator| FFI

    Sigma -->|Match Found| Aggregator
    Sigma -.->|EnqueueAlert<br/>Bypasses Aggregator| FFI

    Sigma -->|No Match / Raw Event| Aggregator
    Aggregator --> Watchdog
    Watchdog -->|Batched JSON Array| FFI

    %% Rust Evaluation
    FFI --> IsTTP

    IsTTP -->|Yes| HotIndexAlert["Alert = [TTP]<br/>Score = 10.0"]
    IsTTP -->|No| IsSigma

    IsSigma -->|Yes| NoiseGate
    NoiseGate -->|Yes| HotIndexAlert2["Alert = [FIRST ALERT] [SIGMA]<br/>Score = 10.0"]
    NoiseGate -->|No| Welford

    IsSigma -->|No| IsolationForest
    IsolationForest --> ZScore

    IsolationForest -->|High Anomaly| AlreadyAlerted
    ZScore -->|High Z-Score| AlreadyAlerted

    AlreadyAlerted -->|No| HotIndexAlert3["Alert = Early UEBA Risk / LotL Anomaly<br/>Score = 1.0"]
    AlreadyAlerted -->|Yes| Welford

    HotIndexAlert --> Welford
    HotIndexAlert2 --> Welford
    HotIndexAlert3 --> Welford

    Welford -->|Targeting 8 Executions| StateLearningOut["Score: -4.0"]
    Welford -->|Count > 8| StateSecuredOut["Score: -1.0"]
    Welford -->|Process Count >= 5| StateSuppressedOut["Score: -2.0"]
    Welford -->|Delta < Tuning Limit| StateRollupOut["Score: -3.0"]

    %% PowerShell Routing
    HotIndexAlert -.-> MeatExtractor
    HotIndexAlert2 -.-> MeatExtractor
    HotIndexAlert3 -.-> MeatExtractor

    StateLearningOut -.-> MeatExtractor
    StateSecuredOut -.-> MeatExtractor
    StateSuppressedOut -.-> MeatExtractor
    StateRollupOut -.-> MeatExtractor

    MeatExtractor --> HotIndex
    MeatExtractor --> ColdIndex

    HotIndex -->|Displays on HUD| End["Threat Hunting Pipeline"]

    ColdIndex --> StateLearning
    ColdIndex --> StateSecured
    ColdIndex --> StateSuppressed
    ColdIndex --> StateRollup

    %% Styling
    classDef os fill:#2d3436,stroke:#636e72,stroke-width:2px,color:#dfe6e9;
    classDef csharp fill:#0984e3,stroke:#74b9ff,stroke-width:2px,color:#ffffff;
    classDef rust fill:#d63031,stroke:#ff7675,stroke-width:2px,color:#ffffff;
    classDef ps fill:#6c5ce7,stroke:#00b894,stroke-width:2px,color:#ffffff;
    classDef alert fill:#e17055,stroke:#fab1a0,stroke-width:2px,color:#ffffff;

    class ETW,Diag os;
    class Listener,Gatekeeper,ScriptBlock,TTP,Sigma,Aggregator,Watchdog csharp;
    class FFI,IsTTP,IsSigma,NoiseGate,AlreadyAlerted,IsolationForest,ZScore,Welford rust;
    class MeatExtractor,HotIndex,ColdIndex,StateLearning,StateSecured,StateSuppressed,StateRollup ps;
    class HotIndexAlert,HotIndexAlert2,HotIndexAlert3,StateLearningOut,StateSecuredOut,StateSuppressedOut,StateRollupOut alert;
```

---

### User Interface

Executing the launcher without the -Background switch initializes both a mathematically pinned, non-scrolling terminal HUD in the console and an auto-tailing browser dashboard, providing a unified interface for real-time sensor event tracking:

* **SIGMA (`Sigma_Match`):** Events triggered when system activity matches compiled Sigma rules, typically indicating known suspicious behavioral patterns such as command-line obfuscation or suspicious module loads.
* **TTP (`TTP_Match`):** High-fidelity alerts generated from custom Threat Intelligence signatures that are explicitly mapped to specific MITRE ATT&CK tactics, techniques, and threat actors (e.g., known APT PowerShell execution commands).
* **Advanced Detection (`Static_Detection`):** Native, hardcoded alerts generated directly by the C# ETW sensor to instantly flag critical threats like process hollowing, sensor tampering, or the loading of known vulnerable drivers (BYOVD).
* **ML Anomaly:** Behavioral outliers identified by the native Rust Machine Learning engine, which triggers an alert when a process's activity score meets or exceeds a high-threat threshold (>= 0.8) without needing a static signature.
* **UEBA (`UEBA_Audit`):** User and Entity Behavior Analytics logs that track the system's baseline states, categorized into phases such as `Learning` (observing initial process behavior), `Secured` (baseline established), and `Suppressed` (silencing known safe noise to prevent alert fatigue).


<p align="center">
  <img src="img/console_ui.png" width="60%">
</p>

<p align="center">
  <img src="img/sensor_hud.png" width="100%">
</p>