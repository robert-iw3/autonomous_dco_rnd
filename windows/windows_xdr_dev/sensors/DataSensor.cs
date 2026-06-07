/*=============================================================================================
 * SYSTEM:          Data Sensor
 * COMPONENT:       DataSensor.cs (Unmanaged ETW Listener & Active Defense)
 * AUTHOR:          Robert Weber
 * DESCRIPTION:
 * High-performance ETW engine monitoring Network volumetric flow & Process Lineage.
 * Deep File Inspection is now delegated to the in-band Ring-3 Rust Interceptor via IPC.
 *============================================================================================*/

using System;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

public class RealTimeDataSensor {

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool SetDllDirectory(string lpPathName);

    // --- NATIVE RUST FFI BOUNDARIES (ML ENGINE) ---
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct FfiPlatformEvent {
        public string timestamp;
        public string event_type;
        public string action;
        public string user;
        public string process;
        public string parent_process;
        public string command_line;
        public string filepath;
        public string destination;
        public string dest_port;
        public string details;
        public long bytes;
        public long duration_ms;
        public bool is_dlp_hit;
    }

    [DllImport("DataSensor_ML.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr init_dlp_engine(string config_json, NativeLogCallback logCb);

    [DllImport("DataSensor_ML.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr process_telemetry_batch(IntPtr engine, string batch_json);

    [DllImport("DataSensor_ML.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern void free_string(IntPtr s);

    [DllImport("DataSensor_ML.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern void teardown_engine(IntPtr engine);

    [DllImport("DataSensor_ML.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr scan_text_payload(
        IntPtr engine,
        string textPayload,
        string sourceProcess,
        string userName,
        string sourceFilepath);

    [DllImport("DataSensor_ML.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int groom_database(IntPtr engine, uint days_to_keep);

    public static int TriggerGrooming(uint days) {
        if (_mlEnginePtr != IntPtr.Zero) {
            return groom_database(_mlEnginePtr, days);
        }
        return -1;
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public delegate void NativeLogCallback(string message);

    private static NativeLogCallback _rustLogger = new NativeLogCallback(RustDiagLog);

    private static void RustDiagLog(string message) {
        EventQueue.Enqueue(new DataEvent { EventType = "DiagLog", RawJson = message });
    }

    // --- PROCESS CACHE & INJECTION P/INVOKES ---
    private static ConcurrentDictionary<int, string> _pidUserCache = new ConcurrentDictionary<int, string>();

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWow64Process([In] IntPtr process, [Out] out bool wow64Process);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool QueryFullProcessImageName(IntPtr hProcess, uint dwFlags, StringBuilder lpExeName, ref uint lpdwSize);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool QueryProcessMitigationPolicy(IntPtr hProcess, int MitigationPolicy, ref int lpBuffer, int dwLength);
    [DllImport("iphlpapi.dll", SetLastError = true)]
    static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, uint reserved);
    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern int NtSuspendProcess(IntPtr processHandle);

    private const uint PROCESS_SUSPEND_RESUME = 0x0800;

    // --- USER P/INVOKES ---
    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool OpenClipboard(IntPtr hWndNewOwner);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CloseClipboard();

    [DllImport("user32.dll")]
    static extern IntPtr GetClipboardData(uint uFormat);

    [DllImport("user32.dll")]
    static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll", SetLastError = true)]
    static extern IntPtr GetClipboardOwner();

    [DllImport("user32.dll", SetLastError = true)]
    static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("kernel32.dll")]
    static extern IntPtr GlobalLock(IntPtr hMem);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GlobalUnlock(IntPtr hMem);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint dwFreeType);

    // --- STATE MANAGEMENT ---
    private static volatile bool _teardownRequested = false;
    private static ConcurrentDictionary<int, byte> _injectedPids = new ConcurrentDictionary<int, byte>();
    private static BlockingCollection<FfiPlatformEvent> _uebaQueue = new BlockingCollection<FfiPlatformEvent>(100000);
    private static BlockingCollection<FfiPlatformEvent> _uebaJsonQueue = new BlockingCollection<FfiPlatformEvent>(100000);
    private static Thread _clipboardWorker;
    private static Thread _uebaJsonWorker;
    private static ConcurrentDictionary<string, string> _volumeMap = new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    private static readonly int _selfPid = System.Diagnostics.Process.GetCurrentProcess().Id;
    private static readonly string[] FilePathSplitter = new[] { "\"filepath\":\"" };

    public class DataEvent {
        public string EventType;
        public string ProcessName;
        public string UserName;
        public string RawJson;
    }

    public static IEnumerable<int> GetInjectedPids() => _injectedPids.Keys;
    public static ConcurrentQueue<DataEvent> EventQueue = new ConcurrentQueue<DataEvent>();
    public static int _eventQueueCount = 0;
    private static int _networkDiagCount = 0;
    private static HashSet<string> _trustedProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    private static readonly HashSet<string> _criticalSystemProcs = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
        "explorer", "taskmgr", "SearchApp", "StartMenuExperienceHost", "sihost", "ctfmon", "RuntimeBroker", "ShellExperienceHost",
        "chrome", "msedge", "firefox", "brave", "iexplore",
        "code", "devenv", "rider64", "idea64", "cmd", "wt"
    };
    private static IntPtr _mlEnginePtr = IntPtr.Zero;
    private static TraceEventSession _session;
    private static CancellationTokenSource _cts = new CancellationTokenSource();
    private static bool _enableUniversalLedger = false;
    private static ManualResetEventSlim _batchProcessorDone = new ManualResetEventSlim(false);
    private static string _hookDllPath = @"C:\ProgramData\DataSensor\Bin\DataSensor_Hook.dll";
    byte[] dllBytes = Encoding.Unicode.GetBytes(_hookDllPath + "\0");

    // --- WIN32 ACCESS RIGHT CONSTANTS ---
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint PROCESS_CREATE_THREAD             = 0x0002;
    private const uint PROCESS_QUERY_INFORMATION         = 0x0400;
    private const uint PROCESS_VM_OPERATION              = 0x0008;
    private const uint PROCESS_VM_WRITE                  = 0x0020;
    private const uint PROCESS_VM_READ                   = 0x0010;
    private const uint INJECT_ACCESS = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION
                                    | PROCESS_VM_OPERATION  | PROCESS_VM_WRITE | PROCESS_VM_READ;

    private static string JsonEscape(string s) {
        if (s == null) return "";
        return s.Replace("\0", "")
                .Replace("\\", "\\\\")
                .Replace("\"", "\\\"")
                .Replace("\n",  "\\n")
                .Replace("\r",  "\\r")
                .Replace("\t",  "\\t")
                .Replace("\b",  "\\b")
                .Replace("\f",  "\\f");
    }

    public static void InitializeEngine(string configJson, long maxMb, string trustedProcsCsv, bool enableLedger) {
        _enableUniversalLedger = enableLedger;

        if (!string.IsNullOrEmpty(trustedProcsCsv)) {
            foreach (var proc in trustedProcsCsv.Split(',')) {
                _trustedProcesses.Add(proc.Trim());
            }
        }

        if (_volumeMap.IsEmpty) { InitializeVolumeMap(); }
        SetDllDirectory(@"C:\ProgramData\DataSensor\Bin");

        try {
            _mlEnginePtr = init_dlp_engine(configJson, _rustLogger);
            if (_mlEnginePtr != IntPtr.Zero) {
                EventQueue.Enqueue(new DataEvent { EventType = "DiagLog", RawJson = "Native Rust ML Engine (FFI) successfully mapped into memory." });
                StartNamedPipeListener();
                StartBatchProcessor();
                StartClipboardMonitor();
                StartActiveNetworkMonitor();
                if (_enableUniversalLedger) { StartUebaJsonLogger(); }
            } else {
                EventQueue.Enqueue(new DataEvent { EventType = "FATAL", RawJson = "Native FFI Pointer returned null." });
            }
        } catch (Exception ex) {
            EventQueue.Enqueue(new DataEvent { EventType = "FATAL", RawJson = ex.Message });
        }
    }

    public static void InjectExistingProcesses() {
        Task.Run(async () => {
            EventQueue.Enqueue(new DataEvent { EventType = "DiagLog", RawJson = "Starting continuous Ring-3 injection watchdog..." });
            while (!_cts.Token.IsCancellationRequested) {
                var injectionTasks = new List<Task>();

                foreach (var proc in System.Diagnostics.Process.GetProcesses()) {
                    IntPtr hProc = IntPtr.Zero;
                    try {
                        if (proc.Id <= 4 || proc.SessionId == 0) continue;
                        if (proc.Id == _selfPid) continue;
                        if (_injectedPids.ContainsKey(proc.Id)) continue;

                        string procName = proc.ProcessName;
                        if (_criticalSystemProcs.Contains(procName)) continue;
                        if (_trustedProcesses.Contains(procName)) continue;

                        hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, proc.Id);
                        if (hProc == IntPtr.Zero) continue;

                        bool shouldInject = true;
                        uint capacity = 1024;
                        StringBuilder exePath = new StringBuilder((int)capacity);
                        if (QueryFullProcessImageName(hProc, 0, exePath, ref capacity)) {
                            string fullPath = exePath.ToString().ToLower();
                            bool isPowerShell = fullPath.Contains("powershell.exe") || fullPath.Contains("pwsh.exe");

                            if (fullPath.StartsWith(@"c:\windows\") && !isPowerShell) shouldInject = false;
                            if (fullPath.Contains(@"\windowsapps\") && !isPowerShell) shouldInject = false;
                            if (fullPath.Contains("chrome.exe") || fullPath.Contains("msedge.exe")) shouldInject = false;
                        }

                        if (!shouldInject) { CloseHandle(hProc); hProc = IntPtr.Zero; continue; }

                        IsWow64Process(hProc, out bool is32Bit);
                        CloseHandle(hProc); hProc = IntPtr.Zero;

                        if (!is32Bit) {
                            int pid = proc.Id; // capture for closure
                            injectionTasks.Add(Task.Run(() => InjectRustHook(pid)));
                        }
                    } catch {
                    } finally {
                        if (hProc != IntPtr.Zero) CloseHandle(hProc);
                    }
                }

                if (injectionTasks.Count > 0) {
                    await Task.WhenAll(injectionTasks);
                }

                await Task.Delay(3000, _cts.Token);
            }
        });
    }

    private static string GetProcessUser(int pid) {
        if (pid <= 4) return "System";
        if (_pidUserCache.TryGetValue(pid, out string cachedUser)) return cachedUser;

        string userName = "System";
        IntPtr processHandle = IntPtr.Zero;
        IntPtr tokenHandle = IntPtr.Zero;

        try {
            processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (processHandle != IntPtr.Zero) {
                if (OpenProcessToken(processHandle, 0x0008, out tokenHandle)) {
                    using (WindowsIdentity wi = new WindowsIdentity(tokenHandle)) {
                        userName = wi.Name;
                        if (userName.Contains("\\")) { userName = userName.Split('\\')[1]; }
                    }
                }
            }
        } catch {
        } finally {
            if (tokenHandle != IntPtr.Zero) CloseHandle(tokenHandle);
            if (processHandle != IntPtr.Zero) CloseHandle(processHandle);
        }

        _pidUserCache.TryAdd(pid, userName);
        return userName;
    }

    public static void InitializeVolumeMap() {
        try {
            foreach (string drive in Environment.GetLogicalDrives()) {
                string driveLetter = drive.Substring(0, 2);
                StringBuilder targetPath = new StringBuilder(256);
                if (QueryDosDevice(driveLetter, targetPath, targetPath.Capacity) != 0) {
                    _volumeMap[targetPath.ToString()] = driveLetter;
                }
            }
        } catch (Exception ex) {
            EventQueue.Enqueue(new DataEvent { EventType = "ERROR", RawJson = "Volume Map Init Failed: " + ex.Message });
        }
    }

    public static string ResolveUniversalPath(string ntPath) {
        if (string.IsNullOrEmpty(ntPath)) return "";
        if (!ntPath.StartsWith(@"\device\", StringComparison.OrdinalIgnoreCase)) return ntPath;

        foreach (var kvp in _volumeMap) {
            if (ntPath.StartsWith(kvp.Key, StringComparison.OrdinalIgnoreCase)) {
                return kvp.Value + ntPath.Substring(kvp.Key.Length);
            }
        }
        return ntPath;
    }

    // --- RUST DLL INJECTION & IPC ---
    public static void InjectRustHook(int targetPid) {
        if (_teardownRequested) return;
        if (!File.Exists(_hookDllPath)) return;
        if (targetPid == _selfPid) return;

        if (!IsSafeToInject(targetPid)) {
            EventQueue.Enqueue(new DataEvent {
                EventType = "WARN",
                RawJson = $"InjectRustHook: ACG (ProhibitDynamicCode) active on PID {targetPid} -- hook injection skipped"
            });
            return;
        }

        // Prevent 64-bit DLL from injecting into 32-bit (WOW64) processes
        IntPtr hCheck = OpenProcess(0x1000, false, targetPid); // PROCESS_QUERY_LIMITED_INFORMATION
        if (hCheck != IntPtr.Zero) {
            bool isWow64 = false;
            IsWow64Process(hCheck, out isWow64);
            CloseHandle(hCheck);
            if (isWow64) {
                _injectedPids.TryRemove(targetPid, out _);
                return;
            }
        }

        if (!_injectedPids.TryAdd(targetPid, 0)) return;

        IntPtr hProcess = OpenProcess(INJECT_ACCESS, false, targetPid);
        if (hProcess == IntPtr.Zero) {
            EventQueue.Enqueue(new DataEvent { EventType = "DiagLog", RawJson = $"InjectRustHook: OpenProcess FAILED for PID {targetPid} err={Marshal.GetLastWin32Error()}" });
            return;
        }

        if (!IsSafeToInject(targetPid)) {
            EventQueue.Enqueue(new DataEvent { EventType = "DiagLog", RawJson = $"InjectRustHook: ACG guard blocked PID {targetPid}" });
            CloseHandle(hProcess);
            return;
        }

        IntPtr allocMemAddress = IntPtr.Zero;
        try {
            byte[] pathBytes = Encoding.Unicode.GetBytes(_hookDllPath + "\0");
            uint size = (uint)pathBytes.Length;

            allocMemAddress = VirtualAllocEx(hProcess, IntPtr.Zero, size, 0x3000, 0x04);
            if (allocMemAddress == IntPtr.Zero) return;

            if (!WriteProcessMemory(hProcess, allocMemAddress, pathBytes, size, out _)) return;

            IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryW");
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLibraryAddr, allocMemAddress, 0, IntPtr.Zero);

            if (hThread != IntPtr.Zero) {
                WaitForSingleObject(hThread, 5000);
                CloseHandle(hThread);

                // Assume success if thread executed to prevent infinite retry spam on managed processes
                EventQueue.Enqueue(new DataEvent { EventType = "DiagLog", RawJson = $"InjectRustHook: Injection command executed for PID {targetPid}" });
            } else {
                _injectedPids.TryRemove(targetPid, out _);
                EventQueue.Enqueue(new DataEvent { EventType = "DiagLog", RawJson = $"InjectRustHook: CreateRemoteThread FAILED for PID {targetPid}" });
            }
        } finally {
            if (allocMemAddress != IntPtr.Zero)
                VirtualFreeEx(hProcess, allocMemAddress, 0, 0x8000); // MEM_RELEASE
            CloseHandle(hProcess);
        }
    }
    /*        if (hThread != IntPtr.Zero) {
                WaitForSingleObject(hThread, 5000);
                CloseHandle(hThread);

                // Allow OS PEB to stabilize after LoadLibraryW completes
                System.Threading.Thread.Sleep(100);

                bool isLoaded = false;
                try {
                    using (var targetProc = System.Diagnostics.Process.GetProcessById(targetPid)) {
                        foreach (System.Diagnostics.ProcessModule mod in targetProc.Modules) {
                            if (mod.ModuleName.Equals("DataSensor_Hook.dll", StringComparison.OrdinalIgnoreCase)) {
                                isLoaded = true;
                                break;
                            }
                        }
                    }
                } catch (System.ComponentModel.Win32Exception) {
                    // Access Denied (PPL/Protected process). If CreateRemoteThread succeeded but verification
                    // is denied, assume success to prevent blocking. The IPC pipe will confirm natively.
                    isLoaded = true;
                    EventQueue.Enqueue(new DataEvent { EventType = "DiagLog", RawJson = $"InjectRustHook: Access denied enumerating modules for PID {targetPid} - assuming success." });
                } catch (Exception ex) {
                    isLoaded = false;
                    EventQueue.Enqueue(new DataEvent { EventType = "DiagLog", RawJson = $"InjectRustHook: Module check fault for PID {targetPid}: {ex.Message}" });
                }

                if (isLoaded) {
                    EventQueue.Enqueue(new DataEvent { EventType = "DiagLog", RawJson = $"InjectRustHook: Injection confirmed for PID {targetPid}" });
                } else {
                    // Remove from injected set to unlock future ETW retry attempts
                    _injectedPids.TryRemove(targetPid, out _);
                    EventQueue.Enqueue(new DataEvent { EventType = "DiagLog", RawJson = $"InjectRustHook: LoadLibrary completed but DLL not found in PID {targetPid} -- primed for retry" });
                }
            }
        } finally {
            if (allocMemAddress != IntPtr.Zero)
                VirtualFreeEx(hProcess, allocMemAddress, 0, 0x8000); // MEM_RELEASE
            CloseHandle(hProcess);
        }
    }
    */

    private static bool IsSafeToInject(int pid) {
        IntPtr hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (hProc == IntPtr.Zero) return false;
        try {
            int policyData = 0;
            int size = sizeof(int);
            const int ProcessDynamicCodePolicy = 2;
            if (QueryProcessMitigationPolicy(hProc, ProcessDynamicCodePolicy,
                    ref policyData, size)) {
                if ((policyData & 0x1) != 0) return false; // ProhibitDynamicCode bit set -- ACG active
            }
            return true;
        } catch {
            return true; // If check fails, proceed optimistically
        } finally {
            CloseHandle(hProc);
        }
    }

    public static void ForceEjectHooks() {
        try {
            bool signaled = false;

            using (EventWaitHandle hooksDetached = new EventWaitHandle(
                       false,
                       EventResetMode.ManualReset,
                       @"Global\DataSensorHooksDetached",
                       out _))
            using (EventWaitHandle teardownEvent = new EventWaitHandle(
                       false,
                       EventResetMode.ManualReset,
                       @"Global\DataSensorTeardown",
                       out _))
            {
                File.WriteAllText(@"C:\ProgramData\DataSensor\Teardown.sig", "");
                teardownEvent.Set();
                signaled = hooksDetached.WaitOne(6000);
            }

            EventQueue.Enqueue(new DataEvent {
                EventType = "DiagLog",
                RawJson   = signaled
                    ? "ForceEjectHooks: HooksDetached event received -- all Rust hooks cleanly ejected."
                    : "ForceEjectHooks: WaitOne timed out (6 000 ms). Proceeding with engine teardown."
            });
        } catch {
            // Fail silently to allow graceful degradation rather than crashing the host
        }
    }

    public static bool SuspendTargetProcess(int pid) {
        IntPtr hProc = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid);
        if (hProc == IntPtr.Zero) return false;

        int status = NtSuspendProcess(hProc);
        CloseHandle(hProc);

        return status == 0; // NT_SUCCESS
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    private static NamedPipeServerStream CreateSecurePipeServer() {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.ReadWrite,
            AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.ReadWrite,
            AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
            PipeAccessRights.Write,
            AccessControlType.Allow));

    #if NETFRAMEWORK
        return new NamedPipeServerStream(
            "DataSensorAlerts",
            PipeDirection.In,
            NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            0,
            0,
            security);
    #else
        return NamedPipeServerStreamAcl.Create(
            "DataSensorAlerts",
            PipeDirection.In,
            NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            0,
            0,
            security);
    #endif
    }

    // --- NETWORK HELPERS ---
    private static string ParseIp(object val) {
        if (val == null) return "";
        string result = "";

        if (val is byte[]) {
            byte[] b = (byte[])val;
            try {
                if (b.Length >= 8 && b[0] == 2 && b[1] == 0) result = new System.Net.IPAddress(new byte[] { b[4], b[5], b[6], b[7] }).ToString();
                else if (b.Length >= 24 && b[0] == 23 && b[1] == 0 && b[18] == 255 && b[19] == 255) result = new System.Net.IPAddress(new byte[] { b[20], b[21], b[22], b[23] }).ToString();
                else if (b.Length == 4 || b.Length == 16) result = new System.Net.IPAddress(b).ToString();
            } catch {}
        }
        else if (val is int || val is uint || val is long) {
            try {
                byte[] bytes = BitConverter.GetBytes(Convert.ToInt64(val));
                result = new System.Net.IPAddress(new byte[] { bytes[0], bytes[1], bytes[2], bytes[3] }).ToString();
            } catch {}
        }
        else { result = val.ToString(); }

        if (result.Contains("::ffff:")) result = result.Replace("::ffff:", "");
        return result;
    }

    private static string FallbackIpExtract(byte[] payload, out string extractedPort) {
        extractedPort = "";
        if (payload == null || payload.Length < 8) return "DECODER_FAILED";
        string lastFound = "DECODER_FAILED";

        for (int i = 0; i < payload.Length - 7; i++) {
            // --- IPv4 (AF_INET = 2) ---
            if (payload[i] == 2 && payload[i+1] == 0) {
                if (payload[i+2] == 0 && payload[i+3] == 0) continue; // Ignore Port 0
                int ip1 = payload[i+4]; int ip2 = payload[i+5]; int ip3 = payload[i+6]; int ip4 = payload[i+7];
                if (ip1 == 0 || ip1 == 127 || ip1 == 255) continue; // Ignore local/broadcast

                string ipStr = ip1 + "." + ip2 + "." + ip3 + "." + ip4;
                lastFound = ipStr;

                // Ignore RFC1918 Private ranges
                if (ip1 == 10 || (ip1 == 192 && ip2 == 168) || (ip1 == 172 && ip2 >= 16 && ip2 <= 31) || (ip1 == 169 && ip2 == 254) || ip1 >= 224) continue;

                extractedPort = ((payload[i+2] << 8) | payload[i+3]).ToString();
                return ipStr;
            }
            // --- IPv6 (AF_INET6 = 23) ---
            else if (i < payload.Length - 23 && payload[i] == 23 && payload[i+1] == 0) {
                if (payload[i+2] == 0 && payload[i+3] == 0) continue; // Ignore Port 0

                if (payload[i+18] == 255 && payload[i+19] == 255) {
                    int ip1 = payload[i+20]; int ip2 = payload[i+21]; int ip3 = payload[i+22]; int ip4 = payload[i+23];
                    if (ip1 == 0 || ip1 == 127 || ip1 == 255) continue;

                    string ipStr = ip1 + "." + ip2 + "." + ip3 + "." + ip4;
                    lastFound = ipStr;

                    if (ip1 == 10 || (ip1 == 192 && ip2 == 168) || (ip1 == 172 && ip2 >= 16 && ip2 <= 31) || (ip1 == 169 && ip2 == 254) || ip1 >= 224) continue;

                    extractedPort = ((payload[i+2] << 8) | payload[i+3]).ToString();
                    return ipStr;
                }
                else {
                    byte[] ipv6Bytes = new byte[16];
                    Array.Copy(payload, i + 8, ipv6Bytes, 0, 16);

                    try {
                        string ipv6Str = new System.Net.IPAddress(ipv6Bytes).ToString();
                        lastFound = ipv6Str;

                        if (ipv6Str == "::1" || ipv6Str.StartsWith("fe80:", StringComparison.OrdinalIgnoreCase) || ipv6Str.StartsWith("ff0", StringComparison.OrdinalIgnoreCase)) continue;

                        extractedPort = ((payload[i+2] << 8) | payload[i+3]).ToString();
                        return ipv6Str;
                    } catch { continue; }
                }
            }
        }
        return lastFound;
    }

    // --- WORKER THREADS ---

    private static void StartNamedPipeListener() {
        Task.Run(async () => {
            while (!_cts.Token.IsCancellationRequested) {
                try {
                    var pipeServer = CreateSecurePipeServer();
                    try { await pipeServer.WaitForConnectionAsync(_cts.Token); } catch { pipeServer.Dispose(); break; }

                    _ = Task.Run(() => {
                        try {
                            using (var reader = new StreamReader(pipeServer)) {
                                string alertJson = reader.ReadLine();
                                if (!string.IsNullOrWhiteSpace(alertJson)) {

                                    // --- DIAGNOSTIC LOG INTERCEPT (RING-3 HOOKS) ---
                                    if (alertJson.Contains("\"DIAG_LOG_EVENT\"")) {
                                        EventQueue.Enqueue(new DataEvent {
                                            EventType = "DiagLog",
                                            RawJson = $"[Ring-3 IPC] {alertJson}"
                                        });
                                        return; // Exit task safely to dispose pipe
                                    }

                                    // --- DEEP ARCHIVE DELEGATION (ORCHESTRATOR INSPECTION) ---
                                    if (alertJson.Contains("ASYNC_INSPECT_QUEUED")) {
                                        EventQueue.Enqueue(new DataEvent { EventType = "DLP_ALERT", ProcessName = "In-Band Hook", UserName = "System", RawJson = "{\"alerts\":[" + alertJson + "]}" });

                                        string zipPath = alertJson.Split(FilePathSplitter, StringSplitOptions.None)[1].Split('"')[0];
                                        zipPath = zipPath.Replace("\\\\", "\\");

                                        if (zipPath.StartsWith("\\??\\") || zipPath.StartsWith("\\\\?\\")) {
                                            zipPath = zipPath.Substring(4);
                                        }

                                        if (zipPath.StartsWith("\\") && !zipPath.StartsWith("\\\\")) {
                                            string hostDrive = System.IO.Path.GetPathRoot(AppDomain.CurrentDomain.BaseDirectory);
                                            zipPath = System.IO.Path.Combine(hostDrive, zipPath.TrimStart('\\'));
                                        }

                                        Task.Run(() => {
                                            string tempDir = @"C:\ProgramData\DataSensor\TempArchive\" + Guid.NewGuid().ToString();

                                            try {
                                                Directory.CreateDirectory(tempDir);
                                                string evDir = @"C:\ProgramData\DataSensor\Evidence";
                                                Directory.CreateDirectory(evDir);

                                                EventQueue.Enqueue(new DataEvent { EventType = "DiagLog", RawJson = "TempArchive Extraction Initiated for: " + zipPath });

                                                int retries = 6;
                                                bool extracted = false;

                                                while (retries > 0 && !extracted) {
                                                    System.Threading.Thread.Sleep(1500); // Wait 1.5 seconds per loop
                                                    try {
                                                        if (File.Exists(zipPath)) {
                                                            System.IO.Compression.ZipFile.ExtractToDirectory(zipPath, tempDir);
                                                            extracted = true;
                                                        } else {
                                                            retries--;
                                                        }
                                                    } catch (IOException) {
                                                        retries--;
                                                    }
                                                }

                                                if (!extracted) {
                                                    EventQueue.Enqueue(new DataEvent { EventType = "ERROR", RawJson = "Archive Extraction Failed or Timeout: " + zipPath });
                                                    return;
                                                }

                                                foreach (string file in Directory.GetFiles(tempDir, "*.*", SearchOption.AllDirectories)) {
                                                    try {
                                                        byte[] buffer = File.ReadAllBytes(file);
                                                        if (buffer.Length < 16) continue;

                                                        string content = Encoding.UTF8.GetString(buffer);
                                                        IntPtr alertPtr = scan_text_payload(_mlEnginePtr, content, "Archive_Extractor", "System", file);
                                                        string resJson = Marshal.PtrToStringAnsi(alertPtr);

                                                        if (!string.IsNullOrEmpty(resJson) && resJson.Contains("ACTION_REQUIRED")) {
                                                            string fileName = Path.GetFileName(file);
                                                            string hash;
                                                            using (var sha = System.Security.Cryptography.SHA256.Create()) {
                                                                hash = BitConverter.ToString(sha.ComputeHash(buffer)).Replace("-", "").Substring(0, 8).ToLowerInvariant();
                                                            }
                                                            string evName = $"{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}_{hash}_{fileName}";
                                                            string evPath = Path.Combine(evDir, evName);

                                                            File.Copy(file, evPath, true);

                                                            resJson = resJson.Replace(JsonEscape(file), JsonEscape(evPath));

                                                            EventQueue.Enqueue(new DataEvent { EventType = "DLP_ALERT", ProcessName = "Archive_Extractor", UserName = "System", RawJson = resJson });
                                                            Interlocked.Increment(ref _eventQueueCount);
                                                        }
                                                        free_string(alertPtr);
                                                    } catch { }
                                                }

                                            } catch (Exception ex) {
                                                EventQueue.Enqueue(new DataEvent { EventType = "ERROR", RawJson = "Archive Extraction Exception: " + ex.Message });
                                            } finally {
                                                try { if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true); } catch { }
                                                try { if (File.Exists(zipPath)) File.Delete(zipPath); } catch { }
                                            }
                                        });
                                    }
                                    else {
                                        EventQueue.Enqueue(new DataEvent {
                                            EventType = "DLP_ALERT",
                                            ProcessName = "In-Band Hook",
                                            UserName = "System",
                                            RawJson = "{\"alerts\":[" + alertJson + "]}"
                                        });
                                        Interlocked.Increment(ref _eventQueueCount);

                                        try {
                                            string evtFilePath = "Unknown";
                                            var fpParts = alertJson.Split(new[] { "\"filepath\":\"" }, StringSplitOptions.None);
                                            if (fpParts.Length > 1) {
                                                evtFilePath = fpParts[1].Split('"')[0].Replace("\\\\", "\\");
                                            }
                                            long evtBytes = 0;
                                            try {
                                                if (File.Exists(evtFilePath))
                                                    evtBytes = new FileInfo(evtFilePath).Length;
                                            } catch { }
                                            var hookEvt = new FfiPlatformEvent {
                                                timestamp   = DateTime.Now.ToString("O"),
                                                event_type  = "File_IO",
                                                action      = "File_Write",
                                                user        = Environment.UserName,
                                                process     = "In-Band Hook",
                                                filepath    = evtFilePath,
                                                destination = "Disk_Write",
                                                details     = alertJson.Contains("ASYNC_INSPECT_QUEUED") ? "Archive Creation Delegated" : "Disk Write Intercepted",
                                                bytes       = evtBytes,
                                                duration_ms = 1,
                                                is_dlp_hit  = true
                                            };
                                            if (!_uebaQueue.IsAddingCompleted) {
                                                _uebaQueue.TryAdd(hookEvt, 50);
                                                if (_enableUniversalLedger) { _uebaJsonQueue.TryAdd(hookEvt, 50); }
                                            }
                                        } catch { }
                                    }
                                }
                            }
                        } catch { } finally { if (pipeServer != null) { pipeServer.Dispose(); } }
                    });
                } catch { Thread.Sleep(100); }
            }
        });
    }

    private static void StartActiveNetworkMonitor() {
        Task.Run(() => {
            var seenConnections = new HashSet<string>();
            while (!_cts.Token.IsCancellationRequested) {
                try {
                    int bufferSize = 0;
                    GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, 2, 5, 0); // IPv4, TCP_TABLE_OWNER_PID_ALL

                    if (bufferSize > 0) {
                        IntPtr tcpTablePtr = Marshal.AllocHGlobal(bufferSize);
                        try {
                            if (GetExtendedTcpTable(tcpTablePtr, ref bufferSize, true, 2, 5, 0) == 0) {
                                int rowCount = Marshal.ReadInt32(tcpTablePtr);
                                IntPtr rowPtr = tcpTablePtr + 4;

                                for (int i = 0; i < rowCount; i++) {
                                    uint state = (uint)Marshal.ReadInt32(rowPtr);
                                    if (state == 5) { // MIB_TCP_STATE_ESTAB
                                        uint remoteAddr = (uint)Marshal.ReadInt32(rowPtr + 12);
                                        int remotePortRaw = Marshal.ReadInt32(rowPtr + 16);
                                        int pid = Marshal.ReadInt32(rowPtr + 20);

                                        byte[] ip = BitConverter.GetBytes(remoteAddr);
                                        string destIp = $"{ip[0]}.{ip[1]}.{ip[2]}.{ip[3]}";

                                        // Port is stored in network byte order; shift bytes to read correctly
                                        int destPort = ((remotePortRaw & 0xFF) << 8) | ((remotePortRaw >> 8) & 0xFF);

                                        string connId = $"{pid}-{destIp}:{destPort}";

                                        if (!seenConnections.Contains(connId)) {
                                            seenConnections.Add(connId);
                                            string procName = pid.ToString();
                                            try { procName = System.Diagnostics.Process.GetProcessById(pid).ProcessName; } catch {}

                                            if (!_trustedProcesses.Contains(procName) && !destIp.StartsWith("127.") && !destIp.StartsWith("224.")) {
                                                var evt = new FfiPlatformEvent {
                                                    timestamp = DateTime.Now.ToString("O"),
                                                    event_type = "Network",
                                                    action = "TCP_Connection_Established",
                                                    user = GetProcessUser(pid),
                                                    process = procName,
                                                    parent_process = "",
                                                    command_line = "",
                                                    filepath = "Network_Socket",
                                                    destination = destIp,
                                                    dest_port = destPort.ToString(),
                                                    bytes = 0,
                                                    duration_ms = 1
                                                };

                                                if (!_uebaQueue.IsAddingCompleted) {
                                                    _uebaQueue.TryAdd(evt, 50);
                                                    if (_enableUniversalLedger) { _uebaJsonQueue.TryAdd(evt, 50); }
                                                }
                                            }
                                        }
                                    }
                                    rowPtr += 24; // Advance struct size
                                }
                            }
                        } finally {
                            Marshal.FreeHGlobal(tcpTablePtr);
                        }
                    }
                } catch { }
                Thread.Sleep(500); // Fast state poll
            }
        });
    }

    private static void StartBatchProcessor() {
        Task.Run(() => {
            var batchMap = new Dictionary<string, FfiPlatformEvent>(5000);

            while (!_cts.Token.IsCancellationRequested) {
                try {
                    if (_uebaQueue.TryTake(out FfiPlatformEvent firstItem, 1000, _cts.Token)) {
                        string firstKey = $"{firstItem.event_type}|{firstItem.process}|{firstItem.destination}";
                        batchMap[firstKey] = firstItem;

                        while (batchMap.Count < 5000 && _uebaQueue.TryTake(out FfiPlatformEvent nextItem)) {
                            string key = $"{nextItem.event_type}|{nextItem.process}|{nextItem.destination}";

                            if (batchMap.TryGetValue(key, out var existing)) {
                                // Squash identical events together to reduce FFI overhead
                                existing.bytes += nextItem.bytes;
                                existing.duration_ms += nextItem.duration_ms;
                                existing.is_dlp_hit = existing.is_dlp_hit || nextItem.is_dlp_hit;
                                existing.timestamp = nextItem.timestamp;
                                batchMap[key] = existing;
                            } else {
                                batchMap[key] = nextItem;
                            }
                        }

                        if (batchMap.Count > 0 && _mlEnginePtr != IntPtr.Zero) {
                            System.Text.StringBuilder sb = new System.Text.StringBuilder(batchMap.Count * 256);
                            sb.Append("[");

                            int count = 0;
                            foreach (var e in batchMap.Values) {
                                string safePath = JsonEscape(e.filepath);
                                string safeDest = JsonEscape(e.destination);
                                sb.Append($"{{\"event_type\":\"{JsonEscape(e.event_type ?? "")}\",\"action\":\"{JsonEscape(e.action ?? "")}\",\"timestamp\":\"{JsonEscape(e.timestamp)}\",\"user\":\"{JsonEscape(e.user)}\",\"process\":\"{JsonEscape(e.process)}\",\"parent_process\":\"{JsonEscape(e.parent_process ?? "")}\",\"command_line\":\"{JsonEscape(e.command_line ?? "")}\",\"filepath\":\"{safePath}\",\"destination\":\"{safeDest}\",\"dest_port\":\"{JsonEscape(e.dest_port ?? "")}\",\"bytes\":{e.bytes},\"duration_ms\":{e.duration_ms},\"is_dlp_hit\":{(e.is_dlp_hit ? "true" : "false")}}}");
                                if (count < batchMap.Count - 1) sb.Append(",");
                                count++;
                            }
                            sb.Append("]");

                            IntPtr resultPtr = process_telemetry_batch(_mlEnginePtr, sb.ToString());
                            ParseResponse(resultPtr, "UEBA_Engine", "System_ML", 0, "UEBA_ALERT");
                            batchMap.Clear();
                        }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) {
                    EventQueue.Enqueue(new DataEvent { EventType = "ERROR", RawJson = "Batch Processor Fault: " + ex.Message });
                    batchMap.Clear();
                }
            }
            _batchProcessorDone.Set();
        });
    }

    public static void StartClipboardMonitor() {
        _clipboardWorker = new Thread(() => {
            string lastClipboardText = string.Empty;
            while (!_cts.Token.IsCancellationRequested) {
                try {
                    if (OpenClipboard(IntPtr.Zero)) {
                        uint format = 13;
                        IntPtr hData = GetClipboardData(format);
                        if (hData != IntPtr.Zero) {
                            IntPtr pData = GlobalLock(hData);
                            if (pData != IntPtr.Zero) {
                                string currentText = null;
                                try {
                                    currentText = Marshal.PtrToStringUni(pData);
                                } finally {
                                    GlobalUnlock(hData);
                                }

                                if (!string.IsNullOrEmpty(currentText) && currentText != lastClipboardText) {
                                    lastClipboardText = currentText;

                                    string activeProcessName = "Unknown_App";
                                    try {
                                        IntPtr hWnd = GetClipboardOwner();
                                        if (hWnd == IntPtr.Zero) hWnd = GetForegroundWindow();
                                        if (hWnd != IntPtr.Zero) {
                                            GetWindowThreadProcessId(hWnd, out uint pid);
                                            using (var proc = System.Diagnostics.Process.GetProcessById((int)pid)) {
                                                activeProcessName = proc.ProcessName;
                                            }
                                        }
                                    } catch { }

                                    var evt = new FfiPlatformEvent {
                                        timestamp = DateTime.Now.ToString("O"),
                                        event_type = "Clipboard",
                                        action = "Clipboard_Copied",
                                        user = Environment.UserName,
                                        process = activeProcessName,
                                        filepath = "Clipboard_Capture",
                                        destination = "Memory_Buffer",
                                        details = $"Payload Size: {currentText.Length} chars",
                                        bytes = currentText.Length * 2,
                                        duration_ms = 1
                                    };

                                    if (_mlEnginePtr != IntPtr.Zero) {
                                        IntPtr alertPtr = scan_text_payload(_mlEnginePtr, currentText, activeProcessName, Environment.UserName, "");
                                        string alertJson = Marshal.PtrToStringAnsi(alertPtr);

                                        if (!string.IsNullOrEmpty(alertJson) && alertJson.Contains("ACTION_REQUIRED")) {
                                            try {
                                                string hash;
                                                using (var sha = System.Security.Cryptography.SHA256.Create()) {
                                                    hash = BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(currentText))).Replace("-", "").Substring(0,8).ToLowerInvariant();
                                                }
                                                string evDir = @"C:\ProgramData\DataSensor\Evidence";
                                                Directory.CreateDirectory(evDir);
                                                string evPath = Path.Combine(evDir, $"{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}_{hash}_Clipboard_Capture.dat");
                                                File.WriteAllText(evPath, currentText);

                                                alertJson = alertJson.Replace("Clipboard_Capture", evPath.Replace("\\", "\\\\"));
                                            } catch { }

                                            EventQueue.Enqueue(new DataEvent { EventType = "DLP_ALERT", ProcessName = activeProcessName, UserName = Environment.UserName, RawJson = alertJson });
                                            Interlocked.Increment(ref _eventQueueCount);
                                            free_string(alertPtr);
                                        } else {
                                            ParseResponse(alertPtr, activeProcessName, Environment.UserName, 0, "DLP_ALERT");
                                        }
                                    }

                                    if (!_uebaQueue.IsAddingCompleted) {
                                        _uebaQueue.TryAdd(evt, 50);
                                        if (_enableUniversalLedger) { _uebaJsonQueue.TryAdd(evt, 50); }
                                    }
                                }
                            }
                        }
                        CloseClipboard();
                    }
                } catch { }
                Thread.Sleep(1000);
            }
        });
        _clipboardWorker.SetApartmentState(ApartmentState.STA);
        _clipboardWorker.IsBackground = true;
        _clipboardWorker.Start();
    }

    private static void StartUebaJsonLogger() {
        _uebaJsonWorker = new Thread(() => {
            string logPath = @"C:\ProgramData\DataSensor\Logs\DataSensor_UEBA.jsonl";

            while (!_cts.Token.IsCancellationRequested) {
                try {
                    Directory.CreateDirectory(System.IO.Path.GetDirectoryName(logPath));

                    using (FileStream fs = new FileStream(
                               logPath,
                               FileMode.Append,
                               FileAccess.Write,
                               FileShare.ReadWrite, // allow concurrent reads (Web HUD)
                               4096))               // small buffer -- we control flushing explicitly
                    using (StreamWriter sw = new StreamWriter(fs) { AutoFlush = false }) {

                        while (!_cts.Token.IsCancellationRequested || _uebaJsonQueue.Count > 0) {
                            try {
                                foreach (var evt in _uebaJsonQueue.GetConsumingEnumerable(_cts.Token)) {
                                    string safePath = evt.filepath    != null ? JsonEscape(evt.filepath)    : "";
                                    string safeDest = evt.destination != null ? JsonEscape(evt.destination) : "";
                                    string safeAction = evt.action    != null ? JsonEscape(evt.action)      : "";
                                    string safeDetails= evt.details   != null ? JsonEscape(evt.details)     : "";

                                    string jsonLine = $"{{\"Timestamp\":\"{JsonEscape(evt.timestamp)}\", \"EventType\":\"{JsonEscape(evt.event_type ?? "")}\", \"Action\":\"{safeAction}\", \"Host\":\"{JsonEscape(Environment.MachineName)}\", \"User\":\"{JsonEscape(evt.user)}\", \"Process\":\"{JsonEscape(evt.process)}\", \"FilePath\":\"{safePath}\", \"Destination\":\"{safeDest}\", \"Details\":\"{safeDetails}\", \"Bytes\":{evt.bytes}, \"DurationMs\":{evt.duration_ms}}}";
                                    sw.WriteLine(jsonLine);

                                    if (_uebaJsonQueue.Count == 0) {
                                        sw.Flush();
                                    }
                                }
                            }
                            catch (OperationCanceledException) {
                                try { sw.Flush(); } catch { }
                                break;
                            }
                            catch {
                                Thread.Sleep(200);
                            }
                        }

                        try { sw.Flush(); } catch { } // final flush before FileStream disposes
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) {
                    EventQueue.Enqueue(new DataEvent {
                        EventType = "ERROR",
                        RawJson   = "UEBA JSON Logger restarting after fault: " + ex.Message
                    });
                    Thread.Sleep(500);
                }
            }
        });
        _uebaJsonWorker.IsBackground = true;
        _uebaJsonWorker.Start();
    }

    private static void ParseResponse(IntPtr resultPtr, string processName, string userName, uint threadId, string defaultAlertType) {
        if (resultPtr != IntPtr.Zero) {
            string resultJson = Marshal.PtrToStringAnsi(resultPtr);
            free_string(resultPtr);

            if (resultJson != null) {
                if (resultJson != null) {
                    if (resultJson.Contains("alert_type")) {
                        bool isHighPriority = resultJson.Contains("ACTION_REQUIRED")
                                        || resultJson.Contains("NETWORK_INTEL")
                                        || resultJson.Contains("ASYNC_INSPECT_QUEUED");

                        if (isHighPriority) {
                            defaultAlertType = "DLP_ALERT";
                        }

                        bool isNoisePath = resultJson.IndexOf("AppData", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                        resultJson.IndexOf("ProfileData", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                        resultJson.IndexOf("History-journal", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                        resultJson.IndexOf("Temp", StringComparison.OrdinalIgnoreCase) >= 0;

                        if (isNoisePath && !isHighPriority) {
                            return; // Silently drop to prevent UI thread deadlock
                        }

                        if (_eventQueueCount < 5000 || isHighPriority) {
                            if (_eventQueueCount >= 5000 && isHighPriority) {
                                if (EventQueue.TryDequeue(out _))
                                    Interlocked.Decrement(ref _eventQueueCount);
                            }
                            EventQueue.Enqueue(new DataEvent {
                                EventType = defaultAlertType,
                                ProcessName = processName,
                                UserName = userName,
                                RawJson = resultJson
                            });
                            Interlocked.Increment(ref _eventQueueCount);
                        }
                    }
                    else if (resultJson.Contains("daemon_error") && !resultJson.Contains("\"daemon_error\":null")) {
                        EventQueue.Enqueue(new DataEvent {
                            EventType = "FATAL",
                            RawJson = "Native Engine Fault: " + resultJson
                        });
                    }
                }
            }
        }
    }

    // --- CORE ETW SESSION ---
    public static void StartSession() {
        if (_volumeMap.IsEmpty) { InitializeVolumeMap(); }

        Task.Run(() => {
            try {
                if (TraceEventSession.GetActiveSessionNames().Contains("DataSensorRealTimeSession")) {
                    var oldSession = new TraceEventSession("DataSensorRealTimeSession");
                    oldSession.Dispose();
                }

                _session = new TraceEventSession("DataSensorRealTimeSession");

                _session.EnableProvider("Microsoft-Windows-Kernel-Process",
                    TraceEventLevel.Informational, 0x10);

                _session.EnableProvider("Microsoft-Windows-Kernel-Network",
                    TraceEventLevel.Informational, 0xFFFFFFFFFFFFFFFFUL);

                _session.EnableProvider("Microsoft-Windows-TCPIP",
                    TraceEventLevel.Verbose, 0xFFFFFFFFFFFFFFFFUL);

                _session.EnableProvider("Microsoft-Windows-Winsock-AFD",
                    TraceEventLevel.Verbose, 0xFFFFFFFFFFFFFFFFUL);

                _session.EnableProvider("Microsoft-Windows-WebIO",
                    TraceEventLevel.Informational, 0xFFFFFFFFFFFFFFFFUL);

                _session.EnableProvider("Microsoft-Windows-WinHttp",
                    TraceEventLevel.Informational, 0xFFFFFFFFFFFFFFFFUL);

                _session.EnableProvider("Microsoft-System-Net-Http",
                    TraceEventLevel.Informational, 0xFFFFFFFFFFFFFFFFUL);

                _session.EnableProvider("Microsoft-System-Net-Sockets",
                    TraceEventLevel.Informational, 0xFFFFFFFFFFFFFFFFUL);

                _session.EnableProvider("Microsoft-Windows-DNS-Client",
                    TraceEventLevel.Verbose, 0xFFFFFFFFFFFFFFFFUL);

                _session.Source.Dynamic.All += delegate (TraceEvent data) {
                    try {
                        string evName = data.EventName;
                        if (evName == "ThreadWorkOnBehalfUpdate" || evName == "CpuPriorityChange" || evName.StartsWith("Thread") || evName == "ImageLoad" || evName == "ImageUnload") return;

                        if (data.ProviderName.Contains("Kernel-Process") && evName.Contains("Stop")) {
                            _injectedPids.TryRemove(data.ProcessID, out _);
                            _pidUserCache.TryRemove(data.ProcessID, out _);
                            return;
                        }

                        // 1. Process Lineage Pre-Caching & DLL INJECTION
                        if (data.ProviderName.Contains("Kernel-Process") && evName.Contains("Start")) {
                            Task.Run(() => {
                                try {
                                    int targetPid = data.ProcessID;
                                    try {
                                        object payloadPid = data.PayloadByName("ProcessID")
                                                         ?? data.PayloadByName("ProcessId")
                                                         ?? data.PayloadByName("NewProcessId");
                                        if (payloadPid != null) targetPid = Convert.ToInt32(payloadPid);
                                    } catch {}

                                    string userName = "System";
                                    IntPtr processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, targetPid);
                                    if (processHandle != IntPtr.Zero) {
                                        if (OpenProcessToken(processHandle, 0x0008, out IntPtr tokenHandle)) {
                                            using (System.Security.Principal.WindowsIdentity wi = new System.Security.Principal.WindowsIdentity(tokenHandle)) {
                                                userName = wi.Name.Contains("\\") ? wi.Name.Split('\\')[1] : wi.Name;
                                            }
                                            CloseHandle(tokenHandle);
                                        }
                                        CloseHandle(processHandle);
                                    }
                                    _pidUserCache.AddOrUpdate(targetPid, userName, (k, v) => userName);

                                    string procName = targetPid.ToString();
                                    try { procName = System.Diagnostics.Process.GetProcessById(targetPid).ProcessName; } catch {}

                                    // --- UEBA: Capture Process Lineage & Command Line ---
                                    string cmdLine = "";
                                    string parentProcName = "Unknown";
                                    try {
                                        cmdLine = data.PayloadByName("CommandLine")?.ToString() ?? "";
                                        object parentPidObj = data.PayloadByName("ParentProcessID");
                                        if (parentPidObj != null) {
                                            int parentPid = Convert.ToInt32(parentPidObj);
                                            try { parentProcName = System.Diagnostics.Process.GetProcessById(parentPid).ProcessName; } catch {}
                                        }
                                    } catch {}

                                    var procEvt = new FfiPlatformEvent {
                                        timestamp = DateTime.Now.ToString("O"),
                                        event_type = "Process",
                                        action = "Process_Created",
                                        user = userName,
                                        process = procName,
                                        parent_process = parentProcName,
                                        command_line = cmdLine,
                                        filepath = data.PayloadByName("ImageFileName")?.ToString() ?? "Unknown_Image",
                                        destination = "Local_System",
                                        bytes = 0,
                                        duration_ms = 1
                                    };
                                    if (_enableUniversalLedger && !_uebaJsonQueue.IsAddingCompleted) {
                                        _uebaJsonQueue.TryAdd(procEvt, 50);
                                    }

                                    if (!_criticalSystemProcs.Contains(procName) && !_trustedProcesses.Contains(procName)) {
                                        Task.Run(async () => {
                                            int retries = 0;
                                            while (retries < 10) {
                                                IntPtr hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, targetPid);

                                                if (hProc != IntPtr.Zero) {
                                                    IsWow64Process(hProc, out bool is32Bit);
                                                    CloseHandle(hProc);

                                                    if (!is32Bit) {
                                                        await Task.Delay(150);
                                                        InjectRustHook(targetPid);
                                                    }
                                                    break; // Injection executed, break the spin-wait loop
                                                }

                                                retries++;
                                                await Task.Delay(50); // Increased from 1ms to prevent CPU thrashing
                                            }
                                        });
                                    }
                                } catch { }
                            });
                        }
                        if (_pidUserCache.Count > 5000) {
                            _pidUserCache.Clear();
                        }

                        string procName = string.IsNullOrEmpty(data.ProcessName) ? data.ProcessID.ToString() : data.ProcessName;
                        if (_trustedProcesses.Contains(procName) && data.ProviderName.IndexOf("DNS", StringComparison.OrdinalIgnoreCase) < 0) return;

                        // 1. Diagnostic Logging
                        if (data.ProviderName.IndexOf("TCPIP",   StringComparison.OrdinalIgnoreCase) >= 0 ||
                            data.ProviderName.IndexOf("Kernel-Network", StringComparison.OrdinalIgnoreCase) >= 0 ||
                            data.ProviderName.IndexOf("AFD",     StringComparison.OrdinalIgnoreCase) >= 0 ||
                            data.ProviderName.IndexOf("DNS",     StringComparison.OrdinalIgnoreCase) >= 0 ||
                            data.ProviderName.IndexOf("WebIO",   StringComparison.OrdinalIgnoreCase) >= 0 ||
                            data.ProviderName.IndexOf("WinHttp", StringComparison.OrdinalIgnoreCase) >= 0) {

                            if (_networkDiagCount < 20) {
                                _networkDiagCount++;
                                EventQueue.Enqueue(new DataEvent { EventType = "DiagLog",
                                    RawJson = $"ETW-NET: Provider={data.ProviderName} Event={data.EventName} PID={data.ProcessID}" });
                            }
                        }

                        // 2. Network & DNS Routing
                        bool isNetworkEvent = data.ProviderName.IndexOf("TCPIP",   StringComparison.OrdinalIgnoreCase) >= 0 ||
                                              data.ProviderName.IndexOf("Kernel-Network", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                              data.ProviderName.IndexOf("AFD",     StringComparison.OrdinalIgnoreCase) >= 0 ||
                                              data.ProviderName.IndexOf("WebIO",   StringComparison.OrdinalIgnoreCase) >= 0 ||
                                              data.ProviderName.IndexOf("WinHttp", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                              data.ProviderName.IndexOf("Net-Http", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                              data.ProviderName.IndexOf("Net-Sockets", StringComparison.OrdinalIgnoreCase) >= 0;

                        bool isDnsEvent = data.ProviderName.IndexOf("DNS", StringComparison.OrdinalIgnoreCase) >= 0;

                        if (isNetworkEvent || isDnsEvent) {

                            if (isNetworkEvent) {
                                bool validNetEvent = evName.IndexOf("Connect", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                                     evName.IndexOf("Send",    StringComparison.OrdinalIgnoreCase) >= 0 ||
                                                     evName.IndexOf("Accept",  StringComparison.OrdinalIgnoreCase) >= 0 ||
                                                     evName.IndexOf("Recv",    StringComparison.OrdinalIgnoreCase) >= 0 ||
                                                     evName.IndexOf("Receive", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                                     evName.IndexOf("Transfer",StringComparison.OrdinalIgnoreCase) >= 0 ||
                                                     evName.IndexOf("Request", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                                     evName.StartsWith("EventID", StringComparison.OrdinalIgnoreCase) ||
                                                     data.ProviderName.IndexOf("WebIO",   StringComparison.OrdinalIgnoreCase) >= 0 ||
                                                     data.ProviderName.IndexOf("WinHttp", StringComparison.OrdinalIgnoreCase) >= 0;

                                if (!validNetEvent) return;
                            }

                            string destIp = "";
                            string query = "";
                            string sizeStr = "0";

                            try {
                                if (isDnsEvent) {
                                    query = data.PayloadByName("QueryName")?.ToString()
                                         ?? data.PayloadByName("Query")?.ToString()
                                         ?? data.PayloadByName("QName")?.ToString() ?? "";
                                } else {
                                    object destObj = data.PayloadByName("ServerName")
                                                  ?? data.PayloadByName("HostName")
                                                  ?? data.PayloadByName("URL")
                                                  ?? data.PayloadByName("Url")
                                                  ?? data.PayloadByName("daddr")
                                                  ?? data.PayloadByName("DestinationAddress")
                                                  ?? data.PayloadByName("DestinationIp")
                                                  ?? data.PayloadByName("dest")
                                                  ?? data.PayloadByName("connRemoteAddr")
                                                  ?? data.PayloadByName("RemoteAddress")
                                                  ?? data.PayloadByName("RemoteAddr");
                                    if (destObj != null) { destIp = ParseIp(destObj); }
                                    if (string.IsNullOrEmpty(destIp)) {
                                        destIp = FallbackIpExtract(data.EventData(), out string extractedPort);
                                    }

                                    if (string.IsNullOrEmpty(destIp) && !string.IsNullOrEmpty(query)) {
                                        destIp = query;
                                    }

                                    object sizeObj = data.PayloadByName("size")
                                                  ?? data.PayloadByName("length")
                                                  ?? data.PayloadByName("BytesSent")
                                                  ?? data.PayloadByName("cb")
                                                  ?? data.PayloadByName("BytesTransferred")
                                                  ?? data.PayloadByName("TransferSize")
                                                  ?? data.PayloadByName("SendLength");
                                    if (sizeObj != null) { sizeStr = sizeObj.ToString(); }
                                }
                            } catch {
                                // Catch localized payload extraction errors
                            }

                            if (isNetworkEvent && string.IsNullOrEmpty(destIp)) {
                                try {
                                    byte[] rawPayload = data.EventData();
                                    string fbIp = FallbackIpExtract(rawPayload, out _);
                                    if (!string.IsNullOrEmpty(fbIp) && fbIp != "DECODER_FAILED") { destIp = fbIp; }
                                } catch { }
                            }

                            string finalDest = string.IsNullOrEmpty(query) ? destIp : query;
                            if (string.IsNullOrEmpty(finalDest)) return;

                            long size = 0;
                            try { size = Convert.ToInt64(sizeStr); } catch { }

                            if (!finalDest.StartsWith("127.") && !finalDest.StartsWith("224.") && !finalDest.StartsWith("::1") && finalDest != "255.255.255.255") {
                                if (size >= 0 || isNetworkEvent || isDnsEvent) {
                                    var evt = new FfiPlatformEvent {
                                        timestamp = DateTime.Now.ToString("O"),
                                        event_type = "Network",
                                        action = isDnsEvent ? "DNS_Query" : "TCP_Connection",
                                        user = GetProcessUser(data.ProcessID),
                                        process = procName,
                                        filepath = "Network_Socket",
                                        destination = finalDest,
                                        details = isDnsEvent ? $"Query: {query}" : $"RemoteIP: {destIp}",
                                        bytes = size > 0 ? size : 0,
                                        duration_ms = 1
                                    };

                                    if (!_uebaQueue.IsAddingCompleted) {
                                        _uebaQueue.TryAdd(evt, 50);
                                        if (_enableUniversalLedger) { _uebaJsonQueue.TryAdd(evt, 50); }
                                    }
                                }
                            }
                        }

                    } catch (Exception ex) {
                        try { EventQueue.Enqueue(new DataEvent { EventType = "ERROR", RawJson = "Hotpath Error: " + ex.Message }); } catch {}
                    }
                };
                _session.Source.Process();
            } catch (Exception ex) {
                EventQueue.Enqueue(new DataEvent { EventType = "FATAL", RawJson = "ETW Core Failure: " + ex.Message });
            }
        });
    }

    public static void RecoverSession() {
        if (_session != null) {
            try { _session.Stop(); _session.Dispose(); } catch { }
        }
        StartSession();
    }

    public static void StopSession() {
        _teardownRequested = true;

        _cts.Cancel();

        ForceEjectHooks();

        if (_session != null) {
            try { _session.Stop(); } catch { }
            try { _session.Dispose(); } catch { }
            _session = null;
        }

        _uebaQueue.CompleteAdding();
        _uebaJsonQueue.CompleteAdding();

        if (_clipboardWorker != null && _clipboardWorker.IsAlive) {
            _clipboardWorker.Join(2000);
        }
        if (_uebaJsonWorker != null && _uebaJsonWorker.IsAlive) {
            _uebaJsonWorker.Join(2000);
        }

        bool batchDone = _batchProcessorDone.Wait(8000);
        if (!batchDone) {
            EventQueue.Enqueue(new DataEvent {
                EventType = "DiagLog",
                RawJson   = "StopSession: batch processor drain timeout (8 000 ms) -- proceeding with teardown."
            });
        }

        Thread.Sleep(500);

        if (_mlEnginePtr != IntPtr.Zero) {
            teardown_engine(_mlEnginePtr);
            _mlEnginePtr = IntPtr.Zero;
            EventQueue.Enqueue(new DataEvent {
                EventType = "DiagLog",
                RawJson   = "Native Rust ML engine safely unloaded. WAL committed."
            });
        }
    }
}