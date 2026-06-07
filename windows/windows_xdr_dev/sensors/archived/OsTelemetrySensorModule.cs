using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Logging;
using UnifiedAgent.Core.Interfaces;
using UnifiedAgent.Core.Models;
using UnifiedAgent.Core.Routing;

namespace UnifiedAgent.Sensors
{
    public class OsTelemetrySensorModule : ISensorModule
    {
        public string ModuleName => "OsTelemetrySensor";
        public bool IsHealthy { get; private set; } = false;

        private readonly ILogger<OsTelemetrySensorModule> _logger;
        private readonly TelemetryRouter _router;
        private readonly SigmaIntelModule _sigmaIntel;

        private TraceEventSession _session;
        private readonly CancellationTokenSource _internalCts = new();

        private readonly ConcurrentDictionary<int, string> _processCache = new();
        private readonly ConcurrentDictionary<int, DateTime> _processStartTime = new();
        private readonly ConcurrentDictionary<int, ModuleMap[]> _processModules = new();
        private readonly ConcurrentDictionary<string, byte> _benignLineages = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _benignExplorerValues = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _benignADSProcs = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _tiDrivers = new(StringComparer.OrdinalIgnoreCase);
        private readonly RuleMatrix _activeMatrix = new();

        private libyaraNET.YaraContext _yaraContext;
        private readonly ConcurrentDictionary<string, libyaraNET.Rules> _yaraMatrices = new(StringComparer.OrdinalIgnoreCase);

        private int _sensorPid = -1;
        private bool _isArmed = true;

        private readonly HashSet<string> _criticalSystemProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "csrss.exe", "lsass.exe", "smss.exe", "services.exe", "wininit.exe", "winlogon.exe", "system",
            "svchost.exe", "dwm.exe", "explorer.exe", "lsaiso.exe", "fontdrvhost.exe", "spoolsv.exe", "taskhostw.exe"
        };

        public OsTelemetrySensorModule(ILogger<OsTelemetrySensorModule> logger, TelemetryRouter router, SigmaIntelModule sigmaIntel)
        {
            _logger = logger;
            _router = router;
            _sigmaIntel = sigmaIntel;

            var defaultBenign = new Dictionary<string, byte>
            {
                { "wininit.exe|services.exe", 0 }, { "wininit.exe|lsass.exe", 0 }, { "wininit.exe|lsm.exe", 0 },
                { "services.exe|svchost.exe", 0 }, { "services.exe|spoolsv.exe", 0 }, { "services.exe|msmpeng.exe", 0 },
                { "svchost.exe|taskhostw.exe", 0 }, { "svchost.exe|wmiprvse.exe", 0 }, { "svchost.exe|dllhost.exe", 0 },
                { "explorer.exe|onedrive.exe", 0 }, { "taskeng.exe|taskhostw.exe", 0 }
            };
            foreach (var kvp in defaultBenign) _benignLineages.TryAdd(kvp.Key, kvp.Value);
        }

        public async Task InitializeAsync(CancellationToken cancellationToken)
        {
            _benignExplorerValues.UnionWith(new[] { "MRUListEx", "Place0", "Place1" });
            _benignADSProcs.UnionWith(new[] { "svchost.exe", "explorer.exe", "msedge.exe" });

            try
            {
                _yaraContext = new libyaraNET.YaraContext();
            }
            catch { }

            IsHealthy = true;
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            Task.Run(() =>
            {
                // Core ETW Listener logic
                _session = new TraceEventSession("DeepXDR_OS_Trace");
                // ... hook Kernel events ...
                _session.Source.Process();
            }, cancellationToken);

            return Task.CompletedTask;
        }

        private void RunEtwSession()
        {
            try
            {
                string sessionName = KernelTraceEventParser.KernelSessionName;
                if (TraceEventSession.GetActiveSessionNames().Contains(sessionName))
                {
                    using var old = new TraceEventSession(sessionName);
                    old.Stop(true);
                }

                _session = new TraceEventSession(sessionName);
                var keywords = KernelTraceEventParser.Keywords.Process | KernelTraceEventParser.Keywords.Registry |
                               KernelTraceEventParser.Keywords.FileIOInit | KernelTraceEventParser.Keywords.FileIO |
                               KernelTraceEventParser.Keywords.ImageLoad | KernelTraceEventParser.Keywords.Memory;

                _session.EnableKernelProvider(keywords);

                _session.Source.Kernel.ProcessStart += data => HandleProcessStart(data);
                _session.Source.Kernel.ProcessStop += data => HandleProcessStop(data);
                _session.Source.Kernel.ImageLoad += data => HandleImageLoad(data);
                _session.Source.Kernel.RegistrySetValue += data => HandleRegistrySet(data);
                _session.Source.Kernel.FileIOCreate += data => HandleFileIOCreate(data);
                _session.Source.Kernel.FileIOWrite += data => HandleFileIOWrite(data);
                _session.Source.Kernel.VirtualMemAlloc += data => HandleVirtualMemAlloc(data);
                _session.Source.Kernel.StackWalkStack += data => HandleStackWalk(data);

                _session.Source.Process();
            }
            catch (Exception ex)
            {
                IsHealthy = false;
            }
        }

        private void HandleProcessStart(ProcessTraceData data)
        {
            _processCache[data.ProcessID] = data.ImageFileName ?? "";
            _processStartTime[data.ProcessID] = DateTime.UtcNow;

            if (data.ProcessID == _sensorPid || data.ParentID == _sensorPid) return;

            string lineage = $"{GetProcessName(data.ParentID)}|{data.ImageFileName}";
            if (_benignLineages.ContainsKey(lineage)) return;

            var evt = CreatePlatformEvent(data, EventCategory.ProcessStart);
            evt.CommandLineHash = ThreatIntelModule.HashDomain(data.CommandLine ?? "");
            _router.PushEvent(evt);
        }

        private void HandleProcessStop(ProcessTraceData data)
        {
            _processCache.TryRemove(data.ProcessID, out _);
            _processStartTime.TryRemove(data.ProcessID, out _);
            _processModules.TryRemove(data.ProcessID, out _);
        }

        private void HandleImageLoad(ImageLoadTraceData data)
        {
            if (data.ProcessID == 0 || data.ProcessID == _sensorPid) return;

            var map = new ModuleMap
            {
                ModuleName = data.FileName,
                BaseAddress = (ulong)data.ImageBase,
                EndAddress = (ulong)data.ImageBase + (ulong)data.ImageSize
            };

            _processModules.AddOrUpdate(data.ProcessID, _ => new[] { map },
                (_, existing) =>
                {
                    var list = new List<ModuleMap>(existing);
                    int idx = list.BinarySearch(map);
                    if (idx < 0) list.Insert(~idx, map);
                    return list.ToArray();
                });

            if (data.FileName?.EndsWith(".sys", StringComparison.OrdinalIgnoreCase) == true &&
                _tiDrivers.Contains(Path.GetFileName(data.FileName)))
            {
                var evt = CreatePlatformEvent(data, EventCategory.ImageLoad);
                evt.ContextScore = 9.0;
                _router.PushEvent(evt);
                return;
            }

            _router.PushEvent(CreatePlatformEvent(data, EventCategory.ImageLoad));
        }

        private void HandleRegistrySet(RegistryTraceData data)
        {
            if (data.ProcessID == _sensorPid) return;
            _router.PushEvent(CreatePlatformEvent(data, EventCategory.RegistryMod));
        }

        private void HandleFileIOCreate(FileIOCreateTraceData data)
        {
            string fileName = data.FileName ?? "";
            if (fileName.Contains("deepsensor_canary.tmp", StringComparison.OrdinalIgnoreCase))
            {
                _router.PushEvent(new PlatformEvent { Category = EventCategory.Unknown, ContextScore = 100 });
                return;
            }

            if (fileName.Contains(@"\Device\NamedPipe\", StringComparison.OrdinalIgnoreCase) ||
                fileName.Contains(@"\pipe\", StringComparison.OrdinalIgnoreCase))
            {
                string pipeName = fileName.Split(new[] { @"\NamedPipe\" }, StringSplitOptions.None).LastOrDefault() ?? "";
                if (ShannonEntropy(pipeName) > 3.5)
                {
                    var evt = CreatePlatformEvent(data, EventCategory.FileWrite);
                    evt.Details = $"SuspiciousPipe:{pipeName}";
                    _router.PushEvent(evt);
                    return;
                }
            }

            _router.PushEvent(CreatePlatformEvent(data, EventCategory.FileWrite));
        }

        private void HandleFileIOWrite(FileIOReadWriteTraceData data)
        {
            if (data.ProcessID == _sensorPid) return;
            _router.PushEvent(CreatePlatformEvent(data, EventCategory.FileWrite));
        }

        private void HandleVirtualMemAlloc(VirtualAllocTraceData data)
        {
            int flags = (int)data.Flags;
            if (flags == 0x40 || flags == 0x20)
            {
                if (data.ProcessID != _sensorPid && data.ProcessID != 0)
                {
                    ulong baseAddr = Convert.ToUInt64(data.PayloadByName("BaseAddress"));
                    ulong size = Convert.ToUInt64(data.PayloadByName("RegionSize"));

                    string yaraResult = NeuterAndDumpPayload(data.ProcessID, baseAddr, size);
                    if (yaraResult != "NoSignatureMatch" && yaraResult != "HandleAccessDenied")
                    {
                        bool neutralized = QuarantineNativeThread(data.ThreadID, data.ProcessID);
                        var evt = CreatePlatformEvent(data, EventCategory.ProcessStart);
                        evt.Details = $"YaraHit:{yaraResult}|Quarantined:{neutralized}";
                        _router.PushEvent(evt);
                    }
                }
            }
        }

        private void HandleStackWalk(StackWalkStackTraceData data)
        {
            if (!_processModules.TryGetValue(data.ProcessID, out var modules)) return;

            int unbacked = 0, forged = 0;
            for (int i = 0; i < data.FrameCount; i++)
            {
                ulong ip = data.InstructionPointer(i);
                bool backed = modules.Any(m => ip >= m.BaseAddress && ip <= m.EndAddress);
                if (!backed)
                {
                    unbacked++;
                    if (IsForgedReturnAddress(data.ProcessID, ip)) forged++;
                }
            }

            if (unbacked >= 2 || forged > 0)
            {
                var evt = CreatePlatformEvent(data, EventCategory.ProcessStart);
                evt.Details = $"StackSpoof: {unbacked} unbacked, {forged} forged";
                _router.PushEvent(evt);
            }
        }

        public bool QuarantineNativeThread(int tid, int pid)
        {
            if (!_isArmed) return false;
            string procName = GetProcessName(pid);
            if (_criticalSystemProcesses.Contains(procName)) return false;

            uint THREAD_SUSPEND_RESUME = 0x0002;
            IntPtr hThread = OpenThread(THREAD_SUSPEND_RESUME, false, (uint)tid);
            if (hThread == IntPtr.Zero) return false;

            uint suspendCount = SuspendThread(hThread);
            CloseHandle(hThread);
            return (suspendCount != 0xFFFFFFFF);
        }

        public string NeuterAndDumpPayload(int pid, ulong address, ulong size)
        {
            string yaraResult = "NoSignatureMatch";
            string procName = GetProcessName(pid);
            if (_criticalSystemProcesses.Contains(procName)) return yaraResult;

            if (size > 52428800) return "AllocationExceedsScanLimit";

            uint PROCESS_VM_READ_OPERATION = 0x0010 | 0x0008;
            IntPtr hProcess = OpenProcess(PROCESS_VM_READ_OPERATION, false, (uint)pid);
            if (hProcess == IntPtr.Zero) return "HandleAccessDenied";

            try
            {
                byte[] buffer = new byte[size];
                if (ReadProcessMemory(hProcess, (IntPtr)address, buffer, (UIntPtr)size, out UIntPtr bytesRead))
                {
                    yaraResult = EvaluatePayloadInMemory(buffer, procName);

                    if (yaraResult != "NoSignatureMatch")
                    {
                        string quarantineDir = @"C:\ProgramData\DeepSensor\Data\Quarantine";
                        Directory.CreateDirectory(quarantineDir);
                        string dumpPath = $@"{quarantineDir}\Payload_{procName}_{pid}_0x{address:X}.bin";
                        File.WriteAllBytes(dumpPath, buffer);
                    }
                }

                uint PAGE_NOACCESS = 0x01;
                VirtualProtectEx(hProcess, (IntPtr)address, (UIntPtr)size, PAGE_NOACCESS, out uint oldProtect);
            }
            catch { return "ForensicError"; }
            finally { CloseHandle(hProcess); }
            return yaraResult;
        }

        public string PreserveForensics(int pid, string procName)
        {
            if (!_isArmed) return "Bypassed";
            string dumpDir = @"C:\ProgramData\DeepSensor\Data\Forensics";
            Directory.CreateDirectory(dumpDir);
            string dumpPath = $@"{dumpDir}\{procName}_{pid}_{DateTime.UtcNow:yyyyMMddHHmmss}.dmp";

            IntPtr hProcess = OpenProcess(0x0400 | 0x0010, false, (uint)pid);
            if (hProcess == IntPtr.Zero) return "AccessDenied";

            try
            {
                using (var fs = new FileStream(dumpPath, FileMode.Create, FileAccess.ReadWrite, FileShare.Write))
                {
                    if (MiniDumpWriteDump(hProcess, (uint)pid, fs.SafeFileHandle, 2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero))
                    {
                        return dumpPath;
                    }
                }
            }
            catch { }
            finally { CloseHandle(hProcess); }
            return "Failed";
        }

        public bool ResumeNativeThread(int tid)
        {
            uint THREAD_SUSPEND_RESUME = 0x0002;
            IntPtr hThread = OpenThread(THREAD_SUSPEND_RESUME, false, (uint)tid);
            if (hThread == IntPtr.Zero) return false;
            uint resumeCount = ResumeThread(hThread);
            CloseHandle(hThread);
            return (resumeCount != 0xFFFFFFFF);
        }

        private string EvaluatePayloadInMemory(byte[] payload, string processName)
        {
            return "NoSignatureMatch";
        }

        private PlatformEvent CreatePlatformEvent(TraceEvent data, EventCategory category, string details = null)
        {
            return new PlatformEvent
            {
                EventId = data.EventIndex,
                TimestampTicks = data.TimeStamp.Ticks,
                SourceSensor = SensorType.ETW_Kernel,
                Category = category,
                ProcessNameHash = ThreatIntelModule.HashDomain(data.ProcessName ?? ""),
                ParentProcessHash = 0,
                CommandLineHash = ThreatIntelModule.HashDomain(data.CommandLine ?? ""),
                ProcessId = data.ProcessID,
                ThreadId = data.ThreadID,
                DestinationIpV4 = 0,
                DestinationPort = 0,
                ContextScore = 0.0,
                Details = details ?? ""
            };
        }

        private string GetProcessName(int pid) => _processCache.TryGetValue(pid, out var name) ? name : pid.ToString();

        private static double ShannonEntropy(string s)
        {
            if (string.IsNullOrEmpty(s)) return 0.0;
            var counts = new Dictionary<char, int>();
            foreach (char c in s) { counts[c] = counts.GetValueOrDefault(c) + 1; }
            double entropy = 0.0;
            int len = s.Length;
            foreach (var count in counts.Values)
            {
                double p = (double)count / len;
                entropy -= p * Math.Log(p, 2);
            }
            return entropy;
        }

        private static bool IsForgedReturnAddress(int pid, ulong returnAddr)
        {
            if (returnAddr < 10) return true;
            uint PROCESS_VM_READ_OPERATION = 0x0010 | 0x0008;
            IntPtr hProcess = OpenProcess(PROCESS_VM_READ_OPERATION, false, (uint)pid);
            if (hProcess == IntPtr.Zero) return true;

            try
            {
                byte[] buffer = new byte[10];
                ulong readAddr = returnAddr - 10;
                if (!ReadProcessMemory(hProcess, (IntPtr)readAddr, buffer, (UIntPtr)10, out _)) return true;

                for (int i = 0; i < 6; i++)
                {
                    byte b = buffer[i];
                    if (b == 0xE8 || b == 0xE9 || b == 0xEB) return false;
                    if (b == 0xFF)
                    {
                        byte modrm = buffer[i + 1];
                        if ((modrm & 0xF8) == 0xD0 || (modrm & 0xF8) == 0x10 ||
                            (modrm & 0xF8) == 0x50 || (modrm & 0xF8) == 0x90) return false;
                    }
                }
                return true;
            }
            catch { return true; }
            finally { CloseHandle(hProcess); }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesRead);

        [DllImport("dbghelp.dll", SetLastError = true)]
        static extern bool MiniDumpWriteDump(IntPtr hProcess, uint processId, Microsoft.Win32.SafeHandles.SafeFileHandle hFile, uint dumpType, IntPtr expParam, IntPtr userStreamParam, IntPtr callbackParam);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);

        public Task StopAsync(CancellationToken cancellationToken)
        {
            _session?.Stop();
            _session?.Dispose();
            _session = null;
            return Task.CompletedTask;
        }
    }

    public struct ModuleMap : IComparable<ModuleMap>
    {
        public string ModuleName;
        public ulong BaseAddress;
        public ulong EndAddress;
        public int CompareTo(ModuleMap other) => BaseAddress.CompareTo(other.BaseAddress);
    }

    public class RuleMatrix { public SigmaRule[] ProcRules = Array.Empty<SigmaRule>(); }
    public class SigmaRule { public string Id; public string Category; public string AnchorString; }
}