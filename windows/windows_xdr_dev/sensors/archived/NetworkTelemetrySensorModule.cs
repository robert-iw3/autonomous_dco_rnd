using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Logging;
using UnifiedAgent.Core.Interfaces;
using UnifiedAgent.Core.Models;
using UnifiedAgent.Core.Routing;
using UnifiedAgent.Core.Defense;

namespace UnifiedAgent.Sensors
{
    public class NetworkTelemetrySensorModule : ISensorModule
    {
        public string ModuleName => "NetworkTelemetrySensor";
        public bool IsHealthy { get; private set; } = false;

        private readonly ILogger<NetworkTelemetrySensorModule> _logger;
        private readonly TelemetryRouter _router;
        private readonly ThreatIntelModule _threatIntel;

        private TraceEventSession _session;

        private readonly ConcurrentDictionary<int, string> _activeWebDaemons = new();
        private readonly ConcurrentDictionary<int, string> _activeDbDaemons = new();
        private readonly HashSet<string> _webDaemons = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _dbDaemons = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _shellInterpreters = new(StringComparer.OrdinalIgnoreCase);
        private readonly string[] _suspiciousPaths = Array.Empty<string>();

        private readonly string[] _maliciousPipes =
        {
            "\\msagent_", "\\postex_", "\\status_", "\\mypipe-f", "\\mypipe-h",
            "\\gilgamesh", "\\mythic_", "\\sliver_", "\\psexec_svc"
        };

        private readonly HashSet<string> _dnsExclusions = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _processExclusions = new(StringComparer.OrdinalIgnoreCase);
        private readonly List<System.Text.RegularExpressions.Regex> _ipPrefixExclusions = new();

        private readonly ConcurrentDictionary<int, string> _processCmdLines = new();

        public NetworkTelemetrySensorModule(
            ILogger<NetworkTelemetrySensorModule> logger,
            TelemetryRouter router,
            ThreatIntelModule threatIntel)
        {
            _logger = logger;
            _router = router;
            _threatIntel = threatIntel;
        }

        public async Task InitializeAsync(CancellationToken cancellationToken)
        {
            _webDaemons.UnionWith(new[] { "w3wp.exe", "nginx.exe", "httpd.exe" });
            _dbDaemons.UnionWith(new[] { "sqlservr.exe", "postgres.exe", "mysqld.exe" });
            _shellInterpreters.UnionWith(new[] { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe" });
            _dnsExclusions.UnionWith(new[] { "microsoft.com", "windows.com", "akadns.net", "azure.com" });

            IsHealthy = true;
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            Task.Run(() => RunNetworkSession(), cancellationToken);
            return Task.CompletedTask;
        }

        private void RunNetworkSession()
        {
            try
            {
                string sessionName = "NetworkTelemetrySession";
                if (TraceEventSession.GetActiveSessionNames().Contains(sessionName))
                {
                    using var old = new TraceEventSession(sessionName);
                    old.Stop(true);
                }

                _session = new TraceEventSession(sessionName);

                _session.EnableProvider("Microsoft-Windows-TCPIP", TraceEventLevel.Informational, 0xFFFFFFFF);
                _session.EnableProvider("Microsoft-Windows-DNS-Client");
                _session.EnableProvider("Microsoft-Windows-Kernel-Process");
                _session.EnableProvider("Microsoft-Windows-Kernel-File");
                _session.EnableProvider("Microsoft-Windows-NDIS-PacketCapture");

                _session.Source.Dynamic.All += data => HandleNetworkEvent(data);

                _session.Source.Process();
            }
            catch (Exception ex)
            {
                IsHealthy = false;
            }
        }

        private void HandleNetworkEvent(TraceEvent data)
        {
            try
            {
                string evName = data.EventName ?? "";
                string provider = data.ProviderName ?? "";

                if (evName.StartsWith("Thread") || evName.Contains("Rundown") || evName == "CpuPriorityChange") return;

                if (provider.Contains("Kernel-Process"))
                {
                    if (evName.Contains("Start")) HandleProcessStart(data);
                    else if (evName.Contains("Stop")) HandleProcessStop(data);
                }

                if (provider.Contains("NDIS-PacketCapture"))
                {
                    HandleNdisPacket(data);
                    return;
                }

                if (provider.Contains("Kernel-File") && (evName == "Create" || evName == "NameCreate"))
                {
                    HandleNamedPipe(data);
                    return;
                }

                if (provider.Contains("DNS") || provider.Contains("TCPIP"))
                {
                    HandleNetworkFlow(data);
                }
            }
            catch { }
        }

        private void HandleProcessStart(TraceEvent data)
        {
            string imageClean = Path.GetFileNameWithoutExtension(data.PayloadStringByName("ImageFileName") ?? "").ToLower();
            string processCmd = data.PayloadStringByName("CommandLine") ?? "";

            if (processCmd.Length > 4096)
                processCmd = processCmd.Substring(0, 4096) + " ...[TRUNCATED]";

            if (!string.IsNullOrEmpty(processCmd))
                _processCmdLines[data.ProcessID] = processCmd;

            if (_webDaemons.Contains(imageClean))
                _activeWebDaemons[data.ProcessID] = processCmd ?? imageClean;
            else if (_dbDaemons.Contains(imageClean))
                _activeDbDaemons[data.ProcessID] = processCmd ?? imageClean;

            if (data.EventName.Contains("Start"))
            {
                int parentPid = Convert.ToInt32(data.PayloadByName("ParentProcessID") ?? -1);
                bool isWebParent = _activeWebDaemons.ContainsKey(parentPid);
                bool isDbParent = _activeDbDaemons.ContainsKey(parentPid);

                if (isWebParent || isDbParent)
                {
                    string childPath = data.PayloadStringByName("ImageFileName") ?? "";
                    string childClean = Path.GetFileNameWithoutExtension(childPath).ToLower();
                    string childCmdLine = data.PayloadStringByName("CommandLine") ?? "";

                    bool isInterpreter = _shellInterpreters.Contains(childClean);
                    bool isSuspiciousPath = _suspiciousPaths.Any(p => childPath.ToLower().Contains(p));

                    if (isInterpreter || isSuspiciousPath)
                    {
                        if (isWebParent && (childClean == "csc" || childClean == "cvtres") &&
                            childCmdLine.IndexOf("Temporary ASP.NET Files", StringComparison.OrdinalIgnoreCase) >= 0)
                            return;

                        string parentContext = isWebParent ? _activeWebDaemons[parentPid] : _activeDbDaemons[parentPid];
                        string eventType = isWebParent ? "WEB_SHELL_DETECTED" : "DB_RCE_DETECTED";
                        string trigger = isInterpreter ? "Command Interpreter" : "Unauthorized Directory";

                        var evt = new PlatformEvent
                        {
                            Category = EventCategory.ProcessStart,
                            SourceSensor = SensorType.NDIS,
                            ProcessId = data.ProcessID,
                            ThreadId = data.ThreadID,
                            ContextScore = 9.5,
                            Details = $"{eventType}|{trigger}|Parent:{parentContext}|Child:{childClean}"
                        };
                        _router.PushEvent(evt);
                    }
                }
            }
        }

        private void HandleProcessStop(TraceEvent data)
        {
            _activeWebDaemons.TryRemove(data.ProcessID, out _);
            _activeDbDaemons.TryRemove(data.ProcessID, out _);
            _processCmdLines.TryRemove(data.ProcessID, out _);
        }

        private void HandleNdisPacket(TraceEvent data)
        {
            try
            {
                byte[] frame = (byte[])data.PayloadByName("Fragment");
                if (frame == null || frame.Length < 60) return;

                if (frame.Length < 14 || frame[12] != 0x08 || frame[13] != 0x00) return;
                int ipHeaderStart = 14;
                if (frame[ipHeaderStart + 9] != 0x06) return;

                int ihl = (frame[ipHeaderStart] & 0x0F) * 4;
                int tcpHeaderStart = ipHeaderStart + ihl;
                int destPort = (frame[tcpHeaderStart + 2] << 8) | frame[tcpHeaderStart + 3];
                if (destPort != 443 && destPort != 8443) return;

                int dataOffset = (frame[tcpHeaderStart + 12] >> 4) * 4;
                int payloadStart = tcpHeaderStart + dataOffset;
                int payloadLength = frame.Length - payloadStart;

                if (payloadLength > 5)
                {
                    string ja3Hash = ExtractJA3(frame, payloadStart, payloadLength);
                    if (!string.IsNullOrEmpty(ja3Hash))
                    {
                        string destIp = $"{frame[ipHeaderStart + 16]}.{frame[ipHeaderStart + 17]}.{frame[ipHeaderStart + 18]}.{frame[ipHeaderStart + 19]}";

                        var evt = new PlatformEvent
                        {
                            Category = EventCategory.TcpConnect,
                            SourceSensor = SensorType.NDIS,
                            ProcessId = data.ProcessID,
                            ThreadId = data.ThreadID,
                            DestinationIpV4 = BitConverter.ToUInt32(new byte[] { frame[ipHeaderStart + 16], frame[ipHeaderStart + 17], frame[ipHeaderStart + 18], frame[ipHeaderStart + 19] }, 0),
                            DestinationPort = destPort,
                            ContextScore = 8.5,
                            Details = $"JA3:{ja3Hash}|Dest:{destIp}"
                        };
                        _router.PushEvent(evt);
                    }
                }
            }
            catch { }
        }

        private void HandleNamedPipe(TraceEvent data)
        {
            string fileName = (data.PayloadStringByName("FileName") ?? "").ToLowerInvariant();
            if (!fileName.Contains("\\device\\namedpipe\\") && !fileName.Contains("\\pipe\\")) return;

            foreach (string pattern in _maliciousPipes)
            {
                if (fileName.Contains(pattern))
                {
                    var evt = new PlatformEvent
                    {
                        Category = EventCategory.FileWrite,
                        SourceSensor = SensorType.ETW_Kernel,
                        ProcessId = data.ProcessID,
                        ThreadId = data.ThreadID,
                        ContextScore = 9.0,
                        Details = $"MaliciousPipe:{fileName}"
                    };
                    _router.PushEvent(evt);
                    break;
                }
            }
        }

        private void HandleNetworkFlow(TraceEvent data)
        {
            string destIp = "";
            string port = "";
            string query = "";
            string size = "0";
            string image = data.ProcessName ?? "Unknown";

            for (int i = 0; i < data.PayloadNames.Length; i++)
            {
                string name = data.PayloadNames[i].ToLower();
                object val = data.PayloadValue(i);

                if (name.Contains("destination") || name == "daddr" || name == "destaddress")
                    destIp = ParseIp(val);
                else if (name == "queryname" || name == "query")
                    query = val?.ToString() ?? "";
                else if (name.Contains("port") && !name.Contains("source"))
                    port = val?.ToString() ?? "";
                else if (name == "size" || name == "bytessent" || name == "length")
                    size = val?.ToString() ?? "0";
            }

            string threatIntelTag = "";
            if (!string.IsNullOrEmpty(destIp))
            {
                uint ipVal = IpToUint(destIp);
                if (ipVal != 0 && _threatIntel.MaliciousIps.Contains(ipVal))
                    threatIntelTag = "Suricata: Malicious IP Match";
            }

            if (string.IsNullOrEmpty(threatIntelTag) && !string.IsNullOrEmpty(query))
            {
                string cleanQuery = query.StartsWith(".") ? query : "." + query;
                ulong domHash = ThreatIntelModule.HashDomain(cleanQuery);
                if (domHash != 0 && _threatIntel.MaliciousDomains.Contains(domHash))
                    threatIntelTag = "Suricata: Malicious Domain Match";
            }

            var evt = new PlatformEvent
            {
                Category = data.ProviderName.Contains("DNS") ? EventCategory.TcpConnect : EventCategory.TcpConnect,
                SourceSensor = SensorType.NDIS,
                ProcessId = data.ProcessID,
                ThreadId = data.ThreadID,
                DestinationIpV4 = IpToUint(destIp),
                DestinationPort = int.TryParse(port, out int p) ? p : 0,
                ContextScore = string.IsNullOrEmpty(threatIntelTag) ? 0.0 : 8.0,
                Details = threatIntelTag
            };

            _router.PushEvent(evt);
        }

        private static string ParseIp(object val)
        {
            if (val == null) return "";
            string result = "";

            if (val is byte[])
            {
                byte[] b = (byte[])val;
                try
                {
                    if (b.Length >= 8 && b[0] == 2 && b[1] == 0) result = new System.Net.IPAddress(new byte[] { b[4], b[5], b[6], b[7] }).ToString();
                    else if (b.Length >= 24 && b[0] == 23 && b[1] == 0 && b[18] == 255 && b[19] == 255) result = new System.Net.IPAddress(new byte[] { b[20], b[21], b[22], b[23] }).ToString();
                    else if (b.Length == 4 || b.Length == 16) result = new System.Net.IPAddress(b).ToString();
                }
                catch { }
            }
            else if (val is int || val is uint || val is long)
            {
                try
                {
                    byte[] bytes = BitConverter.GetBytes(Convert.ToInt64(val));
                    result = new System.Net.IPAddress(new byte[] { bytes[0], bytes[1], bytes[2], bytes[3] }).ToString();
                }
                catch { }
            }
            else { result = val.ToString(); }

            if (result.Contains("::ffff:")) result = result.Replace("::ffff:", "");
            return result;
        }

        private static string FallbackIpExtract(byte[] payload, out string extractedPort)
        {
            extractedPort = "";
            if (payload == null || payload.Length < 8) return "DECODER_FAILED";
            string lastFound = "DECODER_FAILED";

            for (int i = 0; i < payload.Length - 7; i++)
            {
                if (payload[i] == 2 && payload[i + 1] == 0)
                {
                    if (payload[i + 2] == 0 && payload[i + 3] == 0) continue;

                    int ip1 = payload[i + 4]; int ip2 = payload[i + 5]; int ip3 = payload[i + 6]; int ip4 = payload[i + 7];
                    if (ip1 == 0 || ip1 == 127 || ip1 == 255) continue;

                    string ipStr = ip1 + "." + ip2 + "." + ip3 + "." + ip4;
                    lastFound = ipStr;

                    if (ip1 == 10 || (ip1 == 192 && ip2 == 168) || (ip1 == 172 && ip2 >= 16 && ip2 <= 31) || (ip1 == 169 && ip2 == 254) || ip1 >= 224) continue;

                    extractedPort = ((payload[i + 2] << 8) | payload[i + 3]).ToString();
                    return ipStr;
                }
                else if (i < payload.Length - 23 && payload[i] == 23 && payload[i + 1] == 0)
                {
                    if (payload[i + 2] == 0 && payload[i + 3] == 0) continue;

                    if (payload[i + 18] == 255 && payload[i + 19] == 255)
                    {
                        int ip1 = payload[i + 20]; int ip2 = payload[i + 21]; int ip3 = payload[i + 22]; int ip4 = payload[i + 23];
                        if (ip1 == 0 || ip1 == 127 || ip1 == 255) continue;

                        string ipStr = ip1 + "." + ip2 + "." + ip3 + "." + ip4;
                        lastFound = ipStr;

                        if (ip1 == 10 || (ip1 == 192 && ip2 == 168) || (ip1 == 172 && ip2 >= 16 && ip2 <= 31) || (ip1 == 169 && ip2 == 254) || ip1 >= 224) continue;

                        extractedPort = ((payload[i + 2] << 8) | payload[i + 3]).ToString();
                        return ipStr;
                    }
                }
            }
            return lastFound;
        }

        private static bool IsGrease(ushort val) => (val & 0x0F0F) == 0x0A0A;

        private static string ExtractJA3(byte[] payload, int offset, int length)
        {
            try
            {
                if (payload[offset] != 0x16 || payload[offset + 1] != 0x03) return null;
                if (payload[offset + 5] != 0x01) return null;

                int ptr = offset + 9;
                ushort sslVersion = (ushort)((payload[ptr] << 8) | payload[ptr + 1]);
                ptr += 2; ptr += 32;

                int sessionLength = payload[ptr];
                ptr += 1 + sessionLength;

                int cipherLength = (payload[ptr] << 8) | payload[ptr + 1];
                ptr += 2;
                List<ushort> ciphers = new List<ushort>();
                for (int i = 0; i < cipherLength; i += 2)
                {
                    ushort cipher = (ushort)((payload[ptr + i] << 8) | payload[ptr + i + 1]);
                    if (!IsGrease(cipher)) ciphers.Add(cipher);
                }
                ptr += cipherLength;

                int compLength = payload[ptr];
                ptr += 1 + compLength;

                List<ushort> extensions = new List<ushort>();
                List<ushort> curves = new List<ushort>();
                List<ushort> pointFormats = new List<ushort>();

                if (ptr + 2 <= offset + length)
                {
                    int extTotalLength = (payload[ptr] << 8) | payload[ptr + 1];
                    ptr += 2;
                    int extEnd = ptr + extTotalLength;

                    while (ptr + 4 <= extEnd)
                    {
                        ushort extType = (ushort)((payload[ptr] << 8) | payload[ptr + 1]);
                        int extLen = (payload[ptr + 2] << 8) | payload[ptr + 3];
                        ptr += 4;

                        if (!IsGrease(extType))
                        {
                            extensions.Add(extType);
                            if (extType == 10 && extLen >= 2)
                            {
                                int curveListLen = (payload[ptr] << 8) | payload[ptr + 1];
                                for (int i = 2; i < curveListLen + 2; i += 2)
                                {
                                    ushort curve = (ushort)((payload[ptr + i] << 8) | payload[ptr + i + 1]);
                                    if (!IsGrease(curve)) curves.Add(curve);
                                }
                            }
                            else if (extType == 11 && extLen >= 1)
                            {
                                int formatListLen = payload[ptr];
                                for (int i = 1; i < formatListLen + 1; i++)
                                {
                                    pointFormats.Add(payload[ptr + i]);
                                }
                            }
                        }
                        ptr += extLen;
                    }
                }

                string ja3String = string.Format("{0},{1},{2},{3},{4}", sslVersion, string.Join("-", ciphers), string.Join("-", extensions), string.Join("-", curves), string.Join("-", pointFormats));

                using (MD5 md5 = MD5.Create())
                {
                    byte[] hashBytes = md5.ComputeHash(Encoding.UTF8.GetBytes(ja3String));
                    StringBuilder sb = new StringBuilder();
                    foreach (byte b in hashBytes) sb.Append(b.ToString("x2"));
                    return sb.ToString();
                }
            }
            catch { return null; }
        }

        private static uint IpToUint(string ipAddress) => ThreatIntelModule.IpToUint(ipAddress);

        public Task StopAsync(CancellationToken cancellationToken)
        {
            _session?.Stop();
            _session?.Dispose();
            _session = null;
            return Task.CompletedTask;
        }
    }
}