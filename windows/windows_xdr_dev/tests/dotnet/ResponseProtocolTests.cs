using System.Text;
using System.Text.Json;
using UnifiedAgent.Core.Response;
using Xunit;

namespace UnifiedAgent.Core.Response.Tests
{
    // Executed (not just compiled) proof that DeepXDR's C# response protocol signs
    // and canonicalises byte-identically to the Python signer
    // (project_empros/operations/agent/response_executor.py). Cross-language golden
    // vector -- fails on any canonicalisation / HMAC drift.
    public class ResponseProtocolTests
    {
        private static byte[] Secret => Encoding.UTF8.GetBytes(ResponseProtocol.GoldenSecret);

        private static JsonElement Parse(string s) => JsonDocument.Parse(s).RootElement;

        // The golden task WITHOUT signature (Python canonical form is order-independent).
        private const string GoldTask =
            "{\"kind\":\"response\",\"incident_id\":\"INC-GOLD\",\"host\":\"ep-gold\"," +
            "\"os_family\":\"linux\",\"action_type\":\"isolate_host\",\"targets\":[]," +
            "\"mgmt_ips\":[\"10.0.0.0/24\"],\"created_at\":1700000000}";

        private static string Signed(string sig) =>
            GoldTask.Substring(0, GoldTask.Length - 1) + ",\"signature\":\"" + sig + "\"}";

        [Fact]
        public void Canonical_matches_python_golden()
        {
            var canon = Encoding.UTF8.GetString(ResponseProtocol.Canonical(Parse(GoldTask)));
            Assert.Equal(ResponseProtocol.GoldenCanonical, canon);
        }

        [Fact]
        public void Verify_accepts_python_signature()
        {
            // The signature was produced by Python; if C#'s Canonical+HMAC drift,
            // this fails -- the real cross-language conformance assertion.
            Assert.True(ResponseProtocol.VerifyTask(Parse(Signed(ResponseProtocol.GoldenSig)), Secret));
        }

        [Fact]
        public void Verify_rejects_tampered_task()
        {
            var t = Signed(ResponseProtocol.GoldenSig).Replace("10.0.0.0/24", "10.0.0.0/25");
            Assert.False(ResponseProtocol.VerifyTask(Parse(t), Secret));
        }

        [Fact]
        public void Verify_rejects_unsigned_task()
        {
            Assert.False(ResponseProtocol.VerifyTask(Parse(GoldTask), Secret));
        }

        [Theory]
        [InlineData("isolate_host", "01_Contain-Host.ps1")]
        [InlineData("eradicate_process", "02_Eradicate-Process.ps1")]
        [InlineData("block_ip", "04_Block-C2.ps1")]
        [InlineData("restore", "06_Restore-Host.ps1")]
        public void SelectPlaybook_maps_action_to_fixed_script(string action, string script)
        {
            Assert.Equal(script, ResponseProtocol.SelectPlaybook(action));
        }

        [Fact]
        public void SelectPlaybook_rejects_unknown_action()
        {
            Assert.Null(ResponseProtocol.SelectPlaybook("Invoke-Mimikatz"));
        }

        [Fact]
        public void BuildEnv_block_ip_sets_c2_ips()
        {
            var task = Parse(
                "{\"incident_id\":\"INC\",\"action_type\":\"block_ip\",\"targets\":[\"8.8.8.8\"]}");
            var env = ResponseProtocol.BuildEnv(task);
            Assert.Equal("INC", env["NEXUS_INCIDENT_ID"]);
            Assert.Equal("8.8.8.8", env["NEXUS_C2_IPS"]);
        }

        [Fact]
        public void BuildEnv_isolate_host_sets_mgmt_ips()
        {
            var env = ResponseProtocol.BuildEnv(Parse(GoldTask));
            Assert.Equal("10.0.0.0/24", env["NEXUS_MGMT_IPS"]);
        }
    }
}
