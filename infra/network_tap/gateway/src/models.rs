use serde::Deserialize;

// =============================================================================
// Arkime SPI Record -- raw JSON from the Kafka plugin
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct TcpFlags {
    pub syn: Option<u32>,
    pub ack: Option<u32>,
    pub rst: Option<u32>,
    pub fin: Option<u32>,
    pub psh: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct DnsContext {
    pub host:   Option<Vec<String>>,
    pub status: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct HttpContext {
    pub method:     Option<Vec<String>>,
    pub uri:        Option<Vec<String>>,
    pub useragent:  Option<Vec<String>>,
    pub statuscode: Option<Vec<u16>>,
}

#[derive(Debug, Deserialize)]
pub struct TlsContext {
    pub ja3:     Option<Vec<String>>,
    pub ja3s:    Option<Vec<String>>,
    pub cipher:  Option<Vec<String>>,
    pub version: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct CertContext {
    pub cn:          Option<Vec<String>>,
    #[serde(rename = "issuerCn")]
    pub issuer_cn:   Option<Vec<String>>,
    #[serde(rename = "validDays")]
    pub valid_days:  Option<Vec<i32>>,
    #[serde(rename = "selfSigned")]
    pub self_signed: Option<Vec<bool>>,
}

#[derive(Debug, Deserialize)]
pub struct ArkimeSpi<'a> {
    #[serde(borrow)]
    pub id: &'a str,
    #[serde(borrow)]
    pub a1: &'a str,
    #[serde(borrow)]
    pub a2: &'a str,
    #[serde(default)]
    pub p1: u16,
    #[serde(default)]
    pub p2: u16,
    #[serde(default)]
    pub pr: u8,
    #[serde(default)]
    pub by1: u64,
    #[serde(default)]
    pub by2: u64,
    #[serde(default)]
    pub db1: u64,
    #[serde(default)]
    pub db2: u64,
    #[serde(default)]
    pub pa1: u32,
    #[serde(default)]
    pub pa2: u32,
    #[serde(default)]
    pub fp: i64,
    #[serde(default)]
    pub lp: i64,
    #[serde(default)]
    pub pa: Option<Vec<u32>>,
    #[serde(default)]
    pub ps: Option<Vec<u64>>,
    #[serde(default)]
    pub tcpflags: Option<TcpFlags>,
    #[serde(default)]
    pub dns: Option<DnsContext>,
    #[serde(default)]
    pub http: Option<HttpContext>,
    #[serde(default)]
    pub tls: Option<TlsContext>,
    #[serde(default)]
    pub cert: Option<CertContext>,
    #[serde(default, rename = "ho")]
    pub hostname: Option<Vec<String>>,
    #[serde(default)]
    pub g1: Option<String>,
    #[serde(default)]
    pub g2: Option<String>,
    #[serde(default, rename = "as1str")]
    pub as1_org: Option<String>,
    #[serde(default, rename = "as2str")]
    pub as2_org: Option<String>,
}

// =============================================================================
// NetworkFlowRecord -- the rich output sent to the Axum gateway / LLM stack
// =============================================================================

#[derive(Debug, Clone)]
pub struct NetworkFlowRecord {
    // --- Identity ---
    pub session_id:    String,
    pub src_ip:        String,
    pub dst_ip:        String,
    pub src_port:      u16,
    pub dst_port:      u16,
    pub protocol:      u8,
    pub protocol_name: String,

    // --- Temporal ---
    pub timestamp_start:    u64,
    pub timestamp_end:      u64,
    // u64 to handle long-lived sessions (SSH tunnels, persistent connections)
    pub session_duration_ms: u64,

    // --- Volume ---
    pub bytes_src:      u64,
    pub bytes_dst:      u64,
    pub data_bytes_src: u64,
    pub data_bytes_dst: u64,
    pub packets_src:    u32,
    pub packets_dst:    u32,

    // --- Statistical features ---
    pub byte_ratio:             f32,
    pub avg_inter_arrival:      f32,
    pub variance_inter_arrival: f32,
    pub ratio_small_packets:    f32,
    pub ratio_large_packets:    f32,
    // Shannon entropy of packet-size distribution (proxy for payload randomness)
    pub packet_size_entropy:    f32,

    // --- TCP flags (nullable) ---
    pub tcp_syn: Option<u32>,
    pub tcp_rst: Option<u32>,
    pub tcp_fin: Option<u32>,

    // --- DNS context ---
    pub dns_query:  Option<String>,
    pub dns_status: Option<String>,

    // --- HTTP context ---
    pub http_method:      Option<String>,
    pub http_uri:         Option<String>,
    pub http_useragent:   Option<String>,
    pub http_status_code: Option<u16>,

    // --- TLS context ---
    pub tls_ja3:     Option<String>,
    pub tls_ja3s:    Option<String>,
    pub tls_version: Option<String>,
    pub tls_cipher:  Option<String>,

    // --- Certificate context ---
    pub cert_cn:          Option<String>,
    pub cert_issuer_cn:   Option<String>,
    pub cert_self_signed: Option<bool>,
    pub cert_valid_days:  Option<i32>,

    // --- Hostname / SNI ---
    pub hostname: Option<String>,

    // --- GeoIP ---
    pub src_geo_country: Option<String>,
    pub dst_geo_country: Option<String>,
    pub dst_asn_org:     Option<String>,

    // --- Derived ML Features (Network Baseline Pipeline) ---
    /// True if dst_ip is RFC-1918 (10/8, 172.16/12, 192.168/16) or link-local.
    pub is_internal_dst: bool,

    /// Classification of dst_port: "well_known" (0-1023), "registered" (1024-49151),
    /// or "ephemeral" (49152-65535).
    pub port_class: String,
}
