use crate::config::ExtractionConfig;
use crate::models::{ArkimeSpi, NetworkFlowRecord};
use metrics::counter;

const MAX_STR_LEN: usize = 4096;

#[inline]
fn truncate(s: String) -> String {
    if s.len() <= MAX_STR_LEN { s } else { s[..MAX_STR_LEN].to_string() }
}

#[inline]
fn first_str(v: &Option<Vec<String>>) -> Option<String> {
    v.as_ref().and_then(|a| a.first().cloned()).map(truncate)
}

#[inline]
fn protocol_name(pr: u8) -> &'static str {
    match pr {
        1  => "icmp",
        6  => "tcp",
        17 => "udp",
        47 => "gre",
        50 => "esp",
        58 => "icmpv6",
        _  => "other",
    }
}

/// Returns `false` for non-IPv4 strings.
#[inline]
fn is_internal_ip(ip: &str) -> bool {
    let first_dot = match ip.find('.') {
        Some(i) => i,
        None => return false,
    };
    let first_octet: u8 = match ip[..first_dot].parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    match first_octet {
        10  => true,
        127 => true,
        192 => ip.starts_with("192.168."),
        169 => ip.starts_with("169.254."),
        172 => {
            let rest = &ip[first_dot + 1..];
            if let Some(second_dot) = rest.find('.') {
                if let Ok(second) = rest[..second_dot].parse::<u8>() {
                    return (16..=31).contains(&second);
                }
            }
            false
        }
        _ => false,
    }
}

#[inline]
fn port_class(port: u16) -> &'static str {
    match port {
        0..=1023  => "well_known",
        1024..=49151 => "registered",
        _         => "ephemeral",
    }
}

/// Returns `None` if timestamps are invalid (negative or end before start).
#[inline]
pub fn extract(spi: &ArkimeSpi, cfg: &ExtractionConfig) -> Option<NetworkFlowRecord> {
    if spi.fp < 0 || spi.lp < 0 {
        counter!("gateway.sessions_invalid_timestamp").increment(1);
        return None;
    }

    let ts_start = spi.fp as u64;
    let ts_end   = spi.lp as u64;
    let session_duration_ms = ts_end.saturating_sub(ts_start);

    let (avg_ia, var_ia) = match spi.pa.as_ref() {
        Some(arr) if !arr.is_empty() => {
            let n = arr.len() as f32;
            let sum: u32 = arr.iter().sum();
            let mean = sum as f32 / n;
            let var = if arr.len() > 1 {
                arr.iter()
                    .map(|&v| { let d = v as f32 - mean; d * d })
                    .sum::<f32>()
                    / (n - 1.0)
            } else {
                0.0
            };
            (mean, var)
        }
        _ => (0.0, 0.0),
    };

    let (ratio_small, ratio_large) = match spi.ps.as_ref() {
        Some(sizes) if !sizes.is_empty() => {
            let total = sizes.len() as f32;
            let s = sizes.iter().filter(|&&v| v < cfg.small_packet_bytes).count() as f32;
            let l = sizes.iter().filter(|&&v| v > cfg.large_packet_bytes).count() as f32;
            (s / total, l / total)
        }
        _ => (0.0, 0.0),
    };

    // Shannon entropy of the packet-size distribution (proxy for payload randomness)
    let packet_size_entropy = match spi.ps.as_ref() {
        Some(sizes) if sizes.len() > 1 => {
            let total: f64 = sizes.iter().map(|&s| s as f64).sum();
            if total > 0.0 {
                sizes.iter()
                    .filter(|&&s| s > 0)
                    .map(|&s| { let p = s as f64 / total; -p * p.ln() })
                    .sum::<f64>() as f32
            } else {
                0.0
            }
        }
        _ => 0.0,
    };

    let byte_total = (spi.by1 + spi.by2) as f32;
    let byte_ratio = if byte_total > 0.0 { spi.by1 as f32 / byte_total } else { 0.0 };

    let tcp_syn = spi.tcpflags.as_ref().and_then(|t| t.syn);
    let tcp_rst = spi.tcpflags.as_ref().and_then(|t| t.rst);
    let tcp_fin = spi.tcpflags.as_ref().and_then(|t| t.fin);

    let dns_query = spi.dns.as_ref().and_then(|d| first_str(&d.host));
    let dns_status = spi.dns.as_ref().and_then(|d| first_str(&d.status));

    let http_method = spi.http.as_ref().and_then(|h| first_str(&h.method));
    let http_uri = spi.http.as_ref().and_then(|h| first_str(&h.uri));
    let http_useragent = spi.http.as_ref().and_then(|h| first_str(&h.useragent));
    let http_status_code = spi.http.as_ref()
        .and_then(|h| h.statuscode.as_ref())
        .and_then(|v| v.first().copied());

    let tls_ja3 = spi.tls.as_ref().and_then(|t| first_str(&t.ja3));
    let tls_ja3s = spi.tls.as_ref().and_then(|t| first_str(&t.ja3s));
    let tls_version = spi.tls.as_ref().and_then(|t| first_str(&t.version));
    let tls_cipher = spi.tls.as_ref().and_then(|t| first_str(&t.cipher));

    let cert_cn = spi.cert.as_ref().and_then(|c| first_str(&c.cn));
    let cert_issuer_cn = spi.cert.as_ref().and_then(|c| first_str(&c.issuer_cn));
    let cert_self_signed = spi.cert.as_ref()
        .and_then(|c| c.self_signed.as_ref())
        .and_then(|v| v.first().copied());
    let cert_valid_days  = spi.cert.as_ref()
        .and_then(|c| c.valid_days.as_ref())
        .and_then(|v| v.first().copied());

    Some(NetworkFlowRecord {
        session_id:    spi.id.to_string(),
        src_ip:        spi.a1.to_string(),
        dst_ip:        spi.a2.to_string(),
        src_port:      spi.p1,
        dst_port:      spi.p2,
        protocol:      spi.pr,
        protocol_name: protocol_name(spi.pr).to_string(),

        timestamp_start:    ts_start,
        timestamp_end:      ts_end,
        session_duration_ms,

        bytes_src:      spi.by1,
        bytes_dst:      spi.by2,
        data_bytes_src: spi.db1,
        data_bytes_dst: spi.db2,
        packets_src:    spi.pa1,
        packets_dst:    spi.pa2,

        byte_ratio,
        avg_inter_arrival:     avg_ia,
        variance_inter_arrival: var_ia,
        ratio_small_packets:   ratio_small,
        ratio_large_packets:   ratio_large,
        packet_size_entropy,

        tcp_syn,
        tcp_rst,
        tcp_fin,

        dns_query,
        dns_status,

        http_method,
        http_uri,
        http_useragent,
        http_status_code,

        tls_ja3,
        tls_ja3s,
        tls_version,
        tls_cipher,

        cert_cn,
        cert_issuer_cn,
        cert_self_signed,
        cert_valid_days,

        hostname: first_str(&spi.hostname),

        src_geo_country: spi.g1.clone().map(truncate),
        dst_geo_country: spi.g2.clone().map(truncate),
        dst_asn_org:     spi.as2_org.clone().map(truncate),

        is_internal_dst: is_internal_ip(spi.a2),
        port_class:      port_class(spi.p2).to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_internal_ip() {
        assert!(is_internal_ip("10.0.0.1"));
        assert!(is_internal_ip("10.255.255.255"));
        assert!(is_internal_ip("172.16.0.1"));
        assert!(is_internal_ip("172.31.255.255"));
        assert!(is_internal_ip("192.168.1.1"));
        assert!(is_internal_ip("169.254.0.1"));
        assert!(is_internal_ip("127.0.0.1"));

        assert!(!is_internal_ip("172.15.0.1"));
        assert!(!is_internal_ip("172.32.0.1"));
        assert!(!is_internal_ip("8.8.8.8"));
        assert!(!is_internal_ip("185.10.68.22"));
        assert!(!is_internal_ip("192.167.1.1"));
    }

    #[test]
    fn test_port_class() {
        assert_eq!(port_class(80),    "well_known");
        assert_eq!(port_class(443),   "well_known");
        assert_eq!(port_class(1023),  "well_known");
        assert_eq!(port_class(1024),  "registered");
        assert_eq!(port_class(8443),  "registered");
        assert_eq!(port_class(49151), "registered");
        assert_eq!(port_class(49152), "ephemeral");
        assert_eq!(port_class(65535), "ephemeral");
    }
}
