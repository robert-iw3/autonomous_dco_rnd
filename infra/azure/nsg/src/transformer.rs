use crate::cache::TemporalCache;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UnifiedFlowRecord {
    pub timestamp: f64,
    pub process_name: String,
    pub dst_ip: String,
    pub dst_port: i32,
    pub interval: f64,
    pub cv: f64,
    pub outbound_ratio: f64,
    pub entropy: f64,
    pub packet_size_mean: f64,
    pub packet_size_std: f64,
    pub packet_size_min: i32,
    pub packet_size_max: i32,
    pub packet_count: i64,
    pub mitre_tactic: String,
    pub cmd_entropy: f64,
    pub suppressed: i32,
    pub score: i32,
    pub cmd_snippet: String,
    pub process_tree: String,
    pub masquerade_detected: i32,
    pub reasons: String,
    pub mitre_technique: String,
    pub mitre_name: String,
    pub description: String,
    pub ml_result: Option<String>,
    pub process_hash: String,
    pub dns_query: String,
    pub event_type: String,
    pub dns_flags: i32,
    pub ja3_hash: String,
    pub sensor_id: String,
}

pub struct Transformer {
    cache: TemporalCache,
}

impl Transformer {
    pub fn new(cache: TemporalCache) -> Self {
        Self { cache }
    }

    /// Parse an entire NSG flow log blob into UnifiedFlowRecords.
    /// NSG v2 format: records[].properties.flows[].flows[].flowTuples[]
    /// Tuple: "ts,src_ip,dst_ip,src_port,dst_port,proto,dir,action,state,pkts_s,bytes_s,pkts_d,bytes_d"
    pub fn transform_blob(
        &self,
        blob_json: &serde_json::Value,
        metadata: &HashMap<String, String>,
    ) -> Vec<UnifiedFlowRecord> {
        let mut results = Vec::new();

        let records = match blob_json.get("records").and_then(|r| r.as_array()) {
            Some(r) => r,
            None => return results,
        };

        for record in records {
            // Extract NSG resource ID as the network interface identity
            let resource_id = record
                .get("resourceId")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown_nsg");
            // Use the NSG name as the process_name equivalent
            let nsg_name = resource_id.rsplit('/').next().unwrap_or("unknown_nsg");

            let subscription_id = metadata.get("subscription_id").cloned().unwrap_or_default();
            let environment = metadata.get("environment").cloned().unwrap_or_else(|| "unknown".to_string());
            let region = metadata.get("region").cloned().unwrap_or_else(|| "unknown".to_string());

            let flows = match record.pointer("/properties/flows").and_then(|f| f.as_array()) {
                Some(f) => f,
                None => continue,
            };

            for rule_group in flows {
                let rule_name = rule_group.get("rule").and_then(|r| r.as_str()).unwrap_or("unknown_rule");
                let inner_flows = match rule_group.get("flows").and_then(|f| f.as_array()) {
                    Some(f) => f,
                    None => continue,
                };

                for mac_group in inner_flows {
                    let mac = mac_group.get("mac").and_then(|m| m.as_str()).unwrap_or("");
                    let tuples = match mac_group.get("flowTuples").and_then(|t| t.as_array()) {
                        Some(t) => t,
                        None => continue,
                    };

                    for tuple_val in tuples {
                        let tuple_str = match tuple_val.as_str() {
                            Some(s) => s,
                            None => continue,
                        };

                        if let Some(rec) = self.parse_flow_tuple(
                            tuple_str, nsg_name, mac, rule_name,
                            &subscription_id, &environment, &region,
                        ) {
                            results.push(rec);
                        }
                    }
                }
            }
        }

        results
    }

    fn parse_flow_tuple(
        &self,
        tuple: &str,
        nsg_name: &str,
        mac: &str,
        rule_name: &str,
        subscription_id: &str,
        environment: &str,
        region: &str,
    ) -> Option<UnifiedFlowRecord> {
        let parts: Vec<&str> = tuple.split(',').collect();
        if parts.len() < 8 {
            return None;
        }

        let ts: f64 = parts[0].parse().unwrap_or(0.0);
        let src_ip = parts[1].to_string();
        let dst_ip = parts[2].to_string();
        let _src_port: i32 = parts[3].parse().unwrap_or(0);
        let dst_port: i32 = parts[4].parse().unwrap_or(0);
        let _protocol = parts[5]; // T=TCP, U=UDP
        let direction = parts[6]; // I=inbound, O=outbound
        let action = parts[7];    // A=allowed, D=denied

        // NSG v2 extended fields (packets/bytes)
        let (pkts_src, bytes_src, pkts_dst, bytes_dst) = if parts.len() >= 13 {
            (
                parts[9].parse::<i64>().unwrap_or(0),
                parts[10].parse::<f64>().unwrap_or(0.0),
                parts[11].parse::<i64>().unwrap_or(0),
                parts[12].parse::<f64>().unwrap_or(0.0),
            )
        } else {
            (1, 0.0, 0, 0.0)
        };

        let total_packets = pkts_src + pkts_dst;
        let total_bytes = bytes_src + bytes_dst;
        let packet_size_mean = if total_packets > 0 { total_bytes / total_packets as f64 } else { 0.0 };

        let outbound_ratio = if direction == "O" { 1.0 } else { 0.0 };

        // Temporal state per NIC→destination
        let state_key = format!("{}|{}|{}", mac, nsg_name, dst_ip);
        let interval = self.cache.calculate_interval(&state_key, ts);

        let sensor_id = format!("{}|{}|{}", subscription_id, environment, region);

        let (score, mitre_tactic) = if action == "D" {
            (25, "Network_Deny".to_string())
        } else {
            (0, "Cloud_Network_Flow".to_string())
        };

        Some(UnifiedFlowRecord {
            timestamp: ts,
            process_name: format!("{}|{}", nsg_name, rule_name),
            dst_ip,
            dst_port,
            interval,
            cv: 0.0,
            outbound_ratio,
            entropy: 0.0,
            packet_size_mean,
            packet_size_std: 0.0,
            packet_size_min: 0,
            packet_size_max: 0,
            packet_count: total_packets,
            mitre_tactic,
            cmd_entropy: 0.0,
            suppressed: 0,
            score,
            cmd_snippet: String::new(),
            process_tree: String::new(),
            masquerade_detected: 0,
            reasons: "[]".to_string(),
            mitre_technique: String::new(),
            mitre_name: String::new(),
            description: String::new(),
            ml_result: None,
            process_hash: String::new(),
            dns_query: String::new(),
            event_type: "nsg_flow".to_string(),
            dns_flags: 0,
            ja3_hash: String::new(),
            sensor_id,
        })
    }
}
