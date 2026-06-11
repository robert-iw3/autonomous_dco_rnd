// Agent-task emission (DC-N11) -- the Nexus-side signer for outbound-only hosts.
//
// Rust port of `operations/agent/task_dispatch.build_response_task` +
// `response_executor.sign_task`. worker_soar cannot reach into the host, so it
// SIGNS a response task; the on-host agent (linux/sentinel, windows DeepXDR)
// polls it, verifies the same HMAC, and runs the matching bundled playbook.
// The embedded golden test pins byte-identical signing against the Python signer.

use std::collections::BTreeMap;

use hmac::{Hmac, Mac};
use serde_json::{json, Map, Value};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Host response actions that map to a fixed playbook on the agent. Mirror of
/// `task_dispatch.RESPONSE_ACTIONS`.
pub const RESPONSE_ACTIONS: &[&str] = &[
    "isolate_host",
    "block_ip",
    "eradicate_process",
    "eradicate_persistence",
    "restore",
    "collect_forensics",
];

pub fn is_response_action(action: &str) -> bool {
    RESPONSE_ACTIONS.contains(&action)
}

/// Compact, key-sorted JSON with `signature` removed -- byte-identical to the
/// Python signer's `json.dumps(..., separators=(",",":"), sort_keys=True)`.
fn canonical(task: &Map<String, Value>) -> Vec<u8> {
    let sorted: BTreeMap<&String, &Value> =
        task.iter().filter(|(k, _)| k.as_str() != "signature").collect();
    serde_json::to_vec(&sorted).expect("task is serializable")
}

pub fn sign(task: &Map<String, Value>, secret: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&canonical(task));
    hex::encode(mac.finalize().into_bytes())
}

/// Build a signed response task the on-host agent will verify and execute.
pub fn build_signed_task(
    incident_id: &str,
    host: &str,
    os_family: &str,
    action_type: &str,
    targets: &[String],
    created_at: i64,
    secret: &[u8],
) -> Value {
    let mut t = Map::new();
    t.insert("kind".into(), json!("response"));
    t.insert("incident_id".into(), json!(incident_id));
    t.insert("host".into(), json!(host));
    t.insert("os_family".into(), json!(os_family));
    t.insert("action_type".into(), json!(action_type));
    t.insert("targets".into(), json!(targets));
    t.insert("created_at".into(), json!(created_at));
    let sig = sign(&t, secret);
    t.insert("signature".into(), json!(sig));
    Value::Object(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden vector from the canonical Python signer (response_executor.sign_task).
    const GOLD_SECRET: &[u8] = b"nexus-golden-secret-v1";
    const GOLD_SIG: &str = "a163f7be437bb0996a677cd6bb719019c7949490445f0222591375c1528e5370";

    #[test]
    fn signing_matches_python_golden() {
        // same fields/order-independent content as the Python golden task
        let mut t = Map::new();
        t.insert("kind".into(), json!("response"));
        t.insert("incident_id".into(), json!("INC-GOLD"));
        t.insert("host".into(), json!("ep-gold"));
        t.insert("os_family".into(), json!("linux"));
        t.insert("action_type".into(), json!("isolate_host"));
        t.insert("targets".into(), json!([] as [String; 0]));
        t.insert("mgmt_ips".into(), json!(["10.0.0.0/24"]));
        t.insert("created_at".into(), json!(1_700_000_000));
        assert_eq!(sign(&t, GOLD_SECRET), GOLD_SIG);
    }

    #[test]
    fn built_task_is_signed_and_verifiable() {
        let task = build_signed_task(
            "INC-1", "ep-1", "linux", "isolate_host", &["10.0.0.5".into()], 1_700_000_000, GOLD_SECRET,
        );
        let obj = task.as_object().unwrap();
        let provided = obj.get("signature").unwrap().as_str().unwrap();
        assert_eq!(provided, sign(obj, GOLD_SECRET)); // signature covers the task
    }

    #[test]
    fn only_response_actions_recognised() {
        assert!(is_response_action("isolate_host"));
        assert!(!is_response_action("rm_rf_slash"));
    }
}
