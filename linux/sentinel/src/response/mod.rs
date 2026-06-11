// SOAR response executor (DC-N11).
//
// linux-sentinel is detection + outbound telemetry; this is the response side.
// The platform cannot reach into the host, so Nexus ENQUEUES a signed task and
// this module pulls it OUTBOUND: poll `GET {gateway}/api/v1/tasks` (JWT bearer,
// the same client + auth the parquet transmitter uses), verify the HMAC-SHA256
// signature, select a FIXED bundled playbook by `action_type` (never a path the
// task supplies), run it locally with `NEXUS_*` env, and report the outcome
// outbound. Logic mirror + tests: `test/tier0/sentinel_response_mirror.py`,
// canonical contract: `project_empros/operations/agent/response_executor.py`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::Sha256;
use tracing::{error, info, warn};

type HmacSha256 = Hmac<Sha256>;

/// action_type -> fixed bundled playbook. Mirror of `response_executor`'s linux
/// column; the task selects a script by action, never by path. Drift is pinned
/// by the tier0 parity test.
const LINUX_PLAYBOOK: &[(&str, &str)] = &[
    ("isolate_host", "01_contain_host.sh"),
    ("eradicate_process", "02_eradicate_process.sh"),
    ("eradicate_persistence", "03_eradicate_persistence.sh"),
    ("block_ip", "04_block_c2.sh"),
    ("acquire_artifact", "05_acquire_artifact.sh"),
    ("restore", "06_restore.sh"),
    ("collect_forensics", "00_collect_forensics.sh"),
];

pub fn select_playbook(action_type: &str) -> Option<&'static str> {
    LINUX_PLAYBOOK
        .iter()
        .find(|(a, _)| *a == action_type)
        .map(|(_, pb)| *pb)
}

/// Canonical bytes signed by Nexus: a compact, key-sorted JSON object with the
/// `signature` field removed. Byte-identical to the Python signer's
/// `json.dumps(..., separators=(",",":"), sort_keys=True)` (flat task object).
fn canonical(task: &Map<String, Value>) -> Vec<u8> {
    let sorted: BTreeMap<&String, &Value> =
        task.iter().filter(|(k, _)| k.as_str() != "signature").collect();
    serde_json::to_vec(&sorted).expect("task is serializable")
}

/// Verify the task came from Nexus and was not tampered with on the wire.
pub fn verify_task(task: &Map<String, Value>, secret: &[u8]) -> Result<()> {
    let provided = task
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("response task is unsigned -- refusing to execute"))?;
    let expected = hex::decode(provided).map_err(|_| anyhow!("signature hex decode failed"))?;
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&canonical(task));
    // constant-time compare inside the hmac crate
    mac.verify_slice(&expected)
        .map_err(|_| anyhow!("response task signature invalid -- refusing to execute"))
}

/// Map a verified task to the `NEXUS_*` env the playbooks read. Mirror of
/// `response_executor.build_env`.
pub fn build_env(task: &Map<String, Value>) -> Vec<(String, String)> {
    let join = |v: Option<&Value>| -> String {
        v.and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|x| match x {
                        Value::String(s) => s.clone(),
                        other => other.to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default()
    };
    let incident = task.get("incident_id").and_then(Value::as_str).unwrap_or("");
    let mut env = vec![("NEXUS_INCIDENT_ID".into(), incident.to_string())];
    match task.get("action_type").and_then(Value::as_str).unwrap_or("") {
        "isolate_host" => env.push(("NEXUS_MGMT_IPS".into(), join(task.get("mgmt_ips")))),
        "block_ip" => {
            env.push(("NEXUS_C2_IPS".into(), join(task.get("targets"))));
            env.push(("NEXUS_C2_DOMAINS".into(), join(task.get("c2_domains"))));
        }
        "eradicate_process" => {
            env.push(("NEXUS_MALICIOUS_PIDS".into(), join(task.get("pids"))));
            env.push(("NEXUS_MALICIOUS_PROCESSES".into(), join(task.get("processes"))));
            env.push(("NEXUS_MALICIOUS_HASHES".into(), join(task.get("hashes"))));
        }
        "acquire_artifact" => {
            let p = task.get("file_path").and_then(Value::as_str).unwrap_or("");
            let h = task.get("host").and_then(Value::as_str).unwrap_or("");
            env.push(("NEXUS_TARGET_PATH".into(), p.to_string()));
            env.push(("NEXUS_HOST".into(), h.to_string()));
        }
        _ => {}
    }
    env
}

/// The outcome reported outbound to `nexus.soar.callback`.
#[derive(serde::Serialize)]
pub struct Outcome {
    pub incident_id: String,
    pub host: String,
    pub action_type: String,
    pub playbook: String,
    pub status: String,
}

pub struct ResponseExecutor {
    secret: Vec<u8>,
    playbooks_dir: PathBuf,
}

impl ResponseExecutor {
    pub fn new(secret: impl Into<Vec<u8>>, playbooks_dir: impl Into<PathBuf>) -> Self {
        Self { secret: secret.into(), playbooks_dir: playbooks_dir.into() }
    }

    /// Verify -> pick the FIXED bundled playbook -> run with NEXUS_* env -> outcome.
    /// `runner` runs the script; production passes a real process spawner, tests a stub.
    pub async fn execute<F>(&self, task: &Map<String, Value>, runner: F) -> Result<Outcome>
    where
        F: FnOnce(&Path, &[(String, String)]) -> Result<i32>,
    {
        verify_task(task, &self.secret)?;
        let action = task.get("action_type").and_then(Value::as_str).unwrap_or("");
        let playbook = select_playbook(action)
            .ok_or_else(|| anyhow!("no linux playbook for action {action}"))?;
        let path = self.playbooks_dir.join(playbook);
        if !path.exists() {
            return Err(anyhow!("playbook not bundled on host: {playbook}"));
        }
        let env = build_env(task);
        let code = runner(&path, &env)?;
        let host = task.get("host").and_then(Value::as_str).unwrap_or("").to_string();
        let incident = task.get("incident_id").and_then(Value::as_str).unwrap_or("").to_string();
        let status = if code == 0 { "completed" } else { "failed" };
        if code == 0 {
            info!(%incident, %host, playbook, "response playbook completed");
        } else {
            warn!(%incident, %host, playbook, code, "response playbook failed");
        }
        Ok(Outcome {
            incident_id: incident,
            host,
            action_type: action.to_string(),
            playbook: playbook.to_string(),
            status: status.to_string(),
        })
    }
}

/// Outbound poll loop: pull pending tasks from the ingress, execute, report.
/// Mirrors the parquet transmitter's client/auth and the acquisition agent's poll.
/// Tasks are signed by Nexus; a forged/unsigned one is dropped, never run.
pub async fn run_poller(
    gateway_url: String,
    auth_token: String,
    secret: Vec<u8>,
    playbooks_dir: PathBuf,
    ca_cert_pem: Option<String>,
    poll_interval: std::time::Duration,
) {
    let mut builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(30));
    if let Some(pem) = ca_cert_pem {
        if let Ok(cert) = reqwest::Certificate::from_pem(pem.as_bytes()) {
            builder = builder.add_root_certificate(cert);
        }
    }
    let client = match builder.build() {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "response poller: failed to build HTTP client");
            return;
        }
    };
    let executor = ResponseExecutor::new(secret, playbooks_dir);
    let tasks_url = format!("{}/api/v1/tasks", gateway_url.trim_end_matches('/'));
    let outcome_url = format!("{tasks_url}/outcome");
    info!(url = %tasks_url, "response poller started");

    loop {
        match client.get(&tasks_url).bearer_auth(&auth_token).send().await {
            Ok(resp) if resp.status().is_success() => {
                let body: Value = resp.json().await.unwrap_or_else(|_| serde_json::json!({}));
                if let Some(tasks) = body.get("tasks").and_then(Value::as_array) {
                    for task in tasks {
                        if let Some(map) = task.as_object() {
                            match executor.execute(map, |p, env| spawn_playbook(p, env)).await {
                                Ok(outcome) => {
                                    let _ = client
                                        .post(&outcome_url)
                                        .bearer_auth(&auth_token)
                                        .json(&outcome)
                                        .send()
                                        .await;
                                }
                                Err(e) => warn!(error = %e, "response task rejected/failed"),
                            }
                        }
                    }
                }
            }
            Ok(resp) => warn!(status = %resp.status(), "response poll non-200"),
            Err(e) => warn!(error = %e, "response poll request failed"),
        }
        tokio::time::sleep(poll_interval).await;
    }
}

/// Spawn the bundled playbook as a child process (the production `runner`).
pub fn spawn_playbook(path: &Path, env: &[(String, String)]) -> Result<i32> {
    let status = std::process::Command::new("bash")
        .arg(path)
        .envs(env.iter().cloned())
        .status()
        .map_err(|e| {
            error!(error = %e, "failed to spawn response playbook");
            anyhow!("spawn failed: {e}")
        })?;
    Ok(status.code().unwrap_or(-1))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Cross-language golden vector produced by the canonical Python signer
    // (project_empros/operations/agent/response_executor.sign_task). If the Rust
    // canonicalization or HMAC ever drifts from Python, this fails -- the single
    // executable proof that both sides sign identical bytes.
    const GOLD_SECRET: &[u8] = b"nexus-golden-secret-v1";
    const GOLD_SIG: &str = "a163f7be437bb0996a677cd6bb719019c7949490445f0222591375c1528e5370";

    fn gold_task() -> Map<String, Value> {
        serde_json::from_str(
            r#"{"kind":"response","incident_id":"INC-GOLD","host":"ep-gold",
                "os_family":"linux","action_type":"isolate_host","targets":[],
                "mgmt_ips":["10.0.0.0/24"],"created_at":1700000000}"#,
        )
        .unwrap()
    }

    #[test]
    fn canonical_matches_python_golden() {
        let canon = canonical(&gold_task());
        let expected = r#"{"action_type":"isolate_host","created_at":1700000000,"host":"ep-gold","incident_id":"INC-GOLD","kind":"response","mgmt_ips":["10.0.0.0/24"],"os_family":"linux","targets":[]}"#;
        assert_eq!(String::from_utf8(canon).unwrap(), expected);
    }

    #[test]
    fn verify_accepts_python_signature() {
        let mut t = gold_task();
        t.insert("signature".into(), Value::String(GOLD_SIG.into()));
        verify_task(&t, GOLD_SECRET).expect("Python-signed task must verify in Rust");
    }

    #[test]
    fn verify_rejects_tampered_task() {
        let mut t = gold_task();
        t.insert("signature".into(), Value::String(GOLD_SIG.into()));
        t.insert("targets".into(), serde_json::json!(["attacker-added"]));
        assert!(verify_task(&t, GOLD_SECRET).is_err());
    }

    #[test]
    fn every_action_maps_to_a_playbook() {
        for (action, _) in LINUX_PLAYBOOK {
            assert!(select_playbook(action).is_some());
        }
        assert!(select_playbook("rm_rf_slash").is_none());
    }

    #[tokio::test]
    async fn execute_runs_fixed_playbook_ignoring_injected_path() {
        let dir = std::env::temp_dir().join("nexus_pb_test");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("01_contain_host.sh"), "#!/bin/bash\nexit 0\n").unwrap();
        let mut t = gold_task();
        t.insert("playbook".into(), Value::String("/tmp/pwn.sh".into())); // smuggled
        // re-sign WITH the injected field so it verifies, proving exec still ignores it
        let mut mac = HmacSha256::new_from_slice(GOLD_SECRET).unwrap();
        mac.update(&canonical(&t));
        t.insert("signature".into(), Value::String(hex::encode(mac.finalize().into_bytes())));
        let ex = ResponseExecutor::new(GOLD_SECRET.to_vec(), &dir);
        let ran = std::cell::Cell::new(None);
        let out = ex
            .execute(&t, |p, _env| {
                ran.set(Some(p.to_path_buf()));
                Ok(0)
            })
            .await
            .unwrap();
        assert_eq!(out.playbook, "01_contain_host.sh");
        assert_eq!(ran.into_inner().unwrap(), dir.join("01_contain_host.sh"));
    }
}
