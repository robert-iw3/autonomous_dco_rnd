# corpus_testing/ -- Pre-Production Corpus Staging Area

Place new corpus JSONL files here to validate them before promoting to production MLOps.
The eval runner discovers all JSONL files automatically -- no configuration needed.

## Structure (mirrors adversarial_corpus_templates)

```
corpus_testing/
├── 1_Recon/
├── 2_Persistence/
├── 3_C2/
├── 4_Bypass_Detection/
├── 5_Lateral_Movement/
├── 6_LOTL/
│   └── BinaryProxyMshta.jsonl   ← example: 3 records (2 TP + 1 FP)
├── 6_Malware_Tradecraft/
├── 7_Exfiltration/
├── Active-Directory/
├── Windows_Exploitation/
└── Linux_Exploitation/
```

## Record format

```json
{
  "ttp_category": "LOTL",
  "tool_class":   "BinaryProxyMshta",
  "mitre_techniques": ["T1218.005"],
  "source_type":  "sysmon_sensor",
  "vector_name":  "windows_math",
  "classification": "true_positive",
  "messages": [
    {"role": "system",    "content": "You are the Host Forensics Expert..."},
    {"role": "user",      "content": "Spatial Anomaly Detected...<|spatial_vector|>..."},
    {"role": "assistant", "content": "<analysis>[AXIS 1]...[CONCLUSION]...TRUE POSITIVE..."}
  ],
  "event_id": "abc123"
}
```

## Run the eval

```bash
cd tests/eval_minilab
podman-compose up          # or: docker compose up
```

After completion, find the report in `reports/corpus_gate_<timestamp>.json`

Exit 0 = PROMOTED | Exit 1 = NEEDS REVISION
