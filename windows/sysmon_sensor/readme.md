### Sysmon adapter for extended detection on windows endpoints

```text
Windows endpoint
  └─ Sysmon (sysmon_config.xml)
       └─ SysmonSensor.py (reads Win Event Log)
            └─ parquet_shipper.py (HMAC-signed Parquet batch)
                 └─ middleware :8443
                      └─ NATS nexus.sysmon_sensor.telemetry
                           ├─ worker_qdrant     → Qdrant windows_math vector
                           ├─ worker_s3_archive → s3://nexus-cold-storage/telemetry/sysmon_sensor/dt=.../hour=.../
                           └─ worker_elastic    → Elasticsearch nexus-endpoint index
                                                           ↓
                                            01_spool_datasets.py Track 7
                                                           ↓
                                                 sysmon_sft_v1.jsonl
                                                           ↓
                                                 02_train_sft_cot.py
```