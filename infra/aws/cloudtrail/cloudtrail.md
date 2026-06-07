### Infrastructure State: DynamoDB Identity Enrichment

CloudTrail events contain raw AWS Identity and Access Management (IAM) ARNs. To make this actionable for the UEBA engine, we must enrich these events with organizational context.

* **Table Name:** `nexus_cloud_identity_metadata`
* **Primary Key:** `iam_arn` (String)

| Attribute Name | Type | Description / Purpose | Example Value |
| --- | --- | --- | --- |
| **`iam_arn`** *(PK)* | `String` | Unique AWS Identity ARN | `"arn:aws:iam::123456789012:role/DevOps"` |
| `account_id` | `String` | AWS Account ownership identifier | `"123456789012"` |
| `owner_team` | `String` | Internal team responsible for the identity | `"cloud-infra-ops"` |
| `privilege_level` | `String` | Risk classification | `"high-privileged"` |
| `is_service_account` | `Boolean` | Differentiates human vs. machine roles | `true` |

---

### Comprehensive End-to-End Lifecycle

```text
[ AWS Control Plane ] --(API Call)--> [ CloudTrail Org Trail ]
                                             │
                                   (Log File Generated: .json.gz)
                                             ▼
[ Centralized S3 Bucket ] --(ObjectCreated)--> [ SQS Queue ]
                                                   │
                                          (KEDA Triggers Scale)
                                                   ▼
                                         [ EKS Rust ETL Pod ]
                                                   │
                                     ┌-------------┴-------------┐
                                     ▼                           ▼
                     [ Fetch S3 JSON.GZ ]              [ Query DynamoDB ]
                                     │                           │
                                     └-------------┬-------------┘
                                                   ▼
                                        [ Schema Transformation ]
                                                   │
                                        [ Local Spool & Stamp ]
                                                   │
                                                   ▼
                                         [ Axum Gateway (HTTPS) ]

```

#### Phase 1: Automated Extraction (Organization-Wide Configuration)

Unlike VPC Flow Logs, which require per-VPC enablement, CloudTrail is best managed at the AWS Organizations level.

1. **Organizational Trail:** A single CloudTrail is deployed at the AWS Organizations management account level. This guarantees that all member accounts (current and future) inherently log all control plane activity without requiring dynamic stack deployments.
2. **Telemetry Landing:** CloudTrail delivers logs to a centralized S3 Bucket in `.json.gz` format, typically in 5-minute batch intervals.
3. **Queue Mechanism:** S3 Event Notifications push `s3:ObjectCreated:*` events to a KMS-encrypted SQS queue, allowing the event-driven Rust pods to scale dynamically via KEDA.

#### Phase 2: High-Performance Ingestion & Decompression

1. **Queue Draining:** The Rust microservice polls the SQS queue, fetching up to 10 messages simultaneously to maximize network throughput.
2. **In-Memory Decompression:** Because CloudTrail logs are gzipped JSON, the Rust worker streams the S3 object through an asynchronous gzip decoder (`async-compression` crate) directly into a highly efficient JSON parser (`serde_json`), avoiding intermediate disk writes.

#### Phase 3: Schema Transformation & Behavioral Mapping

CloudTrail lacks network 5-tuple data, so the ETL layer must carefully map API contexts to the `UnifiedFlowRecord` schema so the Nexus ML engine can process it without structural faults.

1. **Identity & Action Synthesizing:**
* **`process_name`**: Populated with the exact AWS API action (`eventName`), such as `CreateSnapshot` or `AuthorizeSecurityGroupIngress`.
* **`process_hash`**: Populated with the `userIdentity.arn`. This is critical: it maps the AWS IAM identity into the UEBA process hash logic, allowing Nexus to baseline specific user behavior over time.
* **`dst_ip`**: Populated with the `sourceIPAddress` of the API caller.
* **`sensor_id`**: Composite of `accountId` and `awsRegion`.


2. **Temporal & Volumetric Calculations:**
* **`interval` / `cv**`: Computed using a `DashMap` cache, tracking the time delta between API calls grouped by the `userIdentity.arn` + `sourceIPAddress` key. This allows the system to detect automated API enumeration or programmatic data exfiltration.
* **`packet_size_mean`**: Defaulted to `1.0` (representing one discrete API transaction).


3. **Risk Attribution (MITRE Tactic Mapping):**
* The transformer includes a static mapping layer. For example, if `eventName` equals `StopLogging` (CloudTrail tampering), the `mitre_tactic` is immediately elevated to `Defense_Evasion` and an initial baseline score penalty is applied.



#### Phase 4: Cryptographic Load & Transmission


1. **Local Buffering:** The synthesized API flow records are serialized into the standard JSON/Parquet structure and buffered in the ephemeral `/app/data/spool` volume.
2. **Cryptographic Lineage:** The `LineageStamper` logic applies the `X-Batch-Sequence` and `X-Batch-HMAC` cryptographic signatures using the cluster's secret key.
3. **Delivery & Acknowledgment:** The payload is POSTed to the Axum gateway. A successful `HTTP 200` triggers the deletion of the local spool and the SQS receipt handle.