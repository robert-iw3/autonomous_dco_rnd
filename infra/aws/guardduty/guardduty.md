### Infrastructure State: Unified Context Enrichment

GuardDuty findings span multiple resource types (EC2 instances, IAM users, S3 buckets, Kubernetes clusters). Instead of creating a new DynamoDB table, this connector will intelligently route queries to the existing metadata stores we established in the previous phases.

* **EC2/VPC Findings:** Queries `nexus_cloud_infrastructure_metadata` using the VPC ID or Instance ID.
* **IAM/User Findings:** Queries `nexus_cloud_identity_metadata` using the associated IAM ARN.

---

### Comprehensive End-to-End Lifecycle

#### Phase 1: Automated Extraction (Native S3 Export)

While GuardDuty integrates with EventBridge, utilizing its native S3 Export feature ensures absolute architectural consistency with your VPC and CloudTrail connectors.

1. **Organizational Delegation:** GuardDuty is enabled via AWS Organizations, designating a central security account as the delegated administrator to aggregate findings across the entire AWS footprint.
2. **Native S3 Export:** The delegated administrator account configures an active S3 Export. GuardDuty automatically writes active findings to an encrypted S3 bucket (in JSON Lines format) on a strict 5-minute delivery frequency.
3. **Event Notification:** S3 `ObjectCreated` events are pushed to an SQS queue, providing the same highly durable, event-driven trigger for the ETL pipeline.

#### Phase 2: High-Performance Ingestion

1. **Queue Draining:** The Kubernetes Event-driven Autoscaler (KEDA) monitors the SQS queue and provisions the Rust ETL pods.
2. **Retrieval & Parsing:** The Rust microservice pulls the SQS message, retrieves the KMS-encrypted `.jsonl.gz` (or `.jsonl`) file from S3, and streams it natively into memory using `async-compression` and `serde_json`, iterating through each discrete finding.

#### Phase 3: Schema Transformation & Correlation Mapping

This is the most critical phase. The ETL layer must map a JSON alert into a flow-based behavioral model.

1. **Identity & Structural Mapping:**
* **`process_name`**: Populated with the exact GuardDuty Threat Purpose and Resource Type (e.g., `UnauthorizedAccess:EC2/SSHBruteForce`).
* **`process_hash`**: Populated with the compromised resource's unique identifier (e.g., `i-0abcd1234efgh5678` or `arn:aws:iam::...`).
* **`sensor_id`**: Composite of the AWS Account ID, Region, and the enriched environment tag pulled from DynamoDB.


2. **Scoring Translation (The Key Differentiator):**
* **`score`**: GuardDuty utilizes a severity scale from 0.1 to 10.0. The transformer will multiply this by 10 to map perfectly to the Nexus 0-100 `score` column (e.g., a GuardDuty severity of 8.5 becomes a Nexus score of 85).


3. **Temporal Nullification:**
* **`interval` / `cv**`: Hardcoded to `0.0`. These are discrete alerts, not temporal flows.
* **`packet_size_mean`**: Hardcoded to `1.0`.


4. **MITRE Tactic Alignment:**
* **`mitre_tactic`**: GuardDuty natively maps findings to MITRE ATT&CK tactics in its finding type schema (e.g., `Execution`, `PrivilegeEscalation`, `Exfiltration`). The transformer parses the prefix of the finding type to populate this field accurately.
* **`description` / `reasons**`: The GuardDuty `title` and `description` fields are packed into the `reasons` JSON array to provide the Nexus dashboard with explicit context.



#### Phase 4: Cryptographic Load & Transmission

1. **Local Buffering:** The translated findings are written to the ephemeral `/app/data/spool` directory.
2. **Cryptographic Lineage:** The payload is wrapped with the `X-Batch-Sequence` and `X-Batch-HMAC` signatures using the cluster's secret key.
3. **Transmission:** The HTTPS POST is delivered to the Axum gateway. A successful acknowledgment results in the deletion of the local spool file and the SQS receipt handle.