## End-to-End AWS VPC Flow Logs Integration Plan

---

### Infrastructure State: DynamoDB Metadata Schema

To ensure every flow record is enriched with environment context, tags, and ownership details, a centralized metadata store is established. This data allows the transformation layer to anchor anonymous network flows to structural organizational units.

* **Table Name:** `nexus_cloud_infrastructure_metadata`
* **Primary Key:** `vpc_id` (String)

| Attribute Name | Type | Description / Purpose | Example Value |
| --- | --- | --- | --- |
| **`vpc_id`** *(PK)* | `String` | Unique AWS VPC Identifier | `"vpc-0a1b2c3d4e5f6g7h8"` |
| `account_id` | `String` | AWS Account ownership identifier | `"123456789012"` |
| `region` | `String` | AWS Region hosting the infrastructure | `"us-east-1"` |
| `environment` | `String` | Deployment stage classification | `"production"` |
| `owner_team` | `String` | Internal team responsible for the asset | `"cloud-infra-ops"` |
| `cidr_block` | `String` | Supernet bound allocation | `"10.0.0.0/16"` |
| `tags` | `Map` | Key-value store of all positive identifier tags | `{"Project": "Nexus", "CostCenter": "9940"}` |

---

### Comprehensive End-to-End Lifecycle

```
[ AWS Infrastructure ] --(CreateVpc)--> [ EventBridge ] --> [ Lambda ] --> [ Register DynamoDB ]
         │
  (Flow Logs Generated)
         ▼
[ Centralized S3 Bucket ] --(ObjectCreated)--> [ SQS Queue ]
                                                   │
                                          (KEDA Triggers Scale)
                                                   ▼
                                         [ EKS Rust ETL Pod ]
                                                   │
                                     ┌-------------┴-------------┐
                                     ▼                           ▼
                        [ Fetch S3 Parquet ]           [ Query DynamoDB ]
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

#### Phase 1: Automated Discovery & Provisioning

1. **Infrastructure Trigger:** An engineer or CI/CD pipeline deploys a new VPC. AWS CloudTrail records the `CreateVpc` API call.
2. **Event Dispatch:** An AWS EventBridge rule detects the creation event and invokes a cross-account orchestration Lambda function.
3. **Automated Enablement:** The Lambda function verifies the VPC settings, deploys a pre-configured CloudFormation StackSet to activate VPC Flow Logs, and points the destination output directly to a centralized S3 ingestion bucket using native AWS Parquet formatting.
4. **State Inventory Registration:** The Lambda function queries the live tags on the new VPC resource and registers a new record containing all metadata, environment tags, and ownership descriptors inside the DynamoDB metadata table.

#### Phase 2: Event-Driven Ingestion & Extraction

1. **Telemetry Landing:** Cloud network interfaces write aggregated flow chunks down to the centralized S3 bucket using Hive-compatible partitioning paths (`/account_id/region/year/month/...`).
2. **Notification Event:** S3 fires an `ObjectCreated` notification immediately upon a successful object write, dropping the file metadata pointer into an Amazon SQS tracking queue.
3. **Dynamic Scaling Elasticity:** A Kubernetes Event-driven Autoscaler (**KEDA**) controller running inside the EKS cluster continuously monitors the length of the SQS tracking queue. If the queue length peaks, KEDA scales up the number of specialized Rust ETL pods; when the queue empties, it scales the deployment down to zero pods to eliminate idle resource expenditures.
4. **Queue Draining Engine:** An active Rust pod polls SQS, locks the message visibility window, extracts the target S3 URI path, and downloads the raw AWS Parquet data byte-stream straight into memory.

#### Phase 3: Schema Transformation & Enrichment

1. **Metadata Query Execution:** The Rust service extracts the `vpc_id` out of the S3 file path and references its local cache. If missing from the cache, it performs a `BatchGetItem` query against the DynamoDB tracking table to fetch the environment context (`environment`, `region`, `tags`).
2. **Identity Synthesizing & Alignment:** The ETL application maps the AWS fields to match your core system structure without dropping operational telemetry:
* **`process_name`**: Populated with the Elastic Network Interface ID (`eni-xxxxxxxx`).


* **`sensor_id`**: Formatted as a positive identification composite string containing organizational metadata (`vpc_id|environment|region`).
* **`pid` / `uid**`: Hardcoded to specialized cloud reserved ranges (`0xFFFFFFFF`) to separate host executions from network fabrics.




3. **Volumetric & Feature Calculations:**
* **`packet_size_mean`**: Calculated directly by dividing the raw record `bytes` by the `packets` count.


* **`interval` / `cv**`: Computed by running an in-memory concurrent map (`dashmap`) that monitors the time delta between consecutive `ENI -> Destination IP` conversation pairs.




4. **Feature Nullification:** Host-tied data blocks (`entropy`, `cmd_entropy`, `ja3_hash`, `process_hash`) are padded with default empty values, preventing parsing faults inside the core behavioral analytics layer.



#### Phase 4: Cryptographic Load & Transmission

1. **Local Buffering:** The transformed cloud network events are serialized into the standard system Parquet structure and dumped into an ephemeral workspace storage path (`/app/data/spool`).


2. **Cryptographic Lineage Stamping:** The service wraps the file bytes with a compiled port of the `LineageStamper` engine, tracking sequence indices via state and executing an HMAC-SHA256 signature using the active infrastructure cluster key.


3. **Axum Gateway Delivery:** The microservice executes an HTTPS POST containing the payload alongside the validation headers (`X-Batch-Sequence`, `X-Batch-HMAC`) targeting the Axum routing edge.


4. **Transaction Acknowledgment:** Once the Axum gateway responds with an HTTP `200/202 OK` status code, the local spool file is wiped, and the original SQS receipt message is deleted from the queue, concluding the data lifecycle safely.