### AWS (Amazon Web Services)

AWS provides robust, native logging that can be routed to Amazon SQS or SNS, which a Rust or C# forwarder can poll and push into Nexus.

* **VPC Flow Logs:** The closest cloud equivalent to your network telemetry. They capture IP traffic going to and from network interfaces in the VPC. This maps directly to the flow metrics (destination IPs, bytes transferred, intervals) used by the ML engine.
* **AWS CloudTrail:** The definitive source for Control Plane telemetry. It records API calls across the account. This is essential for detecting infrastructure manipulation, such as unauthorized snapshot creation (exfiltration) or security group modification.
* **Amazon GuardDuty:** A managed threat detection service. Ingesting GuardDuty findings provides high-fidelity alerts that can be correlated with your raw flow data to adjust anomaly scoring.

### Microsoft Azure

Azure's architecture heavily utilizes Azure Event Hubs, which is a high-throughput streaming platform that acts similarly to NATS JetStream, making integration relatively straightforward.

* **NSG (Network Security Group) Flow Logs:** Similar to AWS VPC Flow Logs, these provide 5-tuple information about ingress and egress IP traffic.
* **Azure Activity Logs:** Captures subscription-level events, including resource creation, modification, and role assignments (Control Plane).
* **Microsoft Entra ID (formerly Azure AD) Logs:** Critical for UEBA correlation. Captures sign-ins, audit events, and anomalous identity behavior across the enterprise.

### GCP (Google Cloud Platform)

Google Cloud uses Pub/Sub for messaging, which is highly performant and easy to hook into an external ingestion pipeline.

* **VPC Flow Logs:** GCP’s flow logs are natively sampled and provide excellent visibility into network throughput and latency, which can be fed directly into the isolation forest models for exfiltration detection.
* **Cloud Audit Logs:** Covers Admin Activity, Data Access, and System Events. This provides the "who did what, where, and when" for GCP resources.
* **Security Command Center (SCC):** Aggregates vulnerabilities and threats across the GCP environment, useful for enriching baseline scores.

### VMware (On-Premise Infrastructure)

On-premise virtualization requires a slightly different approach, often relying on Syslog forwarding or direct API polling.

* **VMware NSX-T Distributed Firewall Logs:** If NSX-T is deployed, this is the gold standard for East-West traffic visibility within the hypervisor. It provides flow data before it even hits the physical switches.
* **vCenter Server Events:** Captures VM lifecycle events (creation, deletion, migration, snapshotting). This is typically forwarded via Syslog to a collector that parses the CEF/LEEF formats into JSON for Nexus.
* **ESXi Host Logs:** Provides hardware and hypervisor-level system events. Useful for detecting direct host tampering or unauthorized authenticated access bypassing vCenter.

### Ingestion Strategy for Nexus

Because cloud flow logs lack process-level context (no PID, no process hash), they will require a slightly modified schema or a dedicated table within the database before being scored. The temporal ML logic (intervals, coefficient of variation, entropy) remains highly effective on these datasets, particularly for identifying C2 beacons exiting a cloud NAT gateway.