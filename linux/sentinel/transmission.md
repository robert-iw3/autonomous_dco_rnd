# Enabling Production Cryptographic Integrity (`nexus_integrity`)

By default, Linux Sentinel compiles without the `nexus_integrity` layer to ensure seamless local development and easy open-source builds.

For production environments, enabling the **Integrity Feature** cryptographically guarantees the lineage of the telemetry. It injects a `LineageStamper` into the Parquet transmission pipeline that increments a persistent sequence counter, captures the timestamp, and generates an HMAC-SHA256 signature for every payload. This strictly prevents man-in-the-middle tampering, replay attacks, and dropped telemetry batches.

## 1. Prerequisites

Because `nexus_integrity` is a proprietary internal crate, the host machine (or CI/CD runner) must have SSH access to the organization's GitHub repository.

Ensure the SSH agent is running and has the key loaded:

```bash
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_rsa

```

## 2. Building the Agent (Docker)

Docker containers do not have access to the host's SSH keys by default. Use **Docker BuildKit** to securely forward the SSH agent into the container for the duration of the build.

To compile the agent with the cryptographic layer enabled, run the following command:

```bash
DOCKER_BUILDKIT=1 docker build \
  --ssh default \
  --build-arg CARGO_FEATURES="--features integrity" \
  -t linux-sentinel:production .

```

*(Note: Ensure the `Dockerfile` includes the `--mount=type=ssh` flag on the `cargo build` run step as outlined in the build documentation).*

## 3. Runtime Configuration

Once built, the agent requires a shared cryptographic secret to sign the payloads.

Set this in the `master.toml`:

```toml
[siem]
middleware_gateway_url = "https://nexus-edge.local:443/api/v1/telemetry"
batch_size = 100

# The pre-shared key for HMAC generation
integrity_secret = "${SENTINEL_INTEGRITY_SECRET}"

```

In production, it is highly recommended to pass this securely as an environment variable via the container orchestrator (e.g., Kubernetes Secrets or Docker Compose) rather than hardcoding it:

```bash
export SENTINEL_INTEGRITY_SECRET="your-secure-32-byte-key"

```

## 4. Upstream Gateway Validation

For the integrity layer to function end-to-end, the receiving Nexus Gateway (e.g., `nexus-edge.local`) must implement the inverse validation logic.

The gateway must be compiled with the `validator` feature of the same crate:

```toml
# In the SIEM Gateway's Cargo.toml
nexus_integrity = { git = "ssh://git@github.com/your-org/nexus_integrity.git", tag = "v1.0.4", default-features = false, features = ["validator"] }

```

The gateway will automatically drop any incoming payloads with an HTTP `403 FORBIDDEN` if:

1. The `HDR_BATCH_HMAC` signature does not match the payload body.
2. The `HDR_BATCH_SEQUENCE` is less than or equal to the last recorded sequence for that specific `HDR_SENSOR_ID` (Replay Attack).
3. The `HDR_BATCH_TIMESTAMP` drifts beyond acceptable thresholds (Delayed Transmission Attack).