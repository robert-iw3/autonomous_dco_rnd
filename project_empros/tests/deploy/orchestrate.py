#!/usr/bin/env python3
import subprocess
import sys
import os
import argparse
import logging
import time

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger("nexus-orchestrator")

TF_DIR = "../infrastructure/terraform"
K8S_DIR = "../kubernetes"

def run_cmd(cmd, cwd=None, hide_output=False):
    logger.debug(f"Executing: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            check=True,
            stdout=subprocess.PIPE if hide_output else None,
            stderr=subprocess.PIPE if hide_output else None,
            text=True
        )
        return result.stdout.strip() if result.stdout else ""
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {' '.join(cmd)}")
        if e.stderr:
            logger.error(f"Error output: {e.stderr.strip()}")
        sys.exit(1)

def provision_infrastructure(auto_approve=False):
    logger.info("Step 1: Provisioning AWS Infrastructure via Terraform...")
    run_cmd(["terraform", "init"], cwd=TF_DIR)

    apply_cmd = ["terraform", "apply"]
    if auto_approve:
        apply_cmd.append("-auto-approve")

    run_cmd(apply_cmd, cwd=TF_DIR)
    logger.info("AWS Infrastructure Provisioned Successfully.")

def configure_kubernetes():
    logger.info("Step 2: Configuring local kubeconfig for EKS...")
    # Fetch real cluster name and region from Terraform outputs
    cluster_name = run_cmd(["terraform", "output", "-raw", "cluster_name"], cwd=TF_DIR, hide_output=True)
    region = run_cmd(["terraform", "output", "-raw", "aws_region"], cwd=TF_DIR, hide_output=True)

    run_cmd(["aws", "eks", "update-kubeconfig", "--region", region, "--name", cluster_name])

def deploy_helm_foundations():
    logger.info("Step 3: Bootstrapping Helm Repositories...")
    repos = {
        "nats": "https://nats-io.github.io/k8s/helm/charts/",
        "qdrant": "https://qdrant.github.io/qdrant-helm",
        "kedacore": "https://kedacore.github.io/charts"
    }

    for name, url in repos.items():
        run_cmd(["helm", "repo", "add", name, url], hide_output=True)
    run_cmd(["helm", "repo", "update"], hide_output=True)

    logger.info("Step 4: Deploying Stateful Operators (NATS, Qdrant, KEDA)...")

    try:
        run_cmd(["kubectl", "get", "namespace", "sentinel-nexus"], hide_output=True)
        logger.debug("Namespace 'sentinel-nexus' already exists.")
    except subprocess.CalledProcessError:
        run_cmd(["kubectl", "create", "namespace", "sentinel-nexus"], hide_output=True)

    # Deploy KEDA (Event Driven Autoscaler)
    logger.info("  -> Installing KEDA...")
    run_cmd(["helm", "upgrade", "--install", "keda", "kedacore/keda", "--namespace", "sentinel-nexus"])

    # Deploy NATS JetStream (HA Mode)
    logger.info("  -> Installing NATS JetStream Cluster...")
    run_cmd([
        "helm", "upgrade", "--install", "nats-cluster", "nats/nats",
        "--namespace", "sentinel-nexus",
        "--set", "nats.jetstream.enabled=true",
        "--set", "cluster.enabled=true",
        "--set", "cluster.replicas=3"
    ])

    # Deploy Qdrant (Distributed Mode)
    logger.info("  -> Installing Qdrant Distributed Vector DB...")
    run_cmd([
        "helm", "upgrade", "--install", "qdrant-cluster", "qdrant/qdrant",
        "--namespace", "sentinel-nexus",
        "--set", "replicaCount=3",
        "--set", "persistence.size=100Gi"
    ])

def deploy_nexus_secrets():
    logger.info("Step 4.5: Injecting Secure Environment into Kubernetes...")
    env_file = "nexus.env"
    if not os.path.exists(env_file):
        logger.error(f"Missing {env_file}. Please run setup_env.sh first.")
        sys.exit(1)

    try:
        # Delete existing secret if it exists to allow clean replacement
        run_cmd(["kubectl", "delete", "secret", "nexus-secrets", "--namespace", "sentinel-nexus"], hide_output=True)
    except subprocess.CalledProcessError:
        pass # Secret does not exist yet, safe to proceed

    run_cmd([
        "kubectl", "create", "secret", "generic", "nexus-secrets",
        f"--from-env-file={env_file}",
        "--namespace", "sentinel-nexus"
    ])

def deploy_nexus_workloads():
    logger.info("Step 5: Deploying Sentinel Nexus Custom Workloads...")

    workload_file = os.path.join(K8S_DIR, "nexus-workloads.yaml")
    run_cmd(["kubectl", "apply", "-f", workload_file])

    logger.info("Sentinel Nexus deployment initiated. Waiting for pods to stabilize...")
    time.sleep(10)
    run_cmd(["kubectl", "get", "pods", "-n", "sentinel-nexus"])

def destroy_infrastructure():
    logger.warning("Initiating absolute teardown of AWS Infrastructure...")
    run_cmd(["terraform", "destroy", "-auto-approve"], cwd=TF_DIR)
    logger.info("Infrastructure destroyed.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sentinel Nexus Cloud Orchestrator")
    parser.add_argument("--deploy", action="store_true", help="Provision AWS and deploy Kubernetes workloads")
    parser.add_argument("--destroy", action="store_true", help="Tear down all AWS infrastructure")
    parser.add_argument("--auto-approve", action="store_true", help="Bypass Terraform approval prompts")

    args = parser.parse_args()

    if args.destroy:
        confirm = input("DANGER: This will destroy the entire EKS cluster and VPC. Type 'YES' to proceed: ")
        if confirm == "YES":
            destroy_infrastructure()
        else:
            logger.info("Teardown aborted.")
        sys.exit(0)

    if args.deploy:
        try:
            provision_infrastructure(args.auto_approve)
            configure_kubernetes()
            deploy_helm_foundations()
            deploy_nexus_secrets()
            deploy_nexus_workloads()
            logger.info("\nSentinel Nexus Tier-5 Deployment Complete.")
        except Exception as e:
            logger.error(f"Deployment failed catastrophically: {e}")
            sys.exit(1)
    else:
        parser.print_help()