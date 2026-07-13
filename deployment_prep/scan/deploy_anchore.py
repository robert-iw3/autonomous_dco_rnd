#!/usr/bin/env python3
"""
deploy_anchore.py -- Sentinel Nexus image scanner

Supports Docker or Podman (auto-detected, or set with --runtime).
Generates SBOM (syft) + vulnerability reports (grype) in JSON + CSV for
every image in scan_config.json. Output goes to deployment_prep/scan/reports/.
"""

import subprocess
import logging
import json
import os
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
import argparse
from tqdm import tqdm

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(f"anchore_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)


def detect_runtime(preferred: str | None = None) -> str:
    """Return 'docker' or 'podman' based on what's available."""
    if preferred:
        return preferred
    override = os.environ.get("NEXUS_CONTAINER_RUNTIME", "")
    if override:
        return override
    # Prefer docker if daemon is reachable
    result = subprocess.run(["docker", "info"], capture_output=True)
    if result.returncode == 0:
        return "docker"
    if shutil.which("podman"):
        return "podman"
    if shutil.which("docker"):
        return "docker"
    raise RuntimeError("Neither docker nor podman found. Install one before scanning.")


class NexusAnchoreScanner:
    CONTAINER_NAME = "nexus-anchore"
    IMAGE_TAG      = "nexus-anchore:latest"
    BATCH_SIZE     = 8

    def __init__(self, config_file: str, output_dir: str, max_workers: int, runtime: str):
        self.runtime     = runtime
        self.config_file = Path(config_file)
        self.output_dir  = Path(output_dir)
        self.max_workers = max_workers
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.images      = self._load_config()
        self.settings    = self._load_settings()
        logger.info(f"Runtime: {self.runtime}  |  {len(self.images)} images to scan")

    def _load_config(self) -> list[dict]:
        with open(self.config_file) as f:
            return json.load(f).get("images", [])

    def _load_settings(self) -> dict:
        with open(self.config_file) as f:
            return json.load(f).get("settings", {})

    def _run(self, cmd: str, desc: str = "") -> subprocess.CompletedProcess:
        logger.debug(f"$ {cmd}")
        try:
            result = subprocess.run(cmd, shell=True, check=True, text=True, capture_output=True)
            if desc:
                logger.info(f"  OK: {desc}")
            return result
        except subprocess.CalledProcessError as exc:
            logger.error(f"FAILED [{desc}]: {exc.stderr.strip()[:240]}")
            raise

    # -- Container lifecycle ----------------------------------------------------

    def build_scanner(self):
        logger.info(f"Building Anchore scanner image ({self.runtime})...")
        self._run(
            f"{self.runtime} build -t {self.IMAGE_TAG} .",
            "Anchore image built"
        )
        self._run(f"{self.runtime} image prune -f", "Image prune")

    def start_scanner(self):
        logger.info("Starting scanner container...")
        self._run(
            f"{self.runtime} run --rm -d --name {self.CONTAINER_NAME} {self.IMAGE_TAG} sleep infinity",
            f"Container {self.CONTAINER_NAME} started"
        )

    def stop_scanner(self):
        logger.info("Stopping and removing scanner container...")
        subprocess.run(
            f"{self.runtime} rm -f {self.CONTAINER_NAME}",
            shell=True, capture_output=True
        )
        subprocess.run(
            f"{self.runtime} rmi -f {self.IMAGE_TAG}",
            shell=True, capture_output=True
        )

    # -- Scan helpers -----------------------------------------------------------

    def _exec(self, inner_cmd: str) -> str:
        return f"{self.runtime} exec {self.CONTAINER_NAME} {inner_cmd}"

    def _image_ref(self, image: dict) -> str:
        """Return the syft/grype-compatible image reference.
        For local images (built in Phase 2), use docker-daemon: or podman: scheme
        so syft/grype reads from the local container store rather than pulling.
        """
        repo = image["repo"]
        if image.get("local"):
            scheme = "podman" if self.runtime == "podman" else "docker"
            return f"{scheme}:{repo}"
        return repo

    def scan_sbom(self, image: dict, fmt: str, ext: str) -> str:
        ref   = self._image_ref(image)
        name  = image["name"]
        opts  = self.settings.get("syft_options", "--scope all-layers")
        dest  = self.output_dir / f"{name}_SBOM.{ext}"
        cmd   = self._exec(f"syft {ref} {opts} -o {fmt}={dest}")
        self._run(cmd, f"SBOM {fmt}: {name}")
        return f"SBOM {fmt} done: {name}"

    def scan_vulns(self, image: dict, fmt: str, ext: str) -> str:
        ref   = self._image_ref(image)
        name  = image["name"]
        opts  = self.settings.get("grype_options", "")
        dest  = self.output_dir / f"{name}_vulnerabilities.{ext}"
        cmd   = self._exec(f"grype {ref} {opts} -o {fmt} --file {dest}")
        self._run(cmd, f"Vulns {fmt}: {name}")
        return f"Vulns {fmt} done: {name}"

    # -- Orchestration ----------------------------------------------------------

    def run(self):
        try:
            self.build_scanner()
            self.start_scanner()
            self._run_all_scans()
        finally:
            self.stop_scanner()

    def _run_all_scans(self):
        output_fmts = self.settings.get("output_formats", [
            {"format": "syft-json",  "extension": "json", "type": "sbom"},
            {"format": "syft-table", "extension": "csv",  "type": "sbom"},
            {"format": "json",       "extension": "json", "type": "vulnerabilities"},
            {"format": "table",      "extension": "csv",  "type": "vulnerabilities"},
        ])

        tasks = []
        for img in self.images:
            for ofmt in output_fmts:
                if ofmt["type"] == "sbom":
                    tasks.append((self.scan_sbom, img, ofmt["format"], ofmt["extension"]))
                else:
                    tasks.append((self.scan_vulns, img, ofmt["format"], ofmt["extension"]))

        logger.info(f"Running {len(tasks)} scan tasks across {len(self.images)} images...")

        failed = []
        for batch_start in range(0, len(tasks), self.BATCH_SIZE):
            batch = tasks[batch_start: batch_start + self.BATCH_SIZE]
            batch_num = batch_start // self.BATCH_SIZE + 1
            total_batches = (len(tasks) + self.BATCH_SIZE - 1) // self.BATCH_SIZE
            logger.info(f"Batch {batch_num}/{total_batches} ({len(batch)} tasks)")

            with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
                futures = {pool.submit(fn, img, fmt, ext): (img["name"], fmt)
                           for fn, img, fmt, ext in batch}
                for fut in tqdm(as_completed(futures), total=len(futures),
                                desc=f"Batch {batch_num}"):
                    name, fmt = futures[fut]
                    try:
                        logger.debug(fut.result())
                    except Exception as exc:
                        logger.error(f"  FAIL {name} [{fmt}]: {exc}")
                        failed.append((name, fmt))

        if failed:
            logger.warning(f"{len(failed)} scan(s) failed: {failed}")
        else:
            logger.info("All scans completed successfully.")

    def generate_summary(self):
        summary = {
            "timestamp":  datetime.now().isoformat(),
            "runtime":    self.runtime,
            "image_count": len(self.images),
            "scans": [],
        }
        for img in self.images:
            files = []
            for f in sorted(self.output_dir.glob(f"{img['name']}_*")):
                files.append({
                    "name":     f.name,
                    "size_kb":  round(f.stat().st_size / 1024, 1),
                    "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
                })
            summary["scans"].append({"image": img["repo"], "name": img["name"], "files": files})

        out = self.output_dir / "scan_summary.json"
        out.write_text(json.dumps(summary, indent=2))
        logger.info(f"Summary written: {out}")


def main():
    ap = argparse.ArgumentParser(description="Sentinel Nexus -- Anchore image scanner")
    ap.add_argument("--runtime", choices=["docker", "podman"],
                    help="Container runtime (auto-detected if omitted)")
    ap.add_argument("--config",      default="scan_config.json",
                    help="Scan config JSON (default: scan_config.json)")
    ap.add_argument("--output-dir",  default="reports",
                    help="Output directory for scan reports (default: reports/)")
    ap.add_argument("--max-workers", type=int, default=4,
                    help="Concurrent scan workers per batch (default: 4)")
    args = ap.parse_args()

    runtime = detect_runtime(args.runtime)
    scanner = NexusAnchoreScanner(
        config_file=args.config,
        output_dir=args.output_dir,
        max_workers=args.max_workers,
        runtime=runtime,
    )
    scanner.run()
    scanner.generate_summary()


if __name__ == "__main__":
    main()
