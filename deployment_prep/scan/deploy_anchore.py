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
import shlex
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

# Phase 1 writes deployment_prep/images/ and Phase 2 writes
# deployment_prep/custom-images/; those archives are what the offline bundle
# ships, so they are also what gets scanned.
PREP_DIR        = Path(__file__).resolve().parent.parent
HOST_IMAGES_DIR = PREP_DIR / "images"
HOST_CUSTOM_DIR = PREP_DIR / "custom-images"


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
    # syft/grype run inside the container, so they write here; collect_reports()
    # copies this directory to the host before the container is removed.
    CONTAINER_REPORTS = "/home/anchore/reports"
    # Read-only mounts of the host archive directories.
    CONTAINER_IMAGES  = "/workspace/images"
    CONTAINER_CUSTOM  = "/workspace/custom-images"
    # docker-archive: needs a plain tar and the mounts are read-only, so the
    # gzipped archives are expanded here first.
    CONTAINER_ARCHIVES = "/home/anchore/archives"

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

    def _mount_flags(self) -> str:
        """Read-only mounts of the archive directories Phase 1/2 wrote."""
        flags = []
        for host_dir, mount in ((HOST_IMAGES_DIR, self.CONTAINER_IMAGES),
                                (HOST_CUSTOM_DIR, self.CONTAINER_CUSTOM)):
            if host_dir.is_dir():
                flags.append(f"-v {shlex.quote(str(host_dir))}:{mount}:ro")
        return " ".join(flags)

    def start_scanner(self):
        logger.info("Starting scanner container...")
        self._run(
            " ".join(filter(None, [
                f"{self.runtime} run --rm -d --name {self.CONTAINER_NAME}",
                self._mount_flags(),
                self.IMAGE_TAG,
                "sleep infinity",
            ])),
            f"Container {self.CONTAINER_NAME} started"
        )
        self._run(
            self._exec(f"mkdir -p {self.CONTAINER_REPORTS} {self.CONTAINER_ARCHIVES}"),
            "Report and archive directories ready"
        )

    def collect_reports(self) -> list[str]:
        """Copy the reports out of the scanner container before it is removed.

        Without this the --rm container takes every report with it and the
        phase leaves no SBOM or CVE evidence behind.
        """
        logger.info(f"Copying reports out of {self.CONTAINER_NAME}...")
        try:
            self._run(
                f"{self.runtime} cp {self.CONTAINER_NAME}:{self.CONTAINER_REPORTS}/. {self.output_dir}",
                f"Reports copied to {self.output_dir}"
            )
        except subprocess.CalledProcessError as exc:
            return [f"report copy out of {self.CONTAINER_NAME} failed: {exc.stderr.strip()[:160]}"]
        return []

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

    def _exec_sh(self, script: str) -> str:
        """Run a shell snippet (redirections, pipes) inside the scanner."""
        return f"{self.runtime} exec {self.CONTAINER_NAME} sh -c {shlex.quote(script)}"

    # -- Local image archives ---------------------------------------------------

    def _local_images(self) -> list[dict]:
        return [img for img in self.images if img.get("local")]

    def _archive_host_path(self, image: dict) -> Path:
        """Host path of the archive Phase 1/2 saved for this image."""
        host_dir = HOST_CUSTOM_DIR if image.get("local") else HOST_IMAGES_DIR
        return host_dir / image["save_as"]

    def _archive_mount_path(self, image: dict) -> str:
        """In-container path of the archive as mounted read-only."""
        mount = self.CONTAINER_CUSTOM if image.get("local") else self.CONTAINER_IMAGES
        return f"{mount}/{image['save_as']}"

    def _archive_scan_path(self, image: dict) -> str:
        """In-container path syft/grype reads: the expanded tar for a .gz archive."""
        save_as = image["save_as"]
        if save_as.endswith(".gz"):
            return f"{self.CONTAINER_ARCHIVES}/{save_as[:-3]}"
        return self._archive_mount_path(image)

    def _verify_local_archives(self) -> list[str]:
        """Phase 2 deletes each image it builds from the container store once it is
        saved, so the archive is the only copy the scanner can reach."""
        problems = []
        for img in self._local_images():
            if not img.get("save_as"):
                problems.append(
                    f"local image {img['name']} has no save_as in {self.config_file.name}")
                continue
            path = self._archive_host_path(img)
            if not path.is_file():
                problems.append(
                    f"missing image archive for {img['name']}: {path} (run Phase 2 first)")
        return problems

    def _prepare_local_archives(self) -> list[str]:
        """Expand the gzipped archives inside the scanner before they are scanned."""
        problems = []
        for img in self._local_images():
            if not img["save_as"].endswith(".gz"):
                continue
            script = (f"gzip -dc {shlex.quote(self._archive_mount_path(img))}"
                      f" > {shlex.quote(self._archive_scan_path(img))}")
            try:
                self._run(self._exec_sh(script), f"Archive expanded: {img['save_as']}")
            except subprocess.CalledProcessError as exc:
                problems.append(
                    f"archive expansion failed for {img['name']}: {exc.stderr.strip()[:160]}")
        return problems

    def _image_ref(self, image: dict) -> str:
        """Return the syft/grype-compatible image reference.

        Local images are scanned as the docker-save archive that ships in the
        offline bundle: Phase 2 removes them from the container store, and the
        scanner has no runtime socket to read a store through anyway.
        """
        if image.get("local"):
            return f"docker-archive:{self._archive_scan_path(image)}"
        return image["repo"]

    def scan_sbom(self, image: dict, fmt: str, ext: str) -> str:
        ref   = self._image_ref(image)
        name  = image["name"]
        opts  = self.settings.get("syft_options", "--scope all-layers")
        dest  = f"{self.CONTAINER_REPORTS}/{name}_SBOM.{ext}"
        cmd   = self._exec(f"syft {ref} {opts} -o {fmt}={dest}")
        self._run(cmd, f"SBOM {fmt}: {name}")
        return f"SBOM {fmt} done: {name}"

    def scan_vulns(self, image: dict, fmt: str, ext: str) -> str:
        ref   = self._image_ref(image)
        name  = image["name"]
        opts  = self.settings.get("grype_options", "")
        dest  = f"{self.CONTAINER_REPORTS}/{name}_vulnerabilities.{ext}"
        cmd   = self._exec(f"grype {ref} {opts} -o {fmt} --file {dest}")
        self._run(cmd, f"Vulns {fmt}: {name}")
        return f"Vulns {fmt} done: {name}"

    # -- Orchestration ----------------------------------------------------------

    def run(self) -> list[str]:
        """Run every scan and return the problems found (empty list = clean)."""
        # Without the archives there is nothing for the local images to scan, so
        # stop before building the scanner rather than failing 56 scans later.
        problems = self._verify_local_archives()
        if problems:
            return problems
        try:
            self.build_scanner()
            self.start_scanner()
            problems += self._prepare_local_archives()
            problems += self._run_all_scans()
            problems += self.collect_reports()
        finally:
            self.stop_scanner()
        problems += self._verify_reports()
        return problems

    def _output_formats(self) -> list[dict]:
        return self.settings.get("output_formats", [
            {"format": "syft-json",  "extension": "json", "type": "sbom"},
            {"format": "syft-table", "extension": "csv",  "type": "sbom"},
            {"format": "json",       "extension": "json", "type": "vulnerabilities"},
            {"format": "table",      "extension": "csv",  "type": "vulnerabilities"},
        ])

    def _expected_reports(self) -> list[Path]:
        """Host paths every configured image/format pair must produce."""
        return [
            self.output_dir / "{}_{}.{}".format(
                img["name"],
                "SBOM" if ofmt["type"] == "sbom" else "vulnerabilities",
                ofmt["extension"])
            for img in self.images
            for ofmt in self._output_formats()
        ]

    def _verify_reports(self) -> list[str]:
        """A report that is absent or empty is not evidence — report it as a problem."""
        problems = []
        for path in self._expected_reports():
            if not path.is_file():
                problems.append(f"missing report: {path.name}")
            elif path.stat().st_size == 0:
                problems.append(f"empty report: {path.name}")
        return problems

    def _run_all_scans(self) -> list[str]:
        output_fmts = self._output_formats()

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
        return [f"scan failed: {name} [{fmt}]" for name, fmt in failed]

    def generate_summary(self, problems: list[str]):
        summary = {
            "timestamp":  datetime.now().isoformat(),
            "runtime":    self.runtime,
            "image_count": len(self.images),
            "expected_report_count": len(self._expected_reports()),
            "problems":   problems,
            "passed":     not problems,
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
    problems = scanner.run()
    scanner.generate_summary(problems)
    if problems:
        logger.error(f"Image scan gate FAILED — {len(problems)} problem(s):")
        for problem in problems[:40]:
            logger.error(f"  - {problem}")
        if len(problems) > 40:
            logger.error(f"  ... and {len(problems) - 40} more")
        raise SystemExit(1)
    logger.info("Image scan gate PASSED — every configured report is present.")


if __name__ == "__main__":
    main()
