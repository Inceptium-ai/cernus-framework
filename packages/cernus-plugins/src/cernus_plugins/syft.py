"""Syft scanner wrapper: produce a CycloneDX SBOM for an image or directory.

Normalization of the SBOM itself is the :mod:`cyclonedx` connector's job.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from cernus_core.plugins import Scanner, ScanResult, register_scanner


@register_scanner
class SyftScanner(Scanner):
    name = "syft"
    description = "Generate a CycloneDX SBOM with syft"
    binary = "syft"
    targets = ("image", "fs")

    def version(self) -> str | None:
        try:
            out = subprocess.run(
                [self.binary, "version", "-o", "raw"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            ).stdout
            return out.strip() or None
        except (OSError, subprocess.TimeoutExpired):
            return None

    def scan(self, target_kind: str, target: str, workdir: Path) -> ScanResult:
        if target_kind not in self.targets:
            raise ValueError(f"syft scanner does not support target kind {target_kind!r}")
        workdir.mkdir(parents=True, exist_ok=True)
        slug = "".join(c if c.isalnum() else "-" for c in target).strip("-")[:80]
        out = workdir / f"syft-{slug}.cdx.json"
        src = target if target_kind == "image" else f"dir:{target}"
        argv = [self.binary, src, "-o", f"cyclonedx-json={out}", "-q"]
        proc = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=1800)
        return ScanResult(
            tool="syft",
            output_path=out if out.exists() else None,
            connector="cyclonedx",
            argv=argv,
            returncode=proc.returncode,
            stderr=proc.stderr[-4000:],
        )
