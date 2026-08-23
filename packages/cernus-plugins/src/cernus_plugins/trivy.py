"""Trivy — connector for `trivy … --format json` output, and a scanner wrapper.

Covers image scans (``ArtifactType: container_image``), filesystem scans, and
SBOM scans (``trivy sbom``). Misconfiguration and secret results are mapped to
their own categories when present.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from cernus_core.model import (
    Asset,
    Component,
    EvidenceRecord,
    Finding,
    IngestBatch,
    Source,
    Vuln,
    new_id,
    now_iso,
)
from cernus_core.plugins import Connector, Scanner, ScanResult, register_connector, register_scanner

_KIND_BY_ARTIFACT = {
    "container_image": "container_image",
    "filesystem": "repository",
    "repository": "repository",
    "cyclonedx": "container_image",
    "spdx": "container_image",
}


@register_connector
class TrivyConnector(Connector):
    name = "trivy"
    description = (
        "Trivy JSON reports (image, fs, sbom): vulnerabilities, misconfigurations, secrets"
    )
    tools = ("trivy",)

    def detect(self, path: Path, document: dict[str, Any] | None = None) -> bool:
        return (
            bool(document)
            and "SchemaVersion" in document
            and "Results" in document
            and ("ArtifactName" in document or "ArtifactType" in document)
        )

    def ingest(
        self, path: Path, document: dict[str, Any] | None = None, **context: Any
    ) -> IngestBatch:
        doc = document if document is not None else json.loads(path.read_text())
        version = (doc.get("Trivy") or {}).get("Version")
        source = Source(tool="trivy", version=version, connector=self.name)
        batch = IngestBatch(source=source)

        artifact = doc.get("ArtifactName") or path.stem
        artifact_type = doc.get("ArtifactType", "container_image")
        meta = doc.get("Metadata") or {}
        digest = (meta.get("RepoDigests") or [None])[0]
        image_id = meta.get("ImageID")

        asset_id = context.get("asset_id")
        if asset_id is None:
            # Identity facet is the image *reference* (name:tag) so that trivy,
            # syft, and the Genesis deployment record reconcile to one asset;
            # the digest rides along as an identifier for exact matching.
            asset_id = Asset.id_for(
                _KIND_BY_ARTIFACT.get(artifact_type, "other"), normalize_ref(artifact)
            )
            identifiers = {"image_ref": artifact}
            if digest:
                identifiers["digest"] = digest.split("@")[-1]
            elif image_id:
                identifiers["digest"] = image_id
            batch.assets.append(
                Asset(
                    id=asset_id,
                    asset_kind=_KIND_BY_ARTIFACT.get(artifact_type, "other"),
                    name=artifact,
                    identifiers=identifiers,
                    system_id=context.get("system_id"),
                    deployment_id=context.get("deployment_id"),
                    environment=context.get("environment", "unknown"),
                    source=source,
                )
            )

        seen = now_iso()
        context = {**context, "scan_scope": artifact_type}
        for result in doc.get("Results") or []:
            target = result.get("Target")
            for v in result.get("Vulnerabilities") or []:
                batch.findings.append(self._vuln(v, target, asset_id, source, seen, context))
            for m in result.get("Misconfigurations") or []:
                batch.findings.append(self._misconf(m, target, asset_id, source, seen, context))
            for s in result.get("Secrets") or []:
                batch.findings.append(self._secret(s, target, asset_id, source, seen, context))

        batch.evidence.append(
            EvidenceRecord(
                id=new_id("ev"),
                record_kind="scan",
                subject_kind="asset",
                subject_id=asset_id,
                produced_by=f"trivy {version or ''}".strip(),
                summary=f"trivy scan of {artifact}: {len(batch.findings)} findings",
                payload={
                    "artifact": artifact,
                    "artifact_type": artifact_type,
                    "created_at": doc.get("CreatedAt"),
                    "report_id": doc.get("ReportID"),
                    "os": meta.get("OS"),
                    "counts": _counts(batch.findings),
                },
            )
        )
        return batch

    @staticmethod
    def _vuln(
        v: dict, target: str | None, asset_id: str, source: Source, seen: str, ctx: dict
    ) -> Finding:
        cvss_block = v.get("CVSS") or {}
        score, vector = None, None
        # Prefer NVD v3, then any v3, then v2.
        for key in ("nvd", *sorted(k for k in cvss_block if k != "nvd")):
            c = cvss_block.get(key) or {}
            if c.get("V3Score") is not None:
                score, vector = c["V3Score"], c.get("V3Vector")
                break
        if score is None:
            for c in cvss_block.values():
                if c.get("V2Score") is not None:
                    score, vector = c["V2Score"], c.get("V2Vector")
                    break
        purl = (v.get("PkgIdentifier") or {}).get("PURL")
        return Finding(
            id=new_id("fnd"),
            title=v.get("Title") or f"{v.get('VulnerabilityID')} in {v.get('PkgName')}",
            severity=v.get("Severity"),
            source=source,
            source_ref=v.get("VulnerabilityID"),
            category="vulnerability",
            detail=v.get("Description"),
            location=target,
            remediation=(
                f"Upgrade {v.get('PkgName')} to {v['FixedVersion']}"
                if v.get("FixedVersion")
                else None
            ),
            vuln=Vuln(
                id=v.get("VulnerabilityID", ""),
                cwe=list(v.get("CweIDs") or []),
                cvss=score,
                cvss_vector=vector,
                published=v.get("PublishedDate"),
                references=list(v.get("References") or [])[:5],
            ),
            component=Component(
                name=v.get("PkgName", ""),
                purl=purl,
                version=v.get("InstalledVersion"),
                fixed_version=v.get("FixedVersion"),
                type=(purl.split(":")[1].split("/")[0] if purl else None),
            ),
            asset_id=asset_id,
            deployment_id=ctx.get("deployment_id"),
            system_id=ctx.get("system_id"),
            scan_scope=ctx.get("scan_scope"),
            first_seen=seen,
            last_seen=seen,
            tags=[t for t in (v.get("Status"),) if t],
            raw=v,
        )

    @staticmethod
    def _misconf(
        m: dict, target: str | None, asset_id: str, source: Source, seen: str, ctx: dict
    ) -> Finding:
        return Finding(
            id=new_id("fnd"),
            title=m.get("Title") or m.get("ID", "misconfiguration"),
            severity=m.get("Severity"),
            source=source,
            source_ref=m.get("ID") or m.get("AVDID"),
            category="misconfiguration",
            detail=m.get("Description") or m.get("Message"),
            location=target,
            remediation=m.get("Resolution"),
            asset_id=asset_id,
            deployment_id=ctx.get("deployment_id"),
            system_id=ctx.get("system_id"),
            scan_scope=ctx.get("scan_scope"),
            first_seen=seen,
            last_seen=seen,
            raw=m,
        )

    @staticmethod
    def _secret(
        s: dict, target: str | None, asset_id: str, source: Source, seen: str, ctx: dict
    ) -> Finding:
        return Finding(
            id=new_id("fnd"),
            title=s.get("Title") or f"Secret: {s.get('RuleID')}",
            severity=s.get("Severity"),
            source=source,
            source_ref=s.get("RuleID"),
            category="secret",
            detail=s.get("Match"),
            location=f"{target}:{s.get('StartLine')}" if s.get("StartLine") else target,
            remediation="Remove the secret from the artifact and rotate it.",
            asset_id=asset_id,
            deployment_id=ctx.get("deployment_id"),
            system_id=ctx.get("system_id"),
            scan_scope=ctx.get("scan_scope"),
            first_seen=seen,
            last_seen=seen,
            raw={k: v for k, v in s.items() if k != "Match"},  # never persist the matched secret
        )


def _counts(findings: list[Finding]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        out[f.severity.value] = out.get(f.severity.value, 0) + 1
    return out


@register_scanner
class TrivyScanner(Scanner):
    name = "trivy"
    description = "Run trivy against an image, directory, or SBOM"
    binary = "trivy"
    targets = ("image", "fs", "sbom")

    def version(self) -> str | None:
        try:
            out = subprocess.run(
                [self.binary, "--version"], capture_output=True, text=True, timeout=20, check=False
            ).stdout
            return out.strip().splitlines()[0].replace("Version:", "").strip() or None
        except (OSError, subprocess.TimeoutExpired):
            return None

    def scan(self, target_kind: str, target: str, workdir: Path) -> ScanResult:
        if target_kind not in self.targets:
            raise ValueError(f"trivy scanner does not support target kind {target_kind!r}")
        workdir.mkdir(parents=True, exist_ok=True)
        out = workdir / f"trivy-{target_kind}-{_slug(target)}.json"
        argv = [
            self.binary,
            target_kind,
            "--skip-version-check",
            "--format",
            "json",
            "--output",
            str(out),
            target,
        ]
        if target_kind == "image":
            argv[2:2] = ["--scanners", "vuln,secret"]
        proc = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=1800)
        return ScanResult(
            tool="trivy",
            output_path=out if out.exists() else None,
            connector="trivy",
            argv=argv,
            returncode=proc.returncode,
            stderr=proc.stderr[-4000:],
        )


def normalize_ref(ref: str) -> str:
    """``docker.io/library/python:3.11-slim`` and ``python:3.11-slim`` are one asset."""
    ref = ref.split("@")[0]
    for prefix in (
        "docker.io/library/",
        "docker.io/",
        "index.docker.io/library/",
        "index.docker.io/",
    ):
        if ref.startswith(prefix):
            ref = ref[len(prefix) :]
    return ref if ":" in ref.rsplit("/", 1)[-1] else f"{ref}:latest"


def _slug(s: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in s).strip("-")[:80]
