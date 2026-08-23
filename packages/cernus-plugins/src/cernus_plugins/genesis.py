"""Genesis connector — the seam between build-time proof and Day-2 posture.

Accepts any of:

* a Genesis **EvidencePackage** JSON (``kind: EvidencePackage``), as returned by
  ``GET /api/projects/{id}/evidence`` or stored in ``Evidence.package``;
* a **DeliveryManifest** YAML/JSON (``kind: DeliveryManifest``);
* a Genesis **workspace directory** containing ``.genesis-work/manifest.yaml``
  and optionally ``.genesis-work/evidence.json`` and
  ``.genesis-work/deployment.json`` (written by the Genesis post-deploy hook).

Produces one System (from the manifest's ``service``), one Deployment (carrying
the manifest and evidence verbatim), and one Finding per evidence finding —
mapped losslessly because the Cernus Finding is a superset of the genesis-gates
finding shape.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml
from cernus_core.model import (
    Asset,
    Component,
    Deployment,
    EvidenceRecord,
    Finding,
    IngestBatch,
    Source,
    System,
    canonical_hash,
    new_id,
    now_iso,
)
from cernus_core.plugins import Connector, register_connector

from .trivy import normalize_ref

_GATE_CATEGORY = {
    "secret-scan": "secret",
    "dependency-scan": "vulnerability",
    "container-scan": "vulnerability",
    "sast": "sast",
    "iac-policy-check": "misconfiguration",
    "design-lint": "other",
    "unit-tests": "other",
    "sbom": "other",
    "risk-classify": "other",
}

WORK_DIR = ".genesis-work"


@register_connector
class GenesisConnector(Connector):
    name = "genesis"
    description = (
        "Genesis EvidencePackage / DeliveryManifest / workspace → System, Deployment, Findings"
    )
    tools = ("genesis-gates", "genesis-server")

    def detect(self, path: Path, document: dict[str, Any] | None = None) -> bool:
        if document and document.get("kind") in {"EvidencePackage", "DeliveryManifest"}:
            return True
        if path.is_dir() and (path / WORK_DIR / "manifest.yaml").exists():
            return True
        if path.suffix in {".yaml", ".yml"}:
            try:
                doc = yaml.safe_load(path.read_text())
                return isinstance(doc, dict) and doc.get("kind") == "DeliveryManifest"
            except yaml.YAMLError:
                return False
        return False

    def ingest(
        self, path: Path, document: dict[str, Any] | None = None, **context: Any
    ) -> IngestBatch:
        manifest, evidence, deployment_info = self._load(path, document)
        return self.build(manifest, evidence, deployment_info, fallback_name=path.stem, **context)

    def build(
        self,
        manifest: dict[str, Any] | None,
        evidence: dict[str, Any] | None,
        deployment_info: dict[str, Any] | None = None,
        fallback_name: str = "genesis-app",
        **context: Any,
    ) -> IngestBatch:
        """Build a batch from already-loaded documents (used by the server's
        ``POST /api/ingest/genesis`` as well as by :meth:`ingest`)."""
        deployment_info = deployment_info or {}
        source = Source(tool="genesis-gates", connector=self.name)
        batch = IngestBatch(source=source)
        seen = now_iso()

        service = (manifest or {}).get("service") or {}
        release = (manifest or {}).get("release") or {}
        change = (manifest or {}).get("change") or {}
        service_name = (
            service.get("name")
            or (evidence or {}).get("service")
            or deployment_info.get("service")
            or context.get("system_name")
            or fallback_name
        )
        system_id = (
            context.get("system_id") or f"sys_{canonical_hash(['genesis', service_name])[:16]}"
        )
        batch.systems.append(
            System(
                id=system_id,
                name=service_name,
                owner=service.get("owner") or (evidence or {}).get("owner"),
                criticality=service.get("criticality", "unknown"),
                data_classification=service.get("data_classification", "unknown"),
                genesis_project_id=deployment_info.get("project_id")
                or context.get("genesis_project_id"),
                repository_url=deployment_info.get("repository_url"),
            )
        )

        change_id = change.get("id") or (evidence or {}).get("change_id")
        deployed_at = (
            deployment_info.get("deployed_at") or (evidence or {}).get("created_at") or seen
        )
        environment = (
            deployment_info.get("environment") or context.get("environment") or "development"
        )
        deployment_id = (
            context.get("deployment_id")
            or f"dep_{canonical_hash([system_id, change_id, deployed_at])[:16]}"
        )
        artifact_refs = [
            {"name": a.get("name", "?"), "image_ref": a.get("image_ref"), "digest": a.get("digest")}
            for a in deployment_info.get("artifacts") or []
        ]
        batch.deployments.append(
            Deployment(
                id=deployment_id,
                system_id=system_id,
                environment=environment,
                deployed_at=deployed_at,
                deployed_by=deployment_info.get("deployed_by"),
                change_id=change_id,
                artifact_refs=artifact_refs,
                manifest=manifest,
                evidence=evidence,
                preview_url=deployment_info.get("preview_url"),
                source=source,
            )
        )

        # One asset per deployed artifact (compose service / image) so later
        # image scans reconcile to the same ids. Falls back to one service asset.
        asset_ids: dict[str, str] = {}
        for a in artifact_refs:
            facet = normalize_ref(a.get("image_ref") or a["name"])
            aid = Asset.id_for("container_image", facet)
            asset_ids[a["name"]] = aid
            ident = {
                k: v
                for k, v in (("image_ref", a.get("image_ref")), ("digest", a.get("digest")))
                if v
            }
            batch.assets.append(
                Asset(
                    id=aid,
                    asset_kind="container_image",
                    name=a.get("image_ref") or a["name"],
                    identifiers=ident,
                    system_id=system_id,
                    deployment_id=deployment_id,
                    environment=environment,
                    data_classification=service.get("data_classification", "unknown"),
                    owner=service.get("owner"),
                    source=source,
                )
            )
        service_asset_id = Asset.id_for("service", system_id)
        batch.assets.append(
            Asset(
                id=service_asset_id,
                asset_kind="service",
                name=service_name,
                identifiers={"url": deployment_info.get("preview_url")}
                if deployment_info.get("preview_url")
                else {},
                system_id=system_id,
                deployment_id=deployment_id,
                environment=environment,
                data_classification=service.get("data_classification", "unknown"),
                owner=service.get("owner"),
                source=source,
            )
        )

        for f in (evidence or {}).get("findings") or []:
            gate = f.get("gate")
            component = _component_from_text(f.get("title"), f.get("remediation"))
            batch.findings.append(
                Finding(
                    id=new_id("fnd"),
                    title=f.get("title", gate or "finding"),
                    severity=f.get("severity"),
                    source=Source(tool="genesis-gates", connector=self.name),
                    source_ref=f.get("title"),
                    gate=gate,
                    category=_GATE_CATEGORY.get(gate or "", "other"),
                    detail=f.get("detail"),
                    location=f.get("location"),
                    remediation=f.get("remediation"),
                    component=component,
                    asset_id=service_asset_id,
                    deployment_id=deployment_id,
                    system_id=system_id,
                    first_seen=deployed_at,
                    last_seen=seen,
                    raw=f,
                )
            )

        if evidence:
            batch.evidence.append(
                EvidenceRecord(
                    id=new_id("ev"),
                    record_kind="gate_run",
                    subject_kind="deployment",
                    subject_id=deployment_id,
                    produced_by="genesis-gates",
                    summary=(
                        f"gates {evidence.get('status')} for change {change_id}: "
                        f"{len(evidence.get('gate_results') or [])} gates, "
                        f"{len(evidence.get('findings') or [])} findings"
                    ),
                    payload={
                        "status": evidence.get("status"),
                        "risk_level": evidence.get("risk_level") or release.get("risk_level"),
                        "gate_results": [
                            {k: g.get(k) for k in ("gate", "status", "summary", "duration_s")}
                            for g in evidence.get("gate_results") or []
                        ],
                    },
                    created_at=evidence.get("created_at") or seen,
                )
            )
        if deployment_info:
            batch.evidence.append(
                EvidenceRecord(
                    id=new_id("ev"),
                    record_kind="deploy",
                    subject_kind="deployment",
                    subject_id=deployment_id,
                    produced_by="genesis-server",
                    summary=f"deployed {service_name} to {environment}",
                    payload=deployment_info,
                    created_at=deployed_at,
                )
            )
        return batch

    @staticmethod
    def _load(path: Path, document: dict[str, Any] | None) -> tuple[dict | None, dict | None, dict]:
        manifest: dict | None = None
        evidence: dict | None = None
        deployment: dict = {}
        if document is not None:
            if document.get("kind") == "EvidencePackage":
                evidence = document
                manifest = document.get("manifest") or None
            elif document.get("kind") == "DeliveryManifest":
                manifest = document
            return manifest, evidence, deployment
        if path.is_dir():
            work = path / WORK_DIR
            if (work / "manifest.yaml").exists():
                manifest = yaml.safe_load((work / "manifest.yaml").read_text())
            if (work / "evidence.json").exists():
                evidence = json.loads((work / "evidence.json").read_text())
            if (work / "deployment.json").exists():
                deployment = json.loads((work / "deployment.json").read_text())
            return manifest, evidence, deployment
        text = path.read_text()
        doc = yaml.safe_load(text) if path.suffix in {".yaml", ".yml"} else json.loads(text)
        if isinstance(doc, dict) and doc.get("kind") == "EvidencePackage":
            return doc.get("manifest") or None, doc, deployment
        return doc, None, deployment


_UPGRADE = re.compile(
    r"^Upgrade\s+(?P<name>[A-Za-z0-9_.@/-]+)\s+to\s+(?P<version>[A-Za-z0-9_.:+~-]+)\.?$"
)
_CVE_PKG = re.compile(r"^(?:CVE|GHSA)-[A-Za-z0-9-]+\s+(?P<name>[A-Za-z0-9_.@/-]+)$")


def _component_from_text(title: str | None, remediation: str | None) -> Component | None:
    """Genesis gate findings carry the fix as prose; recover the structure.

    "Upgrade idna to 3.7" → Component(name=idna, fixed_version=3.7). The title
    ("CVE-2024-3651 idna") supplies the name when only that is available.
    """
    name = None
    fixed = None
    if remediation:
        match = _UPGRADE.match(remediation.strip())
        if match:
            name = match.group("name")
            fixed = match.group("version")
    if name is None and title:
        match = _CVE_PKG.match(title.strip())
        if match:
            name = match.group("name")
    if name is None:
        return None
    return Component(name=name, fixed_version=fixed, type="library")
