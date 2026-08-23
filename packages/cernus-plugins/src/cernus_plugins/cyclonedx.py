"""CycloneDX SBOM connector: the document is stored as-is; the subject
(image/application) becomes an Asset so findings from a later scan reconcile
to the same asset id.

Components are *not* turned into assets — that explodes the graph. They are
queryable through the stored SBOM (Phase 1: new-CVE matching).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cernus_core.model import Asset, EvidenceRecord, IngestBatch, Sbom, Source, new_id
from cernus_core.plugins import Connector, register_connector

from .trivy import normalize_ref


@register_connector
class CycloneDXConnector(Connector):
    name = "cyclonedx"
    description = "CycloneDX JSON SBOMs (syft, trivy, cdxgen, …)"
    tools = ("syft", "trivy", "cdxgen")

    def detect(self, path: Path, document: dict[str, Any] | None = None) -> bool:
        return bool(document) and document.get("bomFormat") == "CycloneDX"

    def ingest(
        self, path: Path, document: dict[str, Any] | None = None, **context: Any
    ) -> IngestBatch:
        doc = document if document is not None else json.loads(path.read_text())
        meta = doc.get("metadata") or {}
        tools = _tool_names(meta)
        source = Source(tool=tools[0] if tools else "cyclonedx", connector=self.name)
        batch = IngestBatch(source=source)

        subject = meta.get("component") or {}
        name = subject.get("name") or path.stem
        version = subject.get("version")
        ref = f"{name}:{version}" if version else name
        kind = {"container": "container_image", "application": "service"}.get(
            subject.get("type", ""), "other"
        )
        digest = _digest(subject)
        facet = normalize_ref(ref) if kind == "container_image" else (subject.get("purl") or ref)
        asset_id = context.get("asset_id") or Asset.id_for(kind, facet)
        if not context.get("asset_id"):
            identifiers = (
                {"image_ref": ref}
                if kind == "container_image"
                else {"purl": subject.get("purl", ref)}
            )
            if digest:
                identifiers["digest"] = digest
            batch.assets.append(
                Asset(
                    id=asset_id,
                    asset_kind=kind,
                    name=ref,
                    identifiers=identifiers,
                    system_id=context.get("system_id"),
                    deployment_id=context.get("deployment_id"),
                    environment=context.get("environment", "unknown"),
                    source=source,
                )
            )

        sbom_id = f"sbom_{doc.get('serialNumber', new_id('x'))}".replace("urn:uuid:", "")
        batch.sboms.append(
            Sbom(id=sbom_id, format="cyclonedx-json", document=doc, asset_id=asset_id)
        )
        components = doc.get("components") or []
        batch.evidence.append(
            EvidenceRecord(
                id=new_id("ev"),
                record_kind="sbom",
                subject_kind="asset",
                subject_id=asset_id,
                produced_by=" ".join(tools) or "cyclonedx",
                summary=f"SBOM for {ref}: {len(components)} components",
                payload={
                    "sbom_id": sbom_id,
                    "spec_version": doc.get("specVersion"),
                    "component_count": len(components),
                    "timestamp": meta.get("timestamp"),
                },
            )
        )
        return batch


def _tool_names(meta: dict[str, Any]) -> list[str]:
    tools = meta.get("tools")
    names: list[str] = []
    if isinstance(tools, dict):  # CycloneDX 1.5+
        for c in tools.get("components") or []:
            names.append(f"{c.get('name')} {c.get('version', '')}".strip())
    elif isinstance(tools, list):  # 1.4
        for t in tools:
            names.append(f"{t.get('name')} {t.get('version', '')}".strip())
    return names


def _digest(component: dict[str, Any]) -> str | None:
    for h in component.get("hashes") or []:
        if h.get("alg", "").upper().startswith("SHA-256"):
            return h.get("content")
    purl = component.get("purl") or ""
    if "sha256" in purl:
        return purl.split("sha256")[-1].lstrip(":%3A")[:64]
    return None
