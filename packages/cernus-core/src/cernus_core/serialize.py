"""Round-trip IngestBatch <-> dict/JSON. ``to_dict`` lives on the dataclasses;
this module is the inverse, kept separate so the model stays declarative."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .contracts import assert_valid
from .model import (
    Asset,
    Component,
    Deployment,
    EvidenceRecord,
    Finding,
    IngestBatch,
    Sbom,
    Source,
    System,
    Vuln,
)

_META = {"apiVersion", "kind"}


def _clean(d: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in d.items() if k not in _META}


def source_from_dict(d: dict[str, Any] | None) -> Source | None:
    return Source(**d) if d else None


def finding_from_dict(d: dict[str, Any]) -> Finding:
    d = _clean(d)
    d["source"] = Source(**d["source"])
    if d.get("vuln"):
        d["vuln"] = Vuln(**d["vuln"])
    if d.get("component"):
        d["component"] = Component(**d["component"])
    return Finding(**d)


def asset_from_dict(d: dict[str, Any]) -> Asset:
    d = _clean(d)
    d["source"] = source_from_dict(d.get("source"))
    return Asset(**d)


def system_from_dict(d: dict[str, Any]) -> System:
    return System(**_clean(d))


def deployment_from_dict(d: dict[str, Any]) -> Deployment:
    d = _clean(d)
    d["source"] = source_from_dict(d.get("source"))
    return Deployment(**d)


def evidence_from_dict(d: dict[str, Any]) -> EvidenceRecord:
    return EvidenceRecord(**_clean(d))


def batch_from_dict(d: dict[str, Any], validate: bool = True) -> IngestBatch:
    if validate:
        assert_valid(d, "IngestBatch")
    return IngestBatch(
        source=Source(**d["source"]),
        produced_at=d["produced_at"],
        systems=[system_from_dict(x) for x in d.get("systems", [])],
        deployments=[deployment_from_dict(x) for x in d.get("deployments", [])],
        assets=[asset_from_dict(x) for x in d.get("assets", [])],
        findings=[finding_from_dict(x) for x in d.get("findings", [])],
        sboms=[Sbom(**x) for x in d.get("sboms", [])],
        evidence=[evidence_from_dict(x) for x in d.get("evidence", [])],
    )


def read_batch(path: Path) -> IngestBatch:
    return batch_from_dict(json.loads(path.read_text()))


def write_batch(
    batch: IngestBatch, path: Path, include_raw: bool = False, validate: bool = True
) -> Path:
    doc = batch.to_dict(include_raw=include_raw)
    if validate:
        assert_valid(doc, "IngestBatch")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2))
    return path
