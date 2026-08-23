"""Ingest orchestration: pick a connector, run it, merge and dedup the result."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .model import Asset, Finding, IngestBatch
from .plugins import CONNECTOR_REGISTRY, Connector, get_connector, load_plugins


def _load_document(path: Path) -> dict[str, Any] | None:
    if path.is_file() and path.suffix.lower() in {".json", ".sarif", ".cdx"}:
        try:
            with path.open() as fh:
                doc = json.load(fh)
            return doc if isinstance(doc, dict) else None
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
    return None


def detect_connector(path: Path, document: dict[str, Any] | None = None) -> Connector | None:
    """First registered connector whose ``detect`` accepts the input."""
    load_plugins()
    for cls in CONNECTOR_REGISTRY.values():
        conn = cls()
        try:
            if conn.detect(path, document):
                return conn
        except Exception:
            continue
    return None


def ingest_path(path: Path, connector: str = "auto", **context: Any) -> IngestBatch:
    """Normalize one file/dir into an IngestBatch.

    Raises ``LookupError`` when no connector recognizes the input.
    """
    document = _load_document(path)
    if connector == "auto":
        conn = detect_connector(path, document)
        if conn is None:
            raise LookupError(
                f"no connector recognizes {path}; pass --connector <name> "
                f"(available: {sorted(CONNECTOR_REGISTRY)})"
            )
    else:
        conn = get_connector(connector)
    batch = conn.ingest(path, document, **context)
    return normalize(batch)


def normalize(batch: IngestBatch) -> IngestBatch:
    """Dedup findings and assets in place; return the batch for chaining."""
    batch.findings = dedupe(batch.findings)
    batch.assets = dedupe_assets(batch.assets)
    return batch


def dedupe_assets(assets: list[Asset]) -> list[Asset]:
    """Collapse assets with the same id, unioning identifiers/tags and keeping
    the most specific linkage (system/deployment/environment/owner)."""
    merged: dict[str, Asset] = {}
    for a in assets:
        cur = merged.get(a.id)
        if cur is None:
            merged[a.id] = a
            continue
        cur.identifiers = {**a.identifiers, **cur.identifiers}
        cur.tags = sorted(set(cur.tags) | set(a.tags))
        cur.system_id = cur.system_id or a.system_id
        cur.deployment_id = cur.deployment_id or a.deployment_id
        cur.owner = cur.owner or a.owner
        if cur.environment == "unknown":
            cur.environment = a.environment
        if cur.data_classification == "unknown":
            cur.data_classification = a.data_classification
        if cur.internet_facing is None:
            cur.internet_facing = a.internet_facing
    return list(merged.values())


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse findings with the same fingerprint, keeping the earliest
    ``first_seen`` and latest ``last_seen`` and the highest severity."""
    merged: dict[str, Finding] = {}
    for f in findings:
        cur = merged.get(f.fingerprint)
        if cur is None:
            merged[f.fingerprint] = f
            continue
        cur.first_seen = min(cur.first_seen, f.first_seen)
        cur.last_seen = max(cur.last_seen, f.last_seen)
        if f.severity.rank > cur.severity.rank:
            cur.severity = f.severity
        if not cur.remediation and f.remediation:
            cur.remediation = f.remediation
        if cur.component and f.component and not cur.component.fixed_version:
            cur.component.fixed_version = f.component.fixed_version
    return list(merged.values())
