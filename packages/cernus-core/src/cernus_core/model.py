"""Canonical Cernus objects as dataclasses.

These mirror ``contracts/*.schema.json`` one-to-one. ``to_dict()`` produces the
exact wire shape (and is what gets validated); ``from_dict()`` is the inverse.
Keep them dumb: no I/O, no tool knowledge — that lives in plugins.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from .contracts import API_VERSION


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]

    @classmethod
    def parse(cls, value: str | None) -> Severity:
        """Tolerant parse of scanner severities (``CRITICAL``, ``Moderate``, ``negligible``…)."""
        v = (value or "").strip().lower()
        aliases = {
            "moderate": "medium",
            "important": "high",
            "negligible": "info",
            "unknown": "info",
            "none": "info",
            "informational": "info",
            "error": "high",
            "warning": "medium",
            "note": "low",
        }
        v = aliases.get(v, v)
        try:
            return cls(v)
        except ValueError:
            return cls.INFO


class FindingStatus(str, Enum):
    OPEN = "open"
    FIXED = "fixed"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false_positive"
    SUPPRESSED = "suppressed"


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def canonical_hash(obj: Any) -> str:
    """sha256 over canonical JSON — the evidence-ledger hash and fingerprint basis."""
    data = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(data).hexdigest()


def _strip_none(d: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}


@dataclass
class Source:
    tool: str
    version: str | None = None
    connector: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return _strip_none(asdict(self))


@dataclass
class System:
    id: str
    name: str
    owner: str | None = None
    criticality: str = "unknown"
    data_classification: str = "unknown"
    boundary_id: str | None = None
    genesis_project_id: str | None = None
    repository_url: str | None = None
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"apiVersion": API_VERSION, "kind": "System", **asdict(self)}


@dataclass
class Deployment:
    id: str
    system_id: str
    environment: str
    deployed_at: str
    deployed_by: str | None = None
    change_id: str | None = None
    artifact_refs: list[dict[str, Any]] = field(default_factory=list)
    sbom_ids: list[str] = field(default_factory=list)
    manifest: dict[str, Any] | None = None
    evidence: dict[str, Any] | None = None
    preview_url: str | None = None
    source: Source | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["source"] = self.source.to_dict() if self.source else None
        return {"apiVersion": API_VERSION, "kind": "Deployment", **_strip_none(d)}


@dataclass
class Asset:
    id: str
    asset_kind: str
    name: str
    identifiers: dict[str, str] = field(default_factory=dict)
    system_id: str | None = None
    deployment_id: str | None = None
    environment: str = "unknown"
    internet_facing: bool | None = None
    data_classification: str = "unknown"
    owner: str | None = None
    parent_id: str | None = None
    tags: list[str] = field(default_factory=list)
    source: Source | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["source"] = self.source.to_dict() if self.source else None
        return {"apiVersion": API_VERSION, "kind": "Asset", **_strip_none(d)}

    @staticmethod
    def id_for(kind: str, *facets: str) -> str:
        """Deterministic asset id from identity facets so re-ingest reconciles."""
        return f"asset_{canonical_hash([kind, *facets])[:16]}"


@dataclass
class Vuln:
    id: str
    cwe: list[str] = field(default_factory=list)
    cvss: float | None = None
    cvss_vector: str | None = None
    epss: float | None = None
    kev: bool | None = None
    published: str | None = None
    references: list[str] = field(default_factory=list)


@dataclass
class Component:
    name: str
    purl: str | None = None
    version: str | None = None
    fixed_version: str | None = None
    type: str | None = None


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    source: Source
    fingerprint: str = ""
    source_ref: str | None = None
    gate: str | None = None
    category: str = "vulnerability"
    detail: str | None = None
    location: str | None = None
    remediation: str | None = None
    vuln: Vuln | None = None
    component: Component | None = None
    asset_id: str | None = None
    deployment_id: str | None = None
    system_id: str | None = None
    scan_scope: str | None = None
    status: FindingStatus = FindingStatus.OPEN
    first_seen: str = field(default_factory=now_iso)
    last_seen: str = field(default_factory=now_iso)
    tags: list[str] = field(default_factory=list)
    raw: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if isinstance(self.severity, str):
            self.severity = Severity.parse(self.severity)
        if isinstance(self.status, str):
            self.status = FindingStatus(self.status)
        if not self.fingerprint:
            self.fingerprint = self.compute_fingerprint()

    def compute_fingerprint(self) -> str:
        """Stable identity of *this issue on this asset*.

        Built from what identifies the issue (vuln id or tool rule id) and where
        it lives (component purl, else location) and on which asset. Deliberately
        excludes severity, title wording, and timestamps so rescans match.
        """
        issue = (self.vuln.id if self.vuln else None) or self.source_ref or self.title
        where = (self.component.purl if self.component and self.component.purl else None) or (
            f"{self.component.name}@{self.component.version}" if self.component else self.location
        )
        return canonical_hash([self.source.tool, issue, where, self.asset_id])

    def to_dict(self, include_raw: bool = False) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["status"] = self.status.value
        d["source"] = self.source.to_dict()
        if self.vuln is not None:
            d["vuln"] = _strip_none(asdict(self.vuln))
        if self.component is not None:
            d["component"] = _strip_none(asdict(self.component))
        if not include_raw:
            d["raw"] = None
        return {"apiVersion": API_VERSION, "kind": "Finding", **_strip_none(d)}


@dataclass
class Sbom:
    id: str
    format: str
    document: dict[str, Any]
    asset_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return _strip_none(asdict(self))


@dataclass
class Decision:
    id: str
    finding_id: str
    actor: str
    action: str
    created_at: str = field(default_factory=now_iso)
    policy_set_id: str | None = None
    policy_set_version: int | None = None
    rule_id: str | None = None
    model: str | None = None
    actor_name: str | None = None
    params: dict[str, Any] = field(default_factory=dict)
    reason: str | None = None
    confidence: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"apiVersion": API_VERSION, "kind": "Decision", **_strip_none(asdict(self))}


@dataclass
class EvidenceRecord:
    id: str
    record_kind: str
    subject_kind: str
    subject_id: str
    produced_by: str
    payload: dict[str, Any] | None = None
    payload_ref: str | None = None
    summary: str | None = None
    hash: str = ""
    created_at: str = field(default_factory=now_iso)

    def __post_init__(self) -> None:
        if not self.hash:
            self.hash = canonical_hash(
                self.payload if self.payload is not None else self.payload_ref
            )

    def to_dict(self) -> dict[str, Any]:
        return {"apiVersion": API_VERSION, "kind": "EvidenceRecord", **_strip_none(asdict(self))}


@dataclass
class IngestBatch:
    """What a connector returns and what the server ingests."""

    source: Source
    produced_at: str = field(default_factory=now_iso)
    systems: list[System] = field(default_factory=list)
    deployments: list[Deployment] = field(default_factory=list)
    assets: list[Asset] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    sboms: list[Sbom] = field(default_factory=list)
    evidence: list[EvidenceRecord] = field(default_factory=list)

    def to_dict(self, include_raw: bool = False) -> dict[str, Any]:
        return {
            "apiVersion": API_VERSION,
            "kind": "IngestBatch",
            "source": self.source.to_dict(),
            "produced_at": self.produced_at,
            "systems": [s.to_dict() for s in self.systems],
            "deployments": [d.to_dict() for d in self.deployments],
            "assets": [a.to_dict() for a in self.assets],
            "findings": [f.to_dict(include_raw=include_raw) for f in self.findings],
            "sboms": [s.to_dict() for s in self.sboms],
            "evidence": [e.to_dict() for e in self.evidence],
        }

    def extend(self, other: IngestBatch) -> None:
        for name in ("systems", "deployments", "assets", "findings", "sboms", "evidence"):
            getattr(self, name).extend(getattr(other, name))

    def summary(self) -> dict[str, Any]:
        by_sev: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            by_sev[f.severity.value] += 1
        return {
            "systems": len(self.systems),
            "deployments": len(self.deployments),
            "assets": len(self.assets),
            "findings": len(self.findings),
            "sboms": len(self.sboms),
            "evidence": len(self.evidence),
            "by_severity": by_sev,
        }
