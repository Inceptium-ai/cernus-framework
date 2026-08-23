"""OSCAL exporter — Phase 0 skeleton.

Writes a minimal, schema-shaped **OSCAL 1.1.x Plan of Action and Milestones**
from open findings. Each finding becomes one ``poam-item`` with an
``observation`` carrying the scanner evidence and a ``risk`` carrying severity
and remediation. Control mapping (``related-controls``) is filled in Phase 2
when the gate/finding → 800-53 crosswalk lands.

Validation against the official OSCAL JSON Schema is available through the
optional ``compliance-trestle`` extra; this module does not depend on it.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from cernus_core.model import Finding, IngestBatch, now_iso
from cernus_core.plugins import Exporter, register_exporter

OSCAL_VERSION = "1.1.2"

# FedRAMP remediation windows by severity, in days (Rev 5 ConMon guidance).
FEDRAMP_SLA_DAYS = {"critical": 30, "high": 30, "medium": 90, "low": 180, "info": 180}


def _uuid(seed: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"https://cernus.ai/oscal/{seed}"))


@register_exporter
class OscalExporter(Exporter):
    name = "oscal"
    description = "OSCAL 1.1 Plan of Action & Milestones from open findings"
    formats = ("oscal-poam", "oscal-assessment-results")

    def export(self, fmt: str, batch: IngestBatch, out: Path, **options: Any) -> Path:
        if fmt == "oscal-assessment-results":
            return self._assessment_results(batch, out, **options)
        if fmt != "oscal-poam":
            raise ValueError(f"oscal exporter does not produce {fmt!r}")
        system_name = options.get("system_name") or (
            batch.systems[0].name if batch.systems else "unnamed-system"
        )
        system_id = options.get("system_id") or (
            batch.systems[0].id if batch.systems else "unknown"
        )
        open_findings = [f for f in batch.findings if f.status.value == "open"]

        observations, risks, items = [], [], []
        for f in open_findings:
            obs_uuid = _uuid(f"obs/{f.fingerprint}")
            risk_uuid = _uuid(f"risk/{f.fingerprint}")
            observations.append(_observation(f, obs_uuid))
            risks.append(_risk(f, risk_uuid, obs_uuid))
            items.append(
                {
                    "uuid": _uuid(f"item/{f.fingerprint}"),
                    "title": f.title,
                    "description": f.detail or f.title,
                    "props": [
                        {
                            "name": "cernus-finding-id",
                            "ns": "https://cernus.ai/ns/oscal",
                            "value": f.id,
                        },
                        {
                            "name": "cernus-fingerprint",
                            "ns": "https://cernus.ai/ns/oscal",
                            "value": f.fingerprint,
                        },
                    ],
                    "related-observations": [{"observation-uuid": obs_uuid}],
                    "associated-risks": [{"risk-uuid": risk_uuid}],
                }
            )

        doc = {
            "plan-of-action-and-milestones": {
                "uuid": _uuid(f"poam/{system_id}/{batch.produced_at}"),
                "metadata": {
                    "title": f"POA&M — {system_name}",
                    "last-modified": now_iso(),
                    "version": batch.produced_at,
                    "oscal-version": OSCAL_VERSION,
                    "props": [
                        {"name": "generator", "ns": "https://cernus.ai/ns/oscal", "value": "cernus"}
                    ],
                },
                "system-id": {"identifier-type": "https://cernus.ai/ns/system-id", "id": system_id},
                "observations": observations,
                "risks": risks,
                "poam-items": items,
            }
        }
        out.write_text(json.dumps(doc, indent=2))
        return out

    def _assessment_results(self, batch: IngestBatch, out: Path, **options: Any) -> Path:
        """OSCAL Assessment Results from Cernus ControlResults.

        ``options["control_results"]`` is a list of ControlResult dicts (the
        contract shape, optionally with ``title``/``statement``). Each becomes
        one ``finding`` with a ``target`` of type ``objective-id`` whose status
        is ``satisfied`` / ``not-satisfied``; partial and unknown map to
        ``not-satisfied`` with the Cernus status preserved as a prop.
        """
        results = list(options.get("control_results") or [])
        system_name = options.get("system_name") or (
            batch.systems[0].name if batch.systems else "unnamed-system"
        )
        system_id = options.get("system_id") or (
            batch.systems[0].id if batch.systems else "unknown"
        )
        catalog = results[0]["catalog"] if results else "nist-800-53r5"
        evaluated_at = results[0]["evaluated_at"] if results else now_iso()
        findings = []
        for r in results:
            implemented = r["status"] == "satisfied"
            findings.append(
                {
                    "uuid": _uuid(f"ar-finding/{system_id}/{r['control_id']}/{r['evaluated_at']}"),
                    "title": f"{r['control_id']} {r.get('title') or ''}".strip(),
                    "description": r.get("rationale") or r.get("statement") or r["control_id"],
                    "target": {
                        "type": "objective-id",
                        "target-id": r["control_id"],
                        "status": {"state": "satisfied" if implemented else "not-satisfied"},
                        "props": [
                            {
                                "name": "cernus-status",
                                "ns": "https://cernus.ai/ns/oscal",
                                "value": r["status"],
                            },
                            {
                                "name": "evaluator",
                                "ns": "https://cernus.ai/ns/oscal",
                                "value": r.get("evaluator", ""),
                            },
                        ],
                    },
                }
            )
        doc = {
            "assessment-results": {
                "uuid": _uuid(f"ar/{system_id}/{evaluated_at}"),
                "metadata": {
                    "title": f"Assessment Results — {system_name}",
                    "last-modified": now_iso(),
                    "version": evaluated_at,
                    "oscal-version": OSCAL_VERSION,
                    "props": [
                        {
                            "name": "generator",
                            "ns": "https://cernus.ai/ns/oscal",
                            "value": "cernus",
                        },
                        {"name": "catalog", "ns": "https://cernus.ai/ns/oscal", "value": catalog},
                    ],
                },
                "import-ap": {"href": f"urn:cernus:assessment-plan:{system_id}"},
                "results": [
                    {
                        "uuid": _uuid(f"ar-result/{system_id}/{evaluated_at}"),
                        "title": f"Continuous control evaluation ({catalog})",
                        "description": (
                            "Automated evaluation of runtime facts against the Cernus crosswalk."
                        ),
                        "start": evaluated_at,
                        "end": evaluated_at,
                        "findings": findings,
                    }
                ],
            }
        }
        out.write_text(json.dumps(doc, indent=2))
        return out


def _observation(f: Finding, obs_uuid: str) -> dict[str, Any]:
    subjects = []
    if f.asset_id:
        subjects.append({"subject-uuid": _uuid(f"asset/{f.asset_id}"), "type": "component"})
    return {
        "uuid": obs_uuid,
        "title": f.title,
        "description": f.detail or f.title,
        "methods": ["TEST"],
        "types": ["finding"],
        "origins": [{"actors": [{"type": "tool", "actor-uuid": _uuid(f"tool/{f.source.tool}")}]}],
        **({"subjects": subjects} if subjects else {}),
        "collected": f.last_seen,
        "props": [
            {"name": "tool", "ns": "https://cernus.ai/ns/oscal", "value": f.source.tool},
            *(
                [
                    {
                        "name": "vulnerability-id",
                        "ns": "https://cernus.ai/ns/oscal",
                        "value": f.vuln.id,
                    }
                ]
                if f.vuln
                else []
            ),
            *(
                [{"name": "location", "ns": "https://cernus.ai/ns/oscal", "value": f.location}]
                if f.location
                else []
            ),
        ],
    }


def _risk(f: Finding, risk_uuid: str, obs_uuid: str) -> dict[str, Any]:
    sev = f.severity.value
    props = [
        {"name": "severity", "ns": "https://cernus.ai/ns/oscal", "value": sev},
        {
            "name": "remediation-sla-days",
            "ns": "https://cernus.ai/ns/oscal",
            "value": str(FEDRAMP_SLA_DAYS[sev]),
        },
    ]
    if f.vuln and f.vuln.cvss is not None:
        props.append(
            {"name": "cvss-score", "ns": "https://cernus.ai/ns/oscal", "value": str(f.vuln.cvss)}
        )
    risk: dict[str, Any] = {
        "uuid": risk_uuid,
        "title": f.title,
        "description": f.detail or f.title,
        "statement": f"Open {sev} finding reported by {f.source.tool}.",
        "status": "open",
        "props": props,
        "related-observations": [{"observation-uuid": obs_uuid}],
    }
    if f.remediation:
        risk["remediations"] = [
            {
                "uuid": _uuid(f"rem/{f.fingerprint}"),
                "lifecycle": "planned",
                "title": "Remediate",
                "description": f.remediation,
            }
        ]
    return risk
