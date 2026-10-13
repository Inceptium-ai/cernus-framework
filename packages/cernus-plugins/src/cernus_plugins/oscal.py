"""OSCAL exporter.

Writes minimal, schema-shaped **OSCAL 1.1.x** documents:

- ``oscal-poam`` — Plan of Action and Milestones from open findings. Each
  finding becomes one ``poam-item`` with an ``observation`` (scanner evidence)
  and a ``risk`` (severity + remediation). Pass ``category_controls``
  ({category: [control ids]}) to stamp ``related-control`` props per item
  (OSCAL 1.1 has no first-class related-controls on poam-items).
- ``oscal-assessment-results`` — from ControlResult dicts.
- ``oscal-ssp`` — System Security Plan whose control-implementation sections
  come from a generated artifact (``options["sections"]``). Fields Cernus does
  not hold (authorization boundary, users) are emitted as explicit placeholders
  marked with ``cernus-needs-review`` props — loud honesty over omission.

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
    description = "OSCAL 1.1 POA&M, assessment results, and SSP"
    formats = ("oscal-poam", "oscal-assessment-results", "oscal-ssp")

    def export(self, fmt: str, batch: IngestBatch, out: Path, **options: Any) -> Path:
        if fmt == "oscal-assessment-results":
            return self._assessment_results(batch, out, **options)
        if fmt == "oscal-ssp":
            return self._ssp(batch, out, **options)
        if fmt != "oscal-poam":
            raise ValueError(f"oscal exporter does not produce {fmt!r}")
        system_name = options.get("system_name") or (
            batch.systems[0].name if batch.systems else "unnamed-system"
        )
        system_id = options.get("system_id") or (
            batch.systems[0].id if batch.systems else "unknown"
        )
        open_findings = [f for f in batch.findings if f.status.value == "open"]
        category_controls: dict[str, list[str]] = options.get("category_controls") or {}

        observations, risks, items = [], [], []
        for f in open_findings:
            obs_uuid = _uuid(f"obs/{f.fingerprint}")
            risk_uuid = _uuid(f"risk/{f.fingerprint}")
            observations.append(_observation(f, obs_uuid))
            risks.append(_risk(f, risk_uuid, obs_uuid))
            category = getattr(f.category, "value", f.category)
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
                        *(
                            {
                                "name": "related-control",
                                "ns": "https://cernus.ai/ns/oscal",
                                "value": control_id,
                            }
                            for control_id in category_controls.get(category, [])
                        ),
                    ],
                    "related-observations": [{"observation-uuid": obs_uuid}],
                    "related-risks": [{"risk-uuid": risk_uuid}],
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
                        "reviewed-controls": {
                            "control-selections": [
                                {
                                    "include-controls": [
                                        {"control-id": r["control_id"]} for r in results
                                    ]
                                }
                                if results
                                else {"include-all": {}}
                            ]
                        },
                        "findings": findings,
                    }
                ],
            }
        }
        out.write_text(json.dumps(doc, indent=2))
        return out

    def _ssp(self, batch: IngestBatch, out: Path, **options: Any) -> Path:
        """OSCAL System Security Plan from a generated SSP artifact.

        Options: ``sections`` ({control_id: {narrative, origin, needs_review,
        status_claim, evidence_ids}}), ``baseline``, ``profile_href``,
        ``version`` (artifact version), ``sensitivity`` (data classification),
        ``description``, ``owner``, ``components`` (dicts with id/name/kind/
        description). Schema-required fields Cernus cannot know are emitted as
        placeholders with ``cernus-needs-review`` props.
        """
        system_name = options.get("system_name") or (
            batch.systems[0].name if batch.systems else "unnamed-system"
        )
        system_id = options.get("system_id") or (
            batch.systems[0].id if batch.systems else "unknown"
        )
        sections: dict[str, dict[str, Any]] = options.get("sections") or {}
        sensitivity = options.get("sensitivity") or "moderate"
        baseline = options.get("baseline") or "moderate"
        version = str(options.get("version") or 1)
        owner = options.get("owner") or "System owner"
        ns = "https://cernus.ai/ns/oscal"

        needs_review_prop = {"name": "cernus-needs-review", "ns": ns, "value": "true"}
        components = [
            {
                "uuid": _uuid(f"asset/{c['id']}"),
                "type": c.get("kind") or "software",
                "title": c.get("name") or c["id"],
                "description": c.get("description") or c.get("name") or c["id"],
                "status": {"state": "operational"},
            }
            for c in options.get("components") or []
        ] or [
            {
                "uuid": _uuid(f"asset/{system_id}/placeholder"),
                "type": "this-system",
                "title": system_name,
                "description": "System component inventory pending ingest.",
                "props": [needs_review_prop],
                "status": {"state": "operational"},
            }
        ]

        implemented = []
        for control_id, s in sorted(sections.items()):
            props = [
                {"name": "cernus-origin", "ns": ns, "value": s.get("origin", "ai_draft")},
                {
                    "name": "implementation-status",
                    "ns": ns,
                    "value": s.get("status_claim", "planned"),
                },
            ]
            if s.get("needs_review"):
                props.append(needs_review_prop)
            # OSCAL statements carry prose in `remarks` (no `description`
            # field), and `links` must be omitted when empty.
            statement: dict[str, Any] = {
                "statement-id": f"{control_id.lower()}_smt",
                "uuid": _uuid(f"ssp-smt/{system_id}/{control_id}/{version}"),
                "remarks": s.get("narrative", ""),
            }
            evidence_links = [
                {"href": f"urn:cernus:evidence:{ev}", "rel": "evidence"}
                for ev in s.get("evidence_ids") or []
            ]
            if evidence_links:
                statement["links"] = evidence_links
            implemented.append(
                {
                    "uuid": _uuid(f"ssp-req/{system_id}/{control_id}/{version}"),
                    "control-id": control_id,
                    "props": props,
                    "statements": [statement],
                }
            )

        doc = {
            "system-security-plan": {
                "uuid": _uuid(f"ssp/{system_id}/{version}"),
                "metadata": {
                    "title": f"System Security Plan — {system_name}",
                    "last-modified": now_iso(),
                    "version": version,
                    "oscal-version": OSCAL_VERSION,
                    "props": [{"name": "generator", "ns": ns, "value": "cernus"}],
                },
                "import-profile": {
                    "href": options.get("profile_href")
                    or f"urn:cernus:baseline:nist-800-53r5:{baseline}"
                },
                "system-characteristics": {
                    "system-ids": [
                        {"identifier-type": "https://cernus.ai/ns/system-id", "id": system_id}
                    ],
                    "system-name": system_name,
                    "description": options.get("description") or system_name,
                    "security-sensitivity-level": sensitivity,
                    "system-information": {
                        "information-types": [
                            {
                                "uuid": _uuid(f"ssp-info/{system_id}"),
                                "title": f"{system_name} data",
                                "description": f"Data classification: {sensitivity}.",
                            }
                        ]
                    },
                    "security-impact-level": {
                        "security-objective-confidentiality": baseline,
                        "security-objective-integrity": baseline,
                        "security-objective-availability": baseline,
                    },
                    "status": {"state": "operational"},
                    "authorization-boundary": {
                        "description": (
                            "Authorization boundary description pending operator input — "
                            "Cernus does not infer boundaries."
                        ),
                        "props": [needs_review_prop],
                    },
                },
                "system-implementation": {
                    "users": [
                        {
                            "uuid": _uuid(f"ssp-user/{system_id}"),
                            "title": owner,
                            "role-ids": ["system-owner"],
                        }
                    ],
                    "components": components,
                },
                "control-implementation": {
                    "description": (
                        "Control narratives generated by Cernus from live runtime state; "
                        "sections marked cernus-needs-review await operator confirmation."
                    ),
                    "implemented-requirements": implemented,
                },
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
