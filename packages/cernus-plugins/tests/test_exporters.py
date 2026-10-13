from __future__ import annotations

import json

import cernus_plugins  # noqa: F401
from cernus_core.ingest import ingest_path
from cernus_core.plugins import exporter_for_format


def test_sarif_roundtrip(fixtures, tmp_path):
    batch = ingest_path(fixtures / "trivy-python.json")
    out = exporter_for_format("sarif").export("sarif", batch, tmp_path / "o.sarif")
    doc = json.loads(out.read_text())
    assert doc["version"] == "2.1.0" and doc["runs"][0]["tool"]["driver"]["name"] == "trivy"
    assert len(doc["runs"][0]["results"]) == len(batch.findings)
    back = ingest_path(out)
    assert len(back.findings) == len(batch.findings)


def test_oscal_poam(fixtures, tmp_path):
    batch = ingest_path(fixtures / "genesis-workspace")
    out = exporter_for_format("oscal-poam").export("oscal-poam", batch, tmp_path / "poam.json")
    poam = json.loads(out.read_text())["plan-of-action-and-milestones"]
    assert poam["metadata"]["oscal-version"].startswith("1.1")
    assert poam["system-id"]["id"] == batch.systems[0].id
    assert len(poam["poam-items"]) == len(poam["risks"]) == len(poam["observations"]) == 3
    risk = poam["risks"][0]
    sla = next(p["value"] for p in risk["props"] if p["name"] == "remediation-sla-days")
    assert sla in {"30", "90", "180"}
    assert risk["remediations"][0]["description"]


def test_oscal_assessment_results(fixtures, tmp_path):
    batch = ingest_path(fixtures / "genesis-workspace")
    results = [
        {
            "catalog": "nist-800-53r5",
            "control_id": "RA-5",
            "status": "satisfied",
            "rationale": "fresh",
            "evaluated_at": "2026-08-23T00:00:00Z",
            "evaluator": "rule:scan_fresh",
            "title": "Vulnerability Monitoring",
        },
        {
            "catalog": "nist-800-53r5",
            "control_id": "SI-2",
            "status": "partial",
            "rationale": "due soon",
            "evaluated_at": "2026-08-23T00:00:00Z",
            "evaluator": "rule:sla_met",
        },
    ]
    out = exporter_for_format("oscal-assessment-results").export(
        "oscal-assessment-results", batch, tmp_path / "ar.json", control_results=results
    )
    ar = json.loads(out.read_text())["assessment-results"]
    f = ar["results"][0]["findings"]
    assert [x["target"]["status"]["state"] for x in f] == ["satisfied", "not-satisfied"]
    assert f[1]["target"]["props"][0]["value"] == "partial"


def test_oscal_ssp(fixtures, tmp_path):
    batch = ingest_path(fixtures / "genesis-workspace")
    sections = {
        "RA-5": {
            "narrative": "We scan continuously via the Cernus scheduler.",
            "origin": "grounded",
            "needs_review": False,
            "status_claim": "implemented",
            "evidence_ids": ["ev_abc123"],
        },
        "AC-1": {
            "narrative": "Draft access-control policy narrative.",
            "origin": "ai_draft",
            "needs_review": True,
            "status_claim": "planned",
            "evidence_ids": [],
        },
    }
    out = exporter_for_format("oscal-ssp").export(
        "oscal-ssp",
        batch,
        tmp_path / "ssp.json",
        sections=sections,
        baseline="moderate",
        sensitivity="confidential",
        version=2,
        components=[{"id": "a1", "name": "api", "kind": "software"}],
        owner="customer-platform",
    )
    ssp = json.loads(out.read_text())["system-security-plan"]

    # Schema-required skeleton present.
    assert ssp["metadata"]["oscal-version"].startswith("1.1")
    assert ssp["import-profile"]["href"]
    chars = ssp["system-characteristics"]
    assert chars["security-sensitivity-level"] == "confidential"
    assert chars["system-information"]["information-types"]
    assert chars["security-impact-level"]["security-objective-confidentiality"] == "moderate"
    assert "needs-review" in str(chars["authorization-boundary"]["props"])
    impl = ssp["system-implementation"]
    assert impl["users"] and impl["components"][0]["title"] == "api"

    reqs = {r["control-id"]: r for r in ssp["control-implementation"]["implemented-requirements"]}
    assert set(reqs) == {"RA-5", "AC-1"}
    ra5 = reqs["RA-5"]
    assert ra5["statements"][0]["remarks"].startswith("We scan")
    assert ra5["statements"][0]["links"][0]["href"] == "urn:cernus:evidence:ev_abc123"
    assert "links" not in reqs["AC-1"]["statements"][0]  # empty links omitted
    assert not any(p["name"] == "cernus-needs-review" for p in ra5["props"])
    assert any(p["name"] == "cernus-needs-review" for p in reqs["AC-1"]["props"])

    # Deterministic uuids: same inputs, same document.
    out2 = exporter_for_format("oscal-ssp").export(
        "oscal-ssp",
        batch,
        tmp_path / "ssp2.json",
        sections=sections,
        baseline="moderate",
        sensitivity="confidential",
        version=2,
        components=[{"id": "a1", "name": "api", "kind": "software"}],
        owner="customer-platform",
    )
    a, b = json.loads(out.read_text()), json.loads(out2.read_text())
    a["system-security-plan"]["metadata"].pop("last-modified")
    b["system-security-plan"]["metadata"].pop("last-modified")
    assert a == b


def test_oscal_poam_related_control_props(fixtures, tmp_path):
    batch = ingest_path(fixtures / "genesis-workspace")
    out = exporter_for_format("oscal-poam").export(
        "oscal-poam",
        batch,
        tmp_path / "poam.json",
        category_controls={"vulnerability": ["RA-5", "SI-2"], "sast": ["SA-11(1)"]},
    )
    poam = json.loads(out.read_text())["plan-of-action-and-milestones"]
    related = [
        p["value"]
        for item in poam["poam-items"]
        for p in item["props"]
        if p["name"] == "related-control"
    ]
    assert related  # at least one finding category mapped
    assert set(related) <= {"RA-5", "SI-2", "SA-11(1)"}
