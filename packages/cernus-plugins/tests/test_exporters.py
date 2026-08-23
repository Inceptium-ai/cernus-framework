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
