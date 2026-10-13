"""Validate every emitted OSCAL document against the official NIST schemas.

The vendored schemas under ``fixtures/oscal-schemas/`` are the v1.1.2 release
artifacts from usnistgov/OSCAL — the exact version our documents declare.
This is what a 3PAO's tooling checks first; it runs in CI on every change to
the exporter.
"""

from __future__ import annotations

import json
from pathlib import Path

import cernus_plugins  # noqa: F401
import jsonschema
import pytest
from cernus_core.ingest import ingest_path
from cernus_core.plugins import exporter_for_format

SCHEMAS = Path(__file__).parent / "fixtures" / "oscal-schemas"


def _pythonize_patterns(node):
    """NIST's schemas use XML-regex ``\\p{L}``/``\\p{N}`` classes, which
    Python's ``re`` rejects. Translate to equivalent Python classes (our
    emitted values are ASCII tokens, well inside both)."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "pattern" and isinstance(v, str):
                node[k] = v.replace(r"\p{L}", r"[^\W\d_]").replace(r"\p{N}", r"\d")
            else:
                _pythonize_patterns(v)
    elif isinstance(node, list):
        for v in node:
            _pythonize_patterns(v)


def _validate(doc: dict, model: str) -> None:
    schema = json.loads((SCHEMAS / f"oscal_{model}_schema.json").read_text())
    _pythonize_patterns(schema)
    validator = jsonschema.Draft7Validator(schema)
    errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path))
    if errors:
        details = "\n".join(
            f"  at {'/'.join(str(p) for p in e.absolute_path)}: {e.message[:200]}"
            for e in errors[:10]
        )
        pytest.fail(f"{model} document fails official OSCAL {model} schema:\n{details}")


@pytest.fixture
def batch(fixtures):
    return ingest_path(fixtures / "genesis-workspace")


def test_poam_validates(batch, tmp_path):
    out = exporter_for_format("oscal-poam").export(
        "oscal-poam",
        batch,
        tmp_path / "poam.json",
        category_controls={"vulnerability": ["RA-5", "SI-2"]},
    )
    _validate(json.loads(out.read_text()), "poam")


def test_assessment_results_validate(batch, tmp_path):
    results = [
        {
            "catalog": "nist-800-53r5",
            "control_id": "RA-5",
            "status": "satisfied",
            "rationale": "scan fresh",
            "evaluated_at": "2026-10-06T00:00:00Z",
            "evaluator": "rule:scan_fresh",
        },
        {
            "catalog": "nist-800-53r5",
            "control_id": "SI-2",
            "status": "partial",
            "rationale": "1 overdue",
            "evaluated_at": "2026-10-06T00:00:00Z",
            "evaluator": "rule:sla_met",
        },
    ]
    out = exporter_for_format("oscal-assessment-results").export(
        "oscal-assessment-results", batch, tmp_path / "ar.json", control_results=results
    )
    _validate(json.loads(out.read_text()), "assessment-results")


def test_ssp_validates(batch, tmp_path):
    sections = {
        "RA-5": {
            "narrative": "We scan continuously.",
            "origin": "grounded",
            "needs_review": False,
            "status_claim": "implemented",
            "evidence_ids": ["ev_abc"],
        },
        "AC-1": {
            "narrative": "Draft policy narrative.",
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
        version=1,
        components=[{"id": "a1", "name": "api", "kind": "software"}],
        owner="customer-platform",
    )
    _validate(json.loads(out.read_text()), "ssp")


def test_ssp_validates_with_placeholder_component(batch, tmp_path):
    """The no-assets fallback path must also be schema-valid."""
    out = exporter_for_format("oscal-ssp").export(
        "oscal-ssp",
        batch,
        tmp_path / "ssp.json",
        sections={
            "RA-5": {
                "narrative": "x",
                "origin": "grounded",
                "needs_review": False,
                "status_claim": "implemented",
                "evidence_ids": [],
            }
        },
        baseline="low",
    )
    _validate(json.loads(out.read_text()), "ssp")
