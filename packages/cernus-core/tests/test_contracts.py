from __future__ import annotations

import json

from cernus_core import contracts_dir, validate
from cernus_core.contracts import KINDS


def test_every_kind_has_a_schema_file():
    for name in KINDS.values():
        assert (contracts_dir() / name).is_file(), name


def test_schemas_are_draft_2020_and_have_ids():
    for path in contracts_dir().glob("*.schema.json"):
        s = json.loads(path.read_text())
        assert s["$schema"].endswith("2020-12/schema"), path.name
        assert s["$id"].startswith("https://cernus.ai/schemas/"), path.name


def test_validate_unknown_kind():
    assert validate({"kind": "Nope"}) == [
        "(root): unknown kind 'Nope'; expected one of " + str(sorted(KINDS))
    ]


def test_finding_minimal_valid_and_invalid():
    good = {
        "apiVersion": "cernus.ai/v0",
        "kind": "Finding",
        "id": "fnd_1",
        "fingerprint": "abc",
        "title": "t",
        "severity": "high",
        "source": {"tool": "trivy"},
        "status": "open",
        "first_seen": "2026-08-23T00:00:00Z",
        "last_seen": "2026-08-23T00:00:00Z",
    }
    assert validate(good) == []
    bad = {**good, "severity": "urgent", "extra": 1}
    errors = validate(bad)
    assert any("severity" in e for e in errors)
    assert any("extra" in e for e in errors)
