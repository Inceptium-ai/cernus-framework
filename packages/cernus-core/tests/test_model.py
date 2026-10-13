from __future__ import annotations

from cernus_core import validate
from cernus_core.model import Asset, Component, Finding, Severity, Source, Vuln


def _finding(**kw) -> Finding:
    base = dict(
        id="fnd_x",
        title="CVE-1 in foo",
        severity="HIGH",
        source=Source(tool="trivy"),
        vuln=Vuln(id="CVE-1"),
        component=Component(name="foo", purl="pkg:deb/foo@1", version="1"),
        asset_id="asset_a",
    )
    base.update(kw)
    return Finding(**base)


def test_severity_parse_aliases():
    assert Severity.parse("CRITICAL") is Severity.CRITICAL
    assert Severity.parse("Moderate") is Severity.MEDIUM
    assert Severity.parse("negligible") is Severity.INFO
    assert Severity.parse(None) is Severity.INFO
    assert Severity.HIGH.rank > Severity.MEDIUM.rank


def test_fingerprint_stable_across_cosmetic_changes():
    a = _finding()
    b = _finding(
        id="fnd_y", title="different wording", severity="low", first_seen="2020-01-01T00:00:00Z"
    )
    assert a.fingerprint == b.fingerprint


def test_fingerprint_changes_with_asset_or_issue():
    a = _finding()
    assert _finding(asset_id="asset_b").fingerprint != a.fingerprint
    assert _finding(vuln=Vuln(id="CVE-2")).fingerprint != a.fingerprint


def test_to_dict_validates_and_hides_raw():
    f = _finding(raw={"secret": "x"})
    d = f.to_dict()
    assert validate(d) == []
    assert "raw" not in d
    assert f.to_dict(include_raw=True)["raw"] == {"secret": "x"}


def test_asset_id_deterministic():
    assert Asset.id_for("container_image", "python:3.12") == Asset.id_for(
        "container_image", "python:3.12"
    )
    assert Asset.id_for("container_image", "python:3.12") != Asset.id_for("service", "python:3.12")


def test_enriched_vuln_doc_round_trips():
    """kev/epss merged into doc.vuln must survive validate + finding_from_dict
    (the contract is additionalProperties:false, so only these two may be added)."""
    from cernus_core import validate
    from cernus_core.serialize import finding_from_dict

    f = _finding(vuln=Vuln(id="CVE-2019-8457", kev=True, epss=0.97123))
    d = f.to_dict()
    assert d["vuln"]["kev"] is True and d["vuln"]["epss"] == 0.97123
    assert validate(d) == []
    back = finding_from_dict(d)
    assert back.vuln.kev is True and back.vuln.epss == 0.97123
