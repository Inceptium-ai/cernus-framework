from __future__ import annotations

import pytest
from cernus_core.model import Asset, Component, Finding, Source, System, Vuln
from cernus_core.policy import PolicySet

POLICY = {
    "apiVersion": "cernus.ai/v0",
    "kind": "PolicySet",
    "id": "p",
    "name": "t",
    "version": 1,
    "status": "approved",
    "rules": [
        {
            "id": "crit-prod",
            "priority": 10,
            "action": "escalate",
            "criteria": [
                {"field": "severity", "match": "exact", "pattern": "critical"},
                {"field": "asset.environment", "match": "exact", "pattern": "production"},
            ],
            "params": {"to": "{system.owner}"},
            "reason": "critical {vuln.id} on {asset.name}",
        },
        {
            "id": "fixable",
            "priority": 20,
            "action": "set_autonomy",
            "criteria": [{"field": "component.fixed_version", "match": "exists", "pattern": None}],
            "params": {"autonomy_level": 4},
        },
        {
            "id": "cvss-high",
            "priority": 30,
            "action": "classify",
            "criteria": [{"field": "vuln.cvss", "match": "gte", "pattern": 7}],
            "params": {"queue": "q"},
        },
        {
            "id": "disabled",
            "priority": 5,
            "enabled": False,
            "action": "suppress",
            "criteria": [{"field": "title", "match": "exists", "pattern": None}],
        },
    ],
}


def _f(**kw):
    base = dict(
        id="f",
        title="x",
        severity="critical",
        source=Source(tool="t"),
        vuln=Vuln(id="CVE-9", cvss=9.8),
        component=Component(name="c"),
        asset_id="a",
        system_id="s",
    )
    base.update(kw)
    return Finding(**base)


def test_first_match_by_priority_and_templating():
    p = PolicySet.from_dict(POLICY)
    asset = Asset(id="a", asset_kind="service", name="api", environment="production", system_id="s")
    system = System(id="s", name="svc", owner="team-a")
    d = p.evaluate(_f(), asset, system)
    assert d.rule_id == "crit-prod" and d.action == "escalate"
    assert d.params == {"to": "team-a"}
    assert d.reason == "critical CVE-9 on api"
    assert d.confidence == 1.0


def test_disabled_rule_skipped_and_fallthrough():
    p = PolicySet.from_dict(POLICY)
    d = p.evaluate(
        _f(component=Component(name="c", fixed_version="2"))
    )  # not prod → skips crit-prod
    assert d.rule_id == "fixable" and d.params["autonomy_level"] == 4


def test_numeric_and_unmatched():
    p = PolicySet.from_dict(POLICY)
    assert p.evaluate(_f(severity="low")).rule_id == "cvss-high"
    d = p.evaluate(_f(severity="low", vuln=Vuln(id="CVE-1", cvss=2.0)))
    assert d.action == "unmatched" and d.rule_id is None


def test_evaluate_all_joins_by_ids_and_roundtrip():
    p = PolicySet.from_dict(POLICY)
    assets = {
        "a": Asset(
            id="a", asset_kind="service", name="api", environment="production", system_id="s"
        )
    }
    systems = {"s": System(id="s", name="svc", owner="o")}
    out = p.evaluate_all(
        [_f(), _f(id="g", severity="low", vuln=Vuln(id="CVE-1", cvss=1))], assets, systems
    )
    assert [d.action for d in out] == ["escalate", "unmatched"]
    assert PolicySet.from_dict(p.to_dict()).to_dict() == p.to_dict()


def test_invalid_policy_rejected():
    with pytest.raises(ValueError):
        PolicySet.from_dict(
            {**POLICY, "rules": [{"id": "x", "priority": 1, "action": "nuke", "criteria": []}]}
        )
