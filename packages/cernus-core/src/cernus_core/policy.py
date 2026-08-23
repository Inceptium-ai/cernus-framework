"""Deterministic triage policy engine.

Lineage: Auto-Triage's *criteria library → versioned configuration → rule*
model and its priority-ordered first-match-wins evaluation, generalized:

* A **criterion** is a predicate over a dotted field path into the finding
  joined with its asset and system (``severity``, ``vuln.id``,
  ``component.purl``, ``asset.environment``, ``system.criticality``).
* A **rule** ANDs criteria and names an action (``classify``, ``assign``,
  ``set_autonomy``, ``suppress``, ``accept``, ``escalate``).
* A **PolicySet** is an ordered, versioned, approvable bundle of rules.

Evaluation yields exactly one :class:`~cernus_core.model.Decision` per finding,
with the matched rule id and a rendered reason — or an ``unmatched`` decision,
which is the human-review queue and, later, the input to AI rule proposal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .contracts import API_VERSION, assert_valid
from .model import Asset, Decision, Finding, System, new_id


@dataclass
class Criterion:
    field: str
    match: str
    pattern: Any

    def test(self, ctx: dict[str, Any]) -> bool:
        value = _dig(ctx, self.field)
        m = self.match
        if m == "exists":
            return value is not None
        if m == "is_true":
            return value is True
        if m == "is_false":
            return value is False
        if value is None:
            return False
        if m == "exact":
            return _norm(value) == _norm(self.pattern)
        if m == "contains":
            return _norm(self.pattern) in _norm(value)
        if m == "regex":
            return re.search(str(self.pattern), str(value), re.IGNORECASE) is not None
        if m == "in":
            return _norm(value) in {_norm(p) for p in (self.pattern or [])}
        if m == "gte":
            return _num(value) is not None and _num(value) >= float(self.pattern)
        if m == "lte":
            return _num(value) is not None and _num(value) <= float(self.pattern)
        raise ValueError(f"unknown match type {m!r}")


@dataclass
class Rule:
    id: str
    priority: int
    criteria: list[Criterion]
    action: str
    params: dict[str, Any] = field(default_factory=dict)
    reason: str | None = None
    description: str | None = None
    enabled: bool = True
    origin: str = "human"

    def matches(self, ctx: dict[str, Any]) -> bool:
        return self.enabled and all(c.test(ctx) for c in self.criteria)

    def render_reason(self, ctx: dict[str, Any]) -> str:
        return render(self.reason or f"matched rule {self.id}", ctx)

    def render_params(self, ctx: dict[str, Any]) -> dict[str, Any]:
        return {k: render(v, ctx) if isinstance(v, str) else v for k, v in self.params.items()}


@dataclass
class PolicySet:
    id: str
    name: str
    version: int
    rules: list[Rule]
    status: str = "draft"
    approved_by: str | None = None
    approved_at: str | None = None
    description: str | None = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> PolicySet:
        assert_valid(d, "PolicySet")
        rules = [
            Rule(
                id=r["id"],
                priority=r["priority"],
                criteria=[Criterion(**c) for c in r["criteria"]],
                action=r["action"],
                params=r.get("params", {}),
                reason=r.get("reason"),
                description=r.get("description"),
                enabled=r.get("enabled", True),
                origin=r.get("origin", "human"),
            )
            for r in d["rules"]
        ]
        return cls(
            id=d["id"],
            name=d["name"],
            version=d["version"],
            rules=sorted(rules, key=lambda r: r.priority),
            status=d["status"],
            approved_by=d.get("approved_by"),
            approved_at=d.get("approved_at"),
            description=d.get("description"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "apiVersion": API_VERSION,
            "kind": "PolicySet",
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "status": self.status,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at,
            "description": self.description,
            "rules": [
                {
                    "id": r.id,
                    "description": r.description,
                    "priority": r.priority,
                    "criteria": [
                        {"field": c.field, "match": c.match, "pattern": c.pattern}
                        for c in r.criteria
                    ],
                    "action": r.action,
                    "params": r.params,
                    "reason": r.reason,
                    "enabled": r.enabled,
                    "origin": r.origin,
                }
                for r in self.rules
            ],
        }

    def evaluate(
        self,
        finding: Finding,
        asset: Asset | None = None,
        system: System | None = None,
    ) -> Decision:
        """First matching rule (by priority) decides; otherwise ``unmatched``."""
        ctx = build_context(finding, asset, system)
        for rule in self.rules:  # already priority-sorted
            if rule.matches(ctx):
                return Decision(
                    id=new_id("dec"),
                    finding_id=finding.id,
                    actor="rule",
                    action=rule.action,
                    policy_set_id=self.id,
                    policy_set_version=self.version,
                    rule_id=rule.id,
                    params=rule.render_params(ctx),
                    reason=rule.render_reason(ctx),
                    confidence=1.0,
                )
        return Decision(
            id=new_id("dec"),
            finding_id=finding.id,
            actor="rule",
            action="unmatched",
            policy_set_id=self.id,
            policy_set_version=self.version,
            reason="no rule matched; queued for review",
        )

    def evaluate_all(
        self,
        findings: list[Finding],
        assets: dict[str, Asset] | None = None,
        systems: dict[str, System] | None = None,
    ) -> list[Decision]:
        assets = assets or {}
        systems = systems or {}
        out = []
        for f in findings:
            a = assets.get(f.asset_id or "")
            s = systems.get(f.system_id or (a.system_id if a else "") or "")
            out.append(self.evaluate(f, a, s))
        return out


def build_context(finding: Finding, asset: Asset | None, system: System | None) -> dict[str, Any]:
    """Flatten finding + joined asset/system into one dict for dotted lookup.

    Finding fields are top-level (``severity``, ``vuln.id``); joined objects
    are under ``asset.*`` and ``system.*``.
    """
    ctx = finding.to_dict(include_raw=True)
    ctx["asset"] = asset.to_dict() if asset else {}
    ctx["system"] = system.to_dict() if system else {}
    return ctx


def render(template: str, ctx: dict[str, Any]) -> str:
    """Substitute ``{dotted.path}`` placeholders from ``ctx``; missing → empty."""

    def sub(m: re.Match) -> str:
        v = _dig(ctx, m.group(1))
        return "" if v is None else str(v)

    return re.sub(r"\{([a-zA-Z0-9_.]+)\}", sub, template)


def _dig(obj: Any, path: str) -> Any:
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list) and part.isdigit():
            idx = int(part)
            cur = cur[idx] if idx < len(cur) else None
        else:
            return None
        if cur is None:
            return None
    return cur


def _norm(v: Any) -> str:
    return str(v).strip().lower()


def _num(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None
