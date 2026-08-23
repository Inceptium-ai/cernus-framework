"""SARIF 2.1.0 — connector (semgrep, CodeQL, bandit, genesis-cli …) and exporter."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cernus_core.model import Finding, IngestBatch, Severity, Source, new_id, now_iso
from cernus_core.plugins import Connector, Exporter, register_connector, register_exporter

_LEVEL_TO_SEV = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
_SEV_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
}


@register_connector
class SarifConnector(Connector):
    name = "sarif"
    description = "SARIF 2.1.0 static-analysis logs"
    tools = ("semgrep", "codeql", "bandit", "genesis-cli")

    def detect(self, path: Path, document: dict[str, Any] | None = None) -> bool:
        return bool(document) and document.get("version") == "2.1.0" and "runs" in document

    def ingest(
        self, path: Path, document: dict[str, Any] | None = None, **context: Any
    ) -> IngestBatch:
        doc = document if document is not None else json.loads(path.read_text())
        batch = IngestBatch(source=Source(tool="sarif", connector=self.name))
        seen = now_iso()
        for run in doc.get("runs") or []:
            driver = (run.get("tool") or {}).get("driver") or {}
            source = Source(
                tool=driver.get("name", "sarif").lower(),
                version=driver.get("version"),
                connector=self.name,
            )
            rules = {r.get("id"): r for r in driver.get("rules") or []}
            for res in run.get("results") or []:
                rule_id = res.get("ruleId") or "unknown"
                rule = rules.get(rule_id, {})
                sev = _severity(res, rule)
                loc = _location(res)
                batch.findings.append(
                    Finding(
                        id=new_id("fnd"),
                        title=(rule.get("shortDescription") or {}).get("text") or rule_id,
                        severity=sev,
                        source=source,
                        source_ref=rule_id,
                        category="sast",
                        detail=(res.get("message") or {}).get("text"),
                        location=loc,
                        remediation=(rule.get("help") or {}).get("text"),
                        asset_id=context.get("asset_id"),
                        deployment_id=context.get("deployment_id"),
                        system_id=context.get("system_id"),
                        first_seen=seen,
                        last_seen=seen,
                        tags=[
                            t
                            for t in (rule.get("properties") or {}).get("tags", [])
                            if isinstance(t, str)
                        ][:10],
                        raw=res,
                    )
                )
        if batch.findings:
            batch.source = batch.findings[0].source
        return batch


def _severity(res: dict, rule: dict) -> str:
    props = rule.get("properties") or {}
    if "security-severity" in props:  # GitHub convention: CVSS-like 0–10 string
        try:
            s = float(props["security-severity"])
            return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"
        except ValueError:
            pass
    level = res.get("level") or (rule.get("defaultConfiguration") or {}).get("level") or "warning"
    return _LEVEL_TO_SEV.get(level, "medium")


def _location(res: dict) -> str | None:
    for loc in res.get("locations") or []:
        phys = loc.get("physicalLocation") or {}
        uri = (phys.get("artifactLocation") or {}).get("uri")
        line = (phys.get("region") or {}).get("startLine")
        if uri:
            return f"{uri}:{line}" if line else uri
    return None


@register_exporter
class SarifExporter(Exporter):
    name = "sarif"
    description = "Write findings as SARIF 2.1.0 (one run per source tool)"
    formats = ("sarif",)

    def export(self, fmt: str, batch: IngestBatch, out: Path, **options: Any) -> Path:
        by_tool: dict[str, list[Finding]] = {}
        for f in batch.findings:
            by_tool.setdefault(f.source.tool, []).append(f)
        runs = []
        for tool, findings in by_tool.items():
            rules: dict[str, dict] = {}
            results = []
            for f in findings:
                rid = f.source_ref or f.fingerprint[:12]
                rules.setdefault(rid, {"id": rid, "shortDescription": {"text": f.title}})
                result: dict[str, Any] = {
                    "ruleId": rid,
                    "level": _SEV_TO_LEVEL[f.severity.value],
                    "message": {"text": f.detail or f.title},
                    "fingerprints": {"cernus/v1": f.fingerprint},
                    "properties": {
                        "cernus": {
                            "id": f.id,
                            "severity": f.severity.value,
                            "status": f.status.value,
                        }
                    },
                }
                if f.location:
                    uri, _, line = f.location.partition(":")
                    region = {"startLine": int(line)} if line.isdigit() else {}
                    result["locations"] = [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": uri},
                                **({"region": region} if region else {}),
                            }
                        }
                    ]
                results.append(result)
            runs.append(
                {
                    "tool": {"driver": {"name": tool, "rules": list(rules.values())}},
                    "results": results,
                }
            )
        doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": runs,
        }
        out.write_text(json.dumps(doc, indent=2))
        return out


__all__ = ["SarifConnector", "SarifExporter", "Severity"]
