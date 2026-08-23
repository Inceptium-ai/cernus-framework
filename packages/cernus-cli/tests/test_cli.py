from __future__ import annotations

import json
from pathlib import Path

from cernus_cli.main import main

FIX = Path(__file__).resolve().parents[2] / "cernus-plugins" / "tests" / "fixtures"
POLICY = Path(__file__).resolve().parents[2] / "cernus-core" / "examples" / "policy.sample.yaml"


def test_doctor_and_plugins(capsys):
    assert main(["doctor"]) == 0
    assert "connectors:" in capsys.readouterr().out
    assert main(["plugins"]) == 0


def test_ingest_merge_validate_triage_export(tmp_path, capsys):
    t, g, all_ = tmp_path / "t.json", tmp_path / "g.json", tmp_path / "all.json"
    assert main(["ingest", str(FIX / "trivy-python.json"), "-o", str(t)]) == 0
    assert (
        main(
            ["ingest", str(FIX / "genesis-workspace"), "-o", str(g), "--environment", "production"]
        )
        == 0
    )
    assert main(["merge", str(t), str(g), "-o", str(all_)]) == 0
    assert main(["validate", str(all_)]) == 0
    assert main(["triage", str(all_), "--policy", str(POLICY)]) == 0
    decisions = json.loads((tmp_path / "all.decisions.json").read_text())
    assert {d["action"] for d in decisions} >= {"assign", "classify"}
    assert all(d["reason"] for d in decisions)
    assert (
        main(["export", str(all_), "--format", "oscal-poam", "-o", str(tmp_path / "p.json")]) == 0
    )
    assert main(["export", str(all_), "--format", "sarif", "-o", str(tmp_path / "o.sarif")]) == 0
    out = capsys.readouterr().out
    assert "wrote oscal-poam" in out


def test_unknown_input_is_an_error(tmp_path, capsys):
    p = tmp_path / "x.json"
    p.write_text('{"hello": 1}')
    assert main(["ingest", str(p)]) == 1
    assert "no connector recognizes" in capsys.readouterr().err


def test_validate_reports_errors(tmp_path, capsys):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"apiVersion": "cernus.ai/v0", "kind": "System", "id": "s"}))
    assert main(["validate", str(p)]) == 1
    assert "name" in capsys.readouterr().out
