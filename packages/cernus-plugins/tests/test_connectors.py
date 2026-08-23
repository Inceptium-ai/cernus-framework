from __future__ import annotations

import json

import cernus_plugins  # noqa: F401
from cernus_core import validate
from cernus_core.ingest import detect_connector, ingest_path
from cernus_core.model import Severity


def test_trivy_detect_and_ingest(fixtures):
    path = fixtures / "trivy-python.json"
    assert detect_connector(path, json.loads(path.read_text())).name == "trivy"
    batch = ingest_path(path)
    assert batch.source.tool == "trivy" and batch.source.version
    assert len(batch.assets) == 1 and batch.assets[0].asset_kind == "container_image"
    assert batch.assets[0].identifiers["digest"].startswith("sha256:")
    assert validate(batch.to_dict()) == []
    f = next(x for x in batch.findings if x.vuln and x.vuln.cvss)
    assert f.component.purl.startswith("pkg:") and f.component.type == "deb"
    assert f.asset_id == batch.assets[0].id
    sevs = {x.severity for x in batch.findings}
    assert Severity.CRITICAL in sevs and Severity.LOW in sevs
    assert batch.evidence[0].record_kind == "scan" and batch.evidence[0].hash


def test_cyclonedx_ingest_reconciles_with_trivy_asset(fixtures):
    sbom = ingest_path(fixtures / "syft-python.cdx.json")
    trivy = ingest_path(fixtures / "trivy-python.json")
    assert sbom.sboms[0].format == "cyclonedx-json"
    assert sbom.assets[0].id == trivy.assets[0].id == sbom.sboms[0].asset_id
    assert validate(sbom.to_dict()) == []


def test_sarif_ingest(fixtures):
    batch = ingest_path(fixtures / "sample.sarif")
    assert [f.severity.value for f in batch.findings] == ["high", "medium"]
    assert batch.findings[0].location == "app/db.py:42"
    assert batch.findings[0].category == "sast"
    assert validate(batch.to_dict()) == []


def test_genesis_workspace_ingest(fixtures):
    batch = ingest_path(fixtures / "genesis-workspace")
    assert batch.systems[0].name == "document-api" and batch.systems[0].owner == "customer-platform"
    assert batch.systems[0].data_classification == "confidential"
    dep = batch.deployments[0]
    assert dep.change_id == "CHG-2026-00421" and dep.environment == "development"
    assert dep.manifest["kind"] == "DeliveryManifest" and dep.evidence["status"] == "passed"
    kinds = sorted(a.asset_kind for a in batch.assets)
    assert kinds == ["container_image", "container_image", "service"]
    assert {f.gate for f in batch.findings} == {"dependency-scan", "sast"}
    assert all(f.system_id == batch.systems[0].id for f in batch.findings)
    assert {e.record_kind for e in batch.evidence} == {"gate_run", "deploy"}
    assert validate(batch.to_dict()) == []


def test_genesis_evidence_package_alone(fixtures):
    path = fixtures / "genesis-workspace" / ".genesis-work" / "evidence.json"
    batch = ingest_path(path)
    assert batch.systems[0].name == "document-api"
    assert len(batch.findings) == 3


def test_genesis_ids_are_deterministic(fixtures):
    a = ingest_path(fixtures / "genesis-workspace")
    b = ingest_path(fixtures / "genesis-workspace")
    assert a.systems[0].id == b.systems[0].id and a.deployments[0].id == b.deployments[0].id
    assert {x.fingerprint for x in a.findings} == {x.fingerprint for x in b.findings}
