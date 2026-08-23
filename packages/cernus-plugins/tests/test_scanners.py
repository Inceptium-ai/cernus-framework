from __future__ import annotations

import cernus_plugins  # noqa: F401
from cernus_core.plugins import SCANNER_REGISTRY, get_scanner


def test_scanners_registered_and_skip_cleanly_when_missing(monkeypatch):
    assert {"trivy", "syft"} <= set(SCANNER_REGISTRY)
    monkeypatch.setenv("PATH", "")
    assert not get_scanner("trivy").available()
    assert not get_scanner("syft").available()
