from __future__ import annotations

from pathlib import Path

import pytest
from cernus_core.model import IngestBatch, Source
from cernus_core.plugins import (
    CONNECTOR_REGISTRY,
    Connector,
    PluginError,
    plugin_errors,
    register_connector,
)
from cernus_core.plugins import registry as reg


class _Fake(Connector):
    name = "fake-test"
    description = "x"

    def detect(self, path: Path, document=None) -> bool:
        return path.name == "fake.json"

    def ingest(self, path: Path, document=None, **context) -> IngestBatch:
        return IngestBatch(source=Source(tool="fake"))


def test_register_and_refuse_replacement():
    CONNECTOR_REGISTRY.pop("fake-test", None)
    register_connector(_Fake)
    assert CONNECTOR_REGISTRY["fake-test"] is _Fake

    class Other(_Fake):
        pass

    with pytest.raises(ValueError):
        register_connector(Other)
    CONNECTOR_REGISTRY.pop("fake-test", None)


def test_register_requires_name():
    class NoName(Connector):
        def detect(self, path, document=None):
            return False

        def ingest(self, path, document=None, **context):
            return IngestBatch(source=Source(tool="x"))

    with pytest.raises(ValueError):
        register_connector(NoName)


def test_entry_point_failure_is_reported_not_raised(monkeypatch):
    class BadEP:
        name = "broken"
        value = "nope:Nope"

        def load(self):
            raise ImportError("boom")

    monkeypatch.setattr(reg.metadata, "entry_points", lambda group: [BadEP()])
    reg._load_group("cernus.connectors", Connector, CONNECTOR_REGISTRY, register_connector)
    assert any(
        isinstance(e, PluginError) and e.name == "broken" and "boom" in e.reason
        for e in plugin_errors
    )
    plugin_errors.clear()
