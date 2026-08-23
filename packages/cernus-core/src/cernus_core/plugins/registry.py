"""Plugin registries + entry-point discovery.

Two ways to register:

1. Decorate a class (first-party plugins in ``cernus-plugins`` do this)::

       @register_connector
       class TrivyConnector(Connector): ...

2. Declare an entry point in any installed distribution — no fork needed::

       [project.entry-points."cernus.connectors"]
       nessus = "my_plugin.nessus:NessusConnector"

Governance properties (borrowed from genesis-gates):

* **Append-only.** A plugin may add names; it may never replace one that is
  already registered. Whoever registers first wins — first-party plugins load
  before third-party entry points.
* **Fail-soft but visible.** A plugin that raises on load never breaks the
  CLI; the failure lands in :data:`plugin_errors` for the caller to print.
* **Idempotent discovery.** Re-running discovery recomputes this group's
  errors instead of appending duplicates.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from importlib import metadata
from typing import Any, TypeVar

from .base import Connector, Exporter, Scanner

CONNECTORS_GROUP = "cernus.connectors"
SCANNERS_GROUP = "cernus.scanners"
EXPORTERS_GROUP = "cernus.exporters"

CONNECTOR_REGISTRY: dict[str, type[Connector]] = {}
SCANNER_REGISTRY: dict[str, type[Scanner]] = {}
EXPORTER_REGISTRY: dict[str, type[Exporter]] = {}

T = TypeVar("T", bound=type)


@dataclass(frozen=True)
class PluginError:
    group: str
    name: str
    reason: str
    kind: str = "error"  # or "conflict"

    def __str__(self) -> str:
        return f"{self.name} ({self.group}) — {self.reason}"


#: Load failures and name conflicts, in discovery order.
plugin_errors: list[PluginError] = []


def _make_register(registry: dict[str, Any], base: type) -> Callable[[T], T]:
    def register(cls: T) -> T:
        if not isinstance(cls, type) or not issubclass(cls, base):
            raise TypeError(f"{cls!r} is not a {base.__name__} subclass")
        name = getattr(cls, "name", "")
        if not name:
            raise ValueError(f"{cls.__name__} must set a non-empty `name`")
        existing = registry.get(name)
        if existing is not None and existing is not cls:
            raise ValueError(
                f"{base.__name__} '{name}' is already registered by {existing.__name__}"
            )
        registry[name] = cls
        return cls

    return register


register_connector = _make_register(CONNECTOR_REGISTRY, Connector)
register_scanner = _make_register(SCANNER_REGISTRY, Scanner)
register_exporter = _make_register(EXPORTER_REGISTRY, Exporter)


def _load_group(group: str, base: type, registry: dict[str, Any], register: Callable) -> None:
    plugin_errors[:] = [e for e in plugin_errors if e.group != group]
    try:
        eps = list(metadata.entry_points(group=group))
    except Exception as exc:  # pragma: no cover - malformed metadata
        plugin_errors.append(PluginError(group, "<discovery>", f"{type(exc).__name__}: {exc}"))
        return
    for ep in eps:
        before = dict(registry)
        try:
            obj = ep.load()
        except Exception as exc:
            # Undo anything a partial import may have replaced.
            for k, v in before.items():
                registry[k] = v
            plugin_errors.append(PluginError(group, ep.name, f"{type(exc).__name__}: {exc}"))
            continue
        # Revert replacements performed by import side effects.
        for k, v in before.items():
            if registry.get(k) is not v:
                registry[k] = v
                plugin_errors.append(
                    PluginError(
                        group, ep.name, f"refused to replace already-registered '{k}'", "conflict"
                    )
                )
        if isinstance(obj, type) and issubclass(obj, base):
            name = getattr(obj, "name", None)
            if name in registry and registry[name] is not obj:
                plugin_errors.append(
                    PluginError(
                        group,
                        ep.name,
                        f"refused to replace already-registered '{name}'",
                        "conflict",
                    )
                )
                continue
            try:
                register(obj)
            except (ValueError, TypeError) as exc:
                plugin_errors.append(PluginError(group, ep.name, str(exc)))
        elif not (set(registry) - set(before)):
            plugin_errors.append(
                PluginError(
                    group,
                    ep.name,
                    "loaded but registered nothing (return the class or register on import)",
                )
            )


_loaded = False


def load_plugins(force: bool = False) -> None:
    """Discover entry-point plugins for all three groups (once)."""
    global _loaded
    if _loaded and not force:
        return
    _load_group(CONNECTORS_GROUP, Connector, CONNECTOR_REGISTRY, register_connector)
    _load_group(SCANNERS_GROUP, Scanner, SCANNER_REGISTRY, register_scanner)
    _load_group(EXPORTERS_GROUP, Exporter, EXPORTER_REGISTRY, register_exporter)
    _loaded = True


def get_connector(name: str) -> Connector:
    load_plugins()
    try:
        return CONNECTOR_REGISTRY[name]()
    except KeyError:
        raise KeyError(f"no connector '{name}'; available: {sorted(CONNECTOR_REGISTRY)}") from None


def get_scanner(name: str) -> Scanner:
    load_plugins()
    try:
        return SCANNER_REGISTRY[name]()
    except KeyError:
        raise KeyError(f"no scanner '{name}'; available: {sorted(SCANNER_REGISTRY)}") from None


def get_exporter(name: str) -> Exporter:
    load_plugins()
    try:
        return EXPORTER_REGISTRY[name]()
    except KeyError:
        raise KeyError(f"no exporter '{name}'; available: {sorted(EXPORTER_REGISTRY)}") from None


def exporter_for_format(fmt: str) -> Exporter:
    load_plugins()
    for cls in EXPORTER_REGISTRY.values():
        if fmt in cls.formats:
            return cls()
    known = sorted(f for cls in EXPORTER_REGISTRY.values() for f in cls.formats)
    raise KeyError(f"no exporter handles format '{fmt}'; known formats: {known}")
