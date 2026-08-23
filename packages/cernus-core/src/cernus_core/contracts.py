"""Load + validate against the JSON Schemas in `contracts/` (the SSOT).

Schemas cross-reference each other by `$id` (``common.schema.json#/$defs/…``),
so a single registry is built from every file in the directory and handed to
the validator.
"""

from __future__ import annotations

import json
import os
from functools import cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

API_VERSION = "cernus.ai/v0"

#: kind -> schema file
KINDS = {
    "Finding": "finding.schema.json",
    "Asset": "asset.schema.json",
    "System": "system.schema.json",
    "Deployment": "deployment.schema.json",
    "ControlResult": "control-result.schema.json",
    "PolicySet": "policy.schema.json",
    "Decision": "decision.schema.json",
    "EvidenceRecord": "evidence-record.schema.json",
    "IngestBatch": "ingest-batch.schema.json",
}


def contracts_dir() -> Path:
    """Locate the JSON Schema `contracts/` directory.

    1. ``CERNUS_CONTRACTS_DIR`` env override.
    2. Package-local ``cernus_core/contracts`` (installed wheel, force-included).
    3. Repo-root ``contracts/`` next to ``src/`` (editable install).
    """
    env = os.environ.get("CERNUS_CONTRACTS_DIR")
    if env:
        return Path(env)
    here = Path(__file__).resolve()
    packaged = here.parent / "contracts"
    if packaged.is_dir():
        return packaged
    return here.parents[2] / "contracts"


@cache
def _registry() -> Registry:
    resources = []
    for path in sorted(contracts_dir().glob("*.schema.json")):
        with path.open() as fh:
            schema = json.load(fh)
        resource = Resource.from_contents(schema)
        # Register under both the absolute $id and the bare filename so relative
        # refs ("common.schema.json#/$defs/id") resolve from any base.
        resources.append((schema["$id"], resource))
        resources.append((path.name, resource))
    return Registry().with_resources(resources)


@cache
def schema(name: str) -> dict[str, Any]:
    with (contracts_dir() / name).open() as fh:
        return json.load(fh)


@cache
def _validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(schema(name), registry=_registry())


def validate(instance: dict[str, Any], kind: str | None = None) -> list[str]:
    """Return human-readable errors (empty == valid).

    ``kind`` defaults to ``instance["kind"]``.
    """
    kind = kind or instance.get("kind", "")
    name = KINDS.get(kind)
    if name is None:
        return [f"(root): unknown kind {kind!r}; expected one of {sorted(KINDS)}"]
    errors = []
    for err in sorted(_validator(name).iter_errors(instance), key=lambda e: list(e.path)):
        loc = "/".join(str(p) for p in err.path) or "(root)"
        errors.append(f"{loc}: {err.message}")
    return errors


def assert_valid(instance: dict[str, Any], kind: str | None = None) -> None:
    errors = validate(instance, kind)
    if errors:
        raise ValueError(
            f"{kind or instance.get('kind')} failed contract validation:\n  " + "\n  ".join(errors)
        )
