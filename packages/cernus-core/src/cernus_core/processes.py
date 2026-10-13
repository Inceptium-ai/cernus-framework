"""Compliance process definitions shipped with the wheel (``processes/*.json``).

A process is a data file, not code: phases with named checks, the artifacts the
package must contain, and which baseline/catalogs it rides on. The server's
compliance service resolves ``check`` names to functions (same pattern as the
control-evaluation rules), so new processes — SOC 2, HIPAA — are content
additions, not schema changes.
"""

from __future__ import annotations

import json
import os
from functools import cache
from pathlib import Path
from typing import Any


def processes_dir() -> Path:
    env = os.environ.get("CERNUS_PROCESSES_DIR")
    if env:
        return Path(env)
    here = Path(__file__).resolve()
    packaged = here.parent / "processes"
    if packaged.is_dir():
        return packaged
    return here.parents[2] / "processes"


@cache
def load_process(name: str) -> dict[str, Any]:
    path = processes_dir() / f"{name}.json"
    with path.open() as fh:
        return json.load(fh)


def available_processes() -> list[dict[str, Any]]:
    """Every shipped process definition, full documents, sorted by id."""
    out = []
    for path in sorted(processes_dir().glob("*.json")):
        out.append(load_process(path.stem))
    return out
