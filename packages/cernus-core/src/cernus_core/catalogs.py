"""Control catalogs / crosswalks shipped with the wheel (``catalogs/*.json``).

A crosswalk maps controls to the runtime facts Cernus can observe and names a
``rule`` the evaluator applies. The data is open; the continuous evaluation
service is commercial.
"""

from __future__ import annotations

import json
import os
from functools import cache
from pathlib import Path
from typing import Any


def catalogs_dir() -> Path:
    env = os.environ.get("CERNUS_CATALOGS_DIR")
    if env:
        return Path(env)
    here = Path(__file__).resolve()
    packaged = here.parent / "catalogs"
    if packaged.is_dir():
        return packaged
    return here.parents[2] / "catalogs"


@cache
def load_crosswalk(name: str = "nist-800-53r5") -> dict[str, Any]:
    path = catalogs_dir() / f"{name}-crosswalk.json"
    with path.open() as fh:
        return json.load(fh)


def controls(name: str = "nist-800-53r5") -> list[dict[str, Any]]:
    return list(load_crosswalk(name)["controls"])


def available_catalogs() -> list[dict[str, Any]]:
    """Every shipped crosswalk: catalog id, title, description, control count."""
    out = []
    for path in sorted(catalogs_dir().glob("*-crosswalk.json")):
        cw = load_crosswalk(path.name.removesuffix("-crosswalk.json"))
        out.append(
            {
                "catalog": cw["catalog"],
                "title": cw["title"],
                "description": cw.get("description", ""),
                "controls": len(cw["controls"]),
            }
        )
    return out
