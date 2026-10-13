"""Control baselines shipped with the wheel (``baselines/*.json``).

A baseline file is a trimmed copy of an authoritative control catalog (NIST
SP 800-53B resolved profiles today): per control — id, title, family,
flattened statement prose, and which baseline levels include it. SSP
generation documents a baseline; the crosswalks in :mod:`.catalogs` remain the
(smaller) automated-evaluation layer that overlays it. Regenerate the data
with ``scripts/build_baselines.py`` — never hand-edit.
"""

from __future__ import annotations

import json
import os
from functools import cache
from pathlib import Path
from typing import Any


def baselines_dir() -> Path:
    env = os.environ.get("CERNUS_BASELINES_DIR")
    if env:
        return Path(env)
    here = Path(__file__).resolve()
    packaged = here.parent / "baselines"
    if packaged.is_dir():
        return packaged
    return here.parents[2] / "baselines"


@cache
def _load(catalog: str = "nist-800-53r5") -> dict[str, Any]:
    path = baselines_dir() / f"{catalog}-baselines.json"
    with path.open() as fh:
        return json.load(fh)


def load_baseline(level: str, catalog: str = "nist-800-53r5") -> list[dict[str, Any]]:
    """Controls in the given baseline level, sorted (family, id)."""
    doc = _load(catalog)
    out = [c for c in doc["controls"] if level in c["baselines"]]
    if not out:
        raise KeyError(f"unknown baseline level {level!r} for {catalog}")
    return out


def baseline_families(level: str, catalog: str = "nist-800-53r5") -> list[str]:
    return sorted({c["family"] for c in load_baseline(level, catalog)})
