"""Open-core boundary guard — the dependency arrow never reverses.

OSS packages (cernus-core, cernus-plugins, cernus-cli) must never import the
commercial server. This test fails the whole suite on a reverse import.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[3]
_OSS_SRC = [
    _REPO / "packages" / "cernus-core" / "src",
    _REPO / "packages" / "cernus-plugins" / "src",
    _REPO / "packages" / "cernus-cli" / "src",
]
_FORBIDDEN = re.compile(r"^\s*(from|import)\s+(cernus_server|frontend)\b", re.MULTILINE)


def test_oss_packages_never_import_commercial_code():
    violations = []
    for root in _OSS_SRC:
        assert root.is_dir(), root
        for f in root.rglob("*.py"):
            text = f.read_text(errors="replace")
            for m in _FORBIDDEN.finditer(text):
                line = text[: m.start()].count("\n") + 1
                violations.append(f"{f.relative_to(_REPO)}:{line}: {m.group(0).strip()}")
    assert not violations, "Open-core boundary violated:\n" + "\n".join(violations)
