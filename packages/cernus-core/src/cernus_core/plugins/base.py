"""Plugin contracts. Three kinds; each deliberately small.

* :class:`Connector` — turns a tool's *output* (a file, a directory, an API
  payload) into an :class:`~cernus_core.model.IngestBatch`. Pure: no subprocess.
* :class:`Scanner` — *invokes* a tool you already have installed (trivy, syft,
  grype…) and returns its raw output path/document, which a Connector then
  normalizes. Skips cleanly when the binary is missing.
* :class:`Exporter` — writes Cernus objects out in a standard format
  (OSCAL, SARIF, CSV).

Cernus integrates first and builds second: a plugin wraps a tool, it never
re-implements one.
"""

from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

from ..model import IngestBatch


@dataclass
class ScanResult:
    """Raw output of a Scanner run, ready for a Connector."""

    tool: str
    output_path: Path | None = None
    document: dict[str, Any] | None = None
    connector: str | None = None  # name of the Connector that understands this output
    argv: list[str] = field(default_factory=list)
    returncode: int = 0
    stderr: str = ""


class Connector(ABC):
    """Normalize a tool's output into Cernus objects."""

    #: Registry key, e.g. ``"trivy"``. Must be unique.
    name: ClassVar[str] = ""
    #: Human description shown by ``cernus plugins``.
    description: ClassVar[str] = ""
    #: Tools whose output this connector understands (informational).
    tools: ClassVar[tuple[str, ...]] = ()

    @abstractmethod
    def detect(self, path: Path, document: dict[str, Any] | None = None) -> bool:
        """Return True if ``path``/``document`` looks like this tool's output.

        Used by ``cernus ingest --connector auto``. Must be cheap and must not
        raise on foreign input.
        """

    @abstractmethod
    def ingest(
        self, path: Path, document: dict[str, Any] | None = None, **context: Any
    ) -> IngestBatch:
        """Produce an IngestBatch. ``context`` carries caller hints such as
        ``system_id``, ``deployment_id``, ``asset_id``, ``environment``."""


class Scanner(ABC):
    """Invoke an installed scanning tool."""

    name: ClassVar[str] = ""
    description: ClassVar[str] = ""
    #: Binary looked up on PATH for :meth:`available`.
    binary: ClassVar[str] = ""
    #: Targets this scanner accepts: ``image``, ``sbom``, ``fs``.
    targets: ClassVar[tuple[str, ...]] = ()

    def available(self) -> bool:
        return bool(self.binary) and shutil.which(self.binary) is not None

    def version(self) -> str | None:  # pragma: no cover - tool specific
        return None

    @abstractmethod
    def scan(self, target_kind: str, target: str, workdir: Path) -> ScanResult:
        """Run the tool against ``target`` (an image ref, an SBOM path, a dir)."""


class Exporter(ABC):
    """Write Cernus objects in an external format."""

    name: ClassVar[str] = ""
    description: ClassVar[str] = ""
    #: e.g. ``("oscal-poam", "oscal-assessment-results")``
    formats: ClassVar[tuple[str, ...]] = ()

    @abstractmethod
    def export(self, fmt: str, batch: IngestBatch, out: Path, **options: Any) -> Path:
        """Write ``batch`` as ``fmt`` to ``out`` and return the written path."""
