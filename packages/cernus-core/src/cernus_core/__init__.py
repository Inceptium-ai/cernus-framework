"""Cernus core — canonical model, contracts, plugin SDK, policy engine."""

from __future__ import annotations

from .contracts import contracts_dir, validate
from .model import (
    Asset,
    Decision,
    Deployment,
    EvidenceRecord,
    Finding,
    IngestBatch,
    Sbom,
    Severity,
    System,
)
from .serialize import batch_from_dict, read_batch, write_batch

__all__ = [
    "Asset",
    "Decision",
    "Deployment",
    "EvidenceRecord",
    "Finding",
    "IngestBatch",
    "Sbom",
    "Severity",
    "System",
    "batch_from_dict",
    "contracts_dir",
    "read_batch",
    "validate",
    "write_batch",
]

__version__ = "0.1.0"
