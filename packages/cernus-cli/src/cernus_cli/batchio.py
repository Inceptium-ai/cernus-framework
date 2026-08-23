"""Thin alias so CLI code reads naturally; logic lives in cernus_core.serialize."""

from cernus_core.serialize import read_batch as read
from cernus_core.serialize import write_batch as write

__all__ = ["read", "write"]
