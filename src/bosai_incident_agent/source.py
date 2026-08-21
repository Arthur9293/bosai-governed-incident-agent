from __future__ import annotations

from typing import Protocol, runtime_checkable

from .models import IncidentSnapshot


@runtime_checkable
class IncidentEvidenceSource(Protocol):
    """Read-only evidence source contract for live path inputs."""

    def snapshot(self) -> IncidentSnapshot: ...
