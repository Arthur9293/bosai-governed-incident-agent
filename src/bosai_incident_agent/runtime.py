from __future__ import annotations

from .models import IncidentSnapshot


class SyntheticIncidentRuntime:
    """Small deterministic runtime used for hackathon development and evidence."""

    def __init__(self) -> None:
        self._state = {
            "incident_id": "inc-demo-001",
            "service_id": "checkout-worker",
            "version": 1,
            "health": "degraded",
            "error_rate": 0.42,
            "details": "worker queue is stalled after a synthetic dependency timeout",
        }

    def snapshot(self) -> IncidentSnapshot:
        return IncidentSnapshot(**self._state)

    def inject_drift(self) -> None:
        self._state["version"] += 1
        self._state["details"] = "state changed after approval"

    def apply(self, action: str, target: str) -> IncidentSnapshot:
        if target != self._state["service_id"]:
            raise ValueError("target mismatch")
        if action != "restart_worker":
            raise ValueError("unsupported action")

        self._state["version"] += 1
        self._state["health"] = "healthy"
        self._state["error_rate"] = 0.01
        self._state["details"] = "worker restarted and queue processing restored"
        return self.snapshot()
