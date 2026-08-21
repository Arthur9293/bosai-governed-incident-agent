from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256


def _digest(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class IncidentSnapshot:
    incident_id: str
    service_id: str
    version: int
    health: str
    error_rate: float
    details: str

    def digest(self) -> str:
        return _digest(
            {
                "incident_id": self.incident_id,
                "service_id": self.service_id,
                "version": self.version,
                "health": self.health,
                "error_rate": self.error_rate,
                "details": self.details,
            }
        )


@dataclass(frozen=True)
class RemediationProposal:
    proposal_id: str
    incident_id: str
    action: str
    target: str
    expected_version: int
    expected_snapshot_digest: str
    rationale: str
    requires_human_go: bool = True


@dataclass
class ApprovalPermit:
    permit_id: str
    human_go_event_id: str
    proposal_id: str
    action: str
    target: str
    expected_version: int
    expected_snapshot_digest: str
    issued_at: str
    consumed: bool = False


@dataclass(frozen=True)
class ExecutionReceipt:
    receipt_id: str
    proposal_id: str
    permit_id: str
    before_digest: str
    after_digest: str
    before_version: int
    after_version: int
    outcome: str
    readback_verified: bool
