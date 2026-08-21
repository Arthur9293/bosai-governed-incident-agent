from __future__ import annotations

import json
from datetime import datetime, timezone
from hashlib import sha256
from uuid import uuid4

from .models import ApprovalPermit, ExecutionReceipt, IncidentSnapshot, RemediationProposal
from .runtime import SyntheticIncidentRuntime


class GovernanceError(RuntimeError):
    pass


def _stable_id(prefix: str, payload: dict) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"{prefix}-{sha256(encoded).hexdigest()[:16]}"


def propose(snapshot: IncidentSnapshot) -> RemediationProposal:
    if snapshot.health != "degraded":
        raise GovernanceError("no bounded remediation is justified for current state")

    payload = {
        "incident_id": snapshot.incident_id,
        "target": snapshot.service_id,
        "action": "restart_worker",
        "expected_version": snapshot.version,
        "expected_snapshot_digest": snapshot.digest(),
    }
    return RemediationProposal(
        proposal_id=_stable_id("prop", payload),
        incident_id=snapshot.incident_id,
        action="restart_worker",
        target=snapshot.service_id,
        expected_version=snapshot.version,
        expected_snapshot_digest=snapshot.digest(),
        rationale="Synthetic worker is degraded; bounded restart is the narrowest remediation.",
    )


class PermitRegistry:
    def __init__(self) -> None:
        self._permits: dict[str, ApprovalPermit] = {}

    def issue(self, proposal: RemediationProposal, *, human_authorized: bool) -> ApprovalPermit:
        if proposal.requires_human_go and not human_authorized:
            raise GovernanceError("HUMAN_GO_REQUIRED")

        human_go_event_id = f"go-{uuid4().hex}"
        payload = {
            "human_go_event_id": human_go_event_id,
            "proposal_id": proposal.proposal_id,
            "action": proposal.action,
            "target": proposal.target,
            "expected_version": proposal.expected_version,
            "expected_snapshot_digest": proposal.expected_snapshot_digest,
        }
        permit_id = _stable_id("permit", payload)
        if permit_id in self._permits:
            raise GovernanceError("PERMIT_ID_COLLISION")

        permit = ApprovalPermit(
            permit_id=permit_id,
            human_go_event_id=human_go_event_id,
            proposal_id=proposal.proposal_id,
            action=proposal.action,
            target=proposal.target,
            expected_version=proposal.expected_version,
            expected_snapshot_digest=proposal.expected_snapshot_digest,
            issued_at=datetime.now(timezone.utc).isoformat(),
        )
        self._permits[permit_id] = permit
        return permit

    def get(self, permit_id: str) -> ApprovalPermit:
        try:
            return self._permits[permit_id]
        except KeyError as exc:
            raise GovernanceError("PERMIT_NOT_FOUND") from exc


def execute_authorized(
    runtime: SyntheticIncidentRuntime,
    registry: PermitRegistry,
    proposal: RemediationProposal,
    permit_id: str | None,
) -> ExecutionReceipt:
    if not permit_id:
        raise GovernanceError("PERMIT_REQUIRED")

    permit = registry.get(permit_id)
    if permit.consumed:
        raise GovernanceError("PERMIT_ALREADY_CONSUMED")

    if permit.proposal_id != proposal.proposal_id:
        raise GovernanceError("PROPOSAL_BINDING_MISMATCH")
    if (permit.action, permit.target) != (proposal.action, proposal.target):
        raise GovernanceError("SCOPE_BINDING_MISMATCH")

    before = runtime.snapshot()
    if before.version != permit.expected_version:
        raise GovernanceError("STATE_VERSION_DRIFT")
    if before.digest() != permit.expected_snapshot_digest:
        raise GovernanceError("STATE_DIGEST_DRIFT")

    permit.consumed = True
    after = runtime.apply(proposal.action, proposal.target)

    verified = after.health == "healthy" and after.version == before.version + 1
    receipt_payload = {
        "proposal_id": proposal.proposal_id,
        "permit_id": permit.permit_id,
        "before": before.digest(),
        "after": after.digest(),
    }
    return ExecutionReceipt(
        receipt_id=_stable_id("receipt", receipt_payload),
        proposal_id=proposal.proposal_id,
        permit_id=permit.permit_id,
        before_digest=before.digest(),
        after_digest=after.digest(),
        before_version=before.version,
        after_version=after.version,
        outcome="MATCHED" if verified else "MISMATCH",
        readback_verified=verified,
    )
