from __future__ import annotations

from dataclasses import asdict

from strands import Agent, tool

from .governance import PermitRegistry, execute_authorized, propose
from .runtime import SyntheticIncidentRuntime


def build_agent(runtime: SyntheticIncidentRuntime, registry: PermitRegistry) -> Agent:
    """Build the Strands agent. Human approval is issued outside the model tool surface."""

    proposals = {}

    @tool
    def read_service_state() -> dict:
        """Read the current incident/service state. This tool is read-only."""
        snapshot = runtime.snapshot()
        return asdict(snapshot) | {"snapshot_digest": snapshot.digest()}

    @tool
    def draft_bounded_remediation() -> dict:
        """Draft one bounded remediation proposal from the current service state."""
        proposal = propose(runtime.snapshot())
        proposals[proposal.proposal_id] = proposal
        return asdict(proposal)

    @tool
    def execute_with_permit(proposal_id: str, permit_id: str) -> dict:
        """Execute only when an externally issued, single-use Human GO permit validates."""
        if proposal_id not in proposals:
            raise ValueError("unknown proposal_id")
        receipt = execute_authorized(runtime, registry, proposals[proposal_id], permit_id)
        return asdict(receipt)

    return Agent(
        system_prompt=(
            "You are a professional incident-response agent. Investigate first. "
            "Prefer one bounded remediation. Never invent approval. "
            "Execution is valid only through execute_with_permit with an externally issued permit."
        ),
        tools=[read_service_state, draft_bounded_remediation, execute_with_permit],
    )
