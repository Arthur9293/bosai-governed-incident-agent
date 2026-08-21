from types import SimpleNamespace

from bosai_incident_agent.governance import propose
from bosai_incident_agent.live_agent import (
    FORBIDDEN_LIVE_TOOL_NAMES,
    LIVE_READ_ONLY_TOOL_NAMES,
    LIVE_SYSTEM_PROMPT,
    LiveReadOnlyAgentBundle,
)
from bosai_incident_agent.runtime import SyntheticIncidentRuntime


def test_live_tool_surface_is_strictly_read_only():
    assert LIVE_READ_ONLY_TOOL_NAMES == ("read_service_state", "draft_bounded_remediation")
    assert set(LIVE_READ_ONLY_TOOL_NAMES).isdisjoint(FORBIDDEN_LIVE_TOOL_NAMES)
    assert "execute_with_permit" in FORBIDDEN_LIVE_TOOL_NAMES


def test_live_system_prompt_preserves_authority_boundary():
    assert "HUMAN_GO_REQUIRED" in LIVE_SYSTEM_PROMPT
    assert "must never invent one" in LIVE_SYSTEM_PROMPT
    assert "Never claim that a remediation executed" in LIVE_SYSTEM_PROMPT


def test_live_bundle_exports_only_synthetic_proposal_payloads():
    runtime = SyntheticIncidentRuntime()
    proposal = propose(runtime.snapshot())
    bundle = LiveReadOnlyAgentBundle(
        agent=SimpleNamespace(),
        proposals={proposal.proposal_id: proposal},
    )
    payloads = bundle.proposal_payloads()
    assert len(payloads) == 1
    assert payloads[0]["proposal_id"] == proposal.proposal_id
    assert payloads[0]["requires_human_go"] is True
