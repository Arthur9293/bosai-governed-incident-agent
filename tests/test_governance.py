import pytest

from bosai_incident_agent.governance import (
    GovernanceError,
    PermitRegistry,
    execute_authorized,
    propose,
)
from bosai_incident_agent.runtime import SyntheticIncidentRuntime


def setup_case():
    runtime = SyntheticIncidentRuntime()
    proposal = propose(runtime.snapshot())
    registry = PermitRegistry()
    return runtime, proposal, registry


def test_execute_denied_without_permit():
    runtime, proposal, registry = setup_case()
    with pytest.raises(GovernanceError, match="PERMIT_REQUIRED"):
        execute_authorized(runtime, registry, proposal, None)


def test_human_go_required_to_issue_permit():
    _, proposal, registry = setup_case()
    with pytest.raises(GovernanceError, match="HUMAN_GO_REQUIRED"):
        registry.issue(proposal, human_authorized=False)


def test_permit_is_bound_to_exact_proposal():
    runtime, proposal, registry = setup_case()
    permit = registry.issue(proposal, human_authorized=True)
    altered = type(proposal)(
        proposal_id="prop-different",
        incident_id=proposal.incident_id,
        action=proposal.action,
        target=proposal.target,
        expected_version=proposal.expected_version,
        expected_snapshot_digest=proposal.expected_snapshot_digest,
        rationale=proposal.rationale,
    )
    with pytest.raises(GovernanceError, match="PROPOSAL_BINDING_MISMATCH"):
        execute_authorized(runtime, registry, altered, permit.permit_id)


def test_single_use_permit_denies_replay():
    runtime, proposal, registry = setup_case()
    permit = registry.issue(proposal, human_authorized=True)
    execute_authorized(runtime, registry, proposal, permit.permit_id)
    with pytest.raises(GovernanceError, match="PERMIT_ALREADY_CONSUMED"):
        execute_authorized(runtime, registry, proposal, permit.permit_id)


def test_drift_after_approval_fails_closed():
    runtime, proposal, registry = setup_case()
    permit = registry.issue(proposal, human_authorized=True)
    runtime.inject_drift()
    with pytest.raises(GovernanceError, match="STATE_VERSION_DRIFT"):
        execute_authorized(runtime, registry, proposal, permit.permit_id)


def test_successful_execution_has_verified_readback():
    runtime, proposal, registry = setup_case()
    permit = registry.issue(proposal, human_authorized=True)
    receipt = execute_authorized(runtime, registry, proposal, permit.permit_id)
    assert receipt.readback_verified is True
    assert receipt.outcome == "MATCHED"
    assert receipt.after_version == receipt.before_version + 1
    assert runtime.snapshot().health == "healthy"


def test_proposal_is_read_only():
    runtime = SyntheticIncidentRuntime()
    before = runtime.snapshot()
    proposal = propose(before)
    after = runtime.snapshot()
    assert proposal.requires_human_go is True
    assert before == after
