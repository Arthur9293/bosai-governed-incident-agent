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


def test_permit_is_bound_to_exact_action_and_target():
    runtime, proposal, registry = setup_case()
    permit = registry.issue(proposal, human_authorized=True)
    altered = type(proposal)(
        proposal_id=proposal.proposal_id,
        incident_id=proposal.incident_id,
        action="stop_worker",
        target=proposal.target,
        expected_version=proposal.expected_version,
        expected_snapshot_digest=proposal.expected_snapshot_digest,
        rationale=proposal.rationale,
    )
    with pytest.raises(GovernanceError, match="SCOPE_BINDING_MISMATCH"):
        execute_authorized(runtime, registry, altered, permit.permit_id)


def test_single_use_permit_denies_replay():
    runtime, proposal, registry = setup_case()
    permit = registry.issue(proposal, human_authorized=True)
    execute_authorized(runtime, registry, proposal, permit.permit_id)
    with pytest.raises(GovernanceError, match="PERMIT_ALREADY_CONSUMED"):
        execute_authorized(runtime, registry, proposal, permit.permit_id)


def test_reissue_creates_unique_permit_and_preserves_consumed_record():
    runtime, proposal, registry = setup_case()
    first = registry.issue(proposal, human_authorized=True)
    execute_authorized(runtime, registry, proposal, first.permit_id)

    second = registry.issue(proposal, human_authorized=True)

    assert second.permit_id != first.permit_id
    assert second.human_go_event_id != first.human_go_event_id
    assert registry.get(first.permit_id).consumed is True
    assert registry.get(second.permit_id).consumed is False


def test_version_drift_after_approval_fails_closed():
    runtime, proposal, registry = setup_case()
    permit = registry.issue(proposal, human_authorized=True)
    runtime.inject_drift()
    with pytest.raises(GovernanceError, match="STATE_VERSION_DRIFT"):
        execute_authorized(runtime, registry, proposal, permit.permit_id)


def test_digest_drift_after_approval_fails_closed():
    runtime, proposal, registry = setup_case()
    permit = registry.issue(proposal, human_authorized=True)
    runtime.inject_digest_drift()
    with pytest.raises(GovernanceError, match="STATE_DIGEST_DRIFT"):
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
