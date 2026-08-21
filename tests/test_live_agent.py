from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace

import pytest

from bosai_incident_agent.governance import propose
from bosai_incident_agent.live_agent import (
    FORBIDDEN_LIVE_TOOL_NAMES,
    LIVE_READ_ONLY_TOOL_NAMES,
    LIVE_SYSTEM_PROMPT,
    LiveReadOnlyAgentBundle,
)
from bosai_incident_agent.runtime import SyntheticIncidentRuntime

_RUN_LIVE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "run_live_0b.py"
_RUN_LIVE_SPEC = spec_from_file_location("bosai_run_live_0b", _RUN_LIVE_PATH)
if _RUN_LIVE_SPEC is None or _RUN_LIVE_SPEC.loader is None:
    raise RuntimeError(f"unable to load {_RUN_LIVE_PATH}")
_RUN_LIVE = module_from_spec(_RUN_LIVE_SPEC)
_RUN_LIVE_SPEC.loader.exec_module(_RUN_LIVE)

_tool_metrics_delta = _RUN_LIVE._tool_metrics_delta
_tool_metrics_reconcile = _RUN_LIVE._tool_metrics_reconcile
_usage_delta = _RUN_LIVE._usage_delta
_usage_reconciles = _RUN_LIVE._usage_reconciles


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


def test_usage_delta_is_per_invocation_and_reconciles():
    primary = {"inputTokens": 1300, "outputTokens": 289, "totalTokens": 1589}
    session = {"inputTokens": 4978, "outputTokens": 542, "totalTokens": 5520}

    probe = _usage_delta(primary, session)

    assert probe == {"inputTokens": 3678, "outputTokens": 253, "totalTokens": 3931}
    assert _usage_reconciles(primary, probe, session) is True


def test_tool_metrics_delta_isolates_probe_calls_and_reconciles():
    primary = {
        "read_service_state": {
            "call_count": 1,
            "success_count": 1,
            "error_count": 0,
            "total_time_seconds": 0.003,
        },
        "draft_bounded_remediation": {
            "call_count": 1,
            "success_count": 1,
            "error_count": 0,
            "total_time_seconds": 0.001,
        },
    }
    session = {
        "read_service_state": {
            "call_count": 1,
            "success_count": 1,
            "error_count": 0,
            "total_time_seconds": 0.003,
        },
        "draft_bounded_remediation": {
            "call_count": 2,
            "success_count": 2,
            "error_count": 0,
            "total_time_seconds": 0.0025,
        },
    }

    probe = _tool_metrics_delta(primary, session)

    assert set(probe) == {"draft_bounded_remediation"}
    assert probe["draft_bounded_remediation"]["call_count"] == 1
    assert probe["draft_bounded_remediation"]["success_count"] == 1
    assert probe["draft_bounded_remediation"]["error_count"] == 0
    assert probe["draft_bounded_remediation"]["total_time_seconds"] == pytest.approx(0.0015)
    assert _tool_metrics_reconcile(primary, probe, session) is True


def test_metric_delta_fails_closed_on_non_monotonic_session_metrics():
    with pytest.raises(ValueError, match="non-monotonic accumulated usage"):
        _usage_delta({"totalTokens": 10}, {"totalTokens": 9})

    with pytest.raises(ValueError, match="non-monotonic tool metric"):
        _tool_metrics_delta(
            {"read_service_state": {"call_count": 2}},
            {"read_service_state": {"call_count": 1}},
        )
