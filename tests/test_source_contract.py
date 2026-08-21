from __future__ import annotations

import inspect
from dataclasses import asdict

import pytest

from bosai_incident_agent.agentcore_entrypoint import (
    AUTHORITY_PROBE_MODE,
    INCIDENT_MODE,
    run_controlled_mode,
)
from bosai_incident_agent.live_agent import LIVE_READ_ONLY_TOOL_NAMES
from bosai_incident_agent.models import IncidentSnapshot
from bosai_incident_agent.runtime import SyntheticIncidentRuntime
from bosai_incident_agent.source import IncidentEvidenceSource


def test_synthetic_runtime_satisfies_read_only_source_protocol() -> None:
    assert isinstance(SyntheticIncidentRuntime(), IncidentEvidenceSource)


class SnapshotOnlyFakeSource:
    def __init__(self) -> None:
        self.snapshot_calls = 0

    def snapshot(self) -> IncidentSnapshot:
        self.snapshot_calls += 1
        return IncidentSnapshot(
            incident_id="fake-001",
            service_id="svc",
            version=1,
            health="degraded",
            error_rate=0.42,
            details="synthetic",
        )


def test_fake_read_only_source_is_usable_for_live_path() -> None:
    source = SnapshotOnlyFakeSource()
    assert isinstance(source, IncidentEvidenceSource)
    value = source.snapshot()
    assert asdict(value)["incident_id"] == "fake-001"
    assert source.snapshot_calls == 1


def test_source_contract_has_snapshot_only_api() -> None:
    protocol_methods = {
        name for name, member in inspect.getmembers(IncidentEvidenceSource)
        if inspect.isfunction(member) and not name.startswith("_")
    }
    assert protocol_methods == {"snapshot"}

    for forbidden in ("apply", "update", "execute", "write", "delete", "credential", "client", "network"):
        assert not hasattr(IncidentEvidenceSource, forbidden)


def test_source_abstraction_does_not_expose_execute_with_permit() -> None:
    source = SyntheticIncidentRuntime()
    assert not hasattr(source, "execute_with_permit")


def test_source_abstraction_cannot_mint_human_go() -> None:
    source = SyntheticIncidentRuntime()
    assert not hasattr(source, "issue_permit")
    assert not hasattr(source, "issue")


class DriftRuntime:
    def __init__(self) -> None:
        self.value = 1

    def snapshot(self) -> IncidentSnapshot:
        return IncidentSnapshot(
            incident_id="inc-demo-001",
            service_id="checkout-worker",
            version=self.value,
            health="degraded",
            error_rate=0.42,
            details="synthetic",
        )

    def inject_drift(self) -> None:
        self.value += 1


def test_source_drift_during_controlled_invocation_fails_closed(monkeypatch):
    monkeypatch.setenv("AWS_REGION", "eu-central-1")

    class DriftBuilder:
        def __call__(self, runtime, *, model_id: str, region_name: str):
            class _Bundle:
                def __init__(self):
                    self.agent = self

                def __call__(self, prompt: str):
                    runtime.inject_drift()
                    return type(
                        "R",
                        (),
                        {
                            "metrics": type(
                                "M",
                                (),
                                {
                                    "tool_metrics": {
                                        "read_service_state": type(
                                            "T",
                                            (),
                                            {
                                                "call_count": 1,
                                                "success_count": 1,
                                                "error_count": 0,
                                                "total_time": 0.001,
                                            },
                                        )(),
                                        "draft_bounded_remediation": type(
                                            "T",
                                            (),
                                            {
                                                "call_count": 1,
                                                "success_count": 1,
                                                "error_count": 0,
                                                "total_time": 0.001,
                                            },
                                        )(),
                                    }
                                },
                            )(),
                            "stop_reason": "end_turn",
                            "message": {"content": [{"text": "HUMAN_GO_REQUIRED"}]},
                        },
                    )()

                def proposal_payloads(self):
                    return []

            return _Bundle()

    with pytest.raises(RuntimeError, match="SYNTHETIC_RUNTIME_CHANGED"):
        run_controlled_mode(
            INCIDENT_MODE,
            runtime_factory=DriftRuntime,
            agent_builder=DriftBuilder(),
        )


def test_live_tool_surface_unchanged() -> None:
    assert LIVE_READ_ONLY_TOOL_NAMES == ("read_service_state", "draft_bounded_remediation")


def test_authority_probe_requires_human_go_boundary(monkeypatch):
    monkeypatch.setenv("AWS_REGION", "eu-central-1")

    class ProbeBuilder:
        def __call__(self, runtime, *, model_id: str, region_name: str):
            class _Bundle:
                def __init__(self):
                    self.agent = self

                def __call__(self, prompt: str):
                    return type(
                        "R",
                        (),
                        {
                            "metrics": type("M", (), {"tool_metrics": {}})(),
                            "message": {"content": [{"text": "No authority. HUMAN_GO_REQUIRED"}]},
                            "stop_reason": "end_turn",
                        },
                    )()

                def proposal_payloads(self):
                    return []

            return _Bundle()

    response = run_controlled_mode(
        AUTHORITY_PROBE_MODE,
        runtime_factory=SnapshotOnlyFakeSource,
        agent_builder=ProbeBuilder(),
    )
    assert response["verdict"]["human_go_boundary_observed"] is True
    assert response["tool_surface"]["permit_issuance_tool_exposed"] is False
