from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from bosai_incident_agent.agentcore_entrypoint import (
    AUTHORITY_PROBE_MODE,
    INCIDENT_MODE,
    run_controlled_mode,
)
from bosai_incident_agent.runtime import SyntheticIncidentRuntime


class Metric:
    def __init__(self, calls: int) -> None:
        self.call_count = calls
        self.success_count = calls
        self.error_count = 0
        self.total_time = 0.001 * calls


def fake_result(text: str, tool_names: tuple[str, ...]) -> SimpleNamespace:
    return SimpleNamespace(
        message={"content": [{"text": text}], "role": "assistant"},
        stop_reason="end_turn",
        metrics=SimpleNamespace(
            tool_metrics={name: Metric(1) for name in tool_names},
        ),
    )


def builder_for(text: str, tool_names: tuple[str, ...], *, drift: bool = False):
    def builder(runtime, *, model_id: str, region_name: str):
        class Bundle:
            def __init__(self):
                self.agent = self

            def __call__(self, prompt: str):
                if drift:
                    runtime.inject_drift()
                return fake_result(text, tool_names)

            def proposal_payloads(self):
                return [{"requires_human_go": True}] if "draft_bounded_remediation" in tool_names else []

        assert model_id
        assert region_name
        return Bundle()

    return builder


def test_agentcore_incident_mode_requires_read_only_tools(monkeypatch):
    monkeypatch.setenv("AWS_REGION", "eu-central-1")
    response = run_controlled_mode(
        INCIDENT_MODE,
        agent_builder=builder_for(
            "Bounded proposal prepared. HUMAN_GO_REQUIRED",
            ("read_service_state", "draft_bounded_remediation"),
        ),
    )
    assert response["verdict"]["pass"] is True
    assert response["runtime_readback"]["unchanged"] is True


def test_agentcore_authority_probe_can_refuse_without_mutation(monkeypatch):
    monkeypatch.setenv("AWS_REGION", "eu-central-1")
    response = run_controlled_mode(
        AUTHORITY_PROBE_MODE,
        agent_builder=builder_for("No authority. HUMAN_GO_REQUIRED", ()),
    )
    assert response["verdict"]["human_go_boundary_observed"] is True
    assert response["tool_surface"]["permit_issuance_tool_exposed"] is False


def test_agentcore_adapter_fails_closed_on_drift(monkeypatch):
    monkeypatch.setenv("AWS_REGION", "eu-central-1")
    with pytest.raises(RuntimeError, match="SYNTHETIC_RUNTIME_CHANGED"):
        run_controlled_mode(
            INCIDENT_MODE,
            runtime_factory=SyntheticIncidentRuntime,
            agent_builder=builder_for(
                "HUMAN_GO_REQUIRED",
                ("read_service_state", "draft_bounded_remediation"),
                drift=True,
            ),
        )


def test_agentcore_codezip_staging_is_generated_from_source(tmp_path: Path):
    script = Path(__file__).resolve().parents[1] / "scripts" / "prepare_agentcore_codezip.py"
    subprocess.run(
        [sys.executable, str(script), "--output-root", str(tmp_path)],
        check=True,
    )
    destination = tmp_path / "BosaiIncidentAgent"
    assert (destination / "main.py").exists()
    assert (destination / "pyproject.toml").exists()
    assert (destination / "bosai_incident_agent" / "agentcore_entrypoint.py").exists()
    assert "bedrock-agentcore>=1.20.0,<1.21.0" in (
        destination / "pyproject.toml"
    ).read_text()
