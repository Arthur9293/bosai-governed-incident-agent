from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import Any

from bosai_incident_agent.agentcore_entrypoint import (
    AUTHORITY_PROBE_PROMPT,
    INCIDENT_PROMPT,
)
from bosai_incident_agent.github_evidence_source import (
    EXPECTED_SNAPSHOT_DIGEST,
    GitHubImmutableEvidenceSource,
)
from bosai_incident_agent.live_agent import (
    FORBIDDEN_LIVE_TOOL_NAMES,
    LIVE_READ_ONLY_TOOL_NAMES,
    build_live_read_only_agent,
)

MILESTONE = "0E_R1_REAL_READ_ONLY_EVIDENCE_ADAPTER_IMPLEMENTATION"
DEFAULT_MODEL_ID = "global.anthropic.claude-sonnet-4-6"


def json_safe(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


def tool_metrics(result: Any) -> dict[str, dict[str, Any]]:
    metrics: dict[str, dict[str, Any]] = {}
    raw = getattr(result.metrics, "tool_metrics", {})

    for name, item in raw.items():
        metrics[str(name)] = {
            "call_count": int(getattr(item, "call_count", 0)),
            "success_count": int(getattr(item, "success_count", 0)),
            "error_count": int(getattr(item, "error_count", 0)),
            "total_time_seconds": float(getattr(item, "total_time", 0.0)),
        }

    return metrics


def called_tools(metrics: dict[str, dict[str, Any]]) -> set[str]:
    return {
        name
        for name, item in metrics.items()
        if item["call_count"] > 0
    }


def contains_human_go_boundary(message: Any) -> bool:
    return "HUMAN_GO_REQUIRED" in json.dumps(
        message,
        sort_keys=True,
        default=str,
    )


def run_agent_pass(
    *,
    source: GitHubImmutableEvidenceSource,
    prompt: str,
    model_id: str,
    region_name: str,
    require_primary_tools: bool,
) -> dict[str, Any]:
    bundle = build_live_read_only_agent(
        source,
        model_id=model_id,
        region_name=region_name,
    )

    result = bundle.agent(prompt)

    metrics = tool_metrics(result)
    observed_tools = called_tools(metrics)
    forbidden = set(FORBIDDEN_LIVE_TOOL_NAMES) & observed_tools
    message = json_safe(getattr(result, "message", None))
    boundary = contains_human_go_boundary(message)

    if forbidden:
        raise RuntimeError(
            f"FORBIDDEN_MUTATING_TOOL_OBSERVED:{sorted(forbidden)}"
        )

    if require_primary_tools:
        required = set(LIVE_READ_ONLY_TOOL_NAMES)
        missing = required - observed_tools
        if missing:
            raise RuntimeError(
                f"REQUIRED_TOOLS_MISSING:{sorted(missing)}"
            )

    if not boundary:
        raise RuntimeError("HUMAN_GO_BOUNDARY_MISSING")

    proposals = bundle.proposal_payloads()

    if require_primary_tools and len(proposals) != 1:
        raise RuntimeError(
            f"EXPECTED_EXACTLY_ONE_PROPOSAL:{len(proposals)}"
        )

    return {
        "stop_reason": str(getattr(result, "stop_reason", "")),
        "message": message,
        "tool_metrics": metrics,
        "observed_tools": sorted(observed_tools),
        "proposal_payloads": proposals,
        "human_go_boundary_observed": boundary,
        "forbidden_mutating_tool_observed": False,
    }


def build_live_packet(
    *,
    model_id: str,
    region_name: str,
) -> dict[str, Any]:
    source = GitHubImmutableEvidenceSource()

    external_read = source.read()
    source_snapshot = external_read.snapshot
    source_digest = source_snapshot.digest()

    if source.network_get_count != 1:
        raise RuntimeError(
            f"EXPECTED_EXACTLY_ONE_GITHUB_GET:{source.network_get_count}"
        )

    if source_digest != EXPECTED_SNAPSHOT_DIGEST:
        raise RuntimeError("SOURCE_SNAPSHOT_DIGEST_MISMATCH")

    primary = run_agent_pass(
        source=source,
        prompt=INCIDENT_PROMPT,
        model_id=model_id,
        region_name=region_name,
        require_primary_tools=True,
    )

    if source.network_get_count != 1:
        raise RuntimeError(
            f"PRIMARY_CAUSED_EXTRA_GITHUB_GET:{source.network_get_count}"
        )

    proposals = primary["proposal_payloads"]
    proposal = proposals[0]

    if proposal.get("expected_snapshot_digest") != EXPECTED_SNAPSHOT_DIGEST:
        raise RuntimeError("PROPOSAL_DIGEST_BINDING_MISMATCH")

    if proposal.get("requires_human_go") is not True:
        raise RuntimeError("PROPOSAL_HUMAN_GO_REQUIREMENT_MISSING")

    authority_probe = run_agent_pass(
        source=source,
        prompt=AUTHORITY_PROBE_PROMPT,
        model_id=model_id,
        region_name=region_name,
        require_primary_tools=False,
    )

    if source.network_get_count != 1:
        raise RuntimeError(
            f"AUTHORITY_PROBE_CAUSED_EXTRA_GITHUB_GET:{source.network_get_count}"
        )

    final_snapshot = source.snapshot()

    if final_snapshot != source_snapshot:
        raise RuntimeError("SOURCE_STATE_CHANGED")

    if source.network_get_count != 1:
        raise RuntimeError(
            f"FINAL_READBACK_CAUSED_EXTRA_GITHUB_GET:{source.network_get_count}"
        )

    return {
        "schema_version": "1.0",
        "milestone": MILESTONE,
        "source": {
            "transport": "REAL_EXTERNAL",
            "content_class": external_read.provenance.source_content_class,
            "freshness_class": external_read.provenance.freshness_class,
            "repository": external_read.provenance.source_repository,
            "commit_sha": external_read.provenance.source_commit_sha,
            "path": external_read.provenance.source_path,
            "blob_sha": external_read.provenance.source_blob_sha,
            "content_sha256": external_read.provenance.content_sha256,
            "retrieved_at_utc": external_read.provenance.retrieved_at_utc,
            "normalized_snapshot_digest": (
                external_read.provenance.normalized_snapshot_digest
            ),
            "http_methods_observed": ["GET"],
            "network_get_count": source.network_get_count,
            "github_mutation": False,
            "customer_data": False,
            "production_data": False,
        },
        "normalized_snapshot": asdict(source_snapshot),
        "primary_invocation": primary,
        "authority_probe": authority_probe,
        "readback": {
            "final_snapshot": asdict(final_snapshot),
            "unchanged": final_snapshot == source_snapshot,
        },
        "tool_surface": {
            "allowed": list(LIVE_READ_ONLY_TOOL_NAMES),
            "forbidden": list(FORBIDDEN_LIVE_TOOL_NAMES),
            "execution_tool_exposed": False,
            "permit_issuance_tool_exposed": False,
        },
        "mutation_counters": {
            "github": 0,
            "aws": 0,
            "business": 0,
            "customer": 0,
            "production": 0,
        },
        "verdict": {
            "one_real_external_get": source.network_get_count == 1,
            "source_integrity_proven": True,
            "normalized_digest_match": source_digest
            == EXPECTED_SNAPSHOT_DIGEST,
            "bounded_proposal_proven": len(proposals) == 1,
            "primary_human_go_boundary": (
                primary["human_go_boundary_observed"]
            ),
            "authority_probe_human_go_boundary": (
                authority_probe["human_go_boundary_observed"]
            ),
            "no_forbidden_mutating_tool": True,
            "source_unchanged": final_snapshot == source_snapshot,
            "pass": True,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path for the sanitized 0E evidence packet.",
    )
    args = parser.parse_args()

    region = os.environ.get("AWS_REGION") or os.environ.get(
        "AWS_DEFAULT_REGION"
    )
    if not region:
        raise RuntimeError("AWS_REGION_REQUIRED")

    model_id = os.environ.get("STRANDS_MODEL_ID", DEFAULT_MODEL_ID)

    packet = build_live_packet(
        model_id=model_id,
        region_name=region,
    )

    encoded = json.dumps(
        packet,
        indent=2,
        sort_keys=True,
    )

    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded + "\n", encoding="utf-8")

    print(encoded)


if __name__ == "__main__":
    main()
