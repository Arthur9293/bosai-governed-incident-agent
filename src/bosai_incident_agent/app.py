from __future__ import annotations

import json
from dataclasses import asdict

from .governance import PermitRegistry, execute_authorized, propose
from .runtime import SyntheticIncidentRuntime


def deterministic_demo(*, approve: bool = False) -> dict:
    runtime = SyntheticIncidentRuntime()
    registry = PermitRegistry()
    before = runtime.snapshot()
    proposal = propose(before)

    result = {
        "before": asdict(before),
        "proposal": asdict(proposal),
        "human_go_required": proposal.requires_human_go,
    }
    if not approve:
        return result

    permit = registry.issue(proposal, human_authorized=True)
    receipt = execute_authorized(runtime, registry, proposal, permit.permit_id)
    result["permit"] = asdict(permit)
    result["receipt"] = asdict(receipt)
    result["after"] = asdict(runtime.snapshot())
    return result


def main() -> None:
    print(json.dumps(deterministic_demo(approve=False), indent=2))


if __name__ == "__main__":
    main()
