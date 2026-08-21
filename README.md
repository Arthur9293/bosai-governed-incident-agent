# BOSAI Governed Incident Agent

A **Professional Agents** submission for the AWS **Agents for Humans Hackathon**.

BOSAI Governed Incident Agent uses the **Strands Agents SDK** to remove repetitive incident-response work while preserving a hard authority boundary for consequential actions.

## One workflow, end to end

`Incident -> Evidence -> Diagnosis -> Bounded proposal -> Human GO -> Controlled execution -> Verified readback -> Evidence receipt`

The agent can investigate and prepare remediation autonomously. It cannot mint its own approval. A mutating tool succeeds only when an externally issued, single-use permit is bound to the exact proposal and exact pre-execution state.

## Why this matters

SREs, platform engineers, and AI Ops teams spend substantial time collecting evidence, correlating state, preparing remediation, and proving what happened after an action. The expert should spend attention on the judgment boundary, not the repetitive bookkeeping around it.

## 0A status

This first milestone deliberately proves the control semantics on a deterministic synthetic runtime:

- read-only investigation;
- bounded remediation proposal;
- Human GO outside the LLM tool surface;
- single-use permit;
- proposal/scope/state binding;
- fail-closed drift detection;
- replay denial;
- verified post-execution readback;
- CI tests.

No production system is modified in 0A.

## Local setup

Requirements: Python 3.10+.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest -q
```

Run the deterministic, non-mutating preview:

```bash
python -m bosai_incident_agent.app
```

## Strands

`src/bosai_incident_agent/agent.py` builds a Strands `Agent` with three custom tools:

1. `read_service_state` — read only
2. `draft_bounded_remediation` — read only
3. `execute_with_permit` — mutation allowed only with a valid external permit

The Human GO / permit issuance function is not registered as a model tool.

## Hackathon provenance

This is a new hackathon repository and implementation. BOSAI as a name and broader governance/control-plane concepts pre-date the competition. See [`docs/PREEXISTING-WORK-DISCLOSURE.md`](docs/PREEXISTING-WORK-DISCLOSURE.md).

## License

MIT.

## 0B — Live Strands core loop

0B adds a real Amazon Bedrock-backed Strands invocation while keeping the live model's tool surface
strictly read-only. The model must inspect the synthetic incident with `read_service_state`, create
one bounded proposal with `draft_bounded_remediation`, and stop at `HUMAN_GO_REQUIRED`.

The evidence run is explicit and operator-gated:

```bash
AWS_REGION=<your-region> \
STRANDS_MODEL_ID=global.anthropic.claude-sonnet-4-6 \
python scripts/run_live_0b.py
```

It produces `evidence/0b-live-strands-evidence.json`. The packet contains model/tool metrics and
synthetic before/after readback, but no credentials or AWS account identifiers. GitHub CI stays
credential-free; AgentCore deployment is intentionally deferred to a later gate.
