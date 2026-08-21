# 0D — AgentCore Read-Only Evidence Source Contract

## Objective

Introduce a minimal structural read-only evidence-source contract so the live
AgentCore/Strands workflow is no longer coupled to the concrete
`SyntheticIncidentRuntime` type.

This milestone does **not** integrate a real source. It only establishes a
stable interface boundary and keeps the execution contract strictly read-only.

## In scope

- Define a read-only Python protocol for sources used by controlled live mode.
- Accept any concrete source that exposes only the evidence-read path used by 0C.
- Keep the live tool surface unchanged.

## Out of scope

- CloudWatch integration
- boto3
- HTTP
- MCP
- external APIs
- production data
- Memory
- Gateway
- Policy Engine
- AWS mutation
- deployment
- live invocation
- execution authority

## Contract expectations

Evidence supplies state.
Evidence never supplies authority.

Telemetry supplies proof.
Telemetry never supplies authority.

Future memory may supply historical context.
Memory may never replace current authoritative state readback.
