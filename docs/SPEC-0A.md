# 0A — Strands Governed Incident Bootstrap

## Objective

Prove one narrow Professional Agents workflow before expanding scope:

`incident -> read evidence -> bounded proposal -> Human GO -> single-use permit -> controlled mutation -> verified readback`

## Safety invariants

1. Investigation and proposal tools are read-only.
2. The model cannot mint Human GO.
3. A permit is bound to proposal id, action, target, state version, and state digest.
4. Missing, mismatched, drifted, or replayed permits fail closed.
5. A permit is consumed before the mutation attempt.
6. Execution is followed by an explicit readback.
7. The demo runtime is synthetic until a later gate authorizes AWS deployment.

## Strands integration

`build_agent()` registers three Strands tools:

- `read_service_state`
- `draft_bounded_remediation`
- `execute_with_permit`

The mutating tool accepts only an externally issued permit. The permit registry is intentionally outside the LLM tool surface.

## 0A acceptance

- deterministic governance core implemented;
- 7 governance tests pass;
- CI defined;
- Strands tool wiring present;
- no AWS deployment;
- no production credentials;
- no external mutation;
- no final Devpost submission.
