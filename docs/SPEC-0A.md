# 0A — Strands Governed Incident Bootstrap

## Objective

Prove one narrow Professional Agents workflow before expanding scope:

`incident -> read evidence -> bounded proposal -> Human GO -> single-use permit -> controlled mutation -> verified readback`

## Safety invariants

1. Investigation and proposal tools are read-only.
2. The model cannot mint Human GO.
3. Every Human GO issuance creates a unique event id and a distinct permit id.
4. A permit is bound to proposal id, action, target, state version, and state digest.
5. Consumed permit records are never overwritten or resurrected by re-issuance.
6. Missing, mismatched, drifted, or replayed permits fail closed.
7. A permit is consumed before the mutation attempt.
8. Execution is followed by an explicit readback.
9. The demo runtime is synthetic until a later gate authorizes AWS deployment.

## Strands integration

`build_agent()` registers three Strands tools:

- `read_service_state`
- `draft_bounded_remediation`
- `execute_with_permit`

The mutating tool accepts only an externally issued permit. The permit registry is intentionally outside the LLM tool surface.

## 0A acceptance

- synthetic governance runtime and control outcomes implemented;
- 10 governance tests pass;
- CI defined;
- Strands tool wiring present;
- no AWS deployment;
- no production credentials;
- no external mutation;
- no final Devpost submission.
