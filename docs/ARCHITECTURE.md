# Architecture

```mermaid
flowchart LR
  I[Incident signal] --> A[Strands Agent]
  A --> R[Read-only evidence tool]
  R --> D[Diagnosis]
  D --> P[Bounded remediation proposal]
  P --> G{Human authority required?}
  G -->|Yes| H[Human GO]
  H --> K[Single-use permit]
  K --> X[execute_with_permit]
  G -->|No / future policy| X
  X --> V[Verified readback]
  V --> E[Execution receipt / evidence]
```

## Authority boundary

Strands can investigate, reason, and call tools. It cannot issue its own approval permit.
The Human GO path exists outside the model's registered tools.

## Current 0A runtime

The first slice uses an in-memory synthetic incident runtime. This isolates governance semantics and makes replay/drift behavior deterministic. A later milestone may bind the same contract to AWS/AgentCore after explicit review.
