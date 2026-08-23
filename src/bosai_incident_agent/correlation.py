from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

CORRELATION_STATUS_CONSISTENT = "CONSISTENT"
CORRELATION_STATUS_COMPLEMENTARY = "COMPLEMENTARY"
CORRELATION_STATUS_STALE = "STALE_EVIDENCE"
CORRELATION_STATUS_INSUFFICIENT = "INSUFFICIENT_EVIDENCE"
CORRELATION_STATUS_CONFLICT = "SOURCE_CONFLICT"

ALLOWED_SOURCE_KINDS = frozenset(
    {
        "GITHUB_IMMUTABLE",
        "AGENT_ANALYST_AUTHORIZED_READ_ONLY",
    }
)

ALLOWED_FRESHNESS_CLASSES = frozenset(
    {
        "IMMUTABLE_ARCHIVAL_PROOF",
        "FRESH",
        "STALE",
        "UNKNOWN",
    }
)

ALLOWED_CONFIDENCE_CLASSES = frozenset(
    {
        "VERIFIED_INTEGRITY",
        "AUTHORIZED_BOUNDED_READ",
        "SOURCE_ASSERTED",
        "UNKNOWN",
    }
)

FORBIDDEN_CLAIM_FIELDS = frozenset(
    {
        "raw_incident_body",
        "private_note",
        "runtime_trace",
        "full_diagnostic_payload",
        "scoring_prompt",
        "private_reasoning",
        "hidden_evaluation_payload",
        "live_poll_result",
        "backend_response",
        "connector_response",
        "audit_body",
        "approval_capture_payload",
        "persistence_body",
        "operator_private_data",
        "command_payload",
        "execution_permit",
        "worker_request",
        "mutation_body",
        "secret",
        "token",
        "environment_variable",
    }
)


class CorrelationError(RuntimeError):
    """Fail-closed error raised by deterministic multi-source correlation."""


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _digest(value: Any) -> str:
    return sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _require_non_empty_string(value: str, error: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise CorrelationError(error)


def _require_sha256(value: str, error: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise CorrelationError(error)


@dataclass(frozen=True)
class EvidenceClaim:
    field: str
    value: str | int | float | bool | None

    def __post_init__(self) -> None:
        _require_non_empty_string(self.field, "INVALID_CLAIM_FIELD")

        if self.field in FORBIDDEN_CLAIM_FIELDS:
            raise CorrelationError("FORBIDDEN_CLAIM_FIELD")

        if not isinstance(self.value, (str, int, float, bool, type(None))):
            raise CorrelationError("INVALID_CLAIM_VALUE_TYPE")

    def canonical_value(self) -> str:
        return _canonical_json(self.value)


@dataclass(frozen=True)
class EvidenceProvenance:
    source_provider: str
    source_reference: str
    provenance_label: str
    retrieved_at_utc: str
    content_digest: str

    def __post_init__(self) -> None:
        _require_non_empty_string(
            self.source_provider,
            "INVALID_PROVENANCE_PROVIDER",
        )
        _require_non_empty_string(
            self.source_reference,
            "INVALID_PROVENANCE_REFERENCE",
        )
        _require_non_empty_string(
            self.provenance_label,
            "INVALID_PROVENANCE_LABEL",
        )
        _require_non_empty_string(
            self.retrieved_at_utc,
            "INVALID_PROVENANCE_TIMESTAMP",
        )
        _require_sha256(
            self.content_digest,
            "INVALID_PROVENANCE_CONTENT_DIGEST",
        )

    def digest(self) -> str:
        return _digest(
            {
                "source_provider": self.source_provider,
                "source_reference": self.source_reference,
                "provenance_label": self.provenance_label,
                "retrieved_at_utc": self.retrieved_at_utc,
                "content_digest": self.content_digest,
            }
        )


@dataclass(frozen=True)
class EvidenceObservation:
    source_id: str
    source_kind: str
    incident_id: str
    service_id: str | None
    claims: tuple[EvidenceClaim, ...]
    freshness_class: str
    confidence_class: str
    provenance: EvidenceProvenance
    normalized_digest: str
    observed_at_utc: str | None = None

    def __post_init__(self) -> None:
        _require_non_empty_string(self.source_id, "INVALID_SOURCE_ID")
        _require_non_empty_string(self.incident_id, "INVALID_INCIDENT_ID")

        if self.source_kind not in ALLOWED_SOURCE_KINDS:
            raise CorrelationError("UNKNOWN_SOURCE_TYPE")

        if self.service_id is not None:
            _require_non_empty_string(
                self.service_id,
                "INVALID_SERVICE_ID",
            )

        if self.freshness_class not in ALLOWED_FRESHNESS_CLASSES:
            raise CorrelationError("UNKNOWN_FRESHNESS_CLASS")

        if self.confidence_class not in ALLOWED_CONFIDENCE_CLASSES:
            raise CorrelationError("UNKNOWN_CONFIDENCE_CLASS")

        if not isinstance(self.provenance, EvidenceProvenance):
            raise CorrelationError("MISSING_PROVENANCE")

        _require_sha256(
            self.normalized_digest,
            "INVALID_NORMALIZED_DIGEST",
        )

        claim_fields = [claim.field for claim in self.claims]

        if len(claim_fields) != len(set(claim_fields)):
            raise CorrelationError("DUPLICATE_CLAIM_FIELD")

    def digest(self) -> str:
        return _digest(
            {
                "source_id": self.source_id,
                "source_kind": self.source_kind,
                "incident_id": self.incident_id,
                "service_id": self.service_id,
                "claims": [
                    {
                        "field": claim.field,
                        "value": claim.value,
                    }
                    for claim in sorted(
                        self.claims,
                        key=lambda claim: claim.field,
                    )
                ],
                "freshness_class": self.freshness_class,
                "confidence_class": self.confidence_class,
                "provenance_digest": self.provenance.digest(),
                "normalized_digest": self.normalized_digest,
                "observed_at_utc": self.observed_at_utc,
            }
        )


@dataclass(frozen=True)
class CorrelatedEvidenceSet:
    correlation_key: str
    observations: tuple[EvidenceObservation, ...]
    status: str
    conflicts: tuple[str, ...]
    stale_sources: tuple[str, ...]
    missing_evidence: tuple[str, ...]
    correlation_digest: str

    @property
    def proposal_allowed(self) -> bool:
        return self.status in {
            CORRELATION_STATUS_CONSISTENT,
            CORRELATION_STATUS_COMPLEMENTARY,
        }

    @property
    def human_review_required(self) -> bool:
        return not self.proposal_allowed


def _correlation_key(
    observations: tuple[EvidenceObservation, ...],
) -> str:
    incident_ids = sorted(
        {observation.incident_id for observation in observations}
    )

    if len(incident_ids) == 1:
        return f"incident:{incident_ids[0]}"

    return f"incident-conflict:{_digest(incident_ids)}"


def _claim_index(
    observations: tuple[EvidenceObservation, ...],
) -> dict[str, list[tuple[str, str]]]:
    indexed: dict[str, list[tuple[str, str]]] = {}

    for observation in observations:
        for claim in observation.claims:
            indexed.setdefault(claim.field, []).append(
                (observation.source_id, claim.canonical_value())
            )

    return indexed


def correlate_evidence(
    observations: tuple[EvidenceObservation, ...],
) -> CorrelatedEvidenceSet:
    if len(observations) < 2:
        status = CORRELATION_STATUS_INSUFFICIENT
        missing_evidence = ("SECOND_SOURCE_REQUIRED",)
        conflicts: tuple[str, ...] = ()
        stale_sources: tuple[str, ...] = ()
    else:
        source_ids = [observation.source_id for observation in observations]

        if len(source_ids) != len(set(source_ids)):
            raise CorrelationError("DUPLICATE_SOURCE_ID")

        conflicts_list: list[str] = []

        incident_ids = {
            observation.incident_id for observation in observations
        }
        if len(incident_ids) > 1:
            conflicts_list.append("incident_id")

        known_service_ids = {
            observation.service_id
            for observation in observations
            if observation.service_id is not None
        }
        if len(known_service_ids) > 1:
            conflicts_list.append("service_id")

        claim_index = _claim_index(observations)

        for field, values in sorted(claim_index.items()):
            if len(values) < 2:
                continue

            distinct_values = {
                canonical_value
                for _source_id, canonical_value in values
            }

            if len(distinct_values) > 1:
                conflicts_list.append(f"claim:{field}")

        stale_sources = tuple(
            sorted(
                observation.source_id
                for observation in observations
                if observation.freshness_class == "STALE"
            )
        )

        unknown_freshness = tuple(
            sorted(
                observation.source_id
                for observation in observations
                if observation.freshness_class == "UNKNOWN"
            )
        )

        conflicts = tuple(sorted(set(conflicts_list)))

        if conflicts:
            status = CORRELATION_STATUS_CONFLICT
            missing_evidence = ()
        elif stale_sources:
            status = CORRELATION_STATUS_STALE
            missing_evidence = ()
        elif unknown_freshness:
            status = CORRELATION_STATUS_INSUFFICIENT
            missing_evidence = tuple(
                f"FRESHNESS_UNKNOWN:{source_id}"
                for source_id in unknown_freshness
            )
        else:
            all_field_sets = [
                {claim.field for claim in observation.claims}
                for observation in observations
            ]

            first_fields = all_field_sets[0]
            same_fields = all(
                field_set == first_fields
                for field_set in all_field_sets[1:]
            )

            status = (
                CORRELATION_STATUS_CONSISTENT
                if same_fields
                else CORRELATION_STATUS_COMPLEMENTARY
            )
            missing_evidence = ()

    ordered_observations = tuple(
        sorted(observations, key=lambda observation: observation.source_id)
    )

    correlation_key = _correlation_key(ordered_observations)

    correlation_digest = _digest(
        {
            "correlation_key": correlation_key,
            "sources": [
                {
                    "source_id": observation.source_id,
                    "normalized_digest": observation.normalized_digest,
                    "provenance_digest": observation.provenance.digest(),
                    "observation_digest": observation.digest(),
                    "freshness_class": observation.freshness_class,
                }
                for observation in ordered_observations
            ],
            "status": status,
            "conflicts": list(conflicts),
            "stale_sources": list(stale_sources),
            "missing_evidence": list(missing_evidence),
        }
    )

    return CorrelatedEvidenceSet(
        correlation_key=correlation_key,
        observations=ordered_observations,
        status=status,
        conflicts=conflicts,
        stale_sources=stale_sources,
        missing_evidence=missing_evidence,
        correlation_digest=correlation_digest,
    )
