from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from math import isfinite
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

PROPOSAL_ELIGIBLE_CONFIDENCE_CLASSES = frozenset(
    {
        "VERIFIED_INTEGRITY",
        "AUTHORIZED_BOUNDED_READ",
    }
)

TEMPORAL_CLAIM_FIELDS = frozenset(
    {
        "health",
        "error_rate",
        "review_status",
        "risk_label",
        "queue_state",
        "blocker_label",
        "next_safe_state",
        "freshness_state",
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
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise CorrelationError("NON_CANONICAL_VALUE") from exc


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


def _normalize_timestamp(value: str, error: str) -> str:
    _require_non_empty_string(value, error)

    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value

    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise CorrelationError(error) from exc

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CorrelationError(error)

    return parsed.astimezone(timezone.utc).isoformat()


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

        if self.value is None:
            raise CorrelationError("NULL_CLAIM_VALUE")

        if isinstance(self.value, str) and not self.value.strip():
            raise CorrelationError("EMPTY_CLAIM_VALUE")

        if isinstance(self.value, float) and not isfinite(self.value):
            raise CorrelationError("NON_FINITE_CLAIM_VALUE")

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
        normalized_retrieved_at = _normalize_timestamp(
            self.retrieved_at_utc,
            "INVALID_PROVENANCE_TIMESTAMP",
        )
        object.__setattr__(
            self,
            "retrieved_at_utc",
            normalized_retrieved_at,
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

        if self.observed_at_utc is not None:
            normalized_observed_at = _normalize_timestamp(
                self.observed_at_utc,
                "INVALID_OBSERVED_TIMESTAMP",
            )
            object.__setattr__(
                self,
                "observed_at_utc",
                normalized_observed_at,
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


@dataclass(frozen=True, init=False)
class CorrelatedEvidenceSet:
    correlation_key: str
    observations: tuple[EvidenceObservation, ...]
    status: str
    conflicts: tuple[str, ...]
    stale_sources: tuple[str, ...]
    missing_evidence: tuple[str, ...]
    temporal_baselines: tuple[str, ...]
    correlation_digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise CorrelationError(
            "DIRECT_CORRELATED_RESULT_CONSTRUCTION_FORBIDDEN"
        )

    @classmethod
    def _create(
        cls,
        *,
        correlation_key: str,
        observations: tuple[EvidenceObservation, ...],
        status: str,
        conflicts: tuple[str, ...],
        stale_sources: tuple[str, ...],
        missing_evidence: tuple[str, ...],
        temporal_baselines: tuple[str, ...],
        correlation_digest: str,
    ) -> CorrelatedEvidenceSet:
        valid_statuses = {
            CORRELATION_STATUS_CONSISTENT,
            CORRELATION_STATUS_COMPLEMENTARY,
            CORRELATION_STATUS_STALE,
            CORRELATION_STATUS_INSUFFICIENT,
            CORRELATION_STATUS_CONFLICT,
        }

        if status not in valid_statuses:
            raise CorrelationError("INVALID_CORRELATED_RESULT_STATUS")

        if status in {
            CORRELATION_STATUS_CONSISTENT,
            CORRELATION_STATUS_COMPLEMENTARY,
        } and (
            len(observations) < 2
            or conflicts
            or stale_sources
            or missing_evidence
        ):
            raise CorrelationError(
                "INVALID_PROPOSAL_ELIGIBLE_RESULT"
            )

        if status == CORRELATION_STATUS_CONFLICT and not conflicts:
            raise CorrelationError("INVALID_CONFLICT_RESULT")

        if status == CORRELATION_STATUS_STALE and not stale_sources:
            raise CorrelationError("INVALID_STALE_RESULT")

        if (
            status == CORRELATION_STATUS_INSUFFICIENT
            and not missing_evidence
        ):
            raise CorrelationError("INVALID_INSUFFICIENT_RESULT")

        instance = object.__new__(cls)

        object.__setattr__(instance, "correlation_key", correlation_key)
        object.__setattr__(instance, "observations", observations)
        object.__setattr__(instance, "status", status)
        object.__setattr__(instance, "conflicts", conflicts)
        object.__setattr__(instance, "stale_sources", stale_sources)
        object.__setattr__(instance, "missing_evidence", missing_evidence)
        object.__setattr__(
            instance,
            "temporal_baselines",
            temporal_baselines,
        )
        object.__setattr__(
            instance,
            "correlation_digest",
            correlation_digest,
        )

        return instance

    @property
    def proposal_allowed(self) -> bool:
        return self.status in {
            CORRELATION_STATUS_CONSISTENT,
            CORRELATION_STATUS_COMPLEMENTARY,
        }

    @property
    def correlation_gate_passed(self) -> bool:
        return self.proposal_allowed

    @property
    def correlation_review_required(self) -> bool:
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


def _provenance_identity(
    observation: EvidenceObservation,
) -> tuple[str, str]:
    return (
        observation.provenance.source_provider.strip().casefold(),
        observation.provenance.source_reference.strip(),
    )


def _observed_datetime(
    observation: EvidenceObservation,
) -> datetime | None:
    if observation.observed_at_utc is None:
        return None

    return datetime.fromisoformat(observation.observed_at_utc)


def _temporal_relation(
    left: EvidenceObservation,
    right: EvidenceObservation,
) -> str:
    left_archival = left.freshness_class == "IMMUTABLE_ARCHIVAL_PROOF"
    right_archival = right.freshness_class == "IMMUTABLE_ARCHIVAL_PROOF"

    if left_archival == right_archival:
        return "NOT_TEMPORALLY_COMPARABLE"

    archive = left if left_archival else right
    current = right if left_archival else left

    archive_time = _observed_datetime(archive)
    current_time = _observed_datetime(current)

    if archive_time is None or current_time is None:
        return "TEMPORAL_CONTEXT_MISSING"

    if archive_time < current_time:
        return "TEMPORAL_BASELINE"

    return "INVALID_TEMPORAL_ORDER"


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
        temporal_baselines: tuple[str, ...] = ()
    else:
        source_ids = [observation.source_id for observation in observations]

        if len(source_ids) != len(set(source_ids)):
            raise CorrelationError("DUPLICATE_SOURCE_ID")

        provenance_identities = [
            _provenance_identity(observation)
            for observation in observations
        ]

        if len(provenance_identities) != len(set(provenance_identities)):
            raise CorrelationError("DUPLICATE_PROVENANCE_IDENTITY")

        observations_by_source = {
            observation.source_id: observation
            for observation in observations
        }

        conflicts_list: list[str] = []
        temporal_baselines_list: list[str] = []
        temporal_missing_list: list[str] = []

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

            if len(distinct_values) <= 1:
                continue

            if field not in TEMPORAL_CLAIM_FIELDS:
                conflicts_list.append(f"claim:{field}")
                continue

            field_conflict = False
            field_temporal = False
            field_temporal_missing = False

            for index, (left_source, left_value) in enumerate(values):
                for right_source, right_value in values[index + 1 :]:
                    if left_value == right_value:
                        continue

                    relation = _temporal_relation(
                        observations_by_source[left_source],
                        observations_by_source[right_source],
                    )

                    if relation == "TEMPORAL_BASELINE":
                        field_temporal = True
                    elif relation == "TEMPORAL_CONTEXT_MISSING":
                        field_temporal_missing = True
                    else:
                        field_conflict = True

            if field_conflict:
                conflicts_list.append(f"claim:{field}")
            elif field_temporal_missing:
                temporal_missing_list.append(field)
            elif field_temporal:
                temporal_baselines_list.append(field)

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

        empty_claim_sources = tuple(
            sorted(
                observation.source_id
                for observation in observations
                if not observation.claims
            )
        )

        non_eligible_confidence = tuple(
            sorted(
                (
                    observation.source_id,
                    observation.confidence_class,
                )
                for observation in observations
                if observation.confidence_class
                not in PROPOSAL_ELIGIBLE_CONFIDENCE_CLASSES
            )
        )

        conflicts = tuple(sorted(set(conflicts_list)))
        temporal_baselines = tuple(
            sorted(set(temporal_baselines_list))
        )

        missing_items = [
            *(
                f"FRESHNESS_UNKNOWN:{source_id}"
                for source_id in unknown_freshness
            ),
            *(
                f"NO_INFORMATIVE_CLAIMS:{source_id}"
                for source_id in empty_claim_sources
            ),
            *(
                "CONFIDENCE_NOT_PROPOSAL_ELIGIBLE:"
                f"{source_id}:{confidence_class}"
                for source_id, confidence_class
                in non_eligible_confidence
            ),
            *(
                f"TEMPORAL_CONTEXT_MISSING:{field}"
                for field in sorted(set(temporal_missing_list))
            ),
        ]

        if conflicts:
            status = CORRELATION_STATUS_CONFLICT
            missing_evidence = ()
        elif stale_sources:
            status = CORRELATION_STATUS_STALE
            missing_evidence = ()
        elif missing_items:
            status = CORRELATION_STATUS_INSUFFICIENT
            missing_evidence = tuple(sorted(missing_items))
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
                if same_fields and not temporal_baselines
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
                    "confidence_class": observation.confidence_class,
                }
                for observation in ordered_observations
            ],
            "status": status,
            "conflicts": list(conflicts),
            "stale_sources": list(stale_sources),
            "missing_evidence": list(missing_evidence),
            "temporal_baselines": list(temporal_baselines),
        }
    )

    return CorrelatedEvidenceSet._create(
        correlation_key=correlation_key,
        observations=ordered_observations,
        status=status,
        conflicts=conflicts,
        stale_sources=stale_sources,
        missing_evidence=missing_evidence,
        temporal_baselines=temporal_baselines,
        correlation_digest=correlation_digest,
    )
