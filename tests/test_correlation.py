from __future__ import annotations

import pytest

from bosai_incident_agent.correlation import (
    CORRELATION_STATUS_COMPLEMENTARY,
    CORRELATION_STATUS_CONFLICT,
    CORRELATION_STATUS_CONSISTENT,
    CORRELATION_STATUS_INSUFFICIENT,
    CORRELATION_STATUS_STALE,
    CorrelationError,
    EvidenceClaim,
    EvidenceObservation,
    EvidenceProvenance,
    correlate_evidence,
)

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64


def provenance(
    source_reference: str,
    *,
    content_digest: str = DIGEST_A,
    retrieved_at_utc: str = "2026-08-23T12:00:00+00:00",
) -> EvidenceProvenance:
    return EvidenceProvenance(
        source_provider="TEST",
        source_reference=source_reference,
        provenance_label="TEST_PROVENANCE",
        retrieved_at_utc=retrieved_at_utc,
        content_digest=content_digest,
    )


def observation(
    source_id: str,
    *,
    source_kind: str = "GITHUB_IMMUTABLE",
    incident_id: str = "inc-001",
    service_id: str | None = "checkout-worker",
    claims: tuple[EvidenceClaim, ...] = (
        EvidenceClaim("health", "degraded"),
    ),
    freshness_class: str = "FRESH",
    confidence_class: str = "VERIFIED_INTEGRITY",
    normalized_digest: str = DIGEST_B,
    source_reference: str | None = None,
    observed_at_utc: str | None = "2026-08-23T12:00:00+00:00",
) -> EvidenceObservation:
    return EvidenceObservation(
        source_id=source_id,
        source_kind=source_kind,
        incident_id=incident_id,
        service_id=service_id,
        claims=claims,
        freshness_class=freshness_class,
        confidence_class=confidence_class,
        provenance=provenance(
            source_reference or f"test:{source_id}",
            content_digest=DIGEST_C,
        ),
        normalized_digest=normalized_digest,
        observed_at_utc=observed_at_utc,
    )


def test_matching_sources_are_consistent() -> None:
    source_a = observation(
        "source-a",
        claims=(
            EvidenceClaim("health", "degraded"),
            EvidenceClaim("error_rate", 0.42),
        ),
        normalized_digest=DIGEST_A,
    )
    source_b = observation(
        "source-b",
        source_kind="AGENT_ANALYST_AUTHORIZED_READ_ONLY",
        claims=(
            EvidenceClaim("health", "degraded"),
            EvidenceClaim("error_rate", 0.42),
        ),
        confidence_class="AUTHORIZED_BOUNDED_READ",
        normalized_digest=DIGEST_B,
    )

    result = correlate_evidence((source_a, source_b))

    assert result.status == CORRELATION_STATUS_CONSISTENT
    assert result.conflicts == ()
    assert result.proposal_allowed is True
    assert result.correlation_review_required is False


def test_compatible_non_overlapping_claims_are_complementary() -> None:
    source_a = observation(
        "source-a",
        claims=(EvidenceClaim("health", "degraded"),),
    )
    source_b = observation(
        "source-b",
        source_kind="AGENT_ANALYST_AUTHORIZED_READ_ONLY",
        claims=(EvidenceClaim("review_status", "REVIEW_REQUIRED"),),
        confidence_class="AUTHORIZED_BOUNDED_READ",
        normalized_digest=DIGEST_C,
    )

    result = correlate_evidence((source_a, source_b))

    assert result.status == CORRELATION_STATUS_COMPLEMENTARY
    assert result.conflicts == ()
    assert result.proposal_allowed is True


def test_different_incident_ids_fail_as_source_conflict() -> None:
    source_a = observation("source-a", incident_id="inc-001")
    source_b = observation(
        "source-b",
        incident_id="inc-999",
        source_kind="AGENT_ANALYST_AUTHORIZED_READ_ONLY",
    )

    result = correlate_evidence((source_a, source_b))

    assert result.status == CORRELATION_STATUS_CONFLICT
    assert "incident_id" in result.conflicts
    assert result.proposal_allowed is False
    assert result.correlation_review_required is True


def test_different_known_service_ids_fail_as_source_conflict() -> None:
    source_a = observation(
        "source-a",
        service_id="checkout-worker",
    )
    source_b = observation(
        "source-b",
        service_id="payments-worker",
        source_kind="AGENT_ANALYST_AUTHORIZED_READ_ONLY",
    )

    result = correlate_evidence((source_a, source_b))

    assert result.status == CORRELATION_STATUS_CONFLICT
    assert "service_id" in result.conflicts


def test_same_claim_with_different_values_fails_as_source_conflict() -> None:
    source_a = observation(
        "source-a",
        claims=(EvidenceClaim("health", "degraded"),),
    )
    source_b = observation(
        "source-b",
        source_kind="AGENT_ANALYST_AUTHORIZED_READ_ONLY",
        claims=(EvidenceClaim("health", "healthy"),),
    )

    result = correlate_evidence((source_a, source_b))

    assert result.status == CORRELATION_STATUS_CONFLICT
    assert "claim:health" in result.conflicts


def test_stale_source_requires_review_and_blocks_proposal() -> None:
    source_a = observation("source-a")
    source_b = observation(
        "source-b",
        source_kind="AGENT_ANALYST_AUTHORIZED_READ_ONLY",
        freshness_class="STALE",
    )

    result = correlate_evidence((source_a, source_b))

    assert result.status == CORRELATION_STATUS_STALE
    assert result.stale_sources == ("source-b",)
    assert result.proposal_allowed is False
    assert result.correlation_review_required is True


def test_unknown_freshness_is_insufficient_evidence() -> None:
    source_a = observation("source-a")
    source_b = observation(
        "source-b",
        source_kind="AGENT_ANALYST_AUTHORIZED_READ_ONLY",
        freshness_class="UNKNOWN",
    )

    result = correlate_evidence((source_a, source_b))

    assert result.status == CORRELATION_STATUS_INSUFFICIENT
    assert result.missing_evidence == (
        "FRESHNESS_UNKNOWN:source-b",
    )
    assert result.proposal_allowed is False


def test_single_source_is_insufficient() -> None:
    result = correlate_evidence((observation("source-a"),))

    assert result.status == CORRELATION_STATUS_INSUFFICIENT
    assert result.missing_evidence == ("SECOND_SOURCE_REQUIRED",)
    assert result.proposal_allowed is False


def test_duplicate_source_identity_fails_closed() -> None:
    source_a = observation("same-source", normalized_digest=DIGEST_A)
    source_b = observation(
        "same-source",
        source_kind="AGENT_ANALYST_AUTHORIZED_READ_ONLY",
        normalized_digest=DIGEST_B,
    )

    with pytest.raises(
        CorrelationError,
        match="DUPLICATE_SOURCE_ID",
    ):
        correlate_evidence((source_a, source_b))


def test_unknown_source_type_fails_closed() -> None:
    with pytest.raises(
        CorrelationError,
        match="UNKNOWN_SOURCE_TYPE",
    ):
        observation(
            "source-a",
            source_kind="UNAPPROVED_SOURCE",
        )


def test_forbidden_claim_field_fails_closed() -> None:
    with pytest.raises(
        CorrelationError,
        match="FORBIDDEN_CLAIM_FIELD",
    ):
        EvidenceClaim(
            "execution_permit",
            "permit-must-never-enter-evidence",
        )


def test_invalid_provenance_digest_fails_closed() -> None:
    with pytest.raises(
        CorrelationError,
        match="INVALID_PROVENANCE_CONTENT_DIGEST",
    ):
        provenance(
            "test:bad",
            content_digest="not-a-sha256",
        )


def test_duplicate_claim_field_fails_closed() -> None:
    with pytest.raises(
        CorrelationError,
        match="DUPLICATE_CLAIM_FIELD",
    ):
        observation(
            "source-a",
            claims=(
                EvidenceClaim("health", "degraded"),
                EvidenceClaim("health", "degraded"),
            ),
        )


def test_correlation_digest_is_source_order_independent() -> None:
    source_a = observation(
        "source-a",
        claims=(EvidenceClaim("health", "degraded"),),
        normalized_digest=DIGEST_A,
    )
    source_b = observation(
        "source-b",
        source_kind="AGENT_ANALYST_AUTHORIZED_READ_ONLY",
        claims=(EvidenceClaim("review_status", "READY"),),
        confidence_class="AUTHORIZED_BOUNDED_READ",
        normalized_digest=DIGEST_D,
    )

    forward = correlate_evidence((source_a, source_b))
    reverse = correlate_evidence((source_b, source_a))

    assert forward.status == CORRELATION_STATUS_COMPLEMENTARY
    assert reverse.status == CORRELATION_STATUS_COMPLEMENTARY
    assert forward.correlation_digest == reverse.correlation_digest
    assert forward.correlation_key == reverse.correlation_key


def test_conflict_takes_precedence_over_staleness() -> None:
    source_a = observation(
        "source-a",
        claims=(EvidenceClaim("health", "degraded"),),
    )
    source_b = observation(
        "source-b",
        source_kind="AGENT_ANALYST_AUTHORIZED_READ_ONLY",
        claims=(EvidenceClaim("health", "healthy"),),
        freshness_class="STALE",
    )

    result = correlate_evidence((source_a, source_b))

    assert result.status == CORRELATION_STATUS_CONFLICT
    assert "claim:health" in result.conflicts
    assert result.proposal_allowed is False
def test_duplicate_provenance_identity_fails_closed() -> None:
    source_a = observation(
        "alias-a",
        source_reference="github:exact-source",
        normalized_digest=DIGEST_A,
    )
    source_b = observation(
        "alias-b",
        source_reference="github:exact-source",
        normalized_digest=DIGEST_B,
    )

    with pytest.raises(
        CorrelationError,
        match="DUPLICATE_PROVENANCE_IDENTITY",
    ):
        correlate_evidence((source_a, source_b))


def test_empty_claims_are_insufficient_evidence() -> None:
    source_a = observation(
        "source-a",
        claims=(),
    )
    source_b = observation(
        "source-b",
        source_kind="AGENT_ANALYST_AUTHORIZED_READ_ONLY",
        claims=(),
        confidence_class="AUTHORIZED_BOUNDED_READ",
    )

    result = correlate_evidence((source_a, source_b))

    assert result.status == CORRELATION_STATUS_INSUFFICIENT
    assert "NO_INFORMATIVE_CLAIMS:source-a" in result.missing_evidence
    assert "NO_INFORMATIVE_CLAIMS:source-b" in result.missing_evidence
    assert result.proposal_allowed is False


def test_null_claim_value_fails_closed() -> None:
    with pytest.raises(
        CorrelationError,
        match="NULL_CLAIM_VALUE",
    ):
        EvidenceClaim("health", None)


def test_empty_string_claim_value_fails_closed() -> None:
    with pytest.raises(
        CorrelationError,
        match="EMPTY_CLAIM_VALUE",
    ):
        EvidenceClaim("health", "   ")


def test_unknown_confidence_blocks_proposal() -> None:
    source_a = observation("source-a")
    source_b = observation(
        "source-b",
        source_kind="AGENT_ANALYST_AUTHORIZED_READ_ONLY",
        confidence_class="UNKNOWN",
    )

    result = correlate_evidence((source_a, source_b))

    assert result.status == CORRELATION_STATUS_INSUFFICIENT
    assert (
        "CONFIDENCE_NOT_PROPOSAL_ELIGIBLE:source-b:UNKNOWN"
        in result.missing_evidence
    )
    assert result.proposal_allowed is False


def test_source_asserted_confidence_is_not_proposal_eligible() -> None:
    source_a = observation("source-a")
    source_b = observation(
        "source-b",
        source_kind="AGENT_ANALYST_AUTHORIZED_READ_ONLY",
        confidence_class="SOURCE_ASSERTED",
    )

    result = correlate_evidence((source_a, source_b))

    assert result.status == CORRELATION_STATUS_INSUFFICIENT
    assert (
        "CONFIDENCE_NOT_PROPOSAL_ELIGIBLE:source-b:SOURCE_ASSERTED"
        in result.missing_evidence
    )
    assert result.proposal_allowed is False


def test_review_semantics_are_correlation_local_only() -> None:
    source_a = observation(
        "source-a",
        normalized_digest=DIGEST_A,
    )
    source_b = observation(
        "source-b",
        source_kind="AGENT_ANALYST_AUTHORIZED_READ_ONLY",
        confidence_class="AUTHORIZED_BOUNDED_READ",
        normalized_digest=DIGEST_B,
    )

    result = correlate_evidence((source_a, source_b))

    assert result.status == CORRELATION_STATUS_CONSISTENT
    assert result.correlation_gate_passed is True
    assert result.correlation_review_required is False
    assert not hasattr(result, "human_review_required")


def test_archival_and_later_current_claim_form_temporal_baseline() -> None:
    archival = observation(
        "archive",
        freshness_class="IMMUTABLE_ARCHIVAL_PROOF",
        claims=(EvidenceClaim("health", "degraded"),),
        observed_at_utc="2026-08-23T10:00:00+00:00",
        normalized_digest=DIGEST_A,
    )
    current = observation(
        "current",
        source_kind="AGENT_ANALYST_AUTHORIZED_READ_ONLY",
        freshness_class="FRESH",
        confidence_class="AUTHORIZED_BOUNDED_READ",
        claims=(EvidenceClaim("health", "healthy"),),
        observed_at_utc="2026-08-23T12:00:00+00:00",
        normalized_digest=DIGEST_B,
    )

    result = correlate_evidence((archival, current))

    assert result.status == CORRELATION_STATUS_COMPLEMENTARY
    assert result.conflicts == ()
    assert result.temporal_baselines == ("health",)
    assert result.correlation_gate_passed is True


def test_temporal_comparison_without_timestamps_requires_review() -> None:
    archival = observation(
        "archive",
        freshness_class="IMMUTABLE_ARCHIVAL_PROOF",
        claims=(EvidenceClaim("health", "degraded"),),
        observed_at_utc=None,
    )
    current = observation(
        "current",
        source_kind="AGENT_ANALYST_AUTHORIZED_READ_ONLY",
        freshness_class="FRESH",
        confidence_class="AUTHORIZED_BOUNDED_READ",
        claims=(EvidenceClaim("health", "healthy"),),
        observed_at_utc="2026-08-23T12:00:00+00:00",
    )

    result = correlate_evidence((archival, current))

    assert result.status == CORRELATION_STATUS_INSUFFICIENT
    assert (
        "TEMPORAL_CONTEXT_MISSING:health"
        in result.missing_evidence
    )
    assert result.correlation_gate_passed is False


def test_invalid_temporal_order_is_source_conflict() -> None:
    archival = observation(
        "archive",
        freshness_class="IMMUTABLE_ARCHIVAL_PROOF",
        claims=(EvidenceClaim("health", "degraded"),),
        observed_at_utc="2026-08-23T14:00:00+00:00",
    )
    current = observation(
        "current",
        source_kind="AGENT_ANALYST_AUTHORIZED_READ_ONLY",
        freshness_class="FRESH",
        confidence_class="AUTHORIZED_BOUNDED_READ",
        claims=(EvidenceClaim("health", "healthy"),),
        observed_at_utc="2026-08-23T12:00:00+00:00",
    )

    result = correlate_evidence((archival, current))

    assert result.status == CORRELATION_STATUS_CONFLICT
    assert "claim:health" in result.conflicts
    assert result.correlation_gate_passed is False


@pytest.mark.parametrize(
    "value",
    [
        float("nan"),
        float("inf"),
        float("-inf"),
    ],
)
def test_non_finite_claim_values_fail_closed(value: float) -> None:
    with pytest.raises(
        CorrelationError,
        match="NON_FINITE_CLAIM_VALUE",
    ):
        EvidenceClaim("error_rate", value)


def test_naive_observed_timestamp_fails_closed() -> None:
    with pytest.raises(
        CorrelationError,
        match="INVALID_OBSERVED_TIMESTAMP",
    ):
        observation(
            "source-a",
            observed_at_utc="2026-08-23T12:00:00",
        )


def test_naive_provenance_timestamp_fails_closed() -> None:
    with pytest.raises(
        CorrelationError,
        match="INVALID_PROVENANCE_TIMESTAMP",
    ):
        provenance(
            "test:source",
            retrieved_at_utc="2026-08-23T12:00:00",
        )


def test_non_temporal_claim_difference_remains_conflict() -> None:
    archival = observation(
        "archive",
        freshness_class="IMMUTABLE_ARCHIVAL_PROOF",
        claims=(EvidenceClaim("source_commit", "aaaaaaaa"),),
        observed_at_utc="2026-08-23T10:00:00+00:00",
        normalized_digest=DIGEST_A,
    )
    current = observation(
        "current",
        source_kind="AGENT_ANALYST_AUTHORIZED_READ_ONLY",
        freshness_class="FRESH",
        confidence_class="AUTHORIZED_BOUNDED_READ",
        claims=(EvidenceClaim("source_commit", "bbbbbbbb"),),
        observed_at_utc="2026-08-23T12:00:00+00:00",
        normalized_digest=DIGEST_B,
    )

    result = correlate_evidence((archival, current))

    assert result.status == CORRELATION_STATUS_CONFLICT
    assert "claim:source_commit" in result.conflicts
    assert result.temporal_baselines == ()
    assert result.correlation_gate_passed is False


def test_temporal_allowlisted_claim_can_form_baseline() -> None:
    archival = observation(
        "archive",
        freshness_class="IMMUTABLE_ARCHIVAL_PROOF",
        claims=(EvidenceClaim("health", "degraded"),),
        observed_at_utc="2026-08-23T10:00:00+00:00",
        normalized_digest=DIGEST_A,
    )
    current = observation(
        "current",
        source_kind="AGENT_ANALYST_AUTHORIZED_READ_ONLY",
        freshness_class="FRESH",
        confidence_class="AUTHORIZED_BOUNDED_READ",
        claims=(EvidenceClaim("health", "healthy"),),
        observed_at_utc="2026-08-23T12:00:00+00:00",
        normalized_digest=DIGEST_B,
    )

    result = correlate_evidence((archival, current))

    assert result.status == CORRELATION_STATUS_COMPLEMENTARY
    assert result.conflicts == ()
    assert result.temporal_baselines == ("health",)
    assert result.correlation_gate_passed is True


def test_same_physical_source_with_different_kind_fails_closed() -> None:
    source_a = observation(
        "source-a",
        source_kind="GITHUB_IMMUTABLE",
        source_reference="physical:source-001",
        normalized_digest=DIGEST_A,
    )
    source_b = observation(
        "source-b",
        source_kind="AGENT_ANALYST_AUTHORIZED_READ_ONLY",
        source_reference="physical:source-001",
        confidence_class="AUTHORIZED_BOUNDED_READ",
        normalized_digest=DIGEST_B,
    )

    with pytest.raises(
        CorrelationError,
        match="DUPLICATE_PROVENANCE_IDENTITY",
    ):
        correlate_evidence((source_a, source_b))


def test_physical_source_provider_identity_is_case_insensitive() -> None:
    source_a = EvidenceObservation(
        source_id="source-a",
        source_kind="GITHUB_IMMUTABLE",
        incident_id="inc-001",
        service_id="checkout-worker",
        claims=(EvidenceClaim("health", "degraded"),),
        freshness_class="FRESH",
        confidence_class="VERIFIED_INTEGRITY",
        provenance=EvidenceProvenance(
            source_provider="GitHub",
            source_reference="physical:source-001",
            provenance_label="TEST_PROVENANCE",
            retrieved_at_utc="2026-08-23T12:00:00+00:00",
            content_digest=DIGEST_C,
        ),
        normalized_digest=DIGEST_A,
        observed_at_utc="2026-08-23T12:00:00+00:00",
    )
    source_b = EvidenceObservation(
        source_id="source-b",
        source_kind="AGENT_ANALYST_AUTHORIZED_READ_ONLY",
        incident_id="inc-001",
        service_id="checkout-worker",
        claims=(EvidenceClaim("health", "degraded"),),
        freshness_class="FRESH",
        confidence_class="AUTHORIZED_BOUNDED_READ",
        provenance=EvidenceProvenance(
            source_provider="github",
            source_reference="physical:source-001",
            provenance_label="TEST_PROVENANCE",
            retrieved_at_utc="2026-08-23T12:00:00+00:00",
            content_digest=DIGEST_D,
        ),
        normalized_digest=DIGEST_B,
        observed_at_utc="2026-08-23T12:00:00+00:00",
    )

    with pytest.raises(
        CorrelationError,
        match="DUPLICATE_PROVENANCE_IDENTITY",
    ):
        correlate_evidence((source_a, source_b))


def test_direct_correlated_result_construction_is_forbidden() -> None:
    from bosai_incident_agent.correlation import CorrelatedEvidenceSet

    with pytest.raises(
        CorrelationError,
        match="DIRECT_CORRELATED_RESULT_CONSTRUCTION_FORBIDDEN",
    ):
        CorrelatedEvidenceSet(
            correlation_key="incident:inc-001",
            observations=(),
            status=CORRELATION_STATUS_CONSISTENT,
            conflicts=(),
            stale_sources=(),
            missing_evidence=(),
            temporal_baselines=(),
            correlation_digest=DIGEST_A,
        )


def test_internal_factory_rejects_invalid_proposal_eligible_result() -> None:
    from bosai_incident_agent.correlation import CorrelatedEvidenceSet

    with pytest.raises(
        CorrelationError,
        match="INVALID_PROPOSAL_ELIGIBLE_RESULT",
    ):
        CorrelatedEvidenceSet._create(
            correlation_key="incident:inc-001",
            observations=(),
            status=CORRELATION_STATUS_CONSISTENT,
            conflicts=(),
            stale_sources=(),
            missing_evidence=(),
            temporal_baselines=(),
            correlation_digest=DIGEST_A,
        )
