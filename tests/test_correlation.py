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
) -> EvidenceProvenance:
    return EvidenceProvenance(
        source_provider="TEST",
        source_reference=source_reference,
        provenance_label="TEST_PROVENANCE",
        retrieved_at_utc="2026-08-23T12:00:00+00:00",
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
            f"test:{source_id}",
            content_digest=DIGEST_C,
        ),
        normalized_digest=normalized_digest,
        observed_at_utc="2026-08-23T12:00:00+00:00",
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
    assert result.human_review_required is False


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
    assert result.human_review_required is True


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
    assert result.human_review_required is True


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
