from __future__ import annotations

import base64
import json
from hashlib import sha1
from pathlib import Path
from urllib.error import HTTPError, URLError

import pytest

from bosai_incident_agent.github_evidence_source import (
    EXPECTED_BLOB_SHA,
    EXPECTED_SNAPSHOT_DIGEST,
    SOURCE_PATH,
    GitHubEvidenceSourceError,
    GitHubImmutableEvidenceSource,
)
from bosai_incident_agent.source import IncidentEvidenceSource

REPO_ROOT = Path(__file__).resolve().parents[1]
LOCAL_EVIDENCE = REPO_ROOT / "evidence" / "0b-live-strands-evidence.json"


def git_blob_sha(content: bytes) -> str:
    return sha1(
        b"blob " + str(len(content)).encode("ascii") + b"\0" + content
    ).hexdigest()


def github_envelope(
    content: bytes,
    *,
    path: str = SOURCE_PATH,
    blob_sha: str | None = None,
) -> bytes:
    payload = {
        "type": "file",
        "path": path,
        "sha": blob_sha or git_blob_sha(content),
        "encoding": "base64",
        "content": base64.b64encode(content).decode("ascii"),
    }
    return json.dumps(payload).encode("utf-8")


class FakeResponse:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            return self.payload
        return self.payload[:size]


class RecordingOpener:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.calls = []

    def __call__(self, request, *, timeout: float):
        self.calls.append((request, timeout))
        return FakeResponse(self.payload)


def real_local_content() -> bytes:
    return LOCAL_EVIDENCE.read_bytes()


def test_local_pinned_evidence_matches_expected_blob_and_snapshot_digest() -> None:
    content = real_local_content()

    assert git_blob_sha(content) == EXPECTED_BLOB_SHA

    opener = RecordingOpener(github_envelope(content))
    source = GitHubImmutableEvidenceSource(opener=opener)

    result = source.read()

    assert result.snapshot.incident_id == "inc-demo-001"
    assert result.snapshot.service_id == "checkout-worker"
    assert result.snapshot.version == 1
    assert result.snapshot.health == "degraded"
    assert result.snapshot.error_rate == 0.42
    assert result.snapshot.digest() == EXPECTED_SNAPSHOT_DIGEST

    assert result.provenance.source_blob_sha == EXPECTED_BLOB_SHA
    assert result.provenance.normalized_snapshot_digest == EXPECTED_SNAPSHOT_DIGEST
    assert result.provenance.http_method == "GET"
    assert result.provenance.github_mutation is False
    assert result.provenance.customer_data is False
    assert result.provenance.production_data is False


def test_source_satisfies_incident_evidence_source_protocol() -> None:
    opener = RecordingOpener(github_envelope(real_local_content()))
    source = GitHubImmutableEvidenceSource(opener=opener)

    assert isinstance(source, IncidentEvidenceSource)


def test_successful_read_is_cached_and_performs_exactly_one_get() -> None:
    opener = RecordingOpener(github_envelope(real_local_content()))
    source = GitHubImmutableEvidenceSource(opener=opener)

    first = source.read()
    second = source.read()
    snapshot = source.snapshot()

    assert first is second
    assert snapshot == first.snapshot
    assert source.network_get_count == 1
    assert len(opener.calls) == 1

    request, _timeout = opener.calls[0]
    assert request.get_method() == "GET"


def test_wrong_path_fails_closed() -> None:
    payload = github_envelope(
        real_local_content(),
        path="evidence/not-authorized.json",
    )
    source = GitHubImmutableEvidenceSource(opener=RecordingOpener(payload))

    with pytest.raises(GitHubEvidenceSourceError, match="SOURCE_PATH_DRIFT"):
        source.read()


def test_wrong_api_blob_sha_fails_closed() -> None:
    payload = github_envelope(
        real_local_content(),
        blob_sha="0" * 40,
    )
    source = GitHubImmutableEvidenceSource(opener=RecordingOpener(payload))

    with pytest.raises(GitHubEvidenceSourceError, match="SOURCE_BLOB_DRIFT"):
        source.read()


def test_malformed_github_envelope_fails_closed() -> None:
    source = GitHubImmutableEvidenceSource(
        opener=RecordingOpener(b"{not-json")
    )

    with pytest.raises(GitHubEvidenceSourceError, match="INVALID_JSON"):
        source.read()


def test_missing_required_incident_field_fails_closed(monkeypatch) -> None:
    document = json.loads(real_local_content())
    del document["runtime_readback"]["before"]["service_id"]
    content = json.dumps(document, sort_keys=True).encode("utf-8")

    import bosai_incident_agent.github_evidence_source as module

    monkeypatch.setattr(module, "EXPECTED_BLOB_SHA", git_blob_sha(content))

    source = GitHubImmutableEvidenceSource(
        opener=RecordingOpener(github_envelope(content))
    )

    with pytest.raises(GitHubEvidenceSourceError, match="INCOMPLETE_EVIDENCE"):
        source.read()


def test_invalid_error_rate_fails_closed(monkeypatch) -> None:
    document = json.loads(real_local_content())
    document["runtime_readback"]["before"]["error_rate"] = 2.0
    content = json.dumps(document, sort_keys=True).encode("utf-8")

    import bosai_incident_agent.github_evidence_source as module

    monkeypatch.setattr(module, "EXPECTED_BLOB_SHA", git_blob_sha(content))

    source = GitHubImmutableEvidenceSource(
        opener=RecordingOpener(github_envelope(content))
    )

    with pytest.raises(GitHubEvidenceSourceError, match="INVALID_ERROR_RATE"):
        source.read()


def test_normalized_digest_mismatch_fails_closed(monkeypatch) -> None:
    document = json.loads(real_local_content())
    document["runtime_readback"]["before"]["details"] = "tampered details"
    content = json.dumps(document, sort_keys=True).encode("utf-8")

    import bosai_incident_agent.github_evidence_source as module

    monkeypatch.setattr(module, "EXPECTED_BLOB_SHA", git_blob_sha(content))

    source = GitHubImmutableEvidenceSource(
        opener=RecordingOpener(github_envelope(content))
    )

    with pytest.raises(
        GitHubEvidenceSourceError,
        match="NORMALIZED_DIGEST_MISMATCH",
    ):
        source.read()


@pytest.mark.parametrize(
    ("status_code", "expected_error"),
    [
        (403, "SOURCE_UNAVAILABLE"),
        (404, "SOURCE_NOT_FOUND"),
        (429, "SOURCE_RATE_LIMITED"),
    ],
)
def test_http_failures_fail_closed(status_code: int, expected_error: str) -> None:
    def opener(request, *, timeout: float):
        raise HTTPError(
            request.full_url,
            status_code,
            expected_error,
            hdrs=None,
            fp=None,
        )

    source = GitHubImmutableEvidenceSource(opener=opener)

    with pytest.raises(GitHubEvidenceSourceError, match=expected_error):
        source.read()

    assert source.network_get_count == 1


def test_network_failure_fails_closed() -> None:
    def opener(request, *, timeout: float):
        raise URLError("offline")

    source = GitHubImmutableEvidenceSource(opener=opener)

    with pytest.raises(GitHubEvidenceSourceError, match="NETWORK_FAILURE"):
        source.read()

    assert source.network_get_count == 1


def test_failed_attempt_is_not_silently_retried() -> None:
    calls = 0

    def opener(request, *, timeout: float):
        nonlocal calls
        calls += 1
        raise URLError("offline")

    source = GitHubImmutableEvidenceSource(opener=opener)

    with pytest.raises(GitHubEvidenceSourceError, match="NETWORK_FAILURE"):
        source.read()

    with pytest.raises(
        GitHubEvidenceSourceError,
        match="SOURCE_ALREADY_ATTEMPTED",
    ):
        source.read()

    assert calls == 1
    assert source.network_get_count == 1
