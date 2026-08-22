from __future__ import annotations

import base64
import json
from binascii import Error as BinasciiError
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha1, sha256
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .models import IncidentSnapshot

SOURCE_PROVIDER = "GitHub"
SOURCE_REPOSITORY = "Arthur9293/bosai-governed-incident-agent"
SOURCE_COMMIT = "03735eff72052facd215d3ab39b0e73bd57dd3ef"
SOURCE_PATH = "evidence/0b-live-strands-evidence.json"
EXPECTED_BLOB_SHA = "8a88a4b3f828acfea48810a70f81a579173e235d"
EXPECTED_SNAPSHOT_DIGEST = (
    "62167321912376e467cfed5758a48035f6332295d04ee16175d4d6a34b176f71"
)

SOURCE_CONTENT_CLASS = "SYNTHETIC_APPROVED"
FRESHNESS_CLASS = "IMMUTABLE_ARCHIVAL_PROOF"

GITHUB_API_URL = (
    "https://api.github.com/repos/"
    f"{SOURCE_REPOSITORY}/contents/{SOURCE_PATH}?ref={SOURCE_COMMIT}"
)

DEFAULT_TIMEOUT_SECONDS = 10.0
MAX_RESPONSE_BYTES = 1_048_576


class GitHubEvidenceSourceError(RuntimeError):
    """Fail-closed error raised by the immutable GitHub evidence source."""


@dataclass(frozen=True)
class GitHubEvidenceProvenance:
    source_provider: str
    source_repository: str
    source_commit_sha: str
    source_path: str
    source_blob_sha: str
    retrieved_at_utc: str
    content_sha256: str
    normalized_snapshot_digest: str
    source_content_class: str
    freshness_class: str
    http_method: str = "GET"
    github_mutation: bool = False
    customer_data: bool = False
    production_data: bool = False


@dataclass(frozen=True)
class GitHubEvidenceRead:
    snapshot: IncidentSnapshot
    provenance: GitHubEvidenceProvenance


class GitHubImmutableEvidenceSource:
    """One immutable GitHub evidence object exposed as IncidentEvidenceSource."""

    def __init__(
        self,
        *,
        opener: Any = urlopen,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._opener = opener
        self._timeout_seconds = timeout_seconds
        self._attempted = False
        self._cached_read: GitHubEvidenceRead | None = None
        self._network_get_count = 0

    @property
    def network_get_count(self) -> int:
        return self._network_get_count

    def snapshot(self) -> IncidentSnapshot:
        return self.read().snapshot

    def read(self) -> GitHubEvidenceRead:
        if self._cached_read is not None:
            return self._cached_read

        if self._attempted:
            raise GitHubEvidenceSourceError("SOURCE_ALREADY_ATTEMPTED")

        self._attempted = True
        raw_response = self._fetch_once()
        evidence_read = self._decode_and_validate(raw_response)
        self._cached_read = evidence_read
        return evidence_read

    def _fetch_once(self) -> bytes:
        request = Request(
            GITHUB_API_URL,
            method="GET",
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "BOSAI-Governed-Incident-Agent-0E",
            },
        )

        self._network_get_count += 1

        try:
            with self._opener(request, timeout=self._timeout_seconds) as response:
                payload = response.read(MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            if exc.code == 404:
                raise GitHubEvidenceSourceError("SOURCE_NOT_FOUND") from exc
            if exc.code == 429:
                raise GitHubEvidenceSourceError("SOURCE_RATE_LIMITED") from exc
            if exc.code == 403:
                raise GitHubEvidenceSourceError("SOURCE_UNAVAILABLE") from exc
            raise GitHubEvidenceSourceError(
                f"SOURCE_HTTP_ERROR:{exc.code}"
            ) from exc
        except TimeoutError as exc:
            raise GitHubEvidenceSourceError("HTTP_TIMEOUT") from exc
        except URLError as exc:
            reason = getattr(exc, "reason", None)
            if isinstance(reason, TimeoutError):
                raise GitHubEvidenceSourceError("HTTP_TIMEOUT") from exc
            raise GitHubEvidenceSourceError("NETWORK_FAILURE") from exc

        if len(payload) > MAX_RESPONSE_BYTES:
            raise GitHubEvidenceSourceError("SOURCE_RESPONSE_TOO_LARGE")

        return payload

    def _decode_and_validate(self, raw_response: bytes) -> GitHubEvidenceRead:
        try:
            envelope = json.loads(raw_response.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GitHubEvidenceSourceError("INVALID_JSON") from exc

        if not isinstance(envelope, dict):
            raise GitHubEvidenceSourceError("INVALID_SOURCE_ENVELOPE")

        if envelope.get("type") != "file":
            raise GitHubEvidenceSourceError("SOURCE_TYPE_MISMATCH")

        if envelope.get("path") != SOURCE_PATH:
            raise GitHubEvidenceSourceError("SOURCE_PATH_DRIFT")

        api_blob_sha = envelope.get("sha")
        if api_blob_sha != EXPECTED_BLOB_SHA:
            raise GitHubEvidenceSourceError("SOURCE_BLOB_DRIFT")

        if envelope.get("encoding") != "base64":
            raise GitHubEvidenceSourceError("SOURCE_ENCODING_UNSUPPORTED")

        encoded_content = envelope.get("content")
        if not isinstance(encoded_content, str) or not encoded_content.strip():
            raise GitHubEvidenceSourceError("INCOMPLETE_EVIDENCE")

        try:
            compact_base64 = "".join(encoded_content.split())
            content = base64.b64decode(compact_base64, validate=True)
        except (ValueError, BinasciiError) as exc:
            raise GitHubEvidenceSourceError("INVALID_BASE64_CONTENT") from exc

        if len(content) > MAX_RESPONSE_BYTES:
            raise GitHubEvidenceSourceError("SOURCE_CONTENT_TOO_LARGE")

        computed_blob_sha = sha1(
            b"blob " + str(len(content)).encode("ascii") + b"\0" + content
        ).hexdigest()

        if computed_blob_sha != EXPECTED_BLOB_SHA:
            raise GitHubEvidenceSourceError("SOURCE_BLOB_INTEGRITY_MISMATCH")

        content_sha256 = sha256(content).hexdigest()

        try:
            document = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GitHubEvidenceSourceError("INVALID_EVIDENCE_JSON") from exc

        if not isinstance(document, dict):
            raise GitHubEvidenceSourceError("INVALID_EVIDENCE_DOCUMENT")

        runtime_readback = document.get("runtime_readback")
        if not isinstance(runtime_readback, dict):
            raise GitHubEvidenceSourceError("INCOMPLETE_EVIDENCE")

        before = runtime_readback.get("before")
        if not isinstance(before, dict):
            raise GitHubEvidenceSourceError("INCOMPLETE_EVIDENCE")

        required_fields = {
            "incident_id",
            "service_id",
            "version",
            "health",
            "error_rate",
            "details",
        }
        if set(before) & required_fields != required_fields:
            raise GitHubEvidenceSourceError("INCOMPLETE_EVIDENCE")

        incident_id = before["incident_id"]
        service_id = before["service_id"]
        version = before["version"]
        health = before["health"]
        error_rate = before["error_rate"]
        details = before["details"]

        if not isinstance(incident_id, str) or not incident_id.strip():
            raise GitHubEvidenceSourceError("INVALID_FIELD_TYPE")
        if not isinstance(service_id, str) or not service_id.strip():
            raise GitHubEvidenceSourceError("INVALID_FIELD_TYPE")
        if isinstance(version, bool) or not isinstance(version, int) or version < 1:
            raise GitHubEvidenceSourceError("INVALID_FIELD_TYPE")
        if not isinstance(health, str) or health not in {"healthy", "degraded"}:
            raise GitHubEvidenceSourceError("INVALID_HEALTH_VALUE")
        if (
            isinstance(error_rate, bool)
            or not isinstance(error_rate, (int, float))
            or not 0.0 <= float(error_rate) <= 1.0
        ):
            raise GitHubEvidenceSourceError("INVALID_ERROR_RATE")
        if not isinstance(details, str) or not details.strip():
            raise GitHubEvidenceSourceError("INVALID_FIELD_TYPE")

        snapshot = IncidentSnapshot(
            incident_id=incident_id,
            service_id=service_id,
            version=version,
            health=health,
            error_rate=float(error_rate),
            details=details,
        )

        normalized_digest = snapshot.digest()
        if normalized_digest != EXPECTED_SNAPSHOT_DIGEST:
            raise GitHubEvidenceSourceError("NORMALIZED_DIGEST_MISMATCH")

        provenance = GitHubEvidenceProvenance(
            source_provider=SOURCE_PROVIDER,
            source_repository=SOURCE_REPOSITORY,
            source_commit_sha=SOURCE_COMMIT,
            source_path=SOURCE_PATH,
            source_blob_sha=api_blob_sha,
            retrieved_at_utc=datetime.now(timezone.utc).isoformat(),
            content_sha256=content_sha256,
            normalized_snapshot_digest=normalized_digest,
            source_content_class=SOURCE_CONTENT_CLASS,
            freshness_class=FRESHNESS_CLASS,
        )

        return GitHubEvidenceRead(snapshot=snapshot, provenance=provenance)
