"""The approval queue: human decisions bound to the canonical hash of one exact broker request.

An approval record stores the full canonical request, its hash, the approval caveat id it answers
and who asked. Records are validated on load: a record whose stored request does not hash to its
``request_hash`` is refused, so what a reviewer is shown is always what the discharge releases.
Requests expire, cannot be decided twice and cannot be approved by the principal that requested
them (separation of duties). The caveat key is never stored: the approver re-opens the sealed
caveat id when it mints a discharge.

A persisted store can be shared by several processes (the approver HTTP service and the review
CLI): every operation takes a file lock and reloads the file first.
"""

from __future__ import annotations

import contextlib
import json
import re
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError, model_validator

from capability_tool_broker.agentic.errors import ApprovalError
from capability_tool_broker.capabilities.request import CanonicalRequest
from capability_tool_broker.core.fileio import atomic_write_text, file_lock

__all__ = ["ApprovalRecord", "ApprovalStatus", "ApprovalStore"]

_ID_ATTEMPTS = 100
_ID = re.compile(r"[0-9a-f]{32}")


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"


class ApprovalRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(pattern=r"^[0-9a-f]{32}$")
    request_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    request: dict[str, JsonValue]
    caveat_id: str = Field(min_length=1, max_length=8_192)
    requested_by: str = Field(min_length=1, max_length=128)
    requested_at: float
    status: ApprovalStatus = ApprovalStatus.PENDING
    decided_by: str | None = None
    decided_at: float | None = None
    reason: str | None = Field(default=None, max_length=512)
    discharge: str | None = None

    @model_validator(mode="after")
    def _request_matches_hash(self) -> ApprovalRecord:
        if self.canonical_request().request_hash() != self.request_hash:
            raise ValueError("request_hash does not match the stored request")
        if (self.discharge is not None) != (self.status is ApprovalStatus.APPROVED):
            raise ValueError("only approved records carry a discharge")
        return self

    def canonical_request(self) -> CanonicalRequest:
        fields = {key: value for key, value in self.request.items() if key != "v"}
        if self.request.get("v") != 1:
            raise ValueError("unsupported request version")
        return CanonicalRequest.model_validate(fields)


class _StoreFile(BaseModel):
    version: int = 1
    records: list[ApprovalRecord] = Field(default_factory=list)


class ApprovalStore:
    """Approval records, optionally persisted to a JSON file shared safely between processes."""

    def __init__(
        self,
        path: Path | None = None,
        *,
        ttl_seconds: float = 3600.0,
        clock: Callable[[], float] = time.time,
        id_factory: Callable[[], str] = lambda: uuid.uuid4().hex,
    ) -> None:
        self._path = path
        self._ttl = ttl_seconds
        self._clock = clock
        self._id_factory = id_factory
        self._lock = threading.Lock()
        self._records: dict[str, ApprovalRecord] = {}
        with self._synced():
            pass  # validates an existing file up front

    @contextlib.contextmanager
    def _synced(self) -> Iterator[None]:
        with self._lock:
            if self._path is None:
                yield
                return
            with file_lock(self._path):
                self._load(self._path)
                yield

    def _load(self, path: Path) -> None:
        if not path.exists():
            self._records = {}
            return
        try:
            data = _StoreFile.model_validate_json(path.read_text(encoding="utf-8"))
        except ValidationError as exc:
            raise ApprovalError(f"approval store {path.name} failed validation") from exc
        self._records = {record.id: record for record in data.records}

    def _persist(self) -> None:
        if self._path is None:
            return
        payload = _StoreFile(records=list(self._records.values())).model_dump(mode="json")
        atomic_write_text(self._path, json.dumps(payload, indent=2, sort_keys=True) + "\n")

    def _expired(self, record: ApprovalRecord) -> bool:
        return self._clock() - record.requested_at > self._ttl

    def _get(self, request_id: str) -> ApprovalRecord:
        record = self._records.get(request_id) if _ID.fullmatch(request_id) else None
        if record is None:
            raise ApprovalError("unknown approval request")
        return record

    def _new_id(self) -> str:
        for _ in range(_ID_ATTEMPTS):
            candidate = self._id_factory()
            if _ID.fullmatch(candidate) and candidate not in self._records:
                return candidate
        raise ApprovalError("could not generate a unique approval request id")

    def get(self, request_id: str) -> ApprovalRecord:
        with self._synced():
            return self._get(request_id)

    def pending(self) -> list[ApprovalRecord]:
        with self._synced():
            return sorted(
                (
                    record
                    for record in self._records.values()
                    if record.status is ApprovalStatus.PENDING and not self._expired(record)
                ),
                key=lambda record: record.requested_at,
            )

    def submit(
        self, request: CanonicalRequest, *, caveat_id: str, requested_by: str
    ) -> ApprovalRecord:
        """Create (or return the open) request for this exact call, caveat and principal."""
        request_hash = request.request_hash()
        with self._synced():
            for record in self._records.values():
                if (
                    record.request_hash == request_hash
                    and record.caveat_id == caveat_id
                    and record.requested_by == requested_by
                    and record.status is ApprovalStatus.PENDING
                    and not self._expired(record)
                ):
                    return record
            record = ApprovalRecord(
                id=self._new_id(),
                request_hash=request_hash,
                request=request.canonical_dict(),
                caveat_id=caveat_id,
                requested_by=requested_by,
                requested_at=self._clock(),
            )
            self._records[record.id] = record
            self._persist()
            return record

    def decide(
        self,
        request_id: str,
        *,
        approver: str,
        approve: bool,
        reason: str | None = None,
        discharge: str | None = None,
    ) -> ApprovalRecord:
        with self._synced():
            record = self._get(request_id)
            if record.status is not ApprovalStatus.PENDING:
                raise ApprovalError(f"request is {record.status.value}, not pending")
            if self._expired(record):
                raise ApprovalError("request has expired")
            if approver == record.requested_by:
                raise ApprovalError("separation of duties: requester cannot approve own call")
            if approve and discharge is None:
                raise ApprovalError("an approval needs a discharge")
            decided = ApprovalRecord.model_validate(
                {
                    **record.model_dump(),
                    "status": ApprovalStatus.APPROVED if approve else ApprovalStatus.DENIED,
                    "decided_by": approver,
                    "decided_at": self._clock(),
                    "reason": reason,
                    "discharge": discharge if approve else None,
                }
            )
            self._records[request_id] = decided
            self._persist()
            return decided

    def for_requester(self, request_id: str, requested_by: str) -> ApprovalRecord:
        """The record, only for the principal that requested it (others get 'unknown')."""
        with self._synced():
            record = self._get(request_id)
            if record.requested_by != requested_by:
                raise ApprovalError("unknown approval request")
            return record
