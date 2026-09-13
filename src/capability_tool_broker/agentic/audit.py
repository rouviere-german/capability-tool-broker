"""Hash-chained, append-only audit log (JSONL) with signed checkpoints and a verify CLI.

Each line is the canonical JSON of ``{seq, ts, actor, action, data, prev_hash, hash}`` where
``hash = sha256(canonical_json(entry without hash))`` and ``prev_hash`` is the previous entry's
hash (64 zeros for the first). Verification detects edited, deleted, inserted and reordered
entries and re-encoded lines.

A hash chain alone cannot detect a *shorter* or wholly rebuilt log: truncating the tail leaves a
valid chain, and the hash is unkeyed, so anyone who can rewrite the file can recompute every entry.
Checkpoints close that gap when they are stored where the log's writer-side attacker cannot
rewrite them. After every append the writer publishes an :class:`AuditCheckpoint` ``(log, seq,
head)`` authenticated with HMAC-SHA256 under a checkpoint key to a :class:`CheckpointSink` that
never moves backwards. Opening a log refuses one that is behind its latest checkpoint (truncated,
rolled back or deleted) or whose entry at the checkpoint does not carry the checkpointed hash
(history rewritten), and refuses checkpoints with a bad signature or for another log. What stays
undetected: an attacker who can also rewrite the checkpoint sink with the key, or who restores an
older log *and* an older checkpoint together.

Writers take a file lock per append, so several writers (threads, instances or processes) extend
one chain instead of forking it. A writer also refuses to extend a file that shrank or whose last
known entry changed since it last read it, so truncation or rewriting while the log is open is
detected at the next append.

Usage: ``python -m capability_tool_broker.agentic.audit verify audit.jsonl
[--expect-head HASH] [--checkpoint FILE]``
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError

from capability_tool_broker.agentic.errors import AuditIntegrityError
from capability_tool_broker.core.canonical import canonical_json, sha256_hex
from capability_tool_broker.core.fileio import atomic_write_text, file_lock
from capability_tool_broker.core.redaction import redact_value

__all__ = [
    "GENESIS_HASH",
    "AuditCheckpoint",
    "AuditEntry",
    "AuditLog",
    "CheckpointSink",
    "FileCheckpointSink",
    "VerifyResult",
    "main",
    "verify_file",
]

GENESIS_HASH = "0" * 64
_CHECKPOINT_LABEL = b"ctb-audit-checkpoint-v1\x00"
_BEHIND = "log is behind its last checkpoint (truncated or rolled back)"
_REWRITTEN = "log does not match its last checkpoint (history rewritten)"


class AuditEntry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    seq: int = Field(ge=0)
    ts: str
    actor: str
    action: str
    data: dict[str, JsonValue]
    prev_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class AuditCheckpoint(BaseModel):
    """A signed statement that the log named ``log`` held ``seq`` entries ending in ``head``."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    log: str = Field(min_length=1, max_length=255)
    seq: int = Field(ge=0)
    head: str = Field(pattern=r"^[0-9a-f]{64}$")
    mac: str = Field(pattern=r"^[0-9a-f]{64}$")

    @staticmethod
    def _mac(log: str, seq: int, head: str, key: bytes) -> str:
        body = canonical_json({"head": head, "log": log, "seq": seq}).encode("utf-8")
        return hmac.new(key, _CHECKPOINT_LABEL + body, hashlib.sha256).hexdigest()

    @classmethod
    def sign(cls, log: str, seq: int, head: str, key: bytes) -> AuditCheckpoint:
        return cls(log=log, seq=seq, head=head, mac=cls._mac(log, seq, head, key))

    def verify(self, key: bytes) -> bool:
        return hmac.compare_digest(self.mac, self._mac(self.log, self.seq, self.head, key))


class CheckpointSink(Protocol):
    def latest(self) -> AuditCheckpoint | None: ...

    def publish(self, checkpoint: AuditCheckpoint) -> None:
        """Store ``checkpoint`` unless the stored one already covers as many entries."""
        ...


class FileCheckpointSink:
    """The latest checkpoint in one small file, replaced atomically; it never moves backwards.

    Put the file on storage the log writer's filesystem attacker cannot rewrite (another volume,
    host or mount); next to the log it only catches accidental truncation.
    """

    def __init__(self, path: Path) -> None:
        self._path = path

    @property
    def path(self) -> Path:
        return self._path

    def latest(self) -> AuditCheckpoint | None:
        try:
            raw = self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        try:
            return AuditCheckpoint.model_validate_json(raw)
        except ValidationError as exc:
            raise AuditIntegrityError(f"{self._path.name}: checkpoint is unreadable") from exc

    def publish(self, checkpoint: AuditCheckpoint) -> None:
        with file_lock(self._path):
            current = self.latest()
            if current is not None and current.seq >= checkpoint.seq:
                return
            atomic_write_text(self._path, canonical_json(checkpoint.model_dump(mode="json")))


def _entry_hash(fields: Mapping[str, Any]) -> str:
    return sha256_hex(canonical_json({k: v for k, v in fields.items() if k != "hash"}))


@dataclass(frozen=True, slots=True)
class VerifyResult:
    ok: bool
    entries: int
    head: str
    error: str | None = None
    line: int | None = None


def _verify_chain(raw: bytes, *, prev: str, seq: int) -> VerifyResult:  # noqa: PLR0911
    """Verify ``\\n``-terminated entries that continue a chain whose head is (``seq``, ``prev``).

    Line numbers in the result are 1-based positions in the whole file (entry ``seq`` is on line
    ``seq + 1``). Each early return is a distinct, named failure mode, which keeps reports precise.
    """
    if raw and not raw.endswith(b"\n"):
        count = raw.count(b"\n")
        return VerifyResult(False, seq + count, prev, "truncated final line", seq + count + 1)
    count = seq
    # Split on "\n" only: bytes.splitlines() also splits on "\r", which would let a "\n" -> "\r"
    # substitution pass verification.
    lines = raw[:-1].split(b"\n") if raw else []
    for line in lines:
        line_number = count + 1
        try:
            text = line.decode("utf-8")
            obj = json.loads(text)
            # Strict: a lax validator would read false or 0.0 as seq 0, giving one entry several
            # valid encodings.
            entry = AuditEntry.model_validate(obj, strict=True)
        except (UnicodeDecodeError, json.JSONDecodeError, ValidationError):
            return VerifyResult(False, count, prev, "malformed entry", line_number)
        if canonical_json(obj) != text:
            return VerifyResult(False, count, prev, "non-canonical encoding", line_number)
        if entry.seq != count:
            return VerifyResult(False, count, prev, "sequence gap or reordering", line_number)
        if entry.prev_hash != prev:
            return VerifyResult(False, count, prev, "broken hash chain", line_number)
        if _entry_hash(obj) != entry.hash:
            return VerifyResult(False, count, prev, "entry content modified", line_number)
        prev = entry.hash
        count += 1
    return VerifyResult(True, count, prev)


def _checkpoint_problem(raw: bytes, entries: int, checkpoint: AuditCheckpoint) -> str | None:
    """Compare a verified chain (``raw`` with ``entries`` entries) with a checkpoint."""
    if entries < checkpoint.seq:
        return _BEHIND
    if checkpoint.seq == 0:
        covered = GENESIS_HASH
    else:
        covered = str(json.loads(raw[:-1].split(b"\n")[checkpoint.seq - 1])["hash"])
    return None if hmac.compare_digest(covered, checkpoint.head) else _REWRITTEN


def _last_line(raw: bytes) -> bytes:
    """The final ``\\n``-terminated line of ``raw`` (empty for empty input)."""
    if not raw:
        return b""
    return raw[raw.rfind(b"\n", 0, len(raw) - 1) + 1 :]


def verify_file(
    path: Path, *, expect_head: str | None = None, checkpoint: AuditCheckpoint | None = None
) -> VerifyResult:
    """Verify the whole chain, optionally against an expected head or a checkpoint.

    The checkpoint's signature is not checked here (the caller supplies a checkpoint it trusts;
    :class:`AuditLog` checks signatures with its key). Returns the first failure with its 1-based
    line number when it is a line.
    """
    if not path.exists():
        return VerifyResult(False, 0, GENESIS_HASH, "audit log not found", None)
    raw = path.read_bytes()
    result = _verify_chain(raw, prev=GENESIS_HASH, seq=0)
    if result.ok and expect_head is not None and expect_head != result.head:
        return VerifyResult(
            False, result.entries, result.head, "head mismatch (truncated or rolled back)", None
        )
    if result.ok and checkpoint is not None:
        problem = _checkpoint_problem(raw, result.entries, checkpoint)
        if problem is not None:
            return VerifyResult(False, result.entries, result.head, problem, None)
    return result


class AuditLog:
    """Append-only writer. Opening an existing file verifies it first and refuses a broken one.

    With ``checkpoints`` and ``checkpoint_key`` the log is also checked against its latest signed
    checkpoint when opened, and every append publishes a new checkpoint.
    """

    def __init__(
        self,
        path: Path,
        *,
        redact: bool = True,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        checkpoints: CheckpointSink | None = None,
        checkpoint_key: bytes | None = None,
    ) -> None:
        if (checkpoints is None) != (checkpoint_key is None):
            raise ValueError("checkpoints and checkpoint_key must be configured together")
        self._path = path
        self._redact = redact
        self._clock = clock
        self._checkpoints = checkpoints
        self._checkpoint_key = checkpoint_key
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)
        with file_lock(path):
            # The checkpoint is read under the log's lock, which writers hold while publishing, so
            # the two are a consistent pair.
            raw = path.read_bytes() if path.exists() else b""
            latest = checkpoints.latest() if checkpoints is not None else None
        result = _verify_chain(raw, prev=GENESIS_HASH, seq=0)
        if not result.ok:
            raise AuditIntegrityError(f"{path.name}: {result.error} (line {result.line})")
        if latest is not None and checkpoint_key is not None:
            self._check_against(latest, raw, result.entries, checkpoint_key)
        self._seq = result.entries
        self._head = result.head
        self._size = len(raw)
        self._last = _last_line(raw)

    def _check_against(
        self, checkpoint: AuditCheckpoint, raw: bytes, entries: int, key: bytes
    ) -> None:
        if checkpoint.log != self._path.name:
            raise AuditIntegrityError(f"{self._path.name}: checkpoint belongs to another log")
        if not checkpoint.verify(key):
            raise AuditIntegrityError(f"{self._path.name}: checkpoint signature is invalid")
        problem = _checkpoint_problem(raw, entries, checkpoint)
        if problem is not None:
            raise AuditIntegrityError(f"{self._path.name}: {problem}")

    @property
    def head(self) -> str:
        return self._head

    @property
    def path(self) -> Path:
        return self._path

    def _catch_up(self) -> None:
        """Adopt entries other writers appended; refuse a file that shrank or was rewritten.

        Called with the file lock held. Only the last known entry and the bytes after it are read,
        so an append stays cheap however long the log grows.
        """
        size = self._path.stat().st_size if self._path.exists() else 0
        if size < self._size:
            raise AuditIntegrityError(
                f"{self._path.name}: log shrank since it was last read (truncated or rolled back)"
            )
        if size == self._size and not self._last:
            return
        with self._path.open("rb") as handle:
            handle.seek(self._size - len(self._last))
            if handle.read(len(self._last)) != self._last:
                raise AuditIntegrityError(
                    f"{self._path.name}: history was rewritten since it was last read"
                )
            appended = handle.read()
        if not appended:
            return
        result = _verify_chain(appended, prev=self._head, seq=self._seq)
        if not result.ok:
            raise AuditIntegrityError(f"{self._path.name}: {result.error} (line {result.line})")
        self._seq = result.entries
        self._head = result.head
        self._size += len(appended)
        self._last = _last_line(appended)

    def append(
        self, actor: str, action: str, data: Mapping[str, JsonValue] | None = None
    ) -> AuditEntry:
        payload = dict(data or {})
        if self._redact:
            payload = redact_value(payload)
        with self._lock, file_lock(self._path):
            self._catch_up()
            fields: dict[str, Any] = {
                "seq": self._seq,
                "ts": self._clock().isoformat(),
                "actor": actor,
                "action": action,
                "data": payload,
                "prev_hash": self._head,
            }
            fields["hash"] = _entry_hash(fields)
            line = (canonical_json(fields) + "\n").encode("utf-8")
            with self._path.open("ab") as handle:
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())
            entry = AuditEntry.model_validate(fields)
            self._seq += 1
            self._head = entry.hash
            self._size += len(line)
            self._last = line
            if self._checkpoints is not None and self._checkpoint_key is not None:
                self._checkpoints.publish(
                    AuditCheckpoint.sign(
                        self._path.name, self._seq, self._head, self._checkpoint_key
                    )
                )
            return entry


def _cli_verify(path: Path, expect_head: str | None, checkpoint_file: Path | None) -> VerifyResult:
    checkpoint: AuditCheckpoint | None = None
    if checkpoint_file is not None:
        try:
            checkpoint = FileCheckpointSink(checkpoint_file).latest()
        except AuditIntegrityError as exc:
            return VerifyResult(False, 0, GENESIS_HASH, str(exc), None)
        if checkpoint is None:
            return VerifyResult(False, 0, GENESIS_HASH, "checkpoint not found", None)
    return verify_file(path, expect_head=expect_head, checkpoint=checkpoint)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="audit", description="Hash-chained audit log tools")
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify", help="verify an audit log")
    verify.add_argument("path", type=Path)
    verify.add_argument("--expect-head", default=None, help="expected head hash")
    verify.add_argument(
        "--checkpoint", type=Path, default=None, help="checkpoint file published by the writer"
    )
    args = parser.parse_args(argv)
    result = _cli_verify(args.path, args.expect_head, args.checkpoint)
    report = {
        "ok": result.ok,
        "entries": result.entries,
        "head": result.head,
        "error": result.error,
        "line": result.line,
    }
    sys.stdout.write(json.dumps(report, sort_keys=True) + "\n")
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
