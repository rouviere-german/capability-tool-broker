from __future__ import annotations

import json
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from capability_tool_broker.agentic.audit import (
    GENESIS_HASH,
    AuditCheckpoint,
    AuditLog,
    FileCheckpointSink,
    main,
    verify_file,
)
from capability_tool_broker.agentic.errors import AuditIntegrityError
from capability_tool_broker.core.canonical import canonical_json, sha256_hex

pytestmark = pytest.mark.unit


def fixed_clock() -> Callable[[], datetime]:
    return lambda: datetime(2026, 1, 1, tzinfo=UTC)


def write_log(path: Path, entries: int = 5) -> AuditLog:
    log = AuditLog(path, clock=fixed_clock())
    for index in range(entries):
        log.append("agent:test", "step", {"index": index, "note": f"entry {index}"})
    return log


def lines_of(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines(keepends=True)


def test_a_valid_chain_verifies(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = write_log(path)
    result = verify_file(path, expect_head=log.head)
    assert result.ok
    assert result.entries == 5
    assert result.head == log.head


def test_modified_entry_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    write_log(path)
    lines = lines_of(path)
    entry = json.loads(lines[2])
    entry["data"]["index"] = 99
    lines[2] = canonical_json(entry) + "\n"
    path.write_text("".join(lines), encoding="utf-8", newline="\n")
    result = verify_file(path)
    assert (result.ok, result.error, result.line) == (False, "entry content modified", 3)


def test_rehashed_entry_breaks_the_chain_at_the_next_entry(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    write_log(path)
    lines = lines_of(path)
    entry = json.loads(lines[2])
    entry["data"]["index"] = 99
    entry["hash"] = sha256_hex(canonical_json({k: v for k, v in entry.items() if k != "hash"}))
    lines[2] = canonical_json(entry) + "\n"
    path.write_text("".join(lines), encoding="utf-8", newline="\n")
    result = verify_file(path)
    assert (result.ok, result.error, result.line) == (False, "broken hash chain", 4)


@pytest.mark.parametrize(
    ("mutate", "error"),
    [
        (lambda lines: lines[:2] + lines[3:], "sequence gap or reordering"),
        (lambda lines: [lines[0], lines[2], lines[1], *lines[3:]], "sequence gap or reordering"),
        (
            lambda lines: [*lines[:1], lines[1].replace(":", ": ", 1), *lines[2:]],
            "non-canonical encoding",
        ),
        (lambda lines: [*lines[:1], "{not json\n", *lines[2:]], "malformed entry"),
        (lambda lines: [*lines[:-1], lines[-1].rstrip("\n")], "truncated final line"),
    ],
)
def test_deletion_reordering_reencoding_and_truncation_are_detected(
    tmp_path: Path, mutate: Callable[[list[str]], list[str]], error: str
) -> None:
    path = tmp_path / "audit.jsonl"
    write_log(path)
    path.write_text("".join(mutate(lines_of(path))), encoding="utf-8", newline="\n")
    result = verify_file(path)
    assert not result.ok
    assert result.error == error


def test_tail_truncation_needs_an_anchored_head(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = write_log(path)
    head = log.head
    path.write_text("".join(lines_of(path)[:-1]), encoding="utf-8", newline="\n")
    assert verify_file(path).ok
    anchored = verify_file(path, expect_head=head)
    assert not anchored.ok
    assert anchored.error is not None
    assert "head mismatch" in anchored.error


@settings(max_examples=40)
@given(data=st.data())
def test_any_single_byte_change_is_detected(data: st.DataObject) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "audit.jsonl"
        write_log(path, entries=4)
        raw = bytearray(path.read_bytes())
        index = data.draw(st.integers(min_value=0, max_value=len(raw) - 1))
        original = raw[index]
        raw[index] = data.draw(st.integers(0, 255).filter(lambda value: value != original))
        path.write_bytes(bytes(raw))
        assert not verify_file(path).ok


def test_reopening_continues_the_chain_and_refuses_a_tampered_log(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    write_log(path, entries=2)
    reopened = AuditLog(path, clock=fixed_clock())
    entry = reopened.append("agent:test", "step", {"index": 2})
    assert entry.seq == 2
    assert verify_file(path).entries == 3

    path.write_text(
        path.read_text(encoding="utf-8").replace("entry 0", "entry X"),
        encoding="utf-8",
        newline="\n",
    )
    with pytest.raises(AuditIntegrityError, match="modified"):
        AuditLog(path)


def test_entries_are_redacted_before_hashing(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("agent:test", "tool.executed", {"email": "jane@example.com", "password": "x"})
    text = path.read_text(encoding="utf-8")
    assert "jane@example.com" not in text
    assert '"password":"[REDACTED]"' in text
    assert verify_file(path).ok


def test_two_writers_on_one_file_extend_a_single_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    first = AuditLog(path, clock=fixed_clock())
    second = AuditLog(path, clock=fixed_clock())
    first.append("agent:a", "step", {"n": 1})
    second.append("agent:b", "step", {"n": 2})
    first.append("agent:a", "step", {"n": 3})
    result = verify_file(path, expect_head=first.head)
    assert (result.ok, result.entries) == (True, 3)


def test_truncation_while_open_is_detected_on_the_next_append(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = write_log(path, entries=3)
    path.write_text("".join(lines_of(path)[:2]), encoding="utf-8", newline="\n")
    with pytest.raises(AuditIntegrityError, match="truncated or rolled back"):
        log.append("agent:test", "step", {"index": 3})
    assert verify_file(path).entries == 2


def test_history_rewritten_while_open_is_detected_on_the_next_append(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = write_log(path, entries=2)
    forged = tmp_path / "forged.jsonl"
    forger = AuditLog(forged, clock=fixed_clock())
    for index in range(3):
        forger.append("agent:forger", "step", {"index": index})
    path.write_bytes(forged.read_bytes())
    with pytest.raises(AuditIntegrityError, match="rewritten"):
        log.append("agent:test", "step", {"index": 2})


@pytest.mark.parametrize("value", [False, 0.0])
def test_type_coerced_fields_fail_verification_even_with_a_recomputed_hash(
    tmp_path: Path, value: object
) -> None:
    # A lax validator reads false or 0.0 as seq 0, so one entry would have several valid encodings.
    path = tmp_path / "audit.jsonl"
    write_log(path, entries=1)
    entry = json.loads(path.read_text(encoding="utf-8"))
    entry["seq"] = value
    entry["hash"] = sha256_hex(canonical_json({k: v for k, v in entry.items() if k != "hash"}))
    path.write_text(canonical_json(entry) + "\n", encoding="utf-8", newline="\n")
    result = verify_file(path)
    assert (result.ok, result.error, result.line) == (False, "malformed entry", 1)


def test_missing_log_does_not_verify(tmp_path: Path) -> None:
    result = verify_file(tmp_path / "missing.jsonl")
    assert (result.ok, result.error) == (False, "audit log not found")


def test_verify_cli_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "audit.jsonl"
    log = write_log(path)
    assert main(["verify", str(path), "--expect-head", log.head]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True
    path.write_text(
        path.read_text(encoding="utf-8").replace("entry 1", "entry 7"),
        encoding="utf-8",
        newline="\n",
    )
    assert main(["verify", str(path)]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is False
    assert report["line"] == 2


CHECKPOINT_KEY = b"c" * 32


def checkpointed(path: Path, sink: Path, entries: int) -> AuditLog:
    log = AuditLog(
        path,
        clock=fixed_clock(),
        checkpoints=FileCheckpointSink(sink),
        checkpoint_key=CHECKPOINT_KEY,
    )
    for index in range(entries):
        log.append("agent:test", "step", {"index": index, "note": f"entry {index}"})
    return log


def reopen(path: Path, sink: Path) -> AuditLog:
    return AuditLog(path, checkpoints=FileCheckpointSink(sink), checkpoint_key=CHECKPOINT_KEY)


def test_a_log_behind_its_checkpoint_is_refused(tmp_path: Path) -> None:
    path, sink = tmp_path / "audit.jsonl", tmp_path / "anchor" / "audit.checkpoint"
    log = checkpointed(path, sink, 5)
    latest = FileCheckpointSink(sink).latest()
    assert latest is not None
    assert (latest.seq, latest.head) == (5, log.head)
    path.write_text("".join(lines_of(path)[:3]), encoding="utf-8", newline="\n")
    assert verify_file(path).ok  # the shorter chain is consistent on its own
    with pytest.raises(AuditIntegrityError, match="behind its last checkpoint"):
        reopen(path, sink)
    report = verify_file(path, checkpoint=latest)
    assert not report.ok
    assert report.error == "log is behind its last checkpoint (truncated or rolled back)"
    path.unlink()  # deleting the whole log is a rollback too
    with pytest.raises(AuditIntegrityError, match="behind its last checkpoint"):
        reopen(path, sink)


def test_a_rewritten_log_that_does_not_match_its_checkpoint_is_refused(tmp_path: Path) -> None:
    path, sink = tmp_path / "audit.jsonl", tmp_path / "anchor" / "audit.checkpoint"
    checkpointed(path, sink, 3)
    forged = tmp_path / "forged.jsonl"
    forger = AuditLog(forged, clock=fixed_clock())
    for index in range(4):
        forger.append("agent:forger", "step", {"index": index})
    path.write_bytes(forged.read_bytes())  # a longer, internally valid chain
    with pytest.raises(AuditIntegrityError, match="does not match its last checkpoint"):
        reopen(path, sink)
    latest = FileCheckpointSink(sink).latest()
    assert latest is not None
    assert verify_file(path, checkpoint=latest).error == (
        "log does not match its last checkpoint (history rewritten)"
    )


def test_checkpoints_are_signed_bound_to_their_log_and_never_move_backwards(
    tmp_path: Path,
) -> None:
    path, sink_path = tmp_path / "audit.jsonl", tmp_path / "anchor" / "audit.checkpoint"
    log = checkpointed(path, sink_path, 2)
    sink = FileCheckpointSink(sink_path)
    latest = sink.latest()
    assert latest is not None
    assert latest.verify(CHECKPOINT_KEY)
    assert not latest.verify(b"x" * 32)
    sink.publish(AuditCheckpoint.sign("audit.jsonl", 1, GENESIS_HASH, CHECKPOINT_KEY))
    assert sink.latest() == latest  # an older checkpoint never replaces a newer one
    reopened = reopen(path, sink_path)
    assert reopened.append("agent:test", "step", {"index": 2}).seq == 2
    assert (sink.latest() or latest).seq == 3
    for forged, error in (
        (AuditCheckpoint.sign("audit.jsonl", 0, GENESIS_HASH, b"x" * 32), "checkpoint signature"),
        (AuditCheckpoint.sign("other.jsonl", 3, log.head, CHECKPOINT_KEY), "another log"),
    ):
        sink_path.write_text(forged.model_dump_json(), encoding="utf-8")
        with pytest.raises(AuditIntegrityError, match=error):
            reopen(path, sink_path)
    sink_path.write_text("not a checkpoint", encoding="utf-8")
    with pytest.raises(AuditIntegrityError, match="checkpoint is unreadable"):
        reopen(path, sink_path)
    with pytest.raises(ValueError, match="together"):
        AuditLog(path, checkpoints=sink)


def test_verify_cli_checks_a_checkpoint_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path, sink = tmp_path / "audit.jsonl", tmp_path / "audit.checkpoint"
    checkpointed(path, sink, 3)
    assert main(["verify", str(path), "--checkpoint", str(sink)]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True
    path.write_text("".join(lines_of(path)[:2]), encoding="utf-8", newline="\n")
    assert main(["verify", str(path), "--checkpoint", str(sink)]) == 1
    assert "behind its last checkpoint" in json.loads(capsys.readouterr().out)["error"]
