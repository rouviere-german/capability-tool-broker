"""HMAC request signing between broker and services; the fake services' own behavior."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from capability_tool_broker.broker.signing import (
    HEADER_NONCE,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    RequestSignatureVerifier,
    ServiceCredential,
    SignatureCheck,
    sign_request,
)
from support import make_stack

pytestmark = pytest.mark.unit

NOW = 1_800_000_000
CREDENTIAL = ServiceCredential(key_id="broker-things", secret=b"s" * 32)


def verifier(**kwargs: object) -> RequestSignatureVerifier:
    return RequestSignatureVerifier(
        {CREDENTIAL.key_id: CREDENTIAL.secret},
        clock=lambda: float(NOW),
        **kwargs,  # type: ignore[arg-type]
    )


def test_signed_requests_verify_exactly_once() -> None:
    check = verifier()
    headers = sign_request(CREDENTIAL, method="PUT", path="/things/1", body=b"{}", now=NOW)
    assert check.verify("PUT", "/things/1", headers, b"{}") is SignatureCheck.OK
    assert check.verify("PUT", "/things/1", headers, b"{}") is SignatureCheck.REPLAYED


def test_tampering_staleness_and_unknown_keys_are_rejected() -> None:
    check = verifier()

    def fresh(**overrides: str) -> dict[str, str]:
        headers = sign_request(CREDENTIAL, method="GET", path="/things/1", body=b"", now=NOW)
        headers.update(overrides)
        return headers

    assert check.verify("GET", "/things/2", fresh(), b"") is SignatureCheck.BAD_SIGNATURE
    assert check.verify("DELETE", "/things/1", fresh(), b"") is SignatureCheck.BAD_SIGNATURE
    assert check.verify("GET", "/things/1", fresh(), b"x") is SignatureCheck.BAD_SIGNATURE
    other = ServiceCredential(key_id=CREDENTIAL.key_id, secret=b"o" * 32)
    forged = sign_request(other, method="GET", path="/things/1", body=b"", now=NOW)
    assert check.verify("GET", "/things/1", forged, b"") is SignatureCheck.BAD_SIGNATURE
    unknown = sign_request(
        ServiceCredential("unknown", b"u" * 32), method="GET", path="/", body=b"", now=NOW
    )
    assert check.verify("GET", "/", unknown, b"") is SignatureCheck.UNKNOWN_KEY
    stale = sign_request(CREDENTIAL, method="GET", path="/things/1", body=b"", now=NOW - 31)
    assert check.verify("GET", "/things/1", stale, b"") is SignatureCheck.STALE
    for header in (HEADER_NONCE, HEADER_SIGNATURE, HEADER_TIMESTAMP):
        assert (
            check.verify("GET", "/things/1", fresh(**{header: "zz"}), b"") is SignatureCheck.MISSING
        )
    assert check.verify("GET", "/things/1", {}, b"") is SignatureCheck.MISSING


def test_a_saturated_nonce_cache_fails_closed() -> None:
    check = verifier(max_nonces=2)
    results = [
        check.verify(
            "GET",
            "/",
            sign_request(CREDENTIAL, method="GET", path="/", body=b"", now=NOW),
            b"",
        )
        for _ in range(3)
    ]
    assert results == [SignatureCheck.OK, SignatureCheck.OK, SignatureCheck.REPLAYED]


def test_credentials_never_show_their_secret() -> None:
    assert "sss" not in repr(CREDENTIAL)


def test_services_reject_requests_that_bypass_the_broker(tmp_path: Path) -> None:
    stack = make_stack(tmp_path)
    try:
        unsigned = stack.http.get("http://invoices.internal/invoices/42")
        assert unsigned.status_code == 401
        forged = sign_request(
            ServiceCredential("broker-invoices", b"x" * 32),
            method="GET",
            path="/invoices/42",
            body=b"",
            now=int(stack.clock()),
        )
        assert (
            stack.http.get("http://invoices.internal/invoices/42", headers=forged).status_code
            == 401
        )
        assert [record.authorized for record in stack.invoices.access_log] == [False, False]
        assert stack.invoices.effects == []
        genuine = sign_request(
            stack.keys.credentials()["invoices"],
            method="GET",
            path="/invoices/42",
            body=b"",
            now=int(stack.clock()),
        )
        assert (
            stack.http.get("http://invoices.internal/invoices/42", headers=genuine).status_code
            == 200
        )
    finally:
        stack.close()


def _signed(
    stack_http: httpx.Client,
    credential: ServiceCredential,
    method: str,
    host: str,
    path: str,
    body: bytes,
    now: int,
) -> httpx.Response:
    headers = sign_request(credential, method=method, path=path, body=body, now=now)
    return stack_http.request(method, f"http://{host}{path}", content=body, headers=headers)


def test_fake_service_routes_validate_their_input(tmp_path: Path) -> None:
    stack = make_stack(tmp_path)
    try:
        creds = stack.keys.credentials()
        now = int(stack.clock())

        def send(service: str, method: str, host: str, path: str, body: bytes = b"") -> int:
            return _signed(stack.http, creds[service], method, host, path, body, now).status_code

        assert (
            send("invoices", "PUT", "invoices.internal", "/invoices/42/status", b'{"status":"x"}')
            == 400
        )
        assert send("invoices", "PUT", "invoices.internal", "/invoices/999/status", b"{}") == 404
        assert send("invoices", "GET", "invoices.internal", "/invoices/999") == 404
        assert send("invoices", "DELETE", "invoices.internal", "/invoices/999") == 404
        assert send("invoices", "DELETE", "invoices.internal", "/invoices/41") == 200
        assert (
            send("invoices", "PUT", "invoices.internal", "/invoices/1/status", b"not json") == 400
        )
        assert send("invoices", "GET", "invoices.internal", "/unknown") == 404
        assert send("files", "PUT", "files.internal", "/files/a.txt", b'{"content":1}') == 400
        assert send("files", "PUT", "files.internal", "/files/a.txt", b'{"content":"hi"}') == 200
        assert send("files", "GET", "files.internal", "/files/a.txt") == 200
        assert send("files", "GET", "files.internal", "/files/missing") == 404
        assert send("files", "DELETE", "files.internal", "/files/a.txt") == 200
        assert send("files", "DELETE", "files.internal", "/files/a.txt") == 404
        assert send("mailer", "POST", "mailer.internal", "/messages/a@example.com", b"[]") == 400
        assert (
            send("mailer", "POST", "mailer.internal", "/messages/a@example.com", b'{"subject":1}')
            == 400
        )
        assert (
            send(
                "mailer",
                "POST",
                "mailer.internal",
                "/messages/a@example.com",
                b'{"subject":"s","body":"b"}',
            )
            == 202
        )
        assert send("mailer", "POST", "unknown.internal", "/messages/a@example.com") == 404
        assert (
            send("mailer", "POST", "mailer.internal", "/messages/a@example.com", b"x" * 70_000)
            == 413
        )
        kinds = sorted(effect.kind for effect in stack.router.effects())
        assert kinds == ["delete", "delete", "read", "send", "write"]
        assert len(stack.router.access_log()) > 10
    finally:
        stack.close()
