"""Signed tool manifests: signature checks, readiness and entry validation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from capability_tool_broker.broker.manifest import (
    ArgSpec,
    ManifestBody,
    ManifestError,
    ManifestHolder,
    SignedManifest,
    ToolEntry,
    ToolManifest,
    sign_manifest,
)
from capability_tool_broker.capabilities.keyfiles import generate_ed25519
from capability_tool_broker.capabilities.request import Verb
from capability_tool_broker.deploy import default_manifest_body

pytestmark = pytest.mark.unit


def signed_default() -> tuple[SignedManifest, Any]:
    key = generate_ed25519()
    return sign_manifest(default_manifest_body(issued_at=1), key, "m1"), key


def entry(**overrides: Any) -> ToolEntry:
    values: dict[str, Any] = {
        "name": "things_read",
        "description": "Read a thing.",
        "service": "things",
        "host": "things.internal",
        "effect": "read",
        "method": "GET",
        "resource_template": "thing/{thing_id}",
        "path_template": "/things/{thing_id}",
    }
    values.update(overrides)
    return ToolEntry.model_validate(values)


def test_signed_manifests_verify_and_resolve_tools() -> None:
    signed, key = signed_default()
    manifest = ToolManifest.verify(signed, {"m1": key.public_key()})
    read = manifest.get("invoices_read")
    assert read is not None
    assert read.verb is Verb.READ
    assert manifest.get("mail_send") is not None
    assert manifest.get("nope") is None
    assert manifest.signed() == signed
    assert len(manifest.digest) == 64


def test_modified_unsigned_or_untrusted_manifests_are_refused() -> None:
    signed, key = signed_default()
    trusted = {"m1": key.public_key()}
    tools = list(signed.body.tools)
    tools[0] = tools[0].model_copy(update={"host": "attacker.internal"})
    modified = signed.model_copy(
        update={"body": signed.body.model_copy(update={"tools": tuple(tools)})}
    )
    for bad in (
        modified,
        signed.model_copy(update={"signature": ""}),
        signed.model_copy(update={"key_id": "other"}),
        signed.model_copy(update={"signature": "!!not-base64!!"}),
        sign_manifest(signed.body, generate_ed25519(), "m1"),
    ):
        with pytest.raises(ManifestError):
            ToolManifest.verify(bad, trusted)


def test_holder_reports_readiness_from_the_file(tmp_path: Path) -> None:
    signed, key = signed_default()
    path = tmp_path / "manifest.json"
    holder = ManifestHolder(path, {"m1": key.public_key()})
    assert not holder.ready()
    assert holder.error is not None
    path.write_text(signed.to_json(), encoding="utf-8")
    assert holder.reload()
    assert holder.ready()
    assert holder.current() is not None
    path.write_text(
        signed.to_json().replace("Read one invoice", "Read all invoices"), encoding="utf-8"
    )
    assert not holder.reload()
    assert holder.current() is None


def test_resources_map_onto_routes_only_through_the_template() -> None:
    tool = entry(path_template="/things/{thing_id}/detail")
    assert tool.resolve_path("thing/42") == "/things/42/detail"
    for resource in ("thing/42/extra", "other/42", "thing/..", "thing"):
        assert tool.resolve_path(resource) is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"method": "DELETE"},
        {"effect": "external", "method": "PUT"},
        {"path_template": "/things/{other}"},
        {"path_template": "things/{thing_id}"},
        {"resource_template": "thing/{thing_id}/{thing_id}", "path_template": "/{thing_id}"},
        {"resource_template": "thing/../{thing_id}"},
        {"path_template": "/things/../{thing_id}"},
        {"host": "Not A Host"},
        {"args": {"Bad-Name": {"type": "string"}}},
        {"name": "Bad"},
    ],
)
def test_inconsistent_entries_are_rejected(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        entry(**overrides)


def test_duplicate_tool_names_are_rejected() -> None:
    with pytest.raises(ValidationError):
        ManifestBody(issuer="test", issued_at=0, tools=(entry(), entry()))


def test_argument_specs_and_invalid_argument_reports() -> None:
    assert ArgSpec(type="boolean").accepts(True)
    assert not ArgSpec(type="boolean").accepts(1)
    assert ArgSpec(type="string", max_length=3, enum=("abc",)).accepts("abc")
    assert not ArgSpec(type="string", max_length=2).accepts("abc")
    assert not ArgSpec(type="string", enum=("x",)).accepts("y")
    assert not ArgSpec(type="string").accepts(3)
    assert ArgSpec(type="integer", minimum=1, maximum=5).accepts(5)
    assert not ArgSpec(type="integer").accepts(1.5)
    assert not ArgSpec(type="integer", minimum=1).accepts(0)
    assert not ArgSpec(type="number", maximum=1).accepts(2.5)
    assert not ArgSpec(type="number").accepts(True)
    assert not ArgSpec(type="number").accepts(float("inf"))
    tool = entry(
        args={
            "status": {"type": "string", "enum": ["open"]},
            "note": {"type": "string", "required": False},
        }
    )
    assert tool.invalid_args({"status": "open"}) == []
    assert tool.invalid_args({"status": "closed", "extra": 1}) == ["extra", "status"]
    assert tool.invalid_args({}) == ["status"]


def test_input_schema_offers_the_resource_and_declared_arguments() -> None:
    tool = entry(
        args={
            "amount": {"type": "number", "minimum": 0, "maximum": 10},
            "code": {"type": "string", "max_length": 4, "enum": ["a"]},
            "optional": {"type": "boolean", "required": False},
        }
    )
    schema = tool.input_schema()
    assert schema["required"] == ["resource", "amount", "code"]
    assert schema["additionalProperties"] is False
    properties = schema["properties"]
    assert isinstance(properties, dict)
    assert properties["amount"] == {"type": "number", "minimum": 0, "maximum": 10}
    assert properties["code"] == {"type": "string", "maxLength": 4, "enum": ["a"]}


def test_signed_manifest_files_round_trip(tmp_path: Path) -> None:
    signed, _ = signed_default()
    path = tmp_path / "m.json"
    path.write_text(signed.to_json(), encoding="utf-8")
    assert SignedManifest.load(path) == signed
    (tmp_path / "bad.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ManifestError):
        SignedManifest.load(tmp_path / "bad.json")
