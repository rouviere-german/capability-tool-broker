"""Fake invoice API: read, update status, delete."""

from __future__ import annotations

import copy
import time
from collections.abc import Callable, Mapping

from pydantic import JsonValue

from capability_tool_broker.broker.signing import ServiceCredential
from capability_tool_broker.services.base import FakeService, ServiceResponse

__all__ = ["INVOICE_STATUSES", "InvoiceService", "default_invoices"]

INVOICE_STATUSES = ("open", "approved", "paid", "rejected")
_ID = r"(?P<invoice_id>[A-Za-z0-9._@-]{1,64})"


def default_invoices(count: int = 60) -> dict[str, dict[str, JsonValue]]:
    return {
        str(number): {
            "id": str(number),
            "customer": f"customer-{number % 7}",
            "amount": 100 + number * 10,
            "currency": "EUR",
            "status": "open",
            "notes": "",
        }
        for number in range(1, count + 1)
    }


class InvoiceService(FakeService):
    name = "invoices"
    host = "invoices.internal"

    def __init__(
        self,
        *,
        credential: ServiceCredential,
        clock: Callable[[], float] = time.time,
        invoices: Mapping[str, dict[str, JsonValue]] | None = None,
    ) -> None:
        super().__init__(credential=credential, clock=clock)
        self.invoices = copy.deepcopy(
            dict(invoices if invoices is not None else default_invoices())
        )
        self.route("GET", rf"/invoices/{_ID}", self._read)
        self.route("PUT", rf"/invoices/{_ID}/status", self._update_status)
        self.route("DELETE", rf"/invoices/{_ID}", self._delete)

    def _read(self, params: dict[str, str], payload: JsonValue) -> ServiceResponse:
        del payload
        invoice = self.invoices.get(params["invoice_id"])
        if invoice is None:
            return ServiceResponse(404, {"error": "not_found"})
        self.record_effect("read", f"invoice/{params['invoice_id']}")
        return ServiceResponse(200, invoice)

    def _update_status(self, params: dict[str, str], payload: JsonValue) -> ServiceResponse:
        invoice = self.invoices.get(params["invoice_id"])
        if invoice is None:
            return ServiceResponse(404, {"error": "not_found"})
        status = payload.get("status") if isinstance(payload, dict) else None
        if status not in INVOICE_STATUSES:
            return ServiceResponse(400, {"error": "invalid_status"})
        invoice["status"] = status
        self.record_effect("write", f"invoice/{params['invoice_id']}")
        return ServiceResponse(200, {"id": params["invoice_id"], "status": status})

    def _delete(self, params: dict[str, str], payload: JsonValue) -> ServiceResponse:
        del payload
        if self.invoices.pop(params["invoice_id"], None) is None:
            return ServiceResponse(404, {"error": "not_found"})
        self.record_effect("delete", f"invoice/{params['invoice_id']}")
        return ServiceResponse(200, {"deleted": params["invoice_id"]})
