"""Bundled fake upstream services (invoices, file store, mailer) that accept only signed requests.

They stand in for real SaaS APIs: each holds its own copy of the credential it shares with the
broker, verifies the broker's HMAC signature on every request and records every access and effect,
which is how the escalation benchmark counts unauthorized effects.
"""

from capability_tool_broker.services.base import (
    AccessRecord,
    Effect,
    FakeService,
    ServiceResponse,
    ServiceRouter,
)
from capability_tool_broker.services.files import FileStoreService
from capability_tool_broker.services.invoices import InvoiceService
from capability_tool_broker.services.mailer import MailerService

__all__ = [
    "AccessRecord",
    "Effect",
    "FakeService",
    "FileStoreService",
    "InvoiceService",
    "MailerService",
    "ServiceResponse",
    "ServiceRouter",
]
