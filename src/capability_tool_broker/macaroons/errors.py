"""Errors raised by the macaroon library."""

from __future__ import annotations

__all__ = ["MacaroonError", "MacaroonFormatError"]


class MacaroonError(Exception):
    """Base class for macaroon library errors."""


class MacaroonFormatError(MacaroonError, ValueError):
    """Bytes or text that are not a well-formed, canonically encoded macaroon."""
