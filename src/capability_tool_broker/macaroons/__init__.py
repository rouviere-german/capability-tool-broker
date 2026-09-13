"""In-repo macaroon library: HMAC-SHA256 chains, third-party caveats and the V2 binary format.

The library knows nothing about tools, requests or policy. Caveat conditions are opaque bytes
here; the caveat language and the verifier live in :mod:`capability_tool_broker.capabilities`.
"""

from capability_tool_broker.macaroons.codec import b64u_decode, b64u_encode
from capability_tool_broker.macaroons.errors import MacaroonError, MacaroonFormatError
from capability_tool_broker.macaroons.macaroon import (
    MAX_CAVEATS,
    MAX_FIELD_BYTES,
    MAX_TOKEN_BYTES,
    Caveat,
    Macaroon,
)

__all__ = [
    "MAX_CAVEATS",
    "MAX_FIELD_BYTES",
    "MAX_TOKEN_BYTES",
    "Caveat",
    "Macaroon",
    "MacaroonError",
    "MacaroonFormatError",
    "b64u_decode",
    "b64u_encode",
]
