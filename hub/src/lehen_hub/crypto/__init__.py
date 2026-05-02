"""Hub crypto primitives: AES-256-GCM secret encryption + HMAC-SHA256 audit fingerprinting."""

from lehen_hub.crypto.audit_fingerprint import fingerprint
from lehen_hub.crypto.secrets import (
    UnsupportedKeyVersionError,
    decode_master_key,
    decrypt,
    encrypt,
)

__all__ = [
    "UnsupportedKeyVersionError",
    "decode_master_key",
    "decrypt",
    "encrypt",
    "fingerprint",
]
