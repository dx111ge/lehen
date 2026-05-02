"""HMAC-SHA256 fingerprinting for audit-log diff visibility (A12).

Produces a deterministic hex fingerprint of a secret using a separate audit
pepper key. The pepper is intentionally distinct from the data-encryption
master key so that audit-log compromise does not yield ciphertext-decryption
ability, and master-key compromise does not yield audit-log fingerprint
forgery.

Used by ``AdminAuditEvent`` to render before/after secret changes as
``{is_set: bool, hmac: str | null}`` instead of plaintext or sha256 of
plaintext (which would be brute-forceable).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac

_PEPPER_LEN = 32


class InvalidAuditPepperError(ValueError):
    """Audit pepper is not a valid url-safe base64 of exactly 32 bytes."""


def decode_audit_pepper(b64: str) -> bytes:
    try:
        raw = base64.urlsafe_b64decode(b64.encode("ascii"))
    except (ValueError, binascii.Error) as exc:
        raise InvalidAuditPepperError(f"audit pepper is not valid url-safe base64: {exc}") from exc
    if len(raw) != _PEPPER_LEN:
        raise InvalidAuditPepperError(
            f"audit pepper must decode to {_PEPPER_LEN} bytes (got {len(raw)})"
        )
    return raw


def fingerprint(plaintext: str, *, pepper: bytes) -> str:
    """Return the hex HMAC-SHA256 of ``plaintext`` keyed by ``pepper``.

    Same plaintext + same pepper always produces the same hex output, enabling
    diff visibility ("did this secret change?") in admin audit logs without
    exposing the plaintext.
    """
    if len(pepper) != _PEPPER_LEN:
        raise InvalidAuditPepperError(f"pepper must be exactly {_PEPPER_LEN} bytes")
    return hmac.new(pepper, plaintext.encode("utf-8"), hashlib.sha256).hexdigest()
