"""HMAC-SHA256 audit-fingerprint tests (A12)."""

from __future__ import annotations

import base64
import secrets as stdlib_secrets

import pytest

from lehen_hub.crypto.audit_fingerprint import (
    InvalidAuditPepperError,
    decode_audit_pepper,
    fingerprint,
)


def _generate_pepper() -> bytes:
    return stdlib_secrets.token_bytes(32)


class TestDecodeAuditPepper:
    def test_round_trip(self) -> None:
        raw = _generate_pepper()
        b64 = base64.urlsafe_b64encode(raw).decode("ascii")
        assert decode_audit_pepper(b64) == raw

    def test_rejects_short_pepper(self) -> None:
        b64 = base64.urlsafe_b64encode(b"too-short").decode("ascii")
        with pytest.raises(InvalidAuditPepperError, match="must decode to 32 bytes"):
            decode_audit_pepper(b64)

    def test_rejects_long_pepper(self) -> None:
        b64 = base64.urlsafe_b64encode(stdlib_secrets.token_bytes(64)).decode("ascii")
        with pytest.raises(InvalidAuditPepperError, match="must decode to 32 bytes"):
            decode_audit_pepper(b64)


class TestFingerprint:
    def test_deterministic(self) -> None:
        pepper = _generate_pepper()
        assert fingerprint("secret-x", pepper=pepper) == fingerprint("secret-x", pepper=pepper)

    def test_different_plaintext_different_hmac(self) -> None:
        pepper = _generate_pepper()
        assert fingerprint("secret-a", pepper=pepper) != fingerprint("secret-b", pepper=pepper)

    def test_different_pepper_different_hmac(self) -> None:
        a = fingerprint("same-secret", pepper=_generate_pepper())
        b = fingerprint("same-secret", pepper=_generate_pepper())
        assert a != b

    def test_returns_64_hex_chars(self) -> None:
        result = fingerprint("x", pepper=_generate_pepper())
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_unicode_input(self) -> None:
        pepper = _generate_pepper()
        result = fingerprint("Geheim-äöü-漢字-🔐", pepper=pepper)
        assert len(result) == 64

    def test_rejects_wrong_pepper_size(self) -> None:
        with pytest.raises(InvalidAuditPepperError, match="must be exactly 32 bytes"):
            fingerprint("x", pepper=b"too-short")
