"""AES-256-GCM secret encryption tests."""

from __future__ import annotations

import base64
import secrets as stdlib_secrets

import pytest
from cryptography.exceptions import InvalidTag

from lehen_hub.crypto.secrets import (
    InvalidMasterKeyError,
    UnsupportedKeyVersionError,
    decode_master_key,
    decrypt,
    encrypt,
)


def _generate_key() -> bytes:
    return stdlib_secrets.token_bytes(32)


def _generate_key_b64() -> str:
    return base64.urlsafe_b64encode(_generate_key()).decode("ascii")


class TestDecodeMasterKey:
    def test_round_trip(self) -> None:
        key = _generate_key()
        b64 = base64.urlsafe_b64encode(key).decode("ascii")
        assert decode_master_key(b64) == key

    def test_rejects_short_key(self) -> None:
        b64 = base64.urlsafe_b64encode(b"too-short").decode("ascii")
        with pytest.raises(InvalidMasterKeyError, match="must decode to 32 bytes"):
            decode_master_key(b64)

    def test_rejects_long_key(self) -> None:
        b64 = base64.urlsafe_b64encode(stdlib_secrets.token_bytes(64)).decode("ascii")
        with pytest.raises(InvalidMasterKeyError, match="must decode to 32 bytes"):
            decode_master_key(b64)


class TestEncryptDecrypt:
    def test_round_trip(self) -> None:
        key = _generate_key()
        plaintext = "super-secret-oauth-client-secret-value"
        envelope = encrypt(plaintext, key=key)
        assert decrypt(envelope, key=key) == plaintext

    def test_unicode_round_trip(self) -> None:
        key = _generate_key()
        plaintext = "Mörder-Geheimnis: 漢字 🔐 emoji-and-umlauts-äöü"
        envelope = encrypt(plaintext, key=key)
        assert decrypt(envelope, key=key) == plaintext

    def test_empty_string_round_trip(self) -> None:
        key = _generate_key()
        envelope = encrypt("", key=key)
        assert decrypt(envelope, key=key) == ""

    def test_each_encrypt_uses_fresh_nonce(self) -> None:
        """Same plaintext encrypted twice must produce different ciphertexts."""
        key = _generate_key()
        plaintext = "x"
        a = encrypt(plaintext, key=key)
        b = encrypt(plaintext, key=key)
        assert a != b
        assert decrypt(a, key=key) == decrypt(b, key=key) == plaintext

    def test_decrypt_wrong_key_fails(self) -> None:
        envelope = encrypt("hello", key=_generate_key())
        with pytest.raises(InvalidTag):
            decrypt(envelope, key=_generate_key())

    def test_tampered_ciphertext_fails(self) -> None:
        key = _generate_key()
        envelope = encrypt("hello", key=key)
        blob = bytearray(base64.urlsafe_b64decode(envelope))
        blob[-1] ^= 0xFF  # flip last byte of GCM tag
        tampered = base64.urlsafe_b64encode(bytes(blob)).decode("ascii")
        with pytest.raises(InvalidTag):
            decrypt(tampered, key=key)

    def test_unsupported_version_byte_raises(self) -> None:
        key = _generate_key()
        envelope = encrypt("hello", key=key)
        blob = bytearray(base64.urlsafe_b64decode(envelope))
        blob[0] = 99  # unknown version
        bad = base64.urlsafe_b64encode(bytes(blob)).decode("ascii")
        with pytest.raises(UnsupportedKeyVersionError, match="version 99 not supported"):
            decrypt(bad, key=key)

    def test_truncated_envelope_raises(self) -> None:
        key = _generate_key()
        truncated = base64.urlsafe_b64encode(b"\x01short").decode("ascii")
        with pytest.raises(UnsupportedKeyVersionError, match="too short"):
            decrypt(truncated, key=key)

    def test_encrypt_rejects_wrong_key_size(self) -> None:
        with pytest.raises(InvalidMasterKeyError, match="must be exactly 32 bytes"):
            encrypt("x", key=b"too-short-key")

    def test_decrypt_rejects_wrong_key_size(self) -> None:
        envelope = encrypt("x", key=_generate_key())
        with pytest.raises(InvalidMasterKeyError, match="must be exactly 32 bytes"):
            decrypt(envelope, key=b"too-short-key")
