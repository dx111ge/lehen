"""AES-256-GCM secret encryption with versioned envelope.

Envelope format (binary, then base64 for storage):
    [1 byte version][12 bytes nonce][N bytes ciphertext+tag]

Currently version=1. Any future rotation flips the version byte and accepts both
during a migration window. v1 only ships and reads version=1.
"""

from __future__ import annotations

import base64
import binascii
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_CURRENT_VERSION = 1
_NONCE_LEN = 12
_KEY_LEN = 32  # AES-256


class UnsupportedKeyVersionError(ValueError):
    """Envelope claims a version we do not know how to decrypt."""


class InvalidMasterKeyError(ValueError):
    """Master key is not a valid url-safe base64 of exactly 32 bytes."""


def decode_master_key(b64: str) -> bytes:
    """Decode the url-safe-base64 master key from settings.

    Raises ``InvalidMasterKeyError`` if the decoded length is not 32 bytes.
    """
    try:
        raw = base64.urlsafe_b64decode(b64.encode("ascii"))
    except (ValueError, binascii.Error) as exc:
        raise InvalidMasterKeyError(f"master key is not valid url-safe base64: {exc}") from exc
    if len(raw) != _KEY_LEN:
        raise InvalidMasterKeyError(f"master key must decode to {_KEY_LEN} bytes (got {len(raw)})")
    return raw


def encrypt(plaintext: str, *, key: bytes) -> str:
    """Encrypt ``plaintext`` (UTF-8) with the given 32-byte AES-256-GCM key.

    Returns a url-safe-base64 string suitable for JSON / document storage.
    """
    if len(key) != _KEY_LEN:
        raise InvalidMasterKeyError(f"key must be exactly {_KEY_LEN} bytes")
    nonce = secrets.token_bytes(_NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    envelope = bytes([_CURRENT_VERSION]) + nonce + ct
    return base64.urlsafe_b64encode(envelope).decode("ascii")


def decrypt(envelope_b64: str, *, key: bytes) -> str:
    """Decrypt a previously ``encrypt``-ed envelope.

    Raises ``UnsupportedKeyVersionError`` if the envelope's version byte is unknown.
    Raises ``cryptography.exceptions.InvalidTag`` on tampering or wrong key.
    """
    if len(key) != _KEY_LEN:
        raise InvalidMasterKeyError(f"key must be exactly {_KEY_LEN} bytes")
    blob = base64.urlsafe_b64decode(envelope_b64.encode("ascii"))
    if len(blob) < 1 + _NONCE_LEN + 16:  # min: version + nonce + GCM tag
        raise UnsupportedKeyVersionError("envelope is too short to be valid")
    version = blob[0]
    if version != _CURRENT_VERSION:
        raise UnsupportedKeyVersionError(
            f"envelope version {version} not supported (current is {_CURRENT_VERSION})"
        )
    nonce = blob[1 : 1 + _NONCE_LEN]
    ct = blob[1 + _NONCE_LEN :]
    pt = AESGCM(key).decrypt(nonce, ct, None)
    return pt.decode("utf-8")
