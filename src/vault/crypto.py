"""Authenticated encryption for vault documents."""

from __future__ import annotations

import base64
import json
import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

FORMAT_VERSION = 1
SALT_BYTES = 16
NONCE_BYTES = 12
KEY_BYTES = 32
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1


class VaultAuthenticationError(Exception):
    """Raised when a vault cannot be authenticated with the supplied password."""


class VaultFormatError(Exception):
    """Raised when a vault file has an unsupported or invalid format."""


def _derive_key(password: str, salt: bytes) -> bytes:
    return Scrypt(
        salt=salt,
        length=KEY_BYTES,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    ).derive(password.encode("utf-8"))


def encrypt(vault: dict[str, Any], password: str) -> bytes:
    """Serialize and encrypt a vault document with a password-derived key."""
    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    plaintext = json.dumps(
        vault, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    ciphertext = AESGCM(_derive_key(password, salt)).encrypt(nonce, plaintext, None)
    envelope = {
        "version": FORMAT_VERSION,
        "kdf": "scrypt",
        "n": SCRYPT_N,
        "r": SCRYPT_R,
        "p": SCRYPT_P,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    return json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")


def decrypt(serialized: bytes, password: str) -> dict[str, Any]:
    """Decrypt and validate a vault document."""
    try:
        envelope = json.loads(serialized.decode("utf-8"))
        if (
            envelope.get("version") != FORMAT_VERSION
            or envelope.get("kdf") != "scrypt"
            or (envelope["n"], envelope["r"], envelope["p"])
            != (SCRYPT_N, SCRYPT_R, SCRYPT_P)
        ):
            raise VaultFormatError("Unsupported vault format.")
        salt = base64.b64decode(envelope["salt"], validate=True)
        nonce = base64.b64decode(envelope["nonce"], validate=True)
        ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
        if len(salt) != SALT_BYTES or len(nonce) != NONCE_BYTES:
            raise VaultFormatError("Invalid vault encryption parameters.")
        plaintext = AESGCM(_derive_key(password, salt)).decrypt(nonce, ciphertext, None)
        vault = json.loads(plaintext.decode("utf-8"))
    except InvalidTag as error:
        raise VaultAuthenticationError(
            "Unable to unlock vault: incorrect master password or altered vault data."
        ) from error
    except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VaultFormatError("Vault file is malformed or unsupported.") from error

    if not isinstance(vault, dict) or not isinstance(vault.get("entries"), dict):
        raise VaultFormatError("Vault contents are invalid.")
    return vault
