"""
crypto.py — Encryption-at-rest for the most sensitive guest field.

The "fragmented storage" model splits a guest across three collections
so no single collection holds a full profile. This module adds a second
layer: the guest_sensitive collection (ID proof) is encrypted with
Fernet (AES-128-CBC + HMAC) so that even a full database dump does not
expose government ID numbers in plaintext.

The key is read from DATA_ENCRYPTION_KEY in the environment. Generate
one with:  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""

import os
from cryptography.fernet import Fernet, InvalidToken


def _get_cipher() -> Fernet:
    key = os.environ.get("DATA_ENCRYPTION_KEY")
    if not key:
        raise RuntimeError(
            "DATA_ENCRYPTION_KEY is not set. Generate one with:\n"
            "  python -c \"from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())\""
        )
    return Fernet(key.encode() if isinstance(key, str) else key)


def encrypt(plaintext: str) -> str:
    """Encrypt a string; returns a URL-safe base64 token."""
    if plaintext is None:
        plaintext = ""
    cipher = _get_cipher()
    return cipher.encrypt(str(plaintext).encode()).decode()


def decrypt(token: str) -> str:
    """
    Decrypt a token produced by encrypt().

    Returns "[decryption error]" on a tampered/invalid token rather than
    raising, so a single corrupt record never takes down a whole page.
    """
    if not token:
        return ""
    try:
        cipher = _get_cipher()
        return cipher.decrypt(str(token).encode()).decode()
    except (InvalidToken, ValueError):
        return "[decryption error]"
