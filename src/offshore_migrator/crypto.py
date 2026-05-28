"""
AES-256-GCM file encryption and decryption.

Wire format: [16-byte salt][12-byte nonce][ciphertext + 16-byte GCM tag]
Key derivation: PBKDF2-HMAC-SHA256 with 480 000 iterations.
"""

import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_LEN = 16
NONCE_LEN = 12
PBKDF2_ITERATIONS = 480_000
KEY_LEN = 32  # 256 bits


class CryptoError(Exception):
    """Raised when encryption/decryption fails."""


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from password + salt via PBKDF2."""
    if not password:
        raise CryptoError("Password must not be empty")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_data(plaintext: bytes, password: str) -> bytes:
    """Encrypt raw bytes. Returns salt + nonce + ciphertext(+tag)."""
    salt = os.urandom(SALT_LEN)
    key = derive_key(password, salt)
    nonce = os.urandom(NONCE_LEN)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return salt + nonce + ciphertext


def decrypt_data(blob: bytes, password: str) -> bytes:
    """Decrypt bytes produced by encrypt_data. Raises CryptoError on failure."""
    min_len = SALT_LEN + NONCE_LEN + 16  # at least the GCM tag
    if len(blob) < min_len:
        raise CryptoError("Ciphertext too short — corrupted or truncated")
    salt = blob[:SALT_LEN]
    nonce = blob[SALT_LEN : SALT_LEN + NONCE_LEN]
    ciphertext = blob[SALT_LEN + NONCE_LEN :]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise CryptoError(f"Decryption failed (wrong password or corrupted data): {exc}")


def encrypt_file(input_path: Path, output_path: Path, password: str) -> None:
    """Encrypt a file in-place on disk."""
    input_path = Path(input_path)
    output_path = Path(output_path)
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    plaintext = input_path.read_bytes()
    blob = encrypt_data(plaintext, password)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(blob)


def decrypt_file(input_path: Path, output_path: Path, password: str) -> None:
    """Decrypt a file produced by encrypt_file."""
    input_path = Path(input_path)
    output_path = Path(output_path)
    if not input_path.exists():
        raise FileNotFoundError(f"Encrypted file not found: {input_path}")
    blob = input_path.read_bytes()
    plaintext = decrypt_data(blob, password)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(plaintext)
