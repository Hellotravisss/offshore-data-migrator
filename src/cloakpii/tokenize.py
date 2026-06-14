"""
Reversible, deterministic pseudonymization (tokenization).

Unlike masking (which is irreversible and destroys utility), tokenization
replaces a PII value with a stable token such that:

  * the SAME input value always maps to the SAME token — so joins, GROUP BY,
    de-duplication and referential integrity across columns/files are preserved;
  * the original value can be recovered with the password (reversible);
  * tokens are STABLE across separate runs with the same password, so data
    tokenized in different migrations still joins correctly.

Mechanism: AES-GCM-SIV (a deterministic, nonce-misuse-resistant AEAD). With a
fixed, key-derived nonce, identical plaintexts encrypt to identical ciphertexts
— which is exactly the equality-preserving property tokenization needs.

Token wire format:  ``tkz_<base32-lowercase-ciphertext>``
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re

from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

from .crypto import derive_key, CryptoError

TOKEN_PREFIX = "tkz_"
# Matches a single token; used to find tokens embedded in text / whole cells.
TOKEN_RE = re.compile(r"tkz_[a-z2-7]+")

# Fixed application salt. Tokenization deliberately derives a STABLE key from the
# password alone so the same value tokenizes identically across runs (joins!).
# This is an intentional trade-off vs. the random per-file salt used for the
# bulk AES-256-GCM encryption, which protects the data at rest.
_TOKEN_SALT = b"cloakpii::tokenize::v1::fixed-salt"


class Tokenizer:
    """Deterministic, reversible pseudonymizer keyed by a password."""

    def __init__(self, password: str):
        if not password:
            raise CryptoError("Tokenizer requires a non-empty password")
        key = derive_key(password, _TOKEN_SALT)  # PBKDF2 — run once per instance
        self._aead = AESGCMSIV(key)
        # Deterministic nonce derived from the key (SIV tolerates a fixed nonce;
        # reuse only leaks plaintext equality, which we want).
        self._nonce = hmac.new(key, b"cloakpii::tokenize::nonce", hashlib.sha256).digest()[:12]

    def tokenize(self, value: str) -> str:
        """Map a value to its stable token. Idempotent on already-tokenized input."""
        if value.startswith(TOKEN_PREFIX):
            return value  # don't double-tokenize
        ct = self._aead.encrypt(self._nonce, value.encode("utf-8"), None)
        body = base64.b32encode(ct).decode("ascii").rstrip("=").lower()
        return TOKEN_PREFIX + body

    def detokenize(self, token: str) -> str:
        """Recover the original value from a token. Returns input unchanged if
        it is not a well-formed token produced by this password."""
        if not token.startswith(TOKEN_PREFIX):
            return token
        body = token[len(TOKEN_PREFIX):].upper()
        pad = "=" * ((8 - len(body) % 8) % 8)
        try:
            ct = base64.b32decode(body + pad)
            return self._aead.decrypt(self._nonce, ct, None).decode("utf-8")
        except Exception as exc:
            raise CryptoError(f"Detokenization failed (wrong password or corrupted token): {exc}")

    def detokenize_text(self, text: str) -> str:
        """Replace every token found inside a string with its original value."""
        return TOKEN_RE.sub(lambda m: self.detokenize(m.group()), text)
