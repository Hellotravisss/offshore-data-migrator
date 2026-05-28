"""Tests for AES-256-GCM encryption module."""

import os
import tempfile
import unittest
from pathlib import Path

from offshore_migrator.crypto import (
    CryptoError,
    decrypt_data,
    decrypt_file,
    derive_key,
    encrypt_data,
    encrypt_file,
)


class TestDeriveKey(unittest.TestCase):
    def test_deterministic(self):
        salt = b"\x00" * 16
        k1 = derive_key("password", salt)
        k2 = derive_key("password", salt)
        self.assertEqual(k1, k2)

    def test_different_salts_different_keys(self):
        k1 = derive_key("password", b"\x00" * 16)
        k2 = derive_key("password", b"\x01" * 16)
        self.assertNotEqual(k1, k2)

    def test_key_length(self):
        k = derive_key("test", os.urandom(16))
        self.assertEqual(len(k), 32)

    def test_empty_password_raises(self):
        with self.assertRaises(CryptoError):
            derive_key("", b"\x00" * 16)


class TestEncryptDecryptData(unittest.TestCase):
    def test_roundtrip(self):
        plaintext = b"Hello, offshore world!"
        password = "s3cret_p@ss"
        blob = encrypt_data(plaintext, password)
        result = decrypt_data(blob, password)
        self.assertEqual(result, plaintext)

    def test_wrong_password_raises(self):
        blob = encrypt_data(b"secret", "correct")
        with self.assertRaises(CryptoError):
            decrypt_data(blob, "wrong")

    def test_empty_plaintext_roundtrip(self):
        blob = encrypt_data(b"", "pw")
        self.assertEqual(decrypt_data(blob, "pw"), b"")

    def test_large_data_roundtrip(self):
        plaintext = os.urandom(1024 * 1024)  # 1 MB
        blob = encrypt_data(plaintext, "pw")
        self.assertEqual(decrypt_data(blob, "pw"), plaintext)

    def test_ciphertext_differs_from_plaintext(self):
        plaintext = b"This is not encrypted in the output"
        blob = encrypt_data(plaintext, "pw")
        self.assertNotIn(plaintext, blob)

    def test_truncated_blob_raises(self):
        blob = encrypt_data(b"data", "pw")
        with self.assertRaises(CryptoError):
            decrypt_data(blob[:10], "pw")


class TestEncryptDecryptFile(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.src = Path(self.tmpdir) / "input.txt"
        self.enc = Path(self.tmpdir) / "input.txt.enc"
        self.dec = Path(self.tmpdir) / "input_dec.txt"

    def test_file_roundtrip(self):
        content = b"Sensitive AI model weights here..."
        self.src.write_bytes(content)
        encrypt_file(self.src, self.enc, "mypassword")
        self.assertTrue(self.enc.exists())
        decrypt_file(self.enc, self.dec, "mypassword")
        self.assertEqual(self.dec.read_bytes(), content)

    def test_missing_input_raises(self):
        with self.assertRaises(FileNotFoundError):
            encrypt_file(Path(self.tmpdir) / "nope.txt", self.enc, "pw")

    def test_creates_parent_dirs(self):
        self.src.write_bytes(b"data")
        nested_enc = Path(self.tmpdir) / "deep" / "nested" / "file.enc"
        encrypt_file(self.src, nested_enc, "pw")
        self.assertTrue(nested_enc.exists())
