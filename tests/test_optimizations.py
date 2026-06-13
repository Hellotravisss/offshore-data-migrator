"""Tests for v1.2.0 optimizations: derive-once encryption, decrypt-all, Luhn."""

import os
import tempfile
from pathlib import Path

from offshore_migrator import crypto
from offshore_migrator.migrate import run_migration, decrypt_tree
from offshore_migrator.pii import luhn_valid, mask_value, mask_credit_card


class TestDeriveOnceCompat:
    def test_key_encrypted_blob_decrypts_with_password(self):
        """A blob encrypted with a pre-derived key+salt must still be
        decryptable by password alone (salt is stored in the header)."""
        salt = os.urandom(crypto.SALT_LEN)
        key = crypto.derive_key("hunter2", salt)
        blob = crypto.encrypt_data_with_key(b"secret payload", key, salt)
        # password path (re-derives from stored salt)
        assert crypto.decrypt_data(blob, "hunter2") == b"secret payload"
        # key path (skips KDF)
        assert crypto.decrypt_data_with_key(blob, key) == b"secret payload"

    def test_legacy_encrypt_data_still_roundtrips(self):
        blob = crypto.encrypt_data(b"hello", "pw")
        assert crypto.decrypt_data(blob, "pw") == b"hello"

    def test_wrong_password_fails(self):
        blob = crypto.encrypt_data(b"hello", "pw")
        try:
            crypto.decrypt_data(blob, "nope")
            assert False, "expected CryptoError"
        except crypto.CryptoError:
            pass


class TestDecryptTree:
    def test_migrate_then_decrypt_all_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "src"
            out = Path(tmp) / "out"
            restored = Path(tmp) / "restored"
            src.mkdir()
            (src / "a.csv").write_text("name,email\nAlice,alice@test.com\n")
            (src / "sub").mkdir()
            (src / "sub" / "b.txt").write_text("contact bob@corp.io\n")

            run_migration(
                source_dir=src, output_dir=out, password="pw1234",
                show_progress=False, generate_manifest=False,
            )

            report = decrypt_tree(out / "encrypted", restored, "pw1234")
            assert report["total_decrypted"] == 2
            assert report["total_errors"] == 0

            # Tree structure preserved, suffixes stripped
            assert (restored / "a.csv").exists()
            assert (restored / "sub" / "b.txt").exists()
            # Restored content is the DESENSITIZED data (masking is irreversible)
            assert "alice@test.com" not in (restored / "a.csv").read_text()

    def test_decrypt_all_wrong_password_records_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "src"
            out = Path(tmp) / "out"
            restored = Path(tmp) / "restored"
            src.mkdir()
            (src / "a.txt").write_text("nothing sensitive here\n")
            run_migration(
                source_dir=src, output_dir=out, password="right",
                show_progress=False, generate_manifest=False,
            )
            report = decrypt_tree(out / "encrypted", restored, "wrong")
            assert report["total_decrypted"] == 0
            assert report["total_errors"] == 1


class TestLuhn:
    def test_valid_card_passes(self):
        assert luhn_valid("4111111111111111")  # Visa test number
        assert luhn_valid("5500005555555559")  # Mastercard test number

    def test_random_number_fails(self):
        assert not luhn_valid("1234567890123456")
        assert not luhn_valid("0000000000000001")

    def test_too_short_fails(self):
        assert not luhn_valid("4111")

    def test_mask_credit_card_skips_invalid(self):
        # Valid card gets masked
        assert "****" in mask_credit_card("4111111111111111")
        # Invalid card-shaped number is left for other matchers
        assert mask_credit_card("1234567890123456") == "1234567890123456"


class TestPhoneFalsePositives:
    def test_bare_integer_not_masked_as_phone(self):
        assert mask_value("quantity 5551234567 units") == "quantity 5551234567 units"

    def test_formatted_phone_still_masked(self):
        result = mask_value("call 555-123-4567")
        assert "555-123-4567" not in result
