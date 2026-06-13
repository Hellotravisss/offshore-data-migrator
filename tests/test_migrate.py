"""Tests for migration workflow (dry-run and real)."""

import json
import tempfile
import unittest
from pathlib import Path

from piiguard.crypto import decrypt_data
from piiguard.migrate import run_migration


class TestMigrationDryRun(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.source = self.tmpdir / "source"
        self.source.mkdir()
        self.output = self.tmpdir / "output"

        # Create sample files
        (self.source / "data.csv").write_text(
            "name,email,phone\n"
            "Alice,alice@test.com,555-123-4567\n"
        )
        (self.source / "data.json").write_text(json.dumps([
            {"full_name": "Bob", "email": "bob@test.com"}
        ]))
        (self.source / "notes.txt").write_text("Contact admin@corp.io for help.")

    def test_dry_run_does_not_create_output(self):
        report = run_migration(
            source_dir=self.source,
            output_dir=self.output,
            password="pw",
            dry_run=True,
        )
        self.assertTrue(report.dry_run)
        self.assertEqual(len(report.errors), 0)
        # Dry run should not create encrypted files
        encrypted_dir = self.output / "encrypted"
        self.assertFalse(encrypted_dir.exists())

    def test_dry_run_reports_pii(self):
        report = run_migration(
            source_dir=self.source,
            output_dir=self.output,
            password="pw",
            dry_run=True,
        )
        self.assertEqual(len(report.files_processed), 3)
        # CSV and JSON should have PII detected
        total_pii = sum(
            r.get("values_masked", 0) for r in report.pii_reports.values()
        )
        self.assertGreater(total_pii, 0)

    def test_dry_run_lists_all_files(self):
        report = run_migration(
            source_dir=self.source,
            output_dir=self.output,
            password="pw",
            dry_run=True,
        )
        names = [Path(f).name for f in report.files_processed]
        self.assertIn("data.csv", names)
        self.assertIn("data.json", names)
        self.assertIn("notes.txt", names)


class TestMigrationReal(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.source = self.tmpdir / "source"
        self.source.mkdir()
        self.output = self.tmpdir / "output"

        (self.source / "users.csv").write_text(
            "name,email,phone,score\n"
            "Alice,alice@example.com,555-123-4567,95\n"
            "Bob,bob@corp.io,416-555-7890,82\n"
        )
        (self.source / "users.json").write_text(json.dumps([
            {"full_name": "Charlie", "email": "charlie@x.com", "national_id": "123-45-6789"}
        ]))
        (self.source / "readme.txt").write_text("No PII here.")

    def test_real_migration_encrypts_files(self):
        report = run_migration(
            source_dir=self.source,
            output_dir=self.output,
            password="testpw123",
            dry_run=False,
        )
        self.assertFalse(report.dry_run)
        self.assertEqual(len(report.errors), 0)
        self.assertEqual(len(report.files_encrypted), 3)

        # Verify encrypted files exist
        for rel in report.files_encrypted:
            enc_path = self.output / "encrypted" / (rel + ".enc")
            self.assertTrue(enc_path.exists(), f"Missing: {enc_path}")

    def test_real_migration_desensitizes(self):
        run_migration(
            source_dir=self.source,
            output_dir=self.output,
            password="testpw123",
            dry_run=False,
        )
        # Check desensitized CSV
        desens_csv = self.output / "desensitized" / "users.csv"
        self.assertTrue(desens_csv.exists())
        content = desens_csv.read_text()
        self.assertNotIn("alice@example.com", content)
        self.assertNotIn("bob@corp.io", content)

    def test_encrypted_data_is_decryptable(self):
        run_migration(
            source_dir=self.source,
            output_dir=self.output,
            password="mypw",
            dry_run=False,
        )
        # Decrypt one file and verify content
        enc_path = self.output / "encrypted" / "readme.txt.enc"
        blob = enc_path.read_bytes()
        plaintext = decrypt_data(blob, "mypw")
        # readme.txt had "No PII here." — no masking needed
        self.assertIn(b"No PII here.", plaintext)

    def test_migration_report_structure(self):
        report = run_migration(
            source_dir=self.source,
            output_dir=self.output,
            password="pw",
        )
        d = report.to_dict()
        self.assertIn("started_at", d)
        self.assertIn("finished_at", d)
        self.assertIn("files_processed", d)
        self.assertIn("files_encrypted", d)
        self.assertIn("pii_reports", d)

    def test_nonexistent_source_dir(self):
        report = run_migration(
            source_dir=Path("/nonexistent/path"),
            output_dir=self.output,
            password="pw",
        )
        self.assertGreater(len(report.errors), 0)

    def test_empty_source_dir(self):
        empty = self.tmpdir / "empty"
        empty.mkdir()
        report = run_migration(
            source_dir=empty,
            output_dir=self.output,
            password="pw",
        )
        self.assertEqual(len(report.files_processed), 0)
        self.assertEqual(len(report.errors), 0)
