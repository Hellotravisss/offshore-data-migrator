"""Tests for PII desensitization module."""

import csv
import json
import tempfile
import unittest
from pathlib import Path

from offshore_migrator.pii import (
    DesensitizeReport,
    desensitize_csv,
    desensitize_json,
    desensitize_text,
    mask_credit_card,
    mask_email,
    mask_generic,
    mask_ip,
    mask_phone,
    mask_ssn,
    mask_value,
)


class TestMaskFunctions(unittest.TestCase):
    def test_mask_email(self):
        result = mask_email("alice@example.com")
        self.assertIn("@", result)
        self.assertNotEqual(result, "alice@example.com")
        self.assertTrue(result.startswith("a"))

    def test_mask_phone(self):
        result = mask_phone("555-123-4567")
        self.assertIn("***", result)
        self.assertTrue(result.startswith("555"))

    def test_mask_ssn(self):
        result = mask_ssn("123-45-6789")
        self.assertTrue(result.startswith("***-**-"))
        self.assertTrue(result.endswith("6789"))

    def test_mask_credit_card(self):
        result = mask_credit_card("4111111111111111")
        self.assertTrue(result.startswith("4111"))
        self.assertTrue(result.endswith("1111"))
        self.assertIn("****", result)

    def test_mask_ip(self):
        result = mask_ip("192.168.1.100")
        self.assertEqual(result, "192.168.*.*")

    def test_mask_generic(self):
        self.assertEqual(mask_generic("Alice"), "A***")
        self.assertEqual(mask_generic(""), "***")
        self.assertEqual(mask_generic("X"), "***")


class TestMaskValue(unittest.TestCase):
    def test_email_detected(self):
        result = mask_value("contact user@test.com for info")
        self.assertNotIn("user@test.com", result)

    def test_ssn_detected(self):
        result = mask_value("SSN: 123-45-6789")
        self.assertIn("***-**-6789", result)

    def test_ip_detected(self):
        result = mask_value("Server at 10.0.0.1")
        self.assertIn("10.0.*.*", result)

    def test_no_pii_unchanged(self):
        self.assertEqual(mask_value("hello world"), "hello world")
        self.assertEqual(mask_value("12345"), "12345")

    def test_multiple_pii_in_one_string(self):
        result = mask_value("alice@x.com and 123-45-6789")
        self.assertNotIn("alice@x.com", result)
        self.assertIn("***-**-6789", result)


class TestDesensitizeText(unittest.TestCase):
    def test_masks_pii(self):
        text = "Email: user@example.com, Phone: 555-123-4567"
        masked, count = desensitize_text(text)
        self.assertNotIn("user@example.com", masked)
        self.assertGreater(count, 0)

    def test_no_pii(self):
        text = "No PII here, just regular text."
        masked, count = desensitize_text(text)
        self.assertEqual(masked, text)
        self.assertEqual(count, 0)


class TestDesensitizeCSV(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.input_csv = self.tmpdir / "input.csv"
        self.output_csv = self.tmpdir / "output.csv"

    def test_masks_pii_fields(self):
        self.input_csv.write_text(
            "name,email,phone,score\n"
            "Alice,alice@test.com,555-123-4567,95\n"
            "Bob,bob@corp.io,416-555-7890,82\n"
        )
        report = desensitize_csv(self.input_csv, self.output_csv)
        self.assertTrue(self.output_csv.exists())
        self.assertEqual(report.rows_processed, 2)
        self.assertGreater(report.values_masked, 0)

        # Verify output content is masked
        with open(self.output_csv) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        # Emails should be masked
        for row in rows:
            self.assertNotIn("@test.com", row["email"])
            self.assertNotIn("@corp.io", row["email"])

    def test_empty_csv(self):
        self.input_csv.write_text("name,email\n")
        report = desensitize_csv(self.input_csv, self.output_csv)
        self.assertEqual(report.rows_processed, 0)


class TestDesensitizeJSON(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.input_json = self.tmpdir / "input.json"
        self.output_json = self.tmpdir / "output.json"

    def test_masks_nested_json(self):
        data = [
            {
                "full_name": "Alice Johnson",
                "email": "alice@example.com",
                "phone": "555-123-4567",
                "details": {
                    "national_id": "123-45-6789",
                    "ip_address": "192.168.1.1",
                },
                "score": 95,
            },
        ]
        self.input_json.write_text(json.dumps(data))
        report = desensitize_json(self.input_json, self.output_json)
        self.assertTrue(self.output_json.exists())
        self.assertGreater(report.values_masked, 0)

        masked = json.loads(self.output_json.read_text())
        self.assertNotEqual(masked[0]["email"], "alice@example.com")
        self.assertNotEqual(masked[0]["details"]["national_id"], "123-45-6789")
        # Score should be untouched (integer)
        self.assertEqual(masked[0]["score"], 95)

    def test_flat_json_object(self):
        data = {"user_email": "test@test.com", "count": 42}
        self.input_json.write_text(json.dumps(data))
        report = desensitize_json(self.input_json, self.output_json)
        masked = json.loads(self.output_json.read_text())
        self.assertNotEqual(masked["user_email"], "test@test.com")
        self.assertEqual(masked["count"], 42)
