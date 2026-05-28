"""Comprehensive tests for v0.10+ features: new PII types, formats, compliance, integrity, config, audit."""

import json
import sqlite3
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture
def sample_xml(tmp_path):
    """Create a sample XML file with PII."""
    p = tmp_path / "test.xml"
    p.write_text("""<?xml version="1.0" encoding="UTF-8"?>
<employees>
  <employee id="1">
    <name>Alice Johnson</name>
    <email>alice@example.com</email>
    <phone>555-123-4567</phone>
    <department>Engineering</department>
  </employee>
  <employee id="2">
    <name>Bob Smith</name>
    <email>bob@company.io</email>
    <phone>416-555-0123</phone>
    <department>Marketing</department>
  </employee>
</employees>""")
    return p


@pytest.fixture
def sample_tsv(tmp_path):
    """Create a sample TSV file with PII."""
    p = tmp_path / "test.tsv"
    p.write_text("name\temail\tphone\tdepartment\n"
                 "Alice\talice@test.com\t555-123-4567\tEng\n"
                 "Bob\tbob@test.com\t416-555-0123\tMkt\n")
    return p


@pytest.fixture
def sample_sqlite(tmp_path):
    """Create a sample SQLite database with PII."""
    p = tmp_path / "test.sqlite"
    conn = sqlite3.connect(p)
    c = conn.cursor()
    c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, phone TEXT, dept TEXT)")
    c.executemany("INSERT INTO users VALUES (?,?,?,?,?)", [
        (1, "Alice", "alice@test.com", "555-123-4567", "Eng"),
        (2, "Bob", "bob@test.com", "416-555-0123", "Mkt"),
    ])
    conn.commit()
    conn.close()
    return p


@pytest.fixture
def all_formats_dir(tmp_path, sample_xml, sample_tsv, sample_sqlite):
    """Directory with all 8 supported formats."""
    import shutil
    src = tmp_path / "source"
    src.mkdir()
    (src / "data.csv").write_text("name,email\nAlice,alice@test.com\nBob,bob@test.com\n")
    (src / "data.json").write_text('[{"name":"Alice","email":"alice@test.com"}]')
    (src / "data.txt").write_text("Contact alice@test.com for info.")
    shutil.copy(sample_xml, src / "data.xml")
    shutil.copy(sample_tsv, src / "data.tsv")
    shutil.copy(sample_sqlite, src / "data.sqlite")

    # Excel
    import openpyxl
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(["name", "email"])
    ws.append(["Alice", "alice@test.com"])
    wb.save(src / "data.xlsx")
    wb.close()

    # Parquet
    import pyarrow as pa
    import pyarrow.parquet as pq
    pq.write_table(pa.table({"name": ["Alice"], "email": ["alice@test.com"]}), src / "data.parquet")

    return src


# ===========================================================================
# New PII type tests
# ===========================================================================

class TestNewPIITypes:
    def test_mask_chinese_id(self):
        from offshore_migrator.pii import mask_chinese_id
        assert "1101" in mask_chinese_id("110101199001011234")
        assert "***" in mask_chinese_id("110101199001011234")
        assert mask_chinese_id("110101199001011234").endswith("234")

    def test_mask_passport(self):
        from offshore_migrator.pii import mask_passport
        result = mask_passport("AB1234567")
        assert result.startswith("AB")
        assert "***" in result
        assert result.endswith("4567")

    def test_mask_bank_account(self):
        from offshore_migrator.pii import mask_bank_account
        result = mask_bank_account("1234567890123456")
        assert result.startswith("1234")
        assert "****" in result or "***" in result
        assert result.endswith("3456")

    def test_mask_iban(self):
        from offshore_migrator.pii import mask_iban
        result = mask_iban("GB29NWBK60161331926819")
        assert result.startswith("GB29")
        assert "****" in result

    def test_mask_mac(self):
        from offshore_migrator.pii import mask_mac
        result = mask_mac("00:1B:44:11:3A:B7")
        assert "00:1B" in result
        assert "**" in result
        assert result.endswith("B7")

    def test_mask_dob(self):
        from offshore_migrator.pii import mask_dob
        result = mask_dob("1990-01-15")
        assert "****" in result
        assert result.endswith("15")

    def test_chinese_id_in_mask_value(self):
        from offshore_migrator.pii import mask_value
        result = mask_value("ID: 110101199001011234")
        assert "***" in result
        assert "110101199001011234" not in result

    def test_passport_in_mask_value(self):
        from offshore_migrator.pii import mask_value
        result = mask_value("Passport: AB1234567")
        assert "***" in result

    def test_iban_in_mask_value(self):
        from offshore_migrator.pii import mask_value
        result = mask_value("IBAN: GB29NWBK60161331926819")
        assert "GB29NWBK60161331926819" not in result


# ===========================================================================
# XML desensitization tests
# ===========================================================================

class TestDesensitizeXML:
    def test_masks_text_content(self, sample_xml, tmp_path):
        from offshore_migrator.pii import desensitize_xml
        out = tmp_path / "out.xml"
        report = desensitize_xml(sample_xml, out)
        assert out.exists()
        assert report.values_masked > 0
        assert report.rows_processed > 0

    def test_output_is_valid_xml(self, sample_xml, tmp_path):
        from offshore_migrator.pii import desensitize_xml
        out = tmp_path / "out.xml"
        desensitize_xml(sample_xml, out)
        tree = ET.parse(out)
        root = tree.getroot()
        # Check email was masked
        emails = [elem.text for elem in root.iter("email") if elem.text]
        for email in emails:
            assert "***" in email

    def test_detects_pii_field_names(self, sample_xml, tmp_path):
        from offshore_migrator.pii import desensitize_xml
        out = tmp_path / "out.xml"
        report = desensitize_xml(sample_xml, out)
        assert "name" in report.fields_masked or "email" in report.fields_masked


# ===========================================================================
# TSV desensitization tests
# ===========================================================================

class TestDesensitizeTSV:
    def test_masks_pii(self, sample_tsv, tmp_path):
        from offshore_migrator.pii import desensitize_tsv
        out = tmp_path / "out.tsv"
        report = desensitize_tsv(sample_tsv, out)
        assert out.exists()
        assert report.values_masked > 0
        assert report.rows_processed == 2

    def test_output_is_valid_tsv(self, sample_tsv, tmp_path):
        from offshore_migrator.pii import desensitize_tsv
        out = tmp_path / "out.tsv"
        desensitize_tsv(sample_tsv, out)
        content = out.read_text()
        lines = content.strip().split("\n")
        assert len(lines) == 3  # header + 2 rows
        # Check tab-separated
        assert "\t" in lines[1]
        # Check email masked
        assert "***" in lines[1]


# ===========================================================================
# SQLite desensitization tests
# ===========================================================================

class TestDesensitizeSQLite:
    def test_masks_string_columns(self, sample_sqlite, tmp_path):
        from offshore_migrator.pii import desensitize_sqlite
        out = tmp_path / "out.sqlite"
        report = desensitize_sqlite(sample_sqlite, out)
        assert out.exists()
        assert report.values_masked > 0
        assert report.rows_processed == 2

    def test_output_is_valid_sqlite(self, sample_sqlite, tmp_path):
        from offshore_migrator.pii import desensitize_sqlite
        out = tmp_path / "out.sqlite"
        desensitize_sqlite(sample_sqlite, out)

        conn = sqlite3.connect(out)
        cursor = conn.cursor()
        cursor.execute("SELECT email FROM users")
        emails = [row[0] for row in cursor.fetchall()]
        for email in emails:
            assert "***" in email
        conn.close()

    def test_preserves_non_string_columns(self, sample_sqlite, tmp_path):
        from offshore_migrator.pii import desensitize_sqlite
        out = tmp_path / "out.sqlite"
        desensitize_sqlite(sample_sqlite, out)

        conn = sqlite3.connect(out)
        cursor = conn.cursor()
        cursor.execute("SELECT id, dept FROM users")
        rows = cursor.fetchall()
        assert rows[0][0] == 1  # id preserved
        assert rows[0][1] == "Eng"  # dept (non-PII) preserved
        conn.close()


# ===========================================================================
# File classification tests
# ===========================================================================

class TestFileClassificationNew:
    def test_classify_xml(self):
        from offshore_migrator.migrate import _classify_file
        assert _classify_file(Path("data.xml")) == "xml"

    def test_classify_tsv(self):
        from offshore_migrator.migrate import _classify_file
        assert _classify_file(Path("data.tsv")) == "tsv"

    def test_classify_sqlite(self):
        from offshore_migrator.migrate import _classify_file
        assert _classify_file(Path("data.db")) == "sqlite"
        assert _classify_file(Path("data.sqlite")) == "sqlite"
        assert _classify_file(Path("data.sqlite3")) == "sqlite"


# ===========================================================================
# Full migration with all 8 formats
# ===========================================================================

class TestMigrationAllFormats:
    def test_all_formats_processed(self, all_formats_dir, tmp_path):
        from offshore_migrator.migrate import run_migration
        out = tmp_path / "output"
        report = run_migration(
            source_dir=all_formats_dir,
            output_dir=out,
            password="testpw",
            show_progress=False,
            generate_manifest=False,
        )
        assert len(report.files_processed) == 8
        assert len(report.errors) == 0

    def test_dry_run_all_formats(self, all_formats_dir, tmp_path):
        from offshore_migrator.migrate import run_migration
        out = tmp_path / "output"
        report = run_migration(
            source_dir=all_formats_dir,
            output_dir=out,
            password="testpw",
            dry_run=True,
            show_progress=False,
            generate_manifest=False,
        )
        assert len(report.files_processed) == 8
        assert not (out / "encrypted").exists()

    def test_parallel_all_formats(self, all_formats_dir, tmp_path):
        from offshore_migrator.migrate import run_migration
        out = tmp_path / "output"
        report = run_migration(
            source_dir=all_formats_dir,
            output_dir=out,
            password="testpw",
            workers=4,
            show_progress=False,
            generate_manifest=False,
        )
        assert len(report.files_processed) == 8
        assert len(report.errors) == 0


# ===========================================================================
# Compliance tests
# ===========================================================================

class TestCompliance:
    def test_list_profiles(self):
        from offshore_migrator.compliance import list_profiles
        profiles = list_profiles()
        assert "gdpr" in profiles
        assert "pdpa" in profiles
        assert "ccpa" in profiles
        assert "lgpd" in profiles
        assert "pipl" in profiles

    def test_get_profile(self):
        from offshore_migrator.compliance import get_profile
        gdpr = get_profile("gdpr")
        assert gdpr.name == "gdpr"
        assert gdpr.encryption_required
        assert "email" in gdpr.required_pii_fields

    def test_get_profile_aliases(self):
        from offshore_migrator.compliance import get_profile
        assert get_profile("eu").name == "gdpr"
        assert get_profile("singapore").name == "pdpa"
        assert get_profile("china").name == "pipl"
        assert get_profile("brazil").name == "lgpd"

    def test_unknown_profile_raises(self):
        from offshore_migrator.compliance import get_profile
        with pytest.raises(ValueError, match="Unknown"):
            get_profile("nonexistent")

    def test_validate_migration_pass(self):
        from offshore_migrator.compliance import get_profile, validate_migration
        pii_report = {"file.csv": {"fields_masked": ["name", "email", "phone", "address", "national_id", "ssn",
                                                      "ip_address", "date_of_birth", "bank_account", "credit_card",
                                                      "full_name"]}}
        violations = validate_migration(pii_report, get_profile("pdpa"))
        assert len(violations) == 0

    def test_validate_migration_fail(self):
        from offshore_migrator.compliance import get_profile, validate_migration
        pii_report = {"file.csv": {"fields_masked": ["email"]}}
        violations = validate_migration(pii_report, get_profile("gdpr"))
        assert len(violations) > 0

    def test_migration_with_compliance(self, all_formats_dir, tmp_path):
        from offshore_migrator.migrate import run_migration
        out = tmp_path / "output"
        report = run_migration(
            source_dir=all_formats_dir,
            output_dir=out,
            password="testpw",
            compliance_profile="pdpa",
            show_progress=False,
            generate_manifest=False,
        )
        assert report.compliance_profile == "pdpa"


# ===========================================================================
# Integrity tests
# ===========================================================================

class TestIntegrity:
    def test_compute_sha256(self, tmp_path):
        from offshore_migrator.integrity import compute_sha256
        f = tmp_path / "test.txt"
        f.write_text("hello world")
        h = compute_sha256(f)
        assert len(h) == 64  # SHA-256 hex digest
        # Same content = same hash
        assert compute_sha256(f) == h

    def test_generate_manifest(self, tmp_path):
        from offshore_migrator.integrity import generate_manifest
        d = tmp_path / "data"
        d.mkdir()
        (d / "a.txt").write_text("aaa")
        (d / "b.txt").write_text("bbb")
        manifest = generate_manifest(d)
        assert len(manifest) == 2
        assert "a.txt" in manifest
        assert "b.txt" in manifest

    def test_write_and_verify_manifest(self, tmp_path):
        from offshore_migrator.integrity import write_manifest, verify_manifest
        d = tmp_path / "data"
        d.mkdir()
        (d / "a.txt").write_text("aaa")
        (d / "b.txt").write_text("bbb")

        manifest_path = tmp_path / "manifest.json"
        write_manifest(d, manifest_path)
        assert manifest_path.exists()

        # Verify (should pass)
        mismatches = verify_manifest(d, manifest_path)
        assert len(mismatches) == 0

        # Modify a file
        (d / "a.txt").write_text("modified")
        mismatches = verify_manifest(d, manifest_path)
        assert len(mismatches) > 0
        assert any("MISMATCH" in m for m in mismatches)

    def test_detect_missing_file(self, tmp_path):
        from offshore_migrator.integrity import write_manifest, verify_manifest
        d = tmp_path / "data"
        d.mkdir()
        (d / "a.txt").write_text("aaa")
        manifest_path = tmp_path / "manifest.json"
        write_manifest(d, manifest_path)

        # Delete file
        (d / "a.txt").unlink()
        mismatches = verify_manifest(d, manifest_path)
        assert any("MISSING" in m for m in mismatches)

    def test_directory_hash(self, tmp_path):
        from offshore_migrator.integrity import compute_directory_hash
        d = tmp_path / "data"
        d.mkdir()
        (d / "a.txt").write_text("aaa")
        h1 = compute_directory_hash(d)
        assert len(h1) == 64

        # Same content = same hash
        assert compute_directory_hash(d) == h1

        # Different content = different hash
        (d / "a.txt").write_text("bbb")
        h2 = compute_directory_hash(d)
        assert h1 != h2

    def test_migration_generates_manifest(self, all_formats_dir, tmp_path):
        from offshore_migrator.migrate import run_migration
        out = tmp_path / "output"
        report = run_migration(
            source_dir=all_formats_dir,
            output_dir=out,
            password="testpw",
            show_progress=False,
            generate_manifest=True,
        )
        assert report.manifest_hash
        assert (out / "manifest.json").exists()


# ===========================================================================
# Config tests
# ===========================================================================

class TestConfig:
    def test_default_config(self):
        from offshore_migrator.config import default_config
        c = default_config()
        assert c.source == "examples"
        assert c.workers == 1
        assert c.encryption_method == "aes-256-gcm"

    def test_save_and_load_config(self, tmp_path):
        from offshore_migrator.config import default_config, save_config, load_config
        c = default_config()
        c.workers = 4
        c.compliance_profile = "gdpr"
        path = tmp_path / "config.yaml"
        save_config(c, path)
        assert path.exists()

        loaded = load_config(path)
        assert loaded.workers == 4
        assert loaded.compliance_profile == "gdpr"

    def test_load_missing_raises(self, tmp_path):
        from offshore_migrator.config import load_config
        with pytest.raises(FileNotFoundError):
            load_config(tmp_path / "nonexistent.yaml")


# ===========================================================================
# Audit tests
# ===========================================================================

class TestAudit:
    def test_log_and_read_entries(self, tmp_path):
        from offshore_migrator.audit import AuditLog, AuditEntry
        log_path = tmp_path / "audit.jsonl"
        audit = AuditLog(log_path)

        audit.log(AuditEntry(
            timestamp="2026-01-01T00:00:00Z",
            action="test_action",
            file_path="test.csv",
            details={"key": "value"},
            status="success",
        ))

        entries = audit.get_entries()
        assert len(entries) == 1
        assert entries[0].action == "test_action"
        assert entries[0].file_path == "test.csv"

    def test_log_migration_events(self, tmp_path):
        from offshore_migrator.audit import AuditLog
        log_path = tmp_path / "audit.jsonl"
        audit = AuditLog(log_path)

        audit.log_migration_start({"source": "data/", "target": "singapore"})
        audit.log_file_processed("file.csv", pii_count=5)
        audit.log_error("bad.csv", "parse error")
        audit.log_migration_end({"files_processed": 2})

        entries = audit.get_entries()
        assert len(entries) == 4

    def test_get_summary(self, tmp_path):
        from offshore_migrator.audit import AuditLog
        log_path = tmp_path / "audit.jsonl"
        audit = AuditLog(log_path)

        audit.log_migration_start({})
        audit.log_file_processed("a.csv", pii_count=5)
        audit.log_file_processed("b.csv", pii_count=3)
        audit.log_error("c.csv", "error")
        audit.log_migration_end({})

        summary = audit.get_summary()
        assert summary["total_files_processed"] == 2
        assert summary["total_pii_masked"] == 8
        assert summary["total_errors"] == 1

    def test_migration_creates_audit_log(self, all_formats_dir, tmp_path):
        from offshore_migrator.migrate import run_migration
        out = tmp_path / "output"
        audit_path = tmp_path / "audit.jsonl"
        run_migration(
            source_dir=all_formats_dir,
            output_dir=out,
            password="testpw",
            show_progress=False,
            generate_manifest=False,
            audit_log_path=audit_path,
        )
        assert audit_path.exists()
        content = audit_path.read_text()
        assert "migration_start" in content
        assert "migration_end" in content


# ===========================================================================
# Compression and resume tests
# ===========================================================================

class TestCompressionAndResume:
    def test_compress_output(self, all_formats_dir, tmp_path):
        from offshore_migrator.migrate import run_migration
        out = tmp_path / "output"
        report = run_migration(
            source_dir=all_formats_dir,
            output_dir=out,
            password="testpw",
            compress=True,
            show_progress=False,
            generate_manifest=False,
        )
        assert len(report.errors) == 0
        # Check that .gz files exist
        enc_dir = out / "encrypted"
        gz_files = list(enc_dir.rglob("*.gz"))
        assert len(gz_files) > 0

    def test_resume_skips_processed(self, all_formats_dir, tmp_path):
        from offshore_migrator.migrate import run_migration
        out = tmp_path / "output"

        # First run
        report1 = run_migration(
            source_dir=all_formats_dir,
            output_dir=out,
            password="testpw",
            show_progress=False,
            generate_manifest=False,
        )
        assert len(report1.files_processed) == 8

        # Resume (should skip all)
        report2 = run_migration(
            source_dir=all_formats_dir,
            output_dir=out,
            password="testpw",
            resume=True,
            show_progress=False,
            generate_manifest=False,
        )
        assert len(report2.files_skipped) == 8
        assert len(report2.files_processed) == 0


# ===========================================================================
# Skip patterns tests
# ===========================================================================

class TestSkipPatterns:
    def test_skip_patterns(self, all_formats_dir, tmp_path):
        from offshore_migrator.migrate import run_migration
        out = tmp_path / "output"
        report = run_migration(
            source_dir=all_formats_dir,
            output_dir=out,
            password="testpw",
            skip_patterns=["*.xml", "*.tsv"],
            show_progress=False,
            generate_manifest=False,
        )
        processed = report.files_processed
        assert "data.xml" not in processed
        assert "data.tsv" not in processed
        assert len(processed) == 6
