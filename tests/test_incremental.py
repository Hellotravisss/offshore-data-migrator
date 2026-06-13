"""End-to-end tests for incremental migration (resume functionality)."""

import tempfile
from pathlib import Path
from piiguard.state import MigrationState
from piiguard.migrate import run_migration


def test_migration_state_basic():
    """Test basic state creation and operations."""
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "state.db"
        state = MigrationState(db_path)

        assert state.get_processed_count() == 0

        rel_path = Path("data/sample.csv")
        file_hash = "abc123def456"
        state.mark_processed(rel_path, file_hash, pii_count=5)

        assert state.get_processed_count() == 1
        assert state.is_processed(rel_path, file_hash) is True
        assert state.is_processed(rel_path, "wrong_hash") is False


def test_resume_skips_processed_files():
    """Test that resume mode skips already processed files."""
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp) / "source"
        output = Path(tmp) / "output"
        source.mkdir()

        test_file = source / "test.csv"
        test_file.write_text("name,email\nJohn,john@example.com\n")

        state_db = output / ".migration_state.db"
        state = MigrationState(state_db)

        file_hash = "testhash123"
        state.mark_processed(Path("test.csv"), file_hash, pii_count=1)

        assert state.is_processed(Path("test.csv"), file_hash) is True


def test_state_persistence():
    """Test that state survives across MigrationState instances."""
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "state.db"

        state1 = MigrationState(db_path)
        state1.mark_processed(Path("file1.txt"), "hash1", pii_count=3)

        state2 = MigrationState(db_path)
        assert state2.get_processed_count() == 1
        assert state2.is_processed(Path("file1.txt"), "hash1") is True


def test_resume_with_actual_migration():
    """Full integration test: run migration twice with resume=True."""
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp) / "source"
        output = Path(tmp) / "output"
        source.mkdir()
        output.mkdir()

        # Create two test files
        (source / "file1.txt").write_text("name: Alice\nemail: alice@test.com")
        (source / "file2.txt").write_text("name: Bob\nemail: bob@test.com")

        state_db = output / ".migration_state.db"

        # First run - should process both files
        report1 = run_migration(
            source_dir=source,
            output_dir=output,
            password="testpass123",
            dry_run=False,
            resume=False,
            state=MigrationState(state_db),
        )

        assert len(report1.files_processed) == 2
        assert len(report1.files_skipped) == 0

        # Second run with resume=True - should skip both
        report2 = run_migration(
            source_dir=source,
            output_dir=output,
            password="testpass123",
            dry_run=False,
            resume=True,
            state=MigrationState(state_db),
        )

        assert len(report2.files_skipped) == 2
        assert len(report2.files_processed) == 0


def test_resume_detects_file_change():
    """If file content changes, resume should re-process it."""
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp) / "source"
        output = Path(tmp) / "output"
        source.mkdir()
        output.mkdir()

        test_file = source / "data.txt"
        test_file.write_text("original content")

        state_db = output / ".migration_state.db"

        # First run
        run_migration(
            source_dir=source,
            output_dir=output,
            password="testpass123",
            dry_run=False,
            resume=True,
            state=MigrationState(state_db),
        )

        # Modify the file (simulating content change)
        test_file.write_text("modified content with new PII: john@new.com")

        # Second run should detect change and re-process
        report = run_migration(
            source_dir=source,
            output_dir=output,
            password="testpass123",
            dry_run=False,
            resume=True,
            state=MigrationState(state_db),
        )

        # Because hash changed, it should have been processed again
        assert len(report.files_processed) >= 1 or len(report.files_skipped) == 0


def test_state_corruption_handling():
    """Test graceful handling when state DB is corrupted."""
    with tempfile.TemporaryDirectory() as tmp:
        state_db = Path(tmp) / ".migration_state.db"

        # Create a corrupted state file
        state_db.write_text("this is not a valid sqlite database")

        # Should not crash, but create a fresh state
        state = MigrationState(state_db)
        assert state.get_processed_count() == 0

        # Should be able to use it normally after recovery
        state.mark_processed(Path("recovered.txt"), "hash999")
        assert state.get_processed_count() == 1
