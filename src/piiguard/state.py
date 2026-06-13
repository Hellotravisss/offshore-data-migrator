"""State management for incremental/resume migrations using SQLite."""

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional


class MigrationState:
    """Manage migration state for incremental processing."""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        """Initialize the SQLite database schema. Recovers from corruption."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS processed_files (
                        path TEXT PRIMARY KEY,
                        file_hash TEXT NOT NULL,
                        processed_at TEXT NOT NULL,
                        pii_count INTEGER DEFAULT 0
                    )
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_processed_at 
                    ON processed_files(processed_at)
                """)
                conn.commit()
        except sqlite3.DatabaseError:
            # Corrupted DB - delete and recreate
            if self.db_path.exists():
                self.db_path.unlink()
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS processed_files (
                        path TEXT PRIMARY KEY,
                        file_hash TEXT NOT NULL,
                        processed_at TEXT NOT NULL,
                        pii_count INTEGER DEFAULT 0
                    )
                """)
                conn.commit()

    def is_processed(self, file_path: Path, file_hash: str) -> bool:
        """Check if a file has already been processed with the same hash."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT file_hash FROM processed_files WHERE path = ?",
                (str(file_path),)
            )
            row = cursor.fetchone()
            return row is not None and row[0] == file_hash

    def get_recorded_hash(self, file_path: Path) -> Optional[str]:
        """Return the stored hash for a path, or None if it was never recorded."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT file_hash FROM processed_files WHERE path = ?",
                (str(file_path),)
            )
            row = cursor.fetchone()
            return row[0] if row is not None else None

    def mark_processed(self, file_path: Path, file_hash: str, pii_count: int = 0):
        """Mark a file as processed."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT OR REPLACE INTO processed_files 
                   (path, file_hash, processed_at, pii_count) 
                   VALUES (?, ?, ?, ?)""",
                (str(file_path), file_hash, datetime.utcnow().isoformat(), pii_count)
            )
            conn.commit()

    def get_processed_count(self) -> int:
        """Get total number of processed files."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM processed_files")
            return cursor.fetchone()[0]

    def clear(self):
        """Clear all processed records (for testing/reset)."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM processed_files")
            conn.commit()
