"""
Audit trail logging for migration operations.

Provides thread-safe JSON Lines logging for tracking
all migration activities, errors, and compliance events.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class AuditEntry:
    """Single audit log entry."""

    timestamp: str
    action: str
    file_path: str = ""
    details: dict = field(default_factory=dict)
    status: str = "success"  # success / error / skipped

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class AuditLog:
    """Thread-safe audit log writer (JSON Lines format)."""

    def __init__(self, path: Path) -> None:
        """Initialize audit log.

        Args:
            path: Path to the audit log file (JSON Lines).
        """
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._count = 0

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def log(self, entry: AuditEntry) -> None:
        """Append an entry to the audit log.

        Thread-safe via lock.
        """
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(entry.to_json() + "\n")
            self._count += 1

    def log_migration_start(self, config: dict) -> None:
        """Log migration start event."""
        self.log(AuditEntry(
            timestamp=self._now(),
            action="migration_start",
            details=config,
        ))

    def log_migration_end(self, report: dict) -> None:
        """Log migration end event."""
        self.log(AuditEntry(
            timestamp=self._now(),
            action="migration_end",
            details=report,
        ))

    def log_file_processed(
        self,
        file_path: str,
        pii_count: int,
        status: str = "success",
    ) -> None:
        """Log individual file processing."""
        self.log(AuditEntry(
            timestamp=self._now(),
            action="file_processed",
            file_path=file_path,
            details={"pii_masked": pii_count},
            status=status,
        ))

    def log_error(self, file_path: str, error: str) -> None:
        """Log an error event."""
        self.log(AuditEntry(
            timestamp=self._now(),
            action="error",
            file_path=file_path,
            details={"error": error},
            status="error",
        ))

    def get_entries(self) -> list[AuditEntry]:
        """Read all entries from the audit log."""
        if not self.path.exists():
            return []

        entries = []
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    entries.append(AuditEntry(
                        timestamp=data.get("timestamp", ""),
                        action=data.get("action", ""),
                        file_path=data.get("file_path", ""),
                        details=data.get("details", {}),
                        status=data.get("status", "success"),
                    ))
                except json.JSONDecodeError:
                    continue
        return entries

    def get_summary(self) -> dict:
        """Return summary statistics from the audit log."""
        entries = self.get_entries()

        total_files = 0
        errors = 0
        pii_masked = 0
        actions: dict[str, int] = {}

        for entry in entries:
            actions[entry.action] = actions.get(entry.action, 0) + 1

            if entry.action == "file_processed":
                total_files += 1
                pii_masked += entry.details.get("pii_masked", 0)

            if entry.status == "error":
                errors += 1

        return {
            "total_entries": len(entries),
            "total_files_processed": total_files,
            "total_pii_masked": pii_masked,
            "total_errors": errors,
            "actions": actions,
        }
