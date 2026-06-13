"""
Custom exceptions for PIIGuard.

Provides clear, actionable error types for different failure modes.
"""

from __future__ import annotations


class PIIGuardError(Exception):
    """Base exception for all PIIGuard errors."""
    pass


class ConfigurationError(PIIGuardError):
    """Raised when configuration is invalid or missing required fields."""
    pass


class ComplianceError(PIIGuardError):
    """Raised when a compliance violation is detected that blocks migration."""
    pass


class PIIError(PIIGuardError):
    """Raised when PII detection or desensitization fails."""
    pass


class CryptoError(PIIGuardError):
    """Raised when encryption/decryption operations fail."""
    pass


class IntegrityError(PIIGuardError):
    """Raised when file integrity checks fail."""
    pass


class MigrationStateError(PIIGuardError):
    """Raised when incremental migration state is corrupted or incompatible."""
    pass


class UnsupportedFileError(PIIGuardError):
    """Raised when a file type is not supported for migration."""
    pass
