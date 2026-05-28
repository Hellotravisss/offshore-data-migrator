"""
File integrity verification via SHA-256 manifests.

Generates and verifies manifests for directories to ensure
data integrity during migration.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


def compute_sha256(filepath: Path) -> str:
    """Compute SHA-256 hex digest for a file."""
    filepath = Path(filepath)
    if not filepath.exists():
        raise FileNotFoundError(f"File not found: {filepath}")

    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def generate_manifest(directory: Path) -> dict[str, str]:
    """Walk directory and compute SHA-256 for all files.

    Returns:
        Dict mapping relative path (str) → SHA-256 hex digest.
    """
    directory = Path(directory)
    if not directory.exists():
        raise FileNotFoundError(f"Directory not found: {directory}")

    manifest = {}
    for filepath in sorted(directory.rglob("*")):
        if filepath.is_file():
            rel = str(filepath.relative_to(directory))
            manifest[rel] = compute_sha256(filepath)
    return manifest


def write_manifest(directory: Path, manifest_path: Path) -> Path:
    """Generate manifest and write to JSON file.

    Returns:
        Path to the written manifest file.
    """
    manifest = generate_manifest(directory)
    manifest_path = Path(manifest_path)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "directory": str(directory),
        "file_count": len(manifest),
        "files": manifest,
    }
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    return manifest_path


def verify_manifest(directory: Path, manifest_path: Path) -> list[str]:
    """Verify files against a previously generated manifest.

    Returns:
        List of mismatch descriptions. Empty = all files match.
    """
    directory = Path(directory)
    manifest_path = Path(manifest_path)

    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")

    with open(manifest_path, encoding="utf-8") as f:
        data = json.load(f)

    expected = data.get("files", {})
    mismatches = []

    for rel_path, expected_hash in expected.items():
        filepath = directory / rel_path
        if not filepath.exists():
            mismatches.append(f"MISSING: {rel_path}")
            continue

        actual_hash = compute_sha256(filepath)
        if actual_hash != expected_hash:
            mismatches.append(
                f"MISMATCH: {rel_path} "
                f"(expected {expected_hash[:16]}..., got {actual_hash[:16]}...)"
            )

    # Check for extra files
    current_files = set()
    for filepath in directory.rglob("*"):
        if filepath.is_file():
            current_files.add(str(filepath.relative_to(directory)))

    for extra in current_files - set(expected.keys()):
        mismatches.append(f"EXTRA: {extra} (not in manifest)")

    return mismatches


def compute_directory_hash(directory: Path) -> str:
    """Compute a single SHA-256 hash over all file hashes in a directory.

    Useful for quick comparison: if two directories have the same hash,
    their contents are identical.
    """
    manifest = generate_manifest(directory)
    # Sort for deterministic ordering
    combined = "".join(f"{k}:{v}" for k, v in sorted(manifest.items()))
    return hashlib.sha256(combined.encode()).hexdigest()
