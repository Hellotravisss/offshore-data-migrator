"""
YAML configuration file support for migration settings.

Allows users to define migration parameters in a YAML file,
which can be overridden by CLI arguments.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field, asdict
from pathlib import Path

import yaml


@dataclass
class MigrationConfig:
    """All migration configuration options."""

    # Paths
    source: str = "examples"
    output: str = "output"

    # Security
    password: str | None = None
    key_file: str | None = None
    encryption_method: str = "aes-256-gcm"

    # Target
    target: str = "singapore"
    compliance_profile: str = "pdpa"

    # Processing
    dry_run: bool = False
    workers: int = 1
    batch_size: int = 0
    show_progress: bool = True

    # PII customization
    custom_pii_patterns: list[str] = field(default_factory=list)
    field_mappings: dict[str, str] = field(default_factory=dict)

    # Filtering
    skip_patterns: list[str] = field(default_factory=list)
    include_patterns: list[str] = field(default_factory=list)

    # Output
    log_file: str | None = None
    audit_log: bool = True
    generate_manifest: bool = True
    compress_output: bool = False


def load_config(path: Path) -> MigrationConfig:
    """Load configuration from a YAML file.

    Args:
        path: Path to YAML configuration file.

    Returns:
        MigrationConfig populated from file.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    # Build config from dict
    config = MigrationConfig()
    for key, value in data.items():
        if hasattr(config, key):
            setattr(config, key, value)

    return config


def save_config(config: MigrationConfig, path: Path) -> None:
    """Save configuration to a YAML file.

    Args:
        config: MigrationConfig to save.
        path: Output path for YAML file.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    data = asdict(config)
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)


def default_config() -> MigrationConfig:
    """Return a MigrationConfig with sensible defaults."""
    return MigrationConfig()


def merge_config_with_args(
    config: MigrationConfig,
    args: argparse.Namespace,
) -> MigrationConfig:
    """Merge CLI arguments with config file.

    CLI arguments override config file values when they are not None/default.

    Args:
        config: Base configuration from file.
        args: Parsed CLI arguments.

    Returns:
        Merged MigrationConfig.
    """
    # Map CLI arg names to config field names
    mappings = {
        "source": "source",
        "output": "output",
        "password": "password",
        "target": "target",
        "dry_run": "dry_run",
        "workers": "workers",
        "batch_size": "batch_size",
        "compliance_profile": "compliance_profile",
        "log_file": "log_file",
    }

    for arg_name, config_name in mappings.items():
        if hasattr(args, arg_name):
            value = getattr(args, arg_name)
            # Override only if value is not None and not the default
            if value is not None:
                # Special handling for boolean flags
                if isinstance(value, bool):
                    if value:  # Only override if True (CLI flag was set)
                        setattr(config, config_name, value)
                elif isinstance(value, int):
                    if value != 0:  # Override non-zero ints
                        setattr(config, config_name, value)
                else:
                    setattr(config, config_name, value)

    # Handle --no-progress flag
    if hasattr(args, "no_progress") and args.no_progress:
        config.show_progress = False

    return config
