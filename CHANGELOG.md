# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-05-28

### Added
- **8 file formats**: CSV, JSON, Excel, Parquet, XML, TSV, SQLite, plain text
- **11 PII types**: email, phone, SSN, credit card, IP, Chinese ID, passport, bank account, IBAN, MAC address, date of birth
- **5 compliance profiles**: GDPR (EU), PDPA (Singapore), CCPA (California), LGPD (Brazil), PIPL (China)
- **Integrity verification**: SHA-256 manifest generation and verification
- **Audit trail**: JSON Lines audit logging for all migration events
- **YAML configuration**: Config files with CLI override support
- **Compression**: gzip compression for encrypted output
- **Resume**: Skip already-processed files with `--resume`
- **Skip patterns**: Glob patterns to exclude files
- **New CLI commands**: `verify`, `status`, `profiles`, `init`
- **Environment variable**: `ODM_PASSWORD` for non-interactive usage
- **Docker support**: Multi-stage Dockerfile and docker-compose.yml
- **GitHub Actions CI**: Automated testing on Python 3.10/3.11/3.12
- **104 comprehensive tests** covering all features

## [0.10.0] - 2026-05-28

### Added
- **New file formats**: Excel (.xlsx), Parquet (.parquet), XML, TSV, SQLite
- **Batch processing**: `--workers N` for parallel processing via ThreadPoolExecutor
- **Progress bar**: tqdm-based progress display (disable with `--no-progress`)
- **Batch size**: `--batch-size N` to limit files processed per run
- **Compliance profiles**: GDPR, PDPA, CCPA, LGPD, PIPL with validation
- **Integrity verification**: SHA-256 manifest generation and verification
- **Audit trail**: JSON Lines audit logging for all migration events
- **Configuration files**: YAML-based config with CLI override support
- **Compression**: gzip compression for encrypted output (`--compress`)
- **Resume support**: `--resume` to skip already-processed files
- **New PII types**: Chinese ID, passport, bank account, IBAN, MAC address, date of birth
- **New CLI commands**: `verify`, `status`, `profiles`
- **Environment variable**: `ODM_PASSWORD` for non-interactive usage

### Changed
- Package structure reorganized into modular files
- `pyproject.toml` now includes all dependencies
- CLI help text improved with examples

## [0.9.0] - 2026-05-28

### Added
- Initial MVP release
- AES-256-GCM encryption with PBKDF2 key derivation
- PII detection and desensitization for CSV, JSON, and plain text
- PII types: email, phone, SSN, credit card, IP address
- Field-name heuristic masking
- CLI with `init`, `encrypt`, `decrypt`, `migrate` commands
- Dry-run mode for migration preview
- 39 comprehensive tests
