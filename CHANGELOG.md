# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-06-01

### Added
- **Incremental migration / resume**: SQLite state DB tracks processed files by path + SHA-256 hash (`state.py`)
- **ML-assisted PII detection**: optional `pii_ml.py` for content-based PII recognition
- **`assessment` command**: generate a PIPL Security Assessment template (JSON + Markdown)
- **`scan` command**: detect PII in a directory without migrating
- **`decrypt-all` command**: restore an entire migration output tree in one step (derives the key once per distinct salt)
- **Custom PII pattern registration** framework
- Custom exception hierarchy with graceful CLI exit codes (`exceptions.py`)
- Resume integration tests including state-corruption recovery

### Fixed
- `--resume` now detects content changes: an edited file (different hash) is re-processed instead of being skipped on output existence alone
- Credit-card detection now validates the **Luhn checksum**, so random card-shaped numbers are no longer misclassified
- Phone-number detection requires a separator or `+CC` prefix, eliminating false positives on bare integers (order IDs, counts)

### Changed
- **Encryption key is derived once per migration run** instead of once per file — PBKDF2 (480k iterations) no longer runs N times, dramatically speeding up many-file migrations. Output stays password-decryptable (the run salt is stored in every file header)
- Version is now sourced solely from `offshore_migrator.__version__` (pyproject reads it dynamically)

## [1.1.0] - 2026-06-01

### Added
- Route A: Deep PIPL (China) + PDPA (Singapore) support
- `generate_compliance_report()` with security assessment + DPO notes
- `--compliance-report` flag for migrate command (generates JSON + MD)
- Enhanced `profiles` command with Route A details (DPO, Security Assessment, SLA, etc.)
- `config/china.yaml` and `config/singapore.yaml`
- Dynamic timestamp in compliance reports

### Changed
- `profiles` output now shows sensitive fields, cross-border paths, etc.
- Timestamp in reports is now UTC ISO format instead of hardcoded

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
