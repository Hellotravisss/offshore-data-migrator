# Offshore Data Migrator

[![PyPI version](https://img.shields.io/pypi/v/offshore-data-migrator.svg)](https://pypi.org/project/offshore-data-migrator/)
[![Python](https://img.shields.io/pypi/pyversions/offshore-data-migrator.svg)](https://pypi.org/project/offshore-data-migrator/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/offshore-data-migrator/offshore-data-migrator/actions/workflows/ci.yml/badge.svg)](https://github.com/offshore-data-migrator/offshore-data-migrator/actions/workflows/ci.yml)

Secure, compliant data migration toolkit for offshore transfers. Automatically detects and desensitizes PII (Personally Identifiable Information), encrypts data with AES-256-GCM, and validates compliance against international data protection regulations.

## Features

- **8 file formats**: CSV, JSON, Excel, Parquet, XML, TSV, SQLite, plain text
- **11 PII types**: email, phone, SSN, credit card, IP, Chinese ID, passport, bank account, IBAN, MAC address, date of birth
- **5 compliance profiles**: GDPR (EU), PDPA (Singapore), CCPA (California), LGPD (Brazil), PIPL (China)
- **AES-256-GCM encryption** with PBKDF2 key derivation (480k iterations)
- **Parallel processing** with configurable worker threads
- **Progress bar** for real-time feedback
- **Integrity verification** via SHA-256 manifests
- **Audit trail** logging (JSON Lines)
- **YAML configuration** files with CLI overrides
- **Compression** support (gzip)
- **Resume** interrupted migrations
- **Docker** support

## Quick Start

### Installation

```bash
pip install offshore-data-migrator
```

Or from source:

```bash
git clone https://github.com/offshore-data-migrator/offshore-data-migrator.git
cd offshore-data-migrator
pip install -e .
```

### Basic Usage

```bash
# Migrate a directory (desensitize + encrypt)
offshore-migrator migrate --source data/ --output output/ --password mypassword

# Preview what would happen (dry run)
offshore-migrator migrate --source data/ --dry-run

# Encrypt a single file
offshore-migrator encrypt input.csv output.csv.enc --password mypassword

# Decrypt a file
offshore-migrator decrypt output.csv.enc decrypted.csv --password mypassword
```

### Using Environment Variables

```bash
export ODM_PASSWORD=mypassword
offshore-migrator migrate --source data/ --output output/
```

## CLI Reference

### Commands

| Command    | Description                                  |
|------------|----------------------------------------------|
| `migrate`  | Run full migration pipeline                  |
| `encrypt`  | Encrypt a single file                        |
| `decrypt`  | Decrypt a single file                        |
| `init`     | Initialize project configuration             |
| `verify`   | Verify file integrity against a manifest     |
| `status`   | Show status of a previous migration          |
| `profiles` | List available compliance profiles           |

### migrate

```bash
offshore-migrator migrate [OPTIONS]

Options:
  --source DIR            Source directory (default: examples)
  --output DIR            Output directory (default: output)
  --target NAME           Target jurisdiction (default: singapore)
  --password PW           Encryption password (or use ODM_PASSWORD env var)
  --config FILE           Path to YAML config file
  --dry-run               Preview without modifying files
  --workers N             Number of parallel workers (default: 1)
  --batch-size N          Max files to process (0 = all)
  --no-progress           Disable progress bar
  --compliance-profile P  Validate against profile (gdpr/pdpa/ccpa/lgpd/pipl)
  --compress              Compress encrypted output with gzip
  --resume                Skip already-processed files
  --no-manifest           Skip SHA-256 manifest generation
  --audit FILE            Path for audit log (JSON Lines)
  --skip-patterns PAT...  Glob patterns for files to skip
  --verbose               Enable debug logging
  --log-file FILE         Write logs to file
```

### Examples

```bash
# Parallel processing with 4 workers
offshore-migrator migrate --source data/ --output out/ --workers 4

# GDPR compliance check
offshore-migrator migrate --source data/ --compliance-profile gdpr

# Process only first 10 files
offshore-migrator migrate --source data/ --batch-size 10

# Resume interrupted migration
offshore-migrator migrate --source data/ --output out/ --resume

# With audit log and compression
offshore-migrator migrate --source data/ --audit out/audit.jsonl --compress

# Skip test files
offshore-migrator migrate --source data/ --skip-patterns "test_*" "*.tmp"
```

## Configuration File

Create a `migration.yaml` for reusable settings:

```yaml
source: /path/to/data
output: /path/to/output
target: singapore
compliance_profile: pdpa
workers: 4
batch_size: 0
show_progress: true
encrypt_method: aes-256-gcm
audit_log: true
generate_manifest: true
compress_output: false
skip_patterns:
  - "*.tmp"
  - "test_*"
custom_pii_patterns: []
field_mappings: {}
```

Use it:

```bash
offshore-migrator migrate --config migration.yaml
```

CLI arguments override config file values.

## Supported File Formats

| Format   | Extension              | Description                          |
|----------|------------------------|--------------------------------------|
| CSV      | `.csv`                 | Comma-separated values               |
| JSON     | `.json`                | JSON files (nested structures)       |
| Excel    | `.xlsx`, `.xls`        | Excel workbooks (all sheets)         |
| Parquet  | `.parquet`             | Apache Parquet columnar format       |
| XML      | `.xml`                 | XML documents                        |
| TSV      | `.tsv`                 | Tab-separated values                 |
| SQLite   | `.db`, `.sqlite`       | SQLite databases (all tables)        |
| Text     | `.txt`, `.log`, `.md`  | Plain text files                     |

## Supported PII Types

| PII Type        | Example                    | Masked Output              |
|-----------------|----------------------------|----------------------------|
| Email           | `user@example.com`         | `u***@e******.com`         |
| Phone           | `555-123-4567`             | `555-***-****`             |
| SSN             | `123-45-6789`              | `***-**-6789`              |
| Credit Card     | `4111111111111111`         | `4111****1111`             |
| IP Address      | `192.168.1.100`            | `192.168.*.*`              |
| Chinese ID      | `110101199001011234`       | `1101***********234`       |
| Passport        | `AB1234567`                | `AB***4567`                |
| Bank Account    | `1234567890123456`         | `1234********3456`         |
| IBAN            | `GB29NWBK60161331926819`  | `GB29****6819`             |
| MAC Address     | `00:1B:44:11:3A:B7`        | `00:1B:**:**:**:B7`        |
| Date of Birth   | `1990-01-15`               | `****-**-15`               |

Field names containing keywords like `name`, `email`, `phone`, `ssn`, `address`, `passport`, `bank_account` are automatically masked even if content doesn't match a regex pattern.

## Compliance Profiles

```bash
offshore-migrator profiles
```

| Profile | Jurisdiction | Key Requirements |
|---------|-------------|------------------|
| GDPR    | EU          | Explicit consent, 72h breach notification, right to erasure |
| PDPA    | Singapore   | DPO required, 30-day access requests |
| CCPA    | California  | Right to know/delete/opt-out |
| LGPD    | Brazil      | Legal basis required, ANPD reporting |
| PIPL    | China       | Data localization, cross-border assessment required |

## Docker

```bash
# Build
docker build -t offshore-data-migrator .

# Run
docker run --rm -v $(pwd)/data:/data -v $(pwd)/output:/output \
  -e ODM_PASSWORD=mypassword \
  offshore-data-migrator migrate --source /data --output /output
```

Or with docker-compose:

```bash
ODM_PASSWORD=mypassword docker-compose run migrator
```

## Architecture

```
offshore_migrator/
├── __init__.py        # Version
├── cli.py             # CLI entry point (argparse)
├── crypto.py          # AES-256-GCM encryption
├── pii.py             # PII detection & desensitization (8 formats)
├── migrate.py         # Migration pipeline orchestration
├── compliance.py      # Jurisdiction compliance profiles
├── integrity.py       # SHA-256 manifest verification
├── config.py          # YAML configuration support
└── audit.py           # Audit trail logging
```

**Pipeline flow:**
```
Source files → Classify → Desensitize PII → Encrypt (AES-256-GCM) → Manifest → Output
```

## Development

```bash
# Clone and install
git clone https://github.com/offshore-data-migrator/offshore-data-migrator.git
cd offshore-data-migrator
pip install -e .
pip install pytest ruff

# Run tests
make test

# Lint
make lint

# Build
make build
```

## License

MIT License. See [LICENSE](LICENSE) for details.
