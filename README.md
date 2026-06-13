# PIIGuard

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/Hellotravisss/piiguard/actions/workflows/ci.yml/badge.svg)](https://github.com/Hellotravisss/piiguard/actions/workflows/ci.yml)

Secure, compliant data migration toolkit for offshore transfers. Automatically detects and desensitizes PII (Personally Identifiable Information), encrypts data with AES-256-GCM, and generates regulatory documentation for cross-border data protection regimes.

## What this is — and what it isn't

**Use it to** turn a directory of files containing PII into a **desensitized, encrypted** copy that is safe to move across borders (the design focus is **China ⇄ Singapore**, i.e. PIPL + PDPA), together with the paperwork those regimes expect.

Two things to understand before you rely on it:

- **Desensitization is irreversible.** Masked values (`alice@x.com` → `a***@x******.com`) cannot be recovered — even after you decrypt. `decrypt-all` gives you back the *masked* data, not the original. If you need to move **usable** raw data, this is not the right tool; use transport encryption without the masking step.
- **Compliance output is documentation, not legal sign-off.** The `profiles`, `assessment`, and `--compliance-report` features generate checklists and declaration templates to *help* you prepare a filing. They do not constitute legal advice or a guarantee of compliance — have counsel review actual cross-border filings.

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

Install from source:

```bash
git clone https://github.com/Hellotravisss/piiguard.git
cd piiguard
pip install -e .
```

### Basic Usage

```bash
# Migrate a directory (desensitize + encrypt)
piiguard migrate --source data/ --output output/ --password mypassword

# Preview what would happen (dry run)
piiguard migrate --source data/ --dry-run

# Encrypt a single file
piiguard encrypt input.csv output.csv.enc --password mypassword

# Decrypt a file
piiguard decrypt output.csv.enc decrypted.csv --password mypassword

# Restore an entire migration output tree (desensitized plaintext)
piiguard decrypt-all --input output/encrypted --output restored/ --password mypassword
```

### Using Environment Variables

```bash
export ODM_PASSWORD=mypassword
piiguard migrate --source data/ --output output/
```

## CLI Reference

### Commands

| Command    | Description                                  |
|------------|----------------------------------------------|
| `migrate`  | Run full migration pipeline                  |
| `encrypt`  | Encrypt a single file                        |
| `decrypt`  | Decrypt a single file                        |
| `decrypt-all` | Decrypt a whole migration output tree     |
| `init`     | Initialize project configuration             |
| `verify`   | Verify file integrity against a manifest     |
| `status`   | Show status of a previous migration          |
| `profiles` | List available compliance profiles           |

### migrate

```bash
piiguard migrate [OPTIONS]

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
piiguard migrate --source data/ --output out/ --workers 4

# GDPR compliance check
piiguard migrate --source data/ --compliance-profile gdpr

# Process only first 10 files
piiguard migrate --source data/ --batch-size 10

# Resume interrupted migration
piiguard migrate --source data/ --output out/ --resume

# With audit log and compression
piiguard migrate --source data/ --audit out/audit.jsonl --compress

# Skip test files
piiguard migrate --source data/ --skip-patterns "test_*" "*.tmp"
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
piiguard migrate --config migration.yaml
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
## Route A Focus (v1.1.0+): China & Singapore Compliance

**PIIGuard** is now optimized for **PIPL (China)** and **PDPA (Singapore)** — two of the strictest data protection regimes for cross-border transfers.

### Quick Start - PIPL (China)


Generates:
- Full PII desensitization + AES-256-GCM encryption
- Security assessment checklist
- Cross-border transfer legal path documentation

### Quick Start - PDPA (Singapore)


Includes DPO requirements and 30-day access request handling notes.


```bash
piiguard profiles
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
docker build -t piiguard .

# Run
docker run --rm -v $(pwd)/data:/data -v $(pwd)/output:/output \
  -e ODM_PASSWORD=mypassword \
  piiguard migrate --source /data --output /output
```

Or with docker-compose:

```bash
ODM_PASSWORD=mypassword docker-compose run migrator
```

## Architecture

```
piiguard/
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
git clone https://github.com/Hellotravisss/piiguard.git
cd piiguard
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

## Route A Quickstart (PIPL + PDPA) — v1.1.0

```bash
# 1. List enhanced compliance profiles
piiguard profiles

# 2. Run migration with compliance report (PIPL)
ODM_PASSWORD=yourpass piiguard migrate \
  --source examples \
  --output output/pipl \
  --compliance-profile pipl \
  --compliance-report

# 3. Same for PDPA (Singapore)
ODM_PASSWORD=yourpass piiguard migrate \
  --source examples \
  --output output/pdpa \
  --compliance-profile pdpa \
  --compliance-report

# Reports will be generated:
# - compliance_report_pipl.json + .md
# - compliance_report_pdpa.json + .md
```

## New in v1.1.0 (Route A)

### New Commands
```bash
# Scan a directory for PII without migrating
piiguard scan --source data/ --output scan_report.json

# Generate PIPL Security Assessment template
piiguard assessment --output security_assessment.json
```

### Enhanced migrate command
```bash
# Generate professional compliance report (JSON + Markdown)
piiguard migrate \
  --source examples \
  --compliance-profile pipl \
  --compliance-report
```

### Configuration
You can now store password in your `migration.yaml`:
```yaml
password: "your-password-here"
```


## Incremental Migration & Resume

PIIGuard supports **incremental/resume** migrations using a local SQLite state database.

### How it works

- When you run with `--resume`, the tool records each successfully processed file (path + SHA256 hash) in `.migration_state.db` inside the output directory.
- On subsequent runs with `--resume`, files with the **same path and hash** are automatically skipped.
- If a file is modified after being processed, its hash changes and it will be re-processed.

### Usage

```bash
# First run (processes everything)
piiguard migrate --source data/ --output out/ --resume

# Later runs (only processes new or changed files)
piiguard migrate --source data/ --output out/ --resume
```

### State Database Location

The state file is stored at:
```
<output_directory>/.migration_state.db
```

You can safely delete this file to force a full re-processing.

### Corruption Recovery

If the state database becomes corrupted (e.g. interrupted write), the migrator will automatically delete it and start fresh on the next run.

### Advanced: Custom State Location

For advanced use cases, you can manage the state manually via the Python API:

```python
from piiguard.state import MigrationState
from piiguard.migrate import run_migration
from pathlib import Path

state = MigrationState(Path("custom_state.db"))
report = run_migration(
    source_dir=Path("data"),
    output_dir=Path("out"),
    password="secret",
    resume=True,
    state=state
)
```
