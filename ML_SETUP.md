# ML PII Detection Setup

This project supports optional ML-based PII detection using Microsoft Presidio.

## Quick Start

### 1. Create ML Environment

```bash
python -m venv .venv-ml
source .venv-ml/bin/activate
pip install presidio-analyzer presidio-anonymizer
python -m spacy download en_core_web_sm
deactivate
```

### 2. Run with ML Support

```bash
# Using the helper script (recommended)
./run-with-ml.sh migrate --source examples --compliance-profile pipl --compliance-report

# Or manually
source .venv-ml/bin/activate
piiguard migrate --source data/
deactivate
```

## How It Works

- When Presidio is available, ML detection is automatically enabled
- When Presidio is not available, the system falls back to regex + custom patterns
- The ML environment is isolated from the main project environment

## Benefits

- Higher accuracy for names, organizations, locations
- Better support for contextual PII detection
- No dependency conflicts with main project
