#!/bin/bash
# run-with-ml.sh
# Run PIIGuard with ML PII detection enabled

set -e

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ML_VENV="$SCRIPT_DIR/.venv-ml"

# Check if ML environment exists
if [ ! -d "$ML_VENV" ]; then
    echo "Error: ML virtual environment not found at $ML_VENV"
    echo "Please create it first:"
    echo "  python -m venv .venv-ml"
    echo "  source .venv-ml/bin/activate"
    echo "  pip install presidio-analyzer presidio-anonymizer"
    echo "  python -m spacy download en_core_web_sm"
    exit 1
fi

# Activate ML environment
echo "Activating ML environment..."
source "$ML_VENV/bin/activate"

# Run the migrator with all passed arguments
echo "Running: piiguard $*"
piiguard "$@"

# Deactivate (optional, since script ends)
deactivate 2>/dev/null || true
