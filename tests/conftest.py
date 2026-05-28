import sys
from pathlib import Path

# Make src/ importable for tests
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
