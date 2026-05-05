"""Thin wrapper for users running from a clone, equivalent to
    python -m magisentry.install_hooks
"""
import sys
from pathlib import Path

# Make the sibling package importable when running from a clone without
# `pip install -e .`.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from magisentry.install_hooks import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
