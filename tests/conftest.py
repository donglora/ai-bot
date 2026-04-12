"""Shared pytest fixtures and path setup."""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the project root is on sys.path so `import orac...` works from anywhere.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
