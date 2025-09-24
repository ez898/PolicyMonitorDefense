"""Pytest configuration to ensure project root is importable."""

import sys
from pathlib import Path

# Add project root to sys.path for module imports (agent, audit, policy, etc.)
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


