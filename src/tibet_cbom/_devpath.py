"""Optional dev-source fallback — no hardcoded absolute paths ship in the package.

The published package relies on its installed dependencies (tibet-drop, tibet-pol).
For monorepo development without an editable install, set TIBET_CBOM_DEV_SRC to a
pathsep-separated list of local `src` directories; only existing dirs are added.

This exists so a fresh `pip install tibet-cbom` never carries a path like
`/srv/...` that means nothing on someone else's machine.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


def add_dev_src() -> None:
    """Add TIBET_CBOM_DEV_SRC entries to sys.path (opt-in, existing dirs only)."""
    for p in os.environ.get("TIBET_CBOM_DEV_SRC", "").split(os.pathsep):
        if p and p not in sys.path and Path(p).is_dir():
            sys.path.insert(0, p)
