"""Absolute-path hook entry point, usable from a source checkout or installation."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from hdr.cli import main

raise SystemExit(main())
