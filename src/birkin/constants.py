"""Exit codes and path defaults for Birkin."""

from __future__ import annotations

import os
from pathlib import Path

EXIT_PASS = 0
EXIT_STATIC = 1
EXIT_LIVE_CONTRACT = 2
EXIT_LIVE_TRANSIENT = 3
EXIT_DRIFT = 4
EXIT_TOOL_ERROR = 5

DEFAULT_HERMES_HOME = Path(os.environ.get("HERMES_HOME", str(Path.home() / ".hermes")))
