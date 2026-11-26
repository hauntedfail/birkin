"""Exit-code precedence, human report formatting, and atomic state persistence."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from birkin.constants import (
    EXIT_DRIFT,
    EXIT_LIVE_CONTRACT,
    EXIT_LIVE_TRANSIENT,
    EXIT_PASS,
    EXIT_STATIC,
    EXIT_TOOL_ERROR,
)

_PRECEDENCE = (
    EXIT_TOOL_ERROR,
    EXIT_STATIC,
    EXIT_LIVE_CONTRACT,
    EXIT_DRIFT,
    EXIT_LIVE_TRANSIENT,
    EXIT_PASS,
)


def combine_exit_codes(codes: list[int]) -> int:
    """Severity precedence: tool error > static/policy > live contract > drift > transient > pass."""
    for code in _PRECEDENCE:
        if code in codes:
            return code
    return EXIT_PASS


def format_human(report: dict[str, Any]) -> str:
    lines = [
        f"birkin ({report['command']}): status={report['status']} exit_code={report['exit_code']}",
        f"  config_sha256: {report.get('config_sha256', 'n/a')}",
    ]
    for name, sec in report.get("sections", {}).items():
        lines.append(f"  [{name}] exit_code={sec['exit_code']} findings={len(sec['findings'])}")
        for f in sec["findings"]:
            lines.append(f"    - {f['rule']} ({f['severity']}): {f['message']}")
            lines.append(f"      remediation: {f['remediation']}")
    return "\n".join(lines)


def write_state_atomic(state_file: Path, report: dict[str, Any]) -> None:
    """Write report JSON atomically via temp file + os.replace in the target directory."""
    state_file.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(report, indent=2) + "\n"
    fd, tmp_name = tempfile.mkstemp(prefix=".birkin.", suffix=".tmp", dir=str(state_file.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, state_file)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
