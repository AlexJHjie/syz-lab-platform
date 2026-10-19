"""Load project-local environment defaults without overriding exported values."""
from __future__ import annotations

import os
from pathlib import Path
import re
import shlex

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def load_project_env(path: Path | None = None) -> None:
    path = path if path is not None else PROJECT_ROOT / ".env"
    if not path.is_file():
        return
    defaults: dict[str, str] = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        name, separator, value = line.partition("=")
        name = name.strip()
        if not separator or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise ValueError(f"invalid environment assignment at {path}:{number}")
        try:
            parts = shlex.split(value, comments=True)
        except ValueError as exc:
            raise ValueError(f"invalid environment value at {path}:{number}") from exc
        if len(parts) > 1:
            raise ValueError(f"quote values containing spaces at {path}:{number}")
        defaults[name] = parts[0] if parts else ""
    for name, value in defaults.items():
        os.environ.setdefault(name, value)
