from __future__ import annotations

import os
import re
import subprocess
from functools import cache
from pathlib import Path

from ..builder.kernel import KernelArtifacts
from ..builder.syzkaller import SyzkallerArtifacts
from ..builder.toolchain import target_from_arch
from .verdict import CrashFingerprint, classify_path


DEFAULT_SYMBOLIZER_TIMEOUT = 300
SYMBOLIZER_TIMEOUT_ENV = "PLATFORM_SYMBOLIZER_TIMEOUT"


@cache
def _symbolizer_supports_arch(symbolizer: Path) -> bool:
    result = subprocess.run(
        [str(symbolizer), "-h"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        timeout=30,
        check=False,
    )
    return re.search(r"(?m)^\s+-arch(?:\s|$)", result.stdout + result.stderr) is not None


def symbolize_crash(
    *,
    kernel: KernelArtifacts,
    syzkaller: SyzkallerArtifacts,
    architecture: str,
    source_log: Path,
    target: CrashFingerprint,
    report_text: str | None,
    output_path: Path,
    timeout: int | None = None,
) -> Path | None:
    """Extract the target crash and symbolize it with syz-symbolize."""

    timeout = _symbolizer_timeout() if timeout is None else timeout
    if not source_log.is_file():
        raise FileNotFoundError(f"crash source log does not exist: {source_log}")
    if not kernel.vmlinux.is_file():
        raise FileNotFoundError(f"vmlinux does not exist: {kernel.vmlinux}")
    if syzkaller.symbolizer is None or not syzkaller.symbolizer.is_file():
        raise FileNotFoundError("syz-symbolize is unavailable for this syzkaller checkout")
    target_arch = target_from_arch(architecture).syzkaller_arch
    kernel_tree = kernel.tree.resolve()
    symbolizer = syzkaller.symbolizer.resolve()
    syzkaller_tree = syzkaller.tree.resolve()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.unlink(missing_ok=True)
    raw_path = output_path.with_suffix(".raw.tmp")
    symbolized_path = output_path.with_suffix(".symbolized.tmp")
    try:
        if report_text is None:
            if not extract_crash_segment(source_log, raw_path, target):
                return None
        else:
            raw_path.write_text(report_text, encoding="utf-8", errors="replace")

        env = os.environ.copy()
        if kernel.toolchain:
            env.update(kernel.toolchain.environment())
        command = [str(symbolizer), "-os", "linux"]
        if _symbolizer_supports_arch(symbolizer):
            command.extend(["-arch", target_arch])
        command.extend(
            [
                "-kernel_obj", str(kernel_tree),
                "-kernel_src", str(kernel_tree),
                str(raw_path.resolve()),
            ]
        )
        result = subprocess.run(
            command,
            cwd=syzkaller_tree,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise RuntimeError(f"syz-symbolize failed ({result.returncode}): {detail}")

        symbolized_path.write_text(result.stdout, encoding="utf-8", errors="replace")
        if not extract_crash_segment(symbolized_path, output_path, target):
            raise RuntimeError("syz-symbolize output does not contain the target crash")
        return output_path
    finally:
        raw_path.unlink(missing_ok=True)
        symbolized_path.unlink(missing_ok=True)


def _symbolizer_timeout() -> int:
    value = os.environ.get(SYMBOLIZER_TIMEOUT_ENV)
    if value is None or not value.strip():
        return DEFAULT_SYMBOLIZER_TIMEOUT
    try:
        timeout = int(value)
    except ValueError as exc:
        raise ValueError(f"{SYMBOLIZER_TIMEOUT_ENV} must be a positive integer number of seconds") from exc
    if timeout <= 0:
        raise ValueError(f"{SYMBOLIZER_TIMEOUT_ENV} must be a positive integer number of seconds")
    return timeout


def extract_crash_segment(source_log: Path, output_path: Path, target: CrashFingerprint) -> bool:
    """Write the matched crash report from source_log to output_path."""

    verdict = classify_path(target, source_log)
    if verdict.report is None or verdict.status != "reproduced":
        output_path.unlink(missing_ok=True)
        return False
    output_path.write_text(verdict.report, encoding="utf-8", errors="replace")
    return True
