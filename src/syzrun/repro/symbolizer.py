from __future__ import annotations

import os
import re
import subprocess
from functools import cache
from pathlib import Path

from ..builder.kernel import KernelArtifacts
from ..builder.syzkaller import SyzkallerArtifacts
from ..builder.toolchain import target_from_arch
from .verdict import CRASH_PATTERNS, Verdict


KERNEL_PANIC_END = re.compile(r"---\[\s*end Kernel panic\b.*\]---", re.IGNORECASE)
CUT_HERE = re.compile(r"-+\[\s*cut here\s*\]-+", re.IGNORECASE)
SANITIZER_REPORT_END = re.compile(r"^(?:\[[^\]\r\n]*\]\s*)+=+\s*$")
REPORT_TYPES = ("WARNING", "KASAN", "KMSAN", "BUG", "OOPS", "PANIC", "GPF")
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
    verdict: Verdict,
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
        if not extract_crash_segment(source_log, raw_path, verdict):
            return None

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
        if not extract_crash_segment(symbolized_path, output_path, verdict):
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


def extract_crash_segment(source_log: Path, output_path: Path, verdict: Verdict) -> bool:
    """Write the matched crash report from source_log to output_path."""

    sanitizer_report = _is_sanitizer_verdict(verdict)
    memory_leak_report = bool(re.search(r"\bmemory leak\b", verdict.matched or "", flags=re.IGNORECASE))
    lines = source_log.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    start_index = _find_crash_start(lines, verdict)
    if start_index is None:
        output_path.unlink(missing_ok=True)
        return False

    with output_path.open("w", encoding="utf-8", errors="replace") as output:
        for index, line in enumerate(lines[start_index:]):
            if index > 0 and CUT_HERE.search(line):
                break

            output.write(line)
            if KERNEL_PANIC_END.search(line) or (sanitizer_report and SANITIZER_REPORT_END.match(line)):
                break
            if memory_leak_report and index > 0 and not line.strip():
                break

    return True


def _find_crash_start(lines: list[str], verdict: Verdict) -> int | None:
    matched = verdict.matched or ""
    if re.search(r"\bmemory leak\b", matched, flags=re.IGNORECASE):
        function_match = re.search(r"\bin\s+([A-Za-z_][A-Za-z0-9_.]*)", matched, flags=re.IGNORECASE)
        function = function_match.group(1) if function_match else None
        for index, line in enumerate(lines):
            if not re.search(r"BUG:\s+memory leak\b", line, flags=re.IGNORECASE):
                continue
            block_lines: list[str] = []
            for block_line in lines[index : index + 120]:
                if block_lines and not block_line.strip():
                    break
                block_lines.append(block_line)
            block = "".join(block_lines)
            if function is None or re.search(
                rf"\b{re.escape(function)}(?:\+0x[0-9a-f]+)?\b",
                block,
                re.IGNORECASE,
            ):
                return index
        return None

    return next((index for index, line in enumerate(lines) if _is_crash_start(line, verdict)), None)


def _is_sanitizer_verdict(verdict: Verdict) -> bool:
    matched = verdict.matched or ""
    return bool(re.search(r"\b(?:KASAN|KMSAN)\b", matched, flags=re.IGNORECASE))


def _is_crash_start(line: str, verdict: Verdict) -> bool:
    matched = (verdict.matched or "").strip()
    function_match = re.search(r"\bin\s+([A-Za-z_][A-Za-z0-9_.]*)", matched, flags=re.IGNORECASE)
    report_type = next((item for item in REPORT_TYPES if re.search(rf"\b{item}\b", matched, re.IGNORECASE)), None)

    if function_match:
        function = function_match.group(1)
        return function.lower() in line.lower() and (report_type is None or report_type.lower() in line.lower())
    if matched:
        return matched.lower() in line.lower()
    return any(re.search(pattern, line, flags=re.IGNORECASE) for pattern in CRASH_PATTERNS)
