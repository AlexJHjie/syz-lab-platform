from __future__ import annotations

import os
import shlex
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


@dataclass(frozen=True)
class CommandResult:
    args: Sequence[str]
    returncode: int
    output: str
    duration_seconds: float
    timed_out: bool = False
    log_path: Path | None = None


class CommandError(RuntimeError):
    def __init__(self, message: str, result: CommandResult | None = None):
        super().__init__(message)
        self.result = result


def format_cmd(args: Sequence[str]) -> str:
    return shlex.join(str(arg) for arg in args)


def run(
    args: Sequence[str],
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout: int | None = None,
    log_path: Path | None = None,
    check: bool = True,
) -> CommandResult:
    """Run a command with an optional log file and hard process timeout."""

    started = time.monotonic()
    merged_env = os.environ.copy()
    if env:
        merged_env.update({str(k): str(v) for k, v in env.items()})

    header = f"\n$ {format_cmd(args)}\n"
    if log_path:
        log_path.parent.mkdir(parents=True, exist_ok=True)

    with (log_path.open("a", encoding="utf-8", errors="replace") if log_path else open(os.devnull, "w")) as log:
        if log_path:
            log.write(header)
            log.flush()

        try:
            if log_path:
                process = subprocess.Popen(
                    [str(arg) for arg in args],
                    cwd=str(cwd) if cwd else None,
                    env=merged_env,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    text=True,
                    errors="replace",
                    start_new_session=True,
                )
                returncode = process.wait(timeout=timeout)
                output = ""
            else:
                process = subprocess.Popen(
                    [str(arg) for arg in args],
                    cwd=str(cwd) if cwd else None,
                    env=merged_env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    errors="replace",
                    start_new_session=True,
                )
                output, _ = process.communicate(timeout=timeout)
                returncode = process.returncode
        except subprocess.TimeoutExpired as exc:
            _terminate_process_group(process)
            message = f"command timed out after {timeout}s: {format_cmd(args)}"
            output = exc.output if isinstance(exc.output, str) else ""
            result = CommandResult(
                args=args,
                returncode=-1,
                output=output,
                duration_seconds=time.monotonic() - started,
                timed_out=True,
                log_path=log_path,
            )
            if log_path:
                log.write(f"\n{message}\n")
            raise CommandError(message, result) from exc

    result = CommandResult(
        args=args,
        returncode=returncode,
        output=output,
        duration_seconds=time.monotonic() - started,
        log_path=log_path,
    )
    if check and returncode != 0:
        raise CommandError(f"command failed ({returncode}): {format_cmd(args)}", result)
    return result


def _terminate_process_group(process: subprocess.Popen[str]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except Exception:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except Exception:
            process.kill()
