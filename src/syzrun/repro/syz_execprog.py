from __future__ import annotations

import json
import os
import shlex
import signal
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..builder.syzkaller import SyzkallerArtifacts
from .qemu import QemuVM


@dataclass(frozen=True)
class SyzRunResult:
    exit_code: int | None
    remote_command: str


def parse_syz_options(text: str) -> dict[str, Any]:
    """Parse the syzkaller repro option comment when it is present."""

    for line in text.splitlines()[:20]:
        stripped = line.strip()
        if not stripped.startswith("#") or "{" not in stripped or "}" not in stripped:
            continue
        body = stripped[stripped.find("{") : stripped.rfind("}") + 1]
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return {_normalize_option_key(str(key)): value for key, value in parsed.items()}
    return {}


def _normalize_option_key(key: str) -> str:
    return key.replace("_", "").lower()


def build_execprog_flags(repro_file: Path) -> list[str]:
    options = parse_syz_options(repro_file.read_text(encoding="utf-8", errors="replace"))
    flags = [
        "-executor=/root/syz-executor",
        "-cover=0",
        f"-threaded={1 if options.get('threaded', True) else 0}",
        f"-collide={1 if options.get('collide', False) else 0}",
        f"-procs={int(options.get('procs', 1))}",
    ]

    repeat = options.get("repeat", True)
    repeat_times = int(options.get("repeattimes", 0 if repeat else 1))
    flags.append(f"-repeat={repeat_times}")

    sandbox = options.get("sandbox")
    if sandbox:
        flags.append(f"-sandbox={sandbox}")

    fault_call = int(options.get("faultcall", -1))
    if options.get("fault", fault_call >= 0) and fault_call >= 0:
        flags.append(f"-fault_call={fault_call}")
        if "faultnth" in options:
            flags.append(f"-fault_nth={int(options['faultnth'])}")

    return flags


def start_syz_repro(
    *,
    vm: QemuVM,
    syzkaller: SyzkallerArtifacts,
    repro_file: Path,
    timeout: int,
    env: dict[str, str] | None = None,
    extra_args: list[str] | None = None,
) -> tuple[subprocess.Popen[str], str]:
    vm.scp_to(syzkaller.execprog, "/root/syz-execprog")
    vm.scp_to(syzkaller.executor, "/root/syz-executor")
    vm.scp_to(repro_file, "/root/repro.syz")
    vm.ssh("chmod +x /root/syz-execprog /root/syz-executor", timeout=60, log_path=vm.logs_dir / "repro.log")

    flags = build_execprog_flags(repro_file)
    flags.extend(extra_args or [])
    command_parts = ["timeout", f"{timeout}s"]
    if env:
        command_parts.append("env")
        command_parts.extend(f"{key}={value}" for key, value in sorted(env.items()))
    command_parts.extend(["/root/syz-execprog", *flags, "/root/repro.syz"])
    remote_command = " ".join(shlex.quote(part) for part in command_parts)
    process = vm.start_ssh(remote_command, log_path=vm.logs_dir / "repro.log")
    return process, remote_command


def stop_syz_repro(process: subprocess.Popen[str]) -> int | None:
    if process.poll() is not None:
        return process.returncode
    try:
        os.killpg(process.pid, signal.SIGTERM)
        return process.wait(timeout=5)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            return process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            return process.poll()
