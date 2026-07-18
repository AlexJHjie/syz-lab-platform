from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from ..builder.kernel import KernelArtifacts
from ..builder.syzkaller import SyzkallerArtifacts
from ..cache import WorkspaceLayout
from ..fetcher import FetchedArtifacts
from ..metadata import Vulnerability
from ..runtime_profile import RuntimeProfile
from .qemu import QemuVM
from .rootfs import RootfsLocator
from .symbolizer import symbolize_crash
from .syz_execprog import SyzRunResult, start_syz_repro, stop_syz_repro
from .verdict import Verdict, classify, classify_text, has_crash

ATTEMPT_COUNT = 3
REPRO_TIMEOUT = 2 * 60
MONITOR_INTERVAL = 0.5
CRASH_DRAIN_IDLE_TIMEOUT = 2.0
CRASH_DRAIN_MAX_WAIT = 10.0
CRASH_DRAIN_POST_MARKER_WAIT = 1.0
CRASH_DRAIN_END_MARKERS = (
    "---[ end Kernel panic",
    "---[ end trace",
    "Rebooting in",
)
CRASH_SCAN_WINDOW_LINES = 120


class _IncrementalLogScanner:
    def __init__(self, path: Path, *, start_offset: int, window_lines: int = CRASH_SCAN_WINDOW_LINES) -> None:
        if window_lines <= 0:
            raise ValueError("window_lines must be positive")
        self.path = path
        self.offset = start_offset
        self.window_lines = window_lines
        self._lines: deque[str] = deque(maxlen=window_lines)
        self._partial_line = ""

    def read_window(self) -> str | None:
        if not self.path.exists():
            return None
        if self.path.stat().st_size < self.offset:
            self.offset = 0
            self._lines.clear()
            self._partial_line = ""

        with self.path.open("rb") as stream:
            stream.seek(self.offset)
            chunk = stream.read()
            self.offset = stream.tell()
        if not chunk:
            return None

        text = self._partial_line + chunk.decode("utf-8", errors="replace")
        lines = text.splitlines(keepends=True)
        self._partial_line = ""
        if lines and not lines[-1].endswith(("\n", "\r")):
            self._partial_line = lines.pop()
        self._lines.extend(lines)

        history = list(self._lines)
        if self._partial_line:
            history = history[-(self.window_lines - 1) :] if self.window_lines > 1 else []
            history.append(self._partial_line)
        return "".join(history)


@dataclass(frozen=True)
class AttemptResult:
    number: int
    status: str
    matched: str | None
    reason: str
    duration_seconds: float
    logs_dir: Path
    syz: SyzRunResult | None
    error: str | None = None
    source_log: str | None = None


@dataclass(frozen=True)
class ReproResult:
    syz: SyzRunResult | None
    verdict: Verdict
    attempts: list[AttemptResult]


class ReproductionRunner:
    def __init__(
        self,
        *,
        layout: WorkspaceLayout,
        vuln: Vulnerability,
        kernel: KernelArtifacts,
        syzkaller: SyzkallerArtifacts,
        fetched: FetchedArtifacts,
        timeout: int | None,
        runtime_profile: RuntimeProfile | None = None,
    ) -> None:
        self.layout = layout
        self.vuln = vuln
        self.kernel = kernel
        self.syzkaller = syzkaller
        self.fetched = fetched
        self.runtime_profile = runtime_profile or RuntimeProfile.empty()
        self.timeout = timeout

    def run(self) -> ReproResult:
        rootfs = RootfsLocator(self.layout, self.runtime_profile).locate()
        attempts: list[AttemptResult] = []

        for number in range(1, ATTEMPT_COUNT + 1):
            logs_dir = self.layout.logs_dir / f"attempt-{number:02d}"
            started = time.monotonic()
            logging.info("starting reproduction attempt %d/%d", number, ATTEMPT_COUNT)
            try:
                result = self._run_attempt(number, logs_dir, rootfs)
            except Exception as exc:
                result = AttemptResult(
                    number=number,
                    status="failed",
                    matched=None,
                    reason="attempt infrastructure failure",
                    duration_seconds=time.monotonic() - started,
                    logs_dir=logs_dir,
                    syz=None,
                    error=str(exc),
                    source_log=None,
                )
            if result.status == "reproduced":
                try:
                    source_log = result.source_log or "qemu.log"
                    crash_log = symbolize_crash(
                        kernel=self.kernel,
                        syzkaller=self.syzkaller,
                        architecture=self.vuln.crash.architecture,
                        source_log=logs_dir / source_log,
                        verdict=Verdict(result.status, result.matched, result.reason, source_log),
                        output_path=logs_dir / "crash.log",
                    )
                    if crash_log:
                        logging.info("symbolized crash log: %s", crash_log)
                    else:
                        logging.warning("could not locate reproduced crash in %s", logs_dir / source_log)
                except Exception as exc:
                    logging.warning("failed to symbolize reproduced crash: %s", exc)
            attempts.append(result)
            logging.info("attempt %d finished: %s (%s)", number, result.status, result.reason)
            if result.status == "reproduced":
                break

        verdict = _summarize_attempts(attempts)
        syz = next((item.syz for item in reversed(attempts) if item.syz is not None), None)
        return ReproResult(syz=syz, verdict=verdict, attempts=attempts)

    def _run_attempt(self, number: int, logs_dir: Path, rootfs) -> AttemptResult:
        vm = QemuVM(
            kernel=self.kernel,
            rootfs=rootfs,
            logs_dir=logs_dir,
            runtime_profile=self.runtime_profile,
            timeout=self.timeout,
        )
        started = time.monotonic()
        process = None
        remote_command = None
        try:
            vm.start()
            vm.wait_for_ssh()
            qemu_offset = vm.qemu_log.stat().st_size if vm.qemu_log.exists() else 0
            repro_log = logs_dir / "repro.log"
            repro_offset = repro_log.stat().st_size if repro_log.exists() else 0
            qemu_scanner = _IncrementalLogScanner(vm.qemu_log, start_offset=qemu_offset)
            repro_scanner = _IncrementalLogScanner(repro_log, start_offset=repro_offset)
            process, remote_command = start_syz_repro(
                vm=vm,
                syzkaller=self.syzkaller,
                repro_file=self.fetched.syz_reproducer,
                timeout=REPRO_TIMEOUT,
                env=self.runtime_profile.repro_env,
            )
            deadline = time.monotonic() + REPRO_TIMEOUT

            while time.monotonic() < deadline:
                serial_window = qemu_scanner.read_window()
                if serial_window is not None and has_crash(serial_window):
                    verdict = classify_text(self.vuln, serial_window, source_log="qemu.log")
                    exit_code = stop_syz_repro(process)
                    _drain_qemu_log_after_crash(vm.qemu_log, start_offset=qemu_offset)
                    return _attempt_result(number, verdict, started, logs_dir, exit_code, remote_command)

                repro_window = repro_scanner.read_window()
                if repro_window is not None and has_crash(repro_window):
                    verdict = classify_text(self.vuln, repro_window, source_log="repro.log")
                    # A report can be observed while its stack is still being written.
                    # Stop early only after the complete target signature is available.
                    if verdict.status == "reproduced":
                        exit_code = stop_syz_repro(process)
                        return _attempt_result(number, verdict, started, logs_dir, exit_code, remote_command)

                returncode = process.poll()
                if returncode is not None:
                    verdict = classify(self.vuln, logs_dir)
                    return _attempt_result(number, verdict, started, logs_dir, returncode, remote_command)

                if vm.process and vm.process.poll() is not None:
                    verdict = classify(self.vuln, logs_dir)
                    return _attempt_result(number, verdict, started, logs_dir, process.poll(), remote_command)
                time.sleep(MONITOR_INTERVAL)

            exit_code = stop_syz_repro(process)
            verdict = classify(self.vuln, logs_dir)
            return _attempt_result(number, verdict, started, logs_dir, exit_code, remote_command)
        finally:
            if process is not None and process.poll() is None:
                stop_syz_repro(process)
            vm.stop()


def _read_from(path: Path, offset: int) -> str:
    if not path.exists():
        return ""
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        stream.seek(offset)
        return stream.read()


def _drain_qemu_log_after_crash(
    path: Path,
    *,
    start_offset: int,
    idle_timeout: float = CRASH_DRAIN_IDLE_TIMEOUT,
    max_wait: float = CRASH_DRAIN_MAX_WAIT,
    post_marker_wait: float = CRASH_DRAIN_POST_MARKER_WAIT,
    interval: float = MONITOR_INTERVAL,
    end_markers: tuple[str, ...] = CRASH_DRAIN_END_MARKERS,
) -> None:
    """Let the guest console finish flushing the matched crash before QEMU is stopped."""

    deadline = time.monotonic() + max_wait
    idle_since = time.monotonic()
    marker_seen_at: float | None = None
    last_size = -1

    while True:
        now = time.monotonic()
        if path.exists():
            current_size = path.stat().st_size
            if current_size != last_size:
                last_size = current_size
                idle_since = now

            if current_size > start_offset:
                text = _read_from(path, start_offset)
                if marker_seen_at is None and any(marker in text for marker in end_markers):
                    marker_seen_at = now

        if marker_seen_at is not None and now - marker_seen_at >= post_marker_wait:
            return
        if marker_seen_at is None and now - idle_since >= idle_timeout:
            return
        if now >= deadline:
            return

        sleep_for = min(interval, max(0.0, deadline - now))
        if marker_seen_at is not None:
            sleep_for = min(sleep_for, max(0.0, post_marker_wait - (now - marker_seen_at)))
        elif idle_timeout > 0:
            sleep_for = min(sleep_for, max(0.0, idle_timeout - (now - idle_since)))
        time.sleep(sleep_for)


def _attempt_result(
    number: int,
    verdict: Verdict,
    started: float,
    logs_dir: Path,
    exit_code: int | None,
    remote_command: str,
) -> AttemptResult:
    return AttemptResult(
        number=number,
        status=verdict.status,
        matched=verdict.matched,
        reason=verdict.reason,
        duration_seconds=time.monotonic() - started,
        logs_dir=logs_dir,
        syz=SyzRunResult(exit_code=exit_code, remote_command=remote_command),
        source_log=verdict.source_log,
    )


def _summarize_attempts(attempts: list[AttemptResult]) -> Verdict:
    reproduced = next((item for item in attempts if item.status == "reproduced"), None)
    if reproduced:
        return Verdict(
            "reproduced",
            reproduced.matched,
            f"matched in attempt {reproduced.number}",
            reproduced.source_log,
        )

    crashed = next((item for item in attempts if item.status == "crashed_other"), None)
    if crashed:
        return Verdict(
            "crashed_other",
            crashed.matched,
            "other kernel crash found across attempts",
            crashed.source_log,
        )

    if any(item.status == "not_reproduced" for item in attempts):
        return Verdict("not_reproduced", None, "target crash not found in any attempt")

    return Verdict("failed", None, "all reproduction attempts failed")
