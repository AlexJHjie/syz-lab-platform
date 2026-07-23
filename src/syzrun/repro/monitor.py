from __future__ import annotations

import codecs
import logging
import time
from dataclasses import dataclass, field
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
from .verdict import CrashFingerprint, StreamMatcher, Verdict, classify, split_reports, target_fingerprint

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
NORMAL_REPRO_EXIT_CODES = frozenset({0, 124})


class _IncrementalLogScanner:
    def __init__(self, path: Path, *, start_offset: int) -> None:
        self.path = path
        self.offset = start_offset
        self.decoder = codecs.getincrementaldecoder("utf-8")("replace")

    def read_text(self) -> str | None:
        if not self.path.exists():
            return None
        if self.path.stat().st_size < self.offset:
            self.offset = 0
            self.decoder.reset()

        with self.path.open("rb") as stream:
            stream.seek(self.offset)
            chunk = stream.read()
            self.offset = stream.tell()
        if not chunk:
            return None
        return self.decoder.decode(chunk)


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
    report: str | None = field(default=None, repr=False, compare=False)


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
        self.target: CrashFingerprint = target_fingerprint(fetched.crash_report)
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
            symbolization_target = _symbolization_target(result, self.target)
            if symbolization_target is not None:
                try:
                    source_log = result.source_log or "qemu.log"
                    crash_log = symbolize_crash(
                        kernel=self.kernel,
                        syzkaller=self.syzkaller,
                        architecture=self.vuln.crash.architecture,
                        source_log=logs_dir / source_log,
                        target=symbolization_target,
                        report_text=result.report,
                        output_path=logs_dir / "crash.log",
                    )
                    if crash_log:
                        logging.info("symbolized crash log: %s", crash_log)
                    else:
                        logging.warning("could not locate %s crash in %s", result.status, logs_dir / source_log)
                except Exception as exc:
                    logging.warning("failed to symbolize %s crash: %s", result.status, exc)
            attempts.append(result)
            logging.info("attempt %d finished: %s (%s)", number, result.status, result.reason)
            if _should_stop_attempts(result.status):
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
            qemu_matcher = StreamMatcher(self.target, "qemu.log")
            repro_matcher = StreamMatcher(self.target, "repro.log")
            process, remote_command = start_syz_repro(
                vm=vm,
                syzkaller=self.syzkaller,
                repro_file=self.fetched.syz_reproducer,
                timeout=REPRO_TIMEOUT,
                env=self.runtime_profile.repro_env,
                extra_args=self.runtime_profile.execprog_args,
            )
            deadline = time.monotonic() + REPRO_TIMEOUT

            while time.monotonic() < deadline:
                serial_text = qemu_scanner.read_text()
                if serial_text is not None:
                    verdict = qemu_matcher.feed(serial_text)
                    if verdict.status == "reproduced" or (
                        verdict.status == "crashed_other" and qemu_matcher.terminal
                    ):
                        exit_code = stop_syz_repro(process)
                        _drain_qemu_log_after_crash(vm.qemu_log, start_offset=qemu_offset)
                        verdict = classify(
                            self.target, logs_dir, {"qemu.log": qemu_offset, "repro.log": repro_offset}
                        )
                        return _attempt_result(number, verdict, started, logs_dir, exit_code, remote_command)

                repro_text = repro_scanner.read_text()
                if repro_text is not None:
                    verdict = repro_matcher.feed(repro_text)
                    # A report can be observed while its stack is still being written.
                    # Stop early only after the complete target signature is available.
                    if verdict.status == "reproduced":
                        exit_code = stop_syz_repro(process)
                        verdict = classify(
                            self.target, logs_dir, {"qemu.log": qemu_offset, "repro.log": repro_offset}
                        )
                        return _attempt_result(number, verdict, started, logs_dir, exit_code, remote_command)

                returncode = process.poll()
                if returncode is not None:
                    verdict = classify(self.target, logs_dir, {"qemu.log": qemu_offset, "repro.log": repro_offset})
                    verdict = _verdict_after_repro_exit(verdict, returncode)
                    return _attempt_result(number, verdict, started, logs_dir, returncode, remote_command)

                if vm.process and vm.process.poll() is not None:
                    verdict = classify(self.target, logs_dir, {"qemu.log": qemu_offset, "repro.log": repro_offset})
                    verdict = _verdict_after_vm_exit(verdict)
                    return _attempt_result(number, verdict, started, logs_dir, process.poll(), remote_command)
                time.sleep(MONITOR_INTERVAL)

            exit_code = stop_syz_repro(process)
            verdict = classify(self.target, logs_dir, {"qemu.log": qemu_offset, "repro.log": repro_offset})
            return _attempt_result(number, verdict, started, logs_dir, exit_code, remote_command)
        finally:
            if process is not None and process.poll() is None:
                stop_syz_repro(process)
            vm.stop()


def _read_from(path: Path, offset: int) -> str:
    if not path.exists():
        return ""
    with path.open("rb") as stream:
        stream.seek(offset)
        return stream.read().decode(errors="replace")


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
    marker_offset = start_offset
    marker_tail = ""
    last_size = -1

    while True:
        now = time.monotonic()
        if path.exists():
            current_size = path.stat().st_size
            if current_size != last_size:
                last_size = current_size
                idle_since = now

            if current_size > marker_offset:
                text = marker_tail + _read_from(path, marker_offset)
                marker_offset = current_size
                marker_tail = text[-max(map(len, end_markers)) :]
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
        report=verdict.report,
    )


def _verdict_after_repro_exit(verdict: Verdict, exit_code: int) -> Verdict:
    """Preserve crash verdicts, but reject an otherwise unexplained repro failure."""

    if verdict.status != "not_reproduced" or exit_code in NORMAL_REPRO_EXIT_CODES:
        return verdict
    return Verdict(
        "failed",
        None,
        f"syz repro exited unexpectedly with code {exit_code}",
        verdict.source_log,
    )


def _verdict_after_vm_exit(verdict: Verdict) -> Verdict:
    """An early VM exit without a kernel crash is an infrastructure failure."""

    if verdict.status != "not_reproduced":
        return verdict
    return Verdict("failed", None, "VM exited unexpectedly during reproduction", verdict.source_log)


def _should_stop_attempts(status: str) -> bool:
    return status in {"reproduced", "failed"}


def _symbolization_target(
    result: AttemptResult, target: CrashFingerprint
) -> CrashFingerprint | None:
    if result.status == "reproduced":
        return target
    if result.status != "crashed_other" or result.report is None:
        return None
    reports = split_reports(result.report)
    return reports[0].fingerprint if reports else None


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
