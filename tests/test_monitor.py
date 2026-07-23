from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from syzrun.repro.monitor import (
    AttemptResult,
    ReproductionRunner,
    _IncrementalLogScanner,
    _drain_qemu_log_after_crash,
    _should_stop_attempts,
    _symbolization_target,
    _verdict_after_repro_exit,
    _verdict_after_vm_exit,
)
from syzrun.repro.verdict import CrashFingerprint, Verdict


class IncrementalLogScannerTests(unittest.TestCase):
    def test_each_poll_reads_all_new_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "repro.log"
            log.write_text("old boot warning\n", encoding="utf-8")
            scanner = _IncrementalLogScanner(log, start_offset=log.stat().st_size)

            with log.open("a", encoding="utf-8") as stream:
                stream.write("BUG: memory leak\nunreferenced object\n")
            first = scanner.read_text()
            first_offset = scanner.offset

            with log.open("a", encoding="utf-8") as stream:
                stream.write("  backtrace:\n    __build_skb+0x21/0x60\n")
            second = scanner.read_text()

            self.assertNotIn("old boot warning", first)
            self.assertIn("BUG: memory leak", first)
            self.assertNotIn("BUG: memory leak", second)
            self.assertIn("__build_skb+0x21/0x60", second)
            self.assertGreater(scanner.offset, first_offset)
            self.assertEqual(scanner.offset, log.stat().st_size)
            self.assertIsNone(scanner.read_text())

    def test_does_not_truncate_large_chunks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "qemu.log"
            log.write_text("", encoding="utf-8")
            scanner = _IncrementalLogScanner(log, start_offset=0)

            with log.open("a", encoding="utf-8") as stream:
                stream.writelines(f"line-{index}\n" for index in range(130))
            window = scanner.read_text()

        self.assertEqual(len(window.splitlines()), 130)
        self.assertTrue(window.startswith("line-0\n"))
        self.assertTrue(window.endswith("line-129\n"))


class QemuLogDrainTests(unittest.TestCase):
    def test_returns_after_end_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            qemu_log = Path(tmp) / "qemu.log"
            qemu_log.write_text(
                "WARNING: CPU: 0 at alloc_pages_vma\n"
                "---[ end Kernel panic - not syncing: panic_on_warn set ... ]---\n",
                encoding="utf-8",
            )

            _drain_qemu_log_after_crash(
                qemu_log,
                start_offset=0,
                idle_timeout=10,
                max_wait=10,
                post_marker_wait=0,
                interval=0.01,
            )

    def test_returns_after_idle_timeout_without_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            qemu_log = Path(tmp) / "qemu.log"
            qemu_log.write_text("WARNING: CPU: 0 at alloc_pages_vma\n", encoding="utf-8")

            started = time.monotonic()
            _drain_qemu_log_after_crash(
                qemu_log,
                start_offset=0,
                idle_timeout=0.02,
                max_wait=1,
                post_marker_wait=0,
                interval=0.01,
            )

        self.assertLess(time.monotonic() - started, 0.5)


class EarlyExitVerdictTests(unittest.TestCase):
    def test_reproduction_or_failure_stops_further_attempts(self) -> None:
        self.assertTrue(_should_stop_attempts("reproduced"))
        self.assertTrue(_should_stop_attempts("failed"))
        self.assertFalse(_should_stop_attempts("not_reproduced"))
        self.assertFalse(_should_stop_attempts("crashed_other"))

    def test_abnormal_repro_exit_without_crash_fails(self) -> None:
        verdict = Verdict("not_reproduced", None, "no kernel crash report found")

        result = _verdict_after_repro_exit(verdict, 2)

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.reason, "syz repro exited unexpectedly with code 2")

    def test_normal_repro_exit_without_crash_is_not_reproduced(self) -> None:
        verdict = Verdict("not_reproduced", None, "no kernel crash report found")

        for exit_code in (0, 124):
            with self.subTest(exit_code=exit_code):
                self.assertIs(_verdict_after_repro_exit(verdict, exit_code), verdict)

    def test_crash_verdict_wins_over_abnormal_repro_exit(self) -> None:
        for status in ("reproduced", "crashed_other"):
            with self.subTest(status=status):
                verdict = Verdict(status, None, "kernel crash found")
                self.assertIs(_verdict_after_repro_exit(verdict, 255), verdict)

    def test_vm_exit_without_crash_fails(self) -> None:
        verdict = Verdict("not_reproduced", None, "no kernel crash report found")

        result = _verdict_after_vm_exit(verdict)

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.reason, "VM exited unexpectedly during reproduction")

    def test_crash_verdict_wins_over_vm_exit(self) -> None:
        verdict = Verdict("reproduced", "GPF in uhid_char_write", "matched crash fingerprint")

        self.assertIs(_verdict_after_vm_exit(verdict), verdict)


class CrashSymbolizationTargetTests(unittest.TestCase):
    def test_other_crash_uses_its_observed_fingerprint(self) -> None:
        target = CrashFingerprint("GPF", None, ("target_fn",))
        report = "WARNING: CPU: 0 PID: 1 at other_fn+0x1/0x2\n"
        result = AttemptResult(
            number=1,
            status="crashed_other",
            matched=None,
            reason="other kernel crash found",
            duration_seconds=1,
            logs_dir=Path("logs/attempt-01"),
            syz=None,
            source_log="qemu.log",
            report=report,
        )

        self.assertEqual(
            _symbolization_target(result, target),
            CrashFingerprint("WARNING", None, ("other_fn",)),
        )

    def test_symbolizer_failure_does_not_change_other_crash_verdict(self) -> None:
        target = CrashFingerprint("GPF", None, ("target_fn",))
        report = "WARNING: CPU: 0 PID: 1 at other_fn+0x1/0x2\n"
        attempt = AttemptResult(
            number=1,
            status="crashed_other",
            matched=None,
            reason="other kernel crash found",
            duration_seconds=1,
            logs_dir=Path("logs/attempt-01"),
            syz=None,
            source_log="qemu.log",
            report=report,
        )
        runner = object.__new__(ReproductionRunner)
        runner.layout = SimpleNamespace(logs_dir=Path("logs"))
        runner.vuln = SimpleNamespace(crash=SimpleNamespace(architecture="amd64"))
        runner.kernel = object()
        runner.syzkaller = object()
        runner.target = target
        runner.runtime_profile = None

        with (
            mock.patch("syzrun.repro.monitor.ATTEMPT_COUNT", 1),
            mock.patch("syzrun.repro.monitor.RootfsLocator.locate", return_value=object()),
            mock.patch.object(runner, "_run_attempt", return_value=attempt),
            mock.patch("syzrun.repro.monitor.symbolize_crash", side_effect=RuntimeError("boom")) as symbolize,
        ):
            result = runner.run()

        self.assertEqual(result.verdict.status, "crashed_other")
        self.assertEqual(
            symbolize.call_args.kwargs["target"],
            CrashFingerprint("WARNING", None, ("other_fn",)),
        )


if __name__ == "__main__":
    unittest.main()
