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


class CrashSymbolizationVerdictTests(unittest.TestCase):
    def make_runner(self, logs_dir: Path, target: CrashFingerprint, attempt: AttemptResult) -> ReproductionRunner:
        runner = object.__new__(ReproductionRunner)
        runner.layout = SimpleNamespace(logs_dir=logs_dir.parent)
        runner.vuln = SimpleNamespace(crash=SimpleNamespace(architecture="amd64"))
        runner.kernel = object()
        runner.syzkaller = object()
        runner.target = target
        runner.runtime_profile = None
        runner.attempt_count = 1
        runner._run_attempt = mock.Mock(return_value=attempt)
        return runner

    def test_later_symbolized_report_can_match_target(self) -> None:
        target = CrashFingerprint("KASAN", "vmalloc-out-of-bounds", ("idempotent",))
        with tempfile.TemporaryDirectory() as tmp:
            logs = Path(tmp) / "attempt-01"
            logs.mkdir()
            raw = (
                "BUG: KASAN: vmalloc-out-of-bounds in other_fn+0x1/0x2\n"
                "Read of size 8\n================================\n"
                "BUG: KASAN: vmalloc-out-of-bounds in __se_sys_finit_module+0x371/0x8d0\n"
                "Read of size 8\n================================\n"
            )
            boot = "BUG: KASAN: vmalloc-out-of-bounds in boot_fn+0x1/0x2\n"
            (logs / "qemu.log").write_text(boot + raw, encoding="utf-8")
            attempt = AttemptResult(
                1, "crashed_other", None, "other kernel crash found", 1, logs, None,
                source_log="qemu.log", report=raw.split("================================")[0],
                log_offsets={"qemu.log": len(boot)},
            )
            runner = self.make_runner(logs, target, attempt)

            def symbolize(**kwargs):
                output = kwargs["output_path"]
                if "other_fn" in kwargs["report_text"]:
                    output.write_text("BUG: KASAN: vmalloc-out-of-bounds in other_fn+0x1/0x2\n", encoding="utf-8")
                else:
                    output.write_text(
                        "TITLE: KASAN report\n"
                        "BUG: KASAN: vmalloc-out-of-bounds in __se_sys_finit_module+0x371/0x8d0\n"
                        " idempotent kernel/module/main.c:3078 [inline]\n"
                        "Memory state around the buggy address:\n",
                        encoding="utf-8",
                    )
                return output

            with (
                mock.patch("syzrun.repro.monitor.RootfsLocator.locate", return_value=object()),
                mock.patch("syzrun.repro.monitor.symbolize_crash", side_effect=symbolize) as mocked,
            ):
                result = runner.run()

            self.assertEqual(result.verdict.status, "reproduced")
            self.assertEqual(result.attempts[0].matched, "KASAN in idempotent")
            self.assertEqual(mocked.call_count, 2)
            self.assertTrue(all(call.kwargs["extract_target"] is False for call in mocked.call_args_list))
            self.assertTrue((logs / "crash.log").read_text(encoding="utf-8").startswith("BUG: KASAN:"))
            self.assertIn("idempotent", (logs / "crash.log").read_text(encoding="utf-8"))
            self.assertIn("Memory state around the buggy address:", (logs / "crash.log").read_text(encoding="utf-8"))
            self.assertNotIn("other_fn", (logs / "crash.log").read_text(encoding="utf-8"))

    def test_symbolized_nonmatch_overrides_raw_match(self) -> None:
        target = CrashFingerprint("KASAN", "use-after-free", ("shared_frame",))
        with tempfile.TemporaryDirectory() as tmp:
            logs = Path(tmp) / "attempt-01"
            logs.mkdir()
            raw = "BUG: KASAN: use-after-free in shared_frame+0x1/0x2\n"
            (logs / "qemu.log").write_text(raw, encoding="utf-8")
            attempt = AttemptResult(1, "reproduced", "KASAN in shared_frame", "matched crash fingerprint", 1, logs, None, source_log="qemu.log", report=raw)
            runner = self.make_runner(logs, target, attempt)

            def symbolize(**kwargs):
                output = kwargs["output_path"]
                output.write_text("BUG: KASAN: use-after-free in other_fn+0x1/0x2\n", encoding="utf-8")
                return output

            with mock.patch("syzrun.repro.monitor.symbolize_crash", side_effect=symbolize):
                result = runner._finalize_attempt(attempt)

            self.assertEqual(result.status, "crashed_other")
            self.assertIsNone(result.matched)
            self.assertIn("other_fn", (logs / "crash.log").read_text(encoding="utf-8"))

    def test_symbolizer_failure_keeps_raw_verdict(self) -> None:
        target = CrashFingerprint("GPF", None, ("target_fn",))
        report = "WARNING: CPU: 0 PID: 1 at other_fn+0x1/0x2\n"
        with tempfile.TemporaryDirectory() as tmp:
            logs = Path(tmp) / "attempt-01"
            logs.mkdir()
            (logs / "qemu.log").write_text(report, encoding="utf-8")
            attempt = AttemptResult(
                1, "crashed_other", None, "other kernel crash found", 1, logs, None,
                source_log="qemu.log", report=report,
            )
            runner = self.make_runner(logs, target, attempt)

            with mock.patch(
                "syzrun.repro.monitor.symbolize_crash", side_effect=RuntimeError("boom")
            ) as symbolize:
                result = runner._finalize_attempt(attempt)

            self.assertIs(result, attempt)
            self.assertEqual(symbolize.call_count, 1)
            self.assertFalse((logs / "crash.log").exists())


if __name__ == "__main__":
    unittest.main()
