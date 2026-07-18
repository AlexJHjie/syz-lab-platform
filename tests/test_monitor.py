from pathlib import Path
import tempfile
import time
import unittest

from syzrun.repro.monitor import _IncrementalLogScanner, _drain_qemu_log_after_crash


class IncrementalLogScannerTests(unittest.TestCase):
    def test_reads_only_appended_bytes_and_keeps_cross_write_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "repro.log"
            log.write_text("old boot warning\n", encoding="utf-8")
            scanner = _IncrementalLogScanner(log, start_offset=log.stat().st_size)

            with log.open("a", encoding="utf-8") as stream:
                stream.write("BUG: memory leak\nunreferenced object\n")
            first = scanner.read_window()
            first_offset = scanner.offset

            with log.open("a", encoding="utf-8") as stream:
                stream.write("  backtrace:\n    __build_skb+0x21/0x60\n")
            second = scanner.read_window()

            self.assertNotIn("old boot warning", first)
            self.assertIn("BUG: memory leak", first)
            self.assertIn("BUG: memory leak", second)
            self.assertIn("__build_skb+0x21/0x60", second)
            self.assertGreater(scanner.offset, first_offset)
            self.assertEqual(scanner.offset, log.stat().st_size)
            self.assertIsNone(scanner.read_window())

    def test_limits_window_to_most_recent_120_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "qemu.log"
            log.write_text("", encoding="utf-8")
            scanner = _IncrementalLogScanner(log, start_offset=0)

            with log.open("a", encoding="utf-8") as stream:
                stream.writelines(f"line-{index}\n" for index in range(130))
            window = scanner.read_window()

        self.assertEqual(len(window.splitlines()), 120)
        self.assertTrue(window.startswith("line-10\n"))
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


if __name__ == "__main__":
    unittest.main()
