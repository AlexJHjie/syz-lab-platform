from pathlib import Path
import tempfile
import unittest

from syzrun.metadata import Vulnerability
from syzrun.repro.verdict import classify, classify_text, has_crash


class VerdictTests(unittest.TestCase):
    def test_kernel_warning_pattern_matches_warning_report(self) -> None:
        self.assertTrue(has_crash("WARNING: CPU: 0 PID: 123 at net/core/example.c:42 example_fn+0x1/0x2"))
        self.assertTrue(has_crash("WARNING: at kernel/example.c:42 example_fn+0x1/0x2"))

    def test_kernel_warning_pattern_ignores_spectre_boot_message(self) -> None:
        self.assertFalse(
            has_crash(
                "Spectre V2 : WARNING: Unprivileged eBPF is enabled with eIBRS on, "
                "data leaks possible via Spectre v2 BHB attacks!"
            )
        )

    def test_title_match_is_reproduced(self) -> None:
        data = {
            "version": 1,
            "title": "WARNING in foo",
            "display-title": "WARNING in foo",
            "id": "abc",
            "status": "fixed",
            "fix-commits": [],
            "crashes": [
                {
                    "syz-reproducer": "/text?tag=ReproSyz&x=1",
                    "kernel-config": "/text?tag=KernelConfig&x=2",
                    "kernel-source-git": "git",
                    "kernel-source-commit": "kernel",
                    "syzkaller-git": "syz",
                    "syzkaller-commit": "syzcommit",
                    "compiler-description": "gcc",
                    "architecture": "amd64",
                    "crash-report-link": "/text?tag=CrashReport&x=3",
                }
            ],
            "subsystems": [],
        }
        vuln = Vulnerability.from_dict(data, Path("abc.json"))
        with tempfile.TemporaryDirectory() as tmp:
            logs = Path(tmp)
            (logs / "qemu.log").write_text("some log\nWARNING in foo\n", encoding="utf-8")
            verdict = classify(vuln, logs)
        self.assertEqual(verdict.status, "reproduced")

    def test_memory_leak_type_and_function_match_is_reproduced(self) -> None:
        vuln = Vulnerability.from_dict(
            {
                "version": 1,
                "title": "memory leak in __build_skb",
                "display-title": "memory leak in __build_skb (3)",
                "id": "leak",
                "status": "fixed",
                "fix-commits": [],
                "crashes": [
                    {
                        "title": "memory leak in __build_skb",
                        "syz-reproducer": "/text?tag=ReproSyz&x=1",
                        "kernel-config": "/text?tag=KernelConfig&x=2",
                        "kernel-source-git": "git",
                        "kernel-source-commit": "kernel",
                        "syzkaller-git": "syz",
                        "syzkaller-commit": "syzcommit",
                        "compiler-description": "gcc",
                        "architecture": "amd64",
                        "crash-report-link": "/text?tag=CrashReport&x=3",
                    }
                ],
                "subsystems": [],
            },
            Path("leak.json"),
        )
        text = """\
BUG: memory leak
unreferenced object 0xffff88810535b500 (size 240):
  backtrace:
    [<ffffffff83b0df31>] __build_skb+0x21/0x60 net/core/skbuff.c:377
"""

        verdict = classify_text(vuln, text)

        self.assertEqual(verdict.status, "reproduced")
        self.assertEqual(verdict.matched, "memory leak in __build_skb")

    def test_classify_finds_target_memory_leak_in_repro_log(self) -> None:
        vuln = Vulnerability.from_dict(
            {
                "version": 1,
                "title": "memory leak in __build_skb",
                "display-title": "memory leak in __build_skb (3)",
                "id": "leak",
                "status": "fixed",
                "fix-commits": [],
                "crashes": [
                    {
                        "title": "memory leak in __build_skb",
                        "syz-reproducer": "/text?tag=ReproSyz&x=1",
                        "kernel-config": "/text?tag=KernelConfig&x=2",
                        "kernel-source-git": "git",
                        "kernel-source-commit": "kernel",
                        "syzkaller-git": "syz",
                        "syzkaller-commit": "syzcommit",
                        "compiler-description": "gcc",
                        "architecture": "amd64",
                        "crash-report-link": "/text?tag=CrashReport&x=3",
                    }
                ],
                "subsystems": [],
            },
            Path("leak.json"),
        )
        with tempfile.TemporaryDirectory() as tmp:
            logs = Path(tmp)
            (logs / "qemu.log").write_text("BUG: unrelated kernel failure\n", encoding="utf-8")
            (logs / "repro.log").write_text(
                "BUG: memory leak\n"
                "unreferenced object 0xffff888010b9c300 (size 240):\n"
                "  backtrace:\n"
                "    [<ffffffff83a95391>] __build_skb+0x21/0x60\n"
                "    [<ffffffff82e1bcee>] ath9k_hif_usb_rx_cb+0x1ce/0x660\n",
                encoding="utf-8",
            )

            verdict = classify(vuln, logs)

        self.assertEqual(verdict.status, "reproduced")
        self.assertEqual(verdict.matched, "memory leak in __build_skb")
        self.assertEqual(verdict.source_log, "repro.log")

    def test_memory_leak_in_other_function_is_not_target(self) -> None:
        vuln = Vulnerability.from_dict(
            {
                "version": 1,
                "title": "memory leak in __build_skb",
                "display-title": "memory leak in __build_skb",
                "id": "leak",
                "status": "fixed",
                "fix-commits": [],
                "crashes": [
                    {
                        "syz-reproducer": "/text?tag=ReproSyz&x=1",
                        "kernel-config": "/text?tag=KernelConfig&x=2",
                        "kernel-source-git": "git",
                        "kernel-source-commit": "kernel",
                        "syzkaller-git": "syz",
                        "syzkaller-commit": "syzcommit",
                        "compiler-description": "gcc",
                        "architecture": "amd64",
                        "crash-report-link": "/text?tag=CrashReport&x=3",
                    }
                ],
                "subsystems": [],
            },
            Path("leak.json"),
        )
        text = """\
BUG: memory leak
unreferenced object 0xffff88810535b500 (size 240):
  backtrace:
    [<ffffffff81234567>] unrelated_alloc+0x21/0x60 mm/example.c:10
"""

        verdict = classify_text(vuln, text)

        self.assertEqual(verdict.status, "crashed_other")


if __name__ == "__main__":
    unittest.main()
