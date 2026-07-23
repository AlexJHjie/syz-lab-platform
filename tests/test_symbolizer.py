from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from syzrun.builder.kernel import KernelArtifacts
from syzrun.builder.syzkaller import SyzkallerArtifacts
from syzrun.repro.symbolizer import _symbolizer_supports_arch, extract_crash_segment, symbolize_crash
from syzrun.repro.verdict import CrashFingerprint


class SymbolizerTests(unittest.TestCase):
    def test_extracts_only_target_memory_leak(self) -> None:
        text = """BUG: memory leak
unreferenced object 0xffff888048859c00 (size 1024):
  backtrace:
    [<ffffffff814ef540>] kmalloc_trace+0x20/0x90

BUG: memory leak
unreferenced object 0xffff888010b9c300 (size 240):
  backtrace:
    [<ffffffff83a95391>] __build_skb+0x21/0x60
    [<ffffffff82e1bcee>] ath9k_hif_usb_rx_cb+0x1ce/0x660

BUG: memory leak
unreferenced object 0xffff888049e80c00 (size 64):
"""
        target = CrashFingerprint("MEMORY_LEAK", None, ("__build_skb",))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "repro.log"
            output = root / "segment.log"
            source.write_text(text, encoding="utf-8")

            self.assertTrue(extract_crash_segment(source, output, target))
            segment = output.read_text(encoding="utf-8")

        self.assertIn("__build_skb+0x21", segment)
        self.assertIn("ath9k_hif_usb_rx_cb+0x1ce", segment)
        self.assertNotIn("kmalloc_trace", segment)
        self.assertEqual(segment.count("BUG: memory leak"), 1)

    def test_stops_after_complete_kasan_report(self) -> None:
        text = """boot message
[   38.273988][ T6935] BUG: KASAN: slab-out-of-bounds in decrypt_internal+0x153b/0x1cd0
[   38.275126][ T6935] Read of size 16
[   38.285649][ T6935]  decrypt_internal+0x153b/0x1cd0
[   38.367045][ T6935] ==================================================================
[   38.400037][ T6954] BUG: KASAN: slab-out-of-bounds in decrypt_internal+0x153b/0x1cd0
"""
        target = CrashFingerprint("KASAN", "slab-out-of-bounds", ("decrypt_internal",))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "qemu.log"
            output = root / "segment.log"
            source.write_text(text, encoding="utf-8")

            self.assertTrue(extract_crash_segment(source, output, target))
            segment = output.read_text(encoding="utf-8")

        self.assertIn("T6935", segment)
        self.assertNotIn("T6954", segment)

    def test_symbolizes_with_matching_syzkaller_binary(self) -> None:
        target = CrashFingerprint("MEMORY_LEAK", None, ("__build_skb",))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kernel_tree = root / "linux"
            kernel_tree.mkdir()
            vmlinux = kernel_tree / "vmlinux"
            vmlinux.write_text("elf", encoding="utf-8")
            syzkaller_tree = root / "syzkaller"
            symbolizer = syzkaller_tree / "bin" / "syz-symbolize"
            symbolizer.parent.mkdir(parents=True)
            symbolizer.write_text("binary", encoding="utf-8")
            source = root / "repro.log"
            source.write_text(
                "BUG: memory leak\n"
                "unreferenced object 0xffff888010568400 (size 240):\n"
                "  backtrace:\n"
                "    [<ffffffff83a95391>] __build_skb+0x21/0x60\n\n",
                encoding="utf-8",
            )
            output = root / "crash.log"
            kernel = KernelArtifacts(
                tree=kernel_tree,
                bz_image=kernel_tree / "bzImage",
                vmlinux=vmlinux,
                config=kernel_tree / ".config",
            )
            syzkaller = SyzkallerArtifacts(
                tree=syzkaller_tree,
                execprog=syzkaller_tree / "syz-execprog",
                executor=syzkaller_tree / "syz-executor",
                symbolizer=symbolizer,
            )
            symbolized = (
                "TITLE: memory leak in __build_skb\n"
                "CORRUPTED: false ()\n\n"
                "BUG: memory leak\n"
                "unreferenced object 0xffff888010568400 (size 240):\n"
                "  backtrace:\n"
                "    [<ffffffff83a95391>] __build_skb+0x21/0x60 net/core/skbuff.c:377\n\n"
            )
            help_result = subprocess.CompletedProcess([], 0, "", "  -arch string\n")
            completed = subprocess.CompletedProcess([], 0, symbolized, "")

            with mock.patch(
                "syzrun.repro.symbolizer.subprocess.run",
                side_effect=[help_result, completed],
            ) as run_mock:
                result = symbolize_crash(
                    kernel=kernel,
                    syzkaller=syzkaller,
                    architecture="amd64",
                    source_log=source,
                    target=target,
                    report_text=source.read_text(encoding="utf-8"),
                    output_path=output,
                )

            self.assertEqual(result, output)
            self.assertTrue(output.read_text(encoding="utf-8").startswith("BUG: memory leak"))
            self.assertIn("skbuff.c:377", output.read_text(encoding="utf-8"))
            command = run_mock.call_args_list[1].args[0]
            self.assertEqual(command[0], str(symbolizer))
            self.assertIn("-kernel_obj", command)
            self.assertIn("-kernel_src", command)
            self.assertIn("amd64", command)
            self.assertEqual(run_mock.call_args.kwargs["timeout"], 300)
            self.assertFalse(output.with_suffix(".raw.tmp").exists())
            self.assertFalse(output.with_suffix(".symbolized.tmp").exists())

    def test_symbolizer_failure_does_not_leave_crash_log(self) -> None:
        target = CrashFingerprint("WARNING", None, ("target",))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kernel_tree = root / "linux"
            kernel_tree.mkdir()
            vmlinux = kernel_tree / "vmlinux"
            vmlinux.write_text("elf", encoding="utf-8")
            symbolizer = root / "syzkaller" / "bin" / "syz-symbolize"
            symbolizer.parent.mkdir(parents=True)
            symbolizer.write_text("binary", encoding="utf-8")
            source = root / "qemu.log"
            source.write_text("WARNING: CPU: 0 at target+0x10/0x20\n", encoding="utf-8")
            output = root / "crash.log"
            kernel = KernelArtifacts(kernel_tree, kernel_tree / "bzImage", vmlinux, kernel_tree / ".config")
            syzkaller = SyzkallerArtifacts(root / "syzkaller", root / "execprog", root / "executor", symbolizer)
            help_result = subprocess.CompletedProcess([], 0, "", "  -kernel_obj string\n")
            completed = subprocess.CompletedProcess([], 1, "", "symbolizer error")

            with mock.patch(
                "syzrun.repro.symbolizer.subprocess.run",
                side_effect=[help_result, completed],
            ) as run_mock:
                with self.assertRaisesRegex(RuntimeError, "symbolizer error"):
                    symbolize_crash(
                        kernel=kernel,
                        syzkaller=syzkaller,
                        architecture="amd64",
                        source_log=source,
                        target=target,
                        report_text=source.read_text(encoding="utf-8"),
                        output_path=output,
                    )

            self.assertNotIn("-arch", run_mock.call_args_list[1].args[0])
            self.assertFalse(output.exists())
            self.assertFalse(output.with_suffix(".raw.tmp").exists())
            self.assertFalse(output.with_suffix(".symbolized.tmp").exists())

    def test_symbolizer_flag_detection_is_cached_by_path(self) -> None:
        symbolizer = Path("/tmp/syz-symbolize-cache-test")
        _symbolizer_supports_arch.cache_clear()
        completed = subprocess.CompletedProcess([], 0, "", "  -arch string\n")

        with mock.patch("syzrun.repro.symbolizer.subprocess.run", return_value=completed) as run_mock:
            self.assertTrue(_symbolizer_supports_arch(symbolizer))
            self.assertTrue(_symbolizer_supports_arch(symbolizer))

        run_mock.assert_called_once()

    def test_unavailable_symbolizer_is_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kernel_tree = root / "linux"
            kernel_tree.mkdir()
            vmlinux = kernel_tree / "vmlinux"
            vmlinux.write_text("elf", encoding="utf-8")
            source = root / "qemu.log"
            source.write_text("WARNING: CPU: 0 at target\n", encoding="utf-8")
            kernel = KernelArtifacts(kernel_tree, kernel_tree / "bzImage", vmlinux, kernel_tree / ".config")
            syzkaller = SyzkallerArtifacts(root / "syzkaller", root / "execprog", root / "executor")

            with self.assertRaisesRegex(FileNotFoundError, "syz-symbolize is unavailable"):
                symbolize_crash(
                    kernel=kernel,
                    syzkaller=syzkaller,
                    architecture="amd64",
                    source_log=source,
                    target=CrashFingerprint("WARNING", None, ("target",)),
                    report_text=source.read_text(encoding="utf-8"),
                    output_path=root / "crash.log",
                )


if __name__ == "__main__":
    unittest.main()
