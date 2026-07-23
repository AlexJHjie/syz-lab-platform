from pathlib import Path
import tempfile
import unittest

from syzrun.repro.verdict import CrashFingerprint, ReportStream, classify, classify_text, split_reports, target_fingerprint


class VerdictTests(unittest.TestCase):
    def test_warning_uses_outermost_non_inline_function(self) -> None:
        text = """WARNING: CPU: 1 PID: 2 at mm/mempolicy.c:1745 policy_node mm/mempolicy.c:1745 [inline]
WARNING: CPU: 1 PID: 2 at mm/mempolicy.c:1745 alloc_pages_vma+0x1bd/0x4a0 mm/mempolicy.c:2043
Kernel panic - not syncing: panic_on_warn set ...
"""
        report = split_reports(text)[0]
        self.assertEqual(report.fingerprint, CrashFingerprint("WARNING", None, ("alloc_pages_vma",)))
        observed = "WARNING: CPU: 0 PID: 3 at mm/mempolicy.c:1745 alloc_pages_vma+0x2/0x40\n"
        self.assertEqual(classify_text(report.fingerprint, observed).status, "reproduced")

    def test_warning_outermost_function_is_not_lost_after_many_inline_frames(self) -> None:
        target_text = """WARNING: CPU: 1 PID: 2 at include/linux/swapops.h:323 make_pte_marker_entry include/linux/swapops.h:323 [inline]
WARNING: CPU: 1 PID: 2 at include/linux/swapops.h:323 make_pte_marker include/linux/swapops.h:346 [inline]
WARNING: CPU: 1 PID: 2 at include/linux/swapops.h:323 change_pte_range mm/mprotect.c:270 [inline]
WARNING: CPU: 1 PID: 2 at include/linux/swapops.h:323 change_pmd_range mm/mprotect.c:409 [inline]
WARNING: CPU: 1 PID: 2 at include/linux/swapops.h:323 change_pud_range mm/mprotect.c:438 [inline]
WARNING: CPU: 1 PID: 2 at include/linux/swapops.h:323 change_p4d_range mm/mprotect.c:459 [inline]
WARNING: CPU: 1 PID: 2 at include/linux/swapops.h:323 change_protection_range mm/mprotect.c:483 [inline]
WARNING: CPU: 1 PID: 2 at include/linux/swapops.h:323 change_protection+0x16e9/0x4280 mm/mprotect.c:505
"""
        target = split_reports(target_text)[0].fingerprint
        observed = "WARNING: CPU: 1 PID: 3 at include/linux/swapops.h:323 change_protection+0x16e9/0x4280\n"
        self.assertEqual(target, CrashFingerprint("WARNING", None, ("change_protection",)))
        self.assertEqual(classify_text(target, observed).status, "reproduced")

    def test_non_warning_fingerprint_still_keeps_first_five_functions(self) -> None:
        text = "BUG: KASAN: use-after-free in first+0x1/0x2\n" + "\n".join(
            f" {name}+0x1/0x2" for name in ("second", "third", "fourth", "fifth", "sixth")
        )
        report = split_reports(text)[0]
        self.assertEqual(
            report.fingerprint,
            CrashFingerprint("KASAN", "use-after-free", ("first", "second", "third", "fourth", "fifth")),
        )

    def test_kasan_subtype_is_extracted_and_must_not_conflict(self) -> None:
        target = CrashFingerprint("KASAN", "use-after-free", ("target_fn",))
        matching = "BUG: KASAN: use-after-free in target_fn+0x1/0x2\n"
        other = "BUG: KASAN: slab-out-of-bounds in target_fn+0x1/0x2\n"
        self.assertEqual(classify_text(target, matching).status, "reproduced")
        self.assertEqual(classify_text(target, other).status, "crashed_other")

    def test_gpf_uses_stack_anchors_and_has_no_subtype(self) -> None:
        text = """BUG: GPF in non-whitelisted uaccess (non-canonical address?)
general protection fault: 0000 [#1]
RIP: copy_user_enhanced_fast_string+0xe/0x20
Call Trace:
 copy_from_user+0x1/0x2
 uhid_dev_create+0x20c/0xb40 drivers/hid/uhid.c:542
 uhid_char_write+0xc74/0xef0 drivers/hid/uhid.c:725
"""
        fp = split_reports(text)[0].fingerprint
        self.assertEqual(fp, CrashFingerprint("GPF", None, ("uhid_dev_create", "uhid_char_write")))

    def test_boot_debug_and_non_do_not_fake_bug_match(self) -> None:
        target = CrashFingerprint("GPF", None, ("uhid_dev_create",))
        text = "SGI XFS with no debug enabled\nNon-volatile memory driver\n"
        self.assertEqual(classify_text(target, text).status, "not_reproduced")

    def test_other_crash_does_not_match_target(self) -> None:
        target = CrashFingerprint("GPF", None, ("uhid_dev_create",))
        text = "WARNING: CPU: 0 PID: 1 at kernel/cgroup/cgroup.c:1 cgroup_apply_control_enable+0x1/0x2\n"
        verdict = classify_text(target, text)
        self.assertEqual(verdict.status, "crashed_other")
        self.assertEqual(verdict.report, text)

    def test_target_and_runtime_logs_use_same_parser(self) -> None:
        target_text = "BUG: memory leak\nbacktrace:\n __build_skb+0x1/0x2 net/core/skbuff.c:1\n"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / "crash.report"
            report.write_text(target_text, encoding="utf-8")
            logs = root / "logs"
            logs.mkdir()
            (logs / "repro.log").write_text(target_text, encoding="utf-8")
            verdict = classify(target_fingerprint(report), logs)
        self.assertEqual(verdict.status, "reproduced")
        self.assertEqual(verdict.source_log, "repro.log")

    def test_target_skips_leak_with_only_allocator_frames(self) -> None:
        text = """BUG: memory leak
backtrace:
 kmalloc_trace+0x1/0x2
BUG: memory leak
backtrace:
 __build_skb+0x1/0x2 net/core/skbuff.c:1
"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "crash.report"
            path.write_text(text, encoding="utf-8")
            target = target_fingerprint(path)
        self.assertEqual(target.functions, ("__build_skb",))

    def test_stream_handles_split_lines_and_discards_completed_reports(self) -> None:
        stream = ReportStream()
        self.assertEqual(stream.feed("BUG: KASAN: use-after-free in tar"), [])
        reports = stream.feed("get_fn+0x1/0x2\n================================\n")
        self.assertEqual(reports[0].fingerprint.functions, ("target_fn",))
        self.assertEqual(stream.lines, [])


if __name__ == "__main__":
    unittest.main()
