import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from syzrun.api import RunOptions, ensure_kernel_source, run_vulnerability
from syzrun.builder.toolchain import ToolchainError
from syzrun.metadata import Vulnerability
from syzrun.repro.monitor import ReproResult
from syzrun.repro.verdict import Verdict
from syzrun.reports.report import RunReport
from syzrun.utils.command import CommandError, CommandResult


def write_metadata(path: Path) -> None:
    path.write_text(
        """
        {
          "version": 1,
          "title": "WARNING in alloc_pages_vma",
          "display-title": "WARNING in alloc_pages_vma",
          "id": "abc123",
          "status": "fixed",
          "crashes": [{
            "syz-reproducer": "/text?tag=ReproSyz&x=1",
            "kernel-config": "/text?tag=KernelConfig&x=2",
            "kernel-source-git": "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
            "kernel-source-commit": "deadbeef",
            "syzkaller-git": "https://github.com/google/syzkaller",
            "syzkaller-commit": "cafebabe",
            "compiler-description": "gcc (Debian 10.2.1-6) 10.2.1",
            "architecture": "amd64",
            "crash-report-link": "/text?tag=CrashReport&x=3"
          }]
        }
        """,
        encoding="utf-8",
    )


class ApiTests(unittest.TestCase):
    def test_run_vulnerability_returns_structured_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata = root / "vuln.json"
            write_metadata(metadata)
            vuln = Vulnerability.from_file(metadata)
            report = RunReport.create(
                vuln=vuln,
                work_dir=root / "runs" / "abc123",
                logs_dir=root / "runs" / "abc123" / "logs",
                patch_applied=None,
                repro_result=ReproResult(
                    syz=None,
                    verdict=Verdict("not_reproduced", None, "target crash not found"),
                    attempts=[],
                ),
                verdict=Verdict("not_reproduced", None, "target crash not found"),
            )

            with mock.patch("syzrun.api.Vulnerability.from_file", return_value=vuln):
                with mock.patch("syzrun.api.load_runtime_profile"):
                    with mock.patch("syzrun.api.WorkspaceLayout.create") as layout_create:
                        layout = layout_create.return_value
                        layout.run_dir = root / "runs" / "abc123"
                        layout.logs_dir = layout.run_dir / "logs"
                        layout.report_dir = layout.run_dir
                        layout.reset_logs.return_value = None
                        with mock.patch("syzrun.api.fetch_artifacts"):
                            with mock.patch("syzrun.api.KernelBuilder"):
                                with mock.patch("syzrun.api.SyzkallerBuilder"):
                                    with mock.patch("syzrun.api.ReproductionRunner"):
                                        with mock.patch("syzrun.api.RunReport.create", return_value=report):
                                            with mock.patch(
                                                "syzrun.api.write_report",
                                                return_value=(root / "report.json", root / "report.md"),
                                            ):
                                                result = run_vulnerability(
                                                    RunOptions(metadata=metadata, work_dir=root, timeout="20m")
                                                )

        self.assertEqual(result.exit_code, 1)
        self.assertEqual(result.report, report)
        self.assertEqual(result.report_json, root / "report.json")
        self.assertEqual(result.report_markdown, root / "report.md")
        self.assertIsNone(result.error)

    def test_run_vulnerability_returns_structured_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata = root / "vuln.json"
            write_metadata(metadata)

            with mock.patch("syzrun.api.fetch_artifacts", side_effect=RuntimeError("download failed")):
                with mock.patch("syzrun.api.logging.exception"):
                    result = run_vulnerability(RunOptions(metadata=metadata, work_dir=root, timeout="20m"))
            failure = json.loads(result.failure_json.read_text(encoding="utf-8"))

        self.assertEqual(result.exit_code, 2)
        self.assertIsNone(result.report)
        self.assertEqual(result.error, "download failed")
        self.assertIsNotNone(result.failure_json)
        self.assertEqual(failure["failure_stage"], "asset_fetch")
        self.assertEqual(failure["failure_kind"], "download_failed")
        self.assertIsNone(failure["command"])
        self.assertIsNone(failure["exit_code"])
        self.assertFalse(failure["timed_out"])
        self.assertEqual(failure["work_dir"], str(root.resolve() / "runs" / "abc123"))

    def test_missing_toolchain_stops_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata = root / "vuln.json"
            write_metadata(metadata)

            with mock.patch("syzrun.api.fetch_artifacts"):
                with mock.patch("syzrun.api.KernelBuilder") as kernel_builder:
                    kernel_builder.return_value.build.side_effect = ToolchainError("prepare toolchain here")
                    with mock.patch("syzrun.api.logging.error") as log_error:
                        with mock.patch("syzrun.api.logging.exception") as log_exception:
                            result = run_vulnerability(
                                RunOptions(metadata=metadata, work_dir=root, timeout="20m")
                            )
            failure = json.loads(result.failure_json.read_text(encoding="utf-8"))

        self.assertEqual(result.exit_code, 2)
        self.assertEqual(result.error, "prepare toolchain here")
        self.assertEqual(failure["failure_kind"], "toolchain_unavailable")
        log_error.assert_called_once()
        log_exception.assert_not_called()

    def test_run_vulnerability_writes_command_failure_details(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata = root / "vuln.json"
            patch = root / "candidate.patch"
            write_metadata(metadata)
            patch.write_text("not a patch\n", encoding="utf-8")
            error = CommandError(
                "command failed (1): patch -p1 --forward -i user.patch",
                CommandResult(
                    args=["patch", "-p1", "--forward", "-i", str(root / "runs" / "abc123" / "input" / "user.patch")],
                    returncode=1,
                    output="",
                    duration_seconds=12.345,
                    timed_out=False,
                    log_path=root.resolve() / "runs" / "abc123" / "logs" / "kernel-patch.log",
                ),
            )

            with mock.patch("syzrun.api.fetch_artifacts"):
                with mock.patch("syzrun.api.KernelBuilder") as kernel_builder:
                    kernel_builder.return_value.build.side_effect = error
                    with mock.patch("syzrun.api.logging.exception"):
                        result = run_vulnerability(
                            RunOptions(metadata=metadata, patch=patch, work_dir=root, timeout="20m")
                        )
            failure = json.loads(result.failure_json.read_text(encoding="utf-8"))

        self.assertEqual(result.exit_code, 2)
        self.assertIsNotNone(result.failure_json)
        self.assertEqual(failure["failure_stage"], "kernel_patch")
        self.assertEqual(failure["failure_kind"], "apply_failed")
        self.assertEqual(failure["exit_code"], 1)
        self.assertEqual(failure["duration_seconds"], 12.35)
        self.assertFalse(failure["timed_out"])
        self.assertIn("patch -p1", failure["command"])
        self.assertTrue(failure["log_path"].endswith("kernel-patch.log"))
        self.assertEqual(failure["patch_path"], str(patch.resolve()))
        self.assertIsNotNone(failure["patch_sha256"])

    def test_ensure_kernel_source_checks_out_commit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata = root / "vuln.json"
            dest = root / "sources" / "linux"
            write_metadata(metadata)

            with mock.patch("syzrun.api.ensure_mirror_commit") as ensure_mirror:
                with mock.patch("syzrun.api.ensure_worktree_commit") as ensure_worktree:
                    result = ensure_kernel_source(metadata=metadata, work_dir=root, dest=dest, timeout="20m")

        self.assertEqual(result, dest.resolve())
        ensure_mirror.assert_called_once()
        ensure_worktree.assert_called_once_with(
            mirror=root.resolve() / "cache" / "linux.git",
            tree=dest.resolve(),
            commit="deadbeef",
            log_path=root.resolve() / "runs" / "abc123" / "logs" / "kernel-git.log",
            timeout=20 * 60,
        )


if __name__ == "__main__":
    unittest.main()
