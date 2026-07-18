from __future__ import annotations

import json
import logging
import os
import hashlib
from dataclasses import dataclass
from pathlib import Path

from .builder.kernel import DEFAULT_LINUX_REPO, KernelBuilder
from .builder.syzkaller import SyzkallerBuilder
from .builder.toolchain import ToolchainError
from .cache import WorkspaceLayout
from .fetcher import DEFAULT_SYZBOT_BASE_URL, fetch_artifacts
from .metadata import Vulnerability, safe_identifier
from .repro.monitor import ReproductionRunner
from .reports.report import RunReport, write_report
from .runtime_profile import load_runtime_profile
from .utils.command import CommandError, format_cmd
from .utils.git import ensure_mirror_commit, ensure_worktree_commit
from .utils.timeout import parse_duration


@dataclass(frozen=True)
class RunOptions:
    metadata: Path
    patch: Path | None = None
    work_dir: Path = Path("work")
    timeout: str | int | float | None = "30m"


@dataclass(frozen=True)
class RunResult:
    exit_code: int
    report: RunReport | None
    report_json: Path | None
    report_markdown: Path | None
    failure_json: Path | None = None
    error: str | None = None


def run_vulnerability(options: RunOptions) -> RunResult:
    timeout = parse_duration(options.timeout)
    metadata_path = options.metadata.resolve()
    patch_path = options.patch.resolve() if options.patch else None
    work_dir = options.work_dir.resolve()
    current_stage = "infra"
    layout: WorkspaceLayout | None = None

    try:
        current_stage = "metadata_load"
        vuln = Vulnerability.from_file(metadata_path)
        runtime_profile = load_runtime_profile(vuln)
        layout = WorkspaceLayout.create(work_dir, vuln.safe_id)
        layout.reset_logs()

        logging.info("loading metadata: %s", metadata_path)
        logging.info("run directory: %s", layout.run_dir)

        current_stage = "asset_fetch"
        fetched = fetch_artifacts(
            vuln,
            layout,
            syzbot_base_url=os.environ.get("PLATFORM_SYZBOT_BASE_URL", DEFAULT_SYZBOT_BASE_URL),
        )

        logging.info("building kernel commit %s", vuln.crash.kernel_source_commit)
        current_stage = "kernel_build"
        kernel = KernelBuilder(
            layout,
            vuln,
            fetched,
            patch_file=patch_path,
            runtime_profile=runtime_profile,
            timeout=timeout,
        ).build()

        logging.info("building syzkaller commit %s", vuln.crash.syzkaller_commit)
        current_stage = "syzkaller_build"
        syzkaller = SyzkallerBuilder(layout, vuln, timeout=timeout).build()

        logging.info("booting VM and running syz repro")
        current_stage = "reproduce"
        repro = ReproductionRunner(
            layout=layout,
            vuln=vuln,
            kernel=kernel,
            syzkaller=syzkaller,
            fetched=fetched,
            runtime_profile=runtime_profile,
            timeout=timeout,
        ).run()
        verdict = repro.verdict

        report = RunReport.create(
            vuln=vuln,
            work_dir=layout.run_dir,
            logs_dir=layout.logs_dir,
            patch_applied=patch_path,
            repro_result=repro,
            verdict=verdict,
        )
        current_stage = "report_parse"
        json_report, md_report = write_report(report, layout.report_dir)
        exit_code = _exit_code_for_verdict(verdict.status)
        return RunResult(exit_code=exit_code, report=report, report_json=json_report, report_markdown=md_report)
    except Exception as exc:
        if isinstance(exc, ToolchainError):
            logging.error("run stopped safely:\n%s", exc)
        else:
            logging.exception("run failed")
        failure_json = _write_failure_report_if_possible(
            metadata_path=metadata_path,
            work_dir=work_dir,
            patch_path=patch_path,
            exc=exc,
            current_stage=current_stage,
            layout=layout,
        )
        return RunResult(
            exit_code=2,
            report=None,
            report_json=None,
            report_markdown=None,
            failure_json=failure_json,
            error=str(exc),
        )


def ensure_kernel_source(
    *,
    metadata: Path,
    work_dir: Path = Path("work"),
    dest: Path | None = None,
    timeout: str | int | float | None = "30m",
) -> Path:
    vuln = Vulnerability.from_file(metadata.resolve())
    work_root = work_dir.resolve()
    layout = WorkspaceLayout.create(work_root, vuln.safe_id)
    timeout_seconds = parse_duration(timeout)
    source = (dest or (work_root / "patchagent-sources" / vuln.safe_id / "linux")).resolve()
    log_path = layout.logs_dir / "kernel-git.log"
    repo = os.environ.get("PLATFORM_LINUX_REPO", DEFAULT_LINUX_REPO)

    ensure_mirror_commit(
        repo=repo,
        mirror=layout.linux_mirror,
        commit=vuln.crash.kernel_source_commit,
        log_path=log_path,
        timeout=timeout_seconds,
    )
    ensure_worktree_commit(
        mirror=layout.linux_mirror,
        tree=source,
        commit=vuln.crash.kernel_source_commit,
        log_path=log_path,
        timeout=timeout_seconds,
    )
    return source


def _exit_code_for_verdict(status: str) -> int:
    if status == "failed":
        return 2
    return 0 if status in {"reproduced", "crashed_other"} else 1


def _write_failure_report_if_possible(
    *,
    metadata_path: Path,
    work_dir: Path,
    patch_path: Path | None,
    exc: Exception,
    current_stage: str,
    layout: WorkspaceLayout | None,
) -> Path | None:
    try:
        try:
            vuln = Vulnerability.from_file(metadata_path)
            vuln_id = vuln.vuln_id
            safe_id = vuln.safe_id
        except Exception:
            vuln_id = metadata_path.stem or "unknown"
            safe_id = safe_identifier(vuln_id)
        layout = layout or WorkspaceLayout.create(work_dir, safe_id)
        failure_stage, failure_kind = _classify_failure(exc, current_stage)
        command, exit_code, duration_seconds, timed_out, log_path = _command_failure_fields(exc)
        copied_patch = layout.input_dir / "user.patch"
        effective_patch = copied_patch if copied_patch.is_file() else patch_path
        failure = {
            "vuln_id": vuln_id,
            "status": "failed",
            "failure_stage": failure_stage,
            "failure_kind": failure_kind,
            "error": str(exc),
            "command": command,
            "exit_code": exit_code,
            "duration_seconds": duration_seconds,
            "timed_out": timed_out,
            "logs_dir": str(layout.logs_dir),
            "log_path": str(log_path) if log_path else None,
            "patch_path": str(effective_patch) if effective_patch else None,
            "patch_sha256": _sha256(effective_patch) if effective_patch and effective_patch.is_file() else None,
            "work_dir": str(layout.run_dir),
        }
        path = layout.report_dir / "failure.json"
        path.write_text(json.dumps(failure, indent=2, sort_keys=True), encoding="utf-8")
        return path
    except Exception:
        return None


def _classify_failure(exc: Exception, current_stage: str) -> tuple[str, str]:
    if isinstance(exc, ToolchainError):
        return "kernel_build", "toolchain_unavailable"
    if isinstance(exc, CommandError) and exc.result and exc.result.log_path:
        stage = _stage_from_log_path(exc.result.log_path)
        if stage:
            return stage, _kind_for_stage(stage, timed_out=exc.result.timed_out)
    if isinstance(exc, ValueError) and current_stage == "metadata_load":
        return "metadata_load", "invalid_metadata"
    if current_stage == "asset_fetch":
        return "asset_fetch", "download_failed"
    if current_stage in {"kernel_build", "syzkaller_build"}:
        return current_stage, "compile_error"
    if current_stage == "reproduce":
        return "reproduce", "repro_failed"
    if current_stage == "report_parse":
        return "report_parse", "parse_failed"
    return current_stage, "internal_error"


def _stage_from_log_path(log_path: Path) -> str | None:
    name = log_path.name
    if name == "kernel-patch.log":
        return "kernel_patch"
    if name in {"kernel-git.log"}:
        return "kernel_checkout"
    if name == "kernel-build.log":
        return "kernel_build"
    if name == "syzkaller-git.log":
        return "syzkaller_checkout"
    if name == "syzkaller-build.log":
        return "syzkaller_build"
    if name in {"qemu.log", "ssh.log", "scp.log"}:
        return "vm_boot"
    if name == "repro.log":
        return "reproduce"
    return None


def _kind_for_stage(stage: str, *, timed_out: bool) -> str:
    if timed_out:
        return "timeout"
    if stage == "kernel_patch":
        return "apply_failed"
    if stage in {"kernel_build", "syzkaller_build"}:
        return "compile_error"
    if stage in {"kernel_checkout", "syzkaller_checkout"}:
        return "checkout_failed"
    if stage == "vm_boot":
        return "vm_failed"
    if stage == "reproduce":
        return "repro_failed"
    return "command_failed"


def _command_failure_fields(exc: Exception) -> tuple[str | None, int | None, float | None, bool, Path | None]:
    if not isinstance(exc, CommandError) or not exc.result:
        return None, None, None, False, None
    result = exc.result
    return (
        format_cmd(result.args),
        result.returncode,
        round(result.duration_seconds, 2),
        result.timed_out,
        result.log_path,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
