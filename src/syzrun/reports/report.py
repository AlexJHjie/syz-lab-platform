from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from ..metadata import Vulnerability
from ..repro.monitor import ReproResult
from ..repro.verdict import Verdict


@dataclass(frozen=True)
class RunReport:
    vuln_id: str
    title: str
    kernel_commit: str
    syzkaller_commit: str
    architecture: str
    patch_applied: str | None
    work_dir: str
    syz_exit_code: int | None
    syz_command: str | None
    verdict_status: str
    verdict_reason: str
    verdict_matched: str | None
    verdict_source_log: str | None
    logs_dir: str
    attempts: list[dict[str, Any]]

    @classmethod
    def create(
        cls,
        *,
        vuln: Vulnerability,
        work_dir: Path,
        logs_dir: Path,
        patch_applied: Path | None,
        repro_result: ReproResult,
        verdict: Verdict,
    ) -> "RunReport":
        return cls(
            vuln_id=vuln.vuln_id,
            title=vuln.title,
            kernel_commit=vuln.crash.kernel_source_commit,
            syzkaller_commit=vuln.crash.syzkaller_commit,
            architecture=vuln.crash.architecture,
            patch_applied=str(patch_applied) if patch_applied else None,
            work_dir=str(work_dir),
            syz_exit_code=repro_result.syz.exit_code if repro_result.syz else None,
            syz_command=repro_result.syz.remote_command if repro_result.syz else None,
            verdict_status=verdict.status,
            verdict_reason=verdict.reason,
            verdict_matched=verdict.matched,
            verdict_source_log=verdict.source_log,
            logs_dir=str(logs_dir),
            attempts=[
                {
                    "number": attempt.number,
                    "status": attempt.status,
                    "matched": attempt.matched,
                    "reason": attempt.reason,
                    "duration_seconds": round(attempt.duration_seconds, 2),
                    "logs_dir": str(attempt.logs_dir),
                    "exit_code": attempt.syz.exit_code if attempt.syz else None,
                    "error": attempt.error,
                    "source_log": attempt.source_log,
                }
                for attempt in repro_result.attempts
            ],
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def write_report(report: RunReport, report_dir: Path) -> tuple[Path, Path]:
    report_dir.mkdir(parents=True, exist_ok=True)
    json_path = report_dir / "report.json"
    md_path = report_dir / "report.md"

    json_path.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    md_path.write_text(_render_markdown(report), encoding="utf-8")
    return json_path, md_path


def _render_markdown(report: RunReport) -> str:
    lines = [
        f"# {report.vuln_id}",
        "",
        f"- title: {report.title}",
        f"- kernel commit: `{report.kernel_commit}`",
        f"- syzkaller commit: `{report.syzkaller_commit}`",
        f"- architecture: `{report.architecture}`",
        f"- patch applied: `{report.patch_applied or 'none'}`",
        f"- verdict: `{report.verdict_status}`",
        f"- reason: {report.verdict_reason}",
        f"- matched: `{report.verdict_matched or 'none'}`",
        f"- source log: `{report.verdict_source_log or 'none'}`",
        f"- syz exit code: `{report.syz_exit_code if report.syz_exit_code is not None else 'none'}`",
        f"- logs: `{report.logs_dir}`",
    ]
    if report.syz_command:
        lines.extend(["", "## syz command", "", f"```sh\n{report.syz_command}\n```"])
    lines.extend(["", "## attempts", ""])
    for attempt in report.attempts:
        lines.append(
            f"- attempt {attempt['number']}: `{attempt['status']}` "
            f"({attempt['duration_seconds']}s), matched: `{attempt['matched'] or 'none'}`, "
            f"source: `{attempt['source_log'] or 'none'}`, "
            f"logs: `{attempt['logs_dir']}`"
        )
    return "\n".join(lines) + "\n"
