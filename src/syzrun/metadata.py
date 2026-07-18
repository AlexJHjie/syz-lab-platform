from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def safe_identifier(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in value)


@dataclass(frozen=True)
class FixCommit:
    title: str
    link: str
    hash: str
    repo: str
    branch: str


@dataclass(frozen=True)
class CrashMetadata:
    syz_reproducer: str
    c_reproducer: str | None
    kernel_config: str
    kernel_source_git: str
    kernel_source_commit: str
    syzkaller_git: str
    syzkaller_commit: str
    compiler_description: str
    architecture: str
    crash_report_link: str
    title: str | None = None


@dataclass(frozen=True)
class Vulnerability:
    source_path: Path
    version: int
    vuln_id: str
    title: str
    display_title: str
    status: str
    crash: CrashMetadata
    fix_commits: list[FixCommit]
    subsystems: list[str]
    parent_of_fix_commit: str | None
    raw: dict[str, Any]

    @classmethod
    def from_file(cls, path: Path) -> "Vulnerability":
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls.from_dict(data, path)

    @classmethod
    def from_dict(cls, data: dict[str, Any], path: Path | None = None) -> "Vulnerability":
        crashes = data.get("crashes") or []
        if not crashes:
            raise ValueError("metadata does not contain crashes[]")
        crash = crashes[0]

        required_crash_keys = [
            "syz-reproducer",
            "kernel-config",
            "kernel-source-git",
            "kernel-source-commit",
            "syzkaller-git",
            "syzkaller-commit",
            "compiler-description",
            "architecture",
            "crash-report-link",
        ]
        missing = [key for key in required_crash_keys if not crash.get(key)]
        if missing:
            raise ValueError(f"crash metadata missing required keys: {', '.join(missing)}")

        fix_commits = [
            FixCommit(
                title=str(item.get("title", "")),
                link=str(item.get("link", "")),
                hash=str(item.get("hash", "")),
                repo=str(item.get("repo", "")),
                branch=str(item.get("branch", "")),
            )
            for item in data.get("fix-commits", [])
        ]

        vuln_id = str(data.get("id") or (path.stem if path else "unknown"))
        return cls(
            source_path=path or Path(f"{vuln_id}.json"),
            version=int(data.get("version", 0)),
            vuln_id=vuln_id,
            title=str(data.get("title") or ""),
            display_title=str(data.get("display-title") or data.get("title") or ""),
            status=str(data.get("status") or ""),
            crash=CrashMetadata(
                title=crash.get("title") or None,
                syz_reproducer=str(crash["syz-reproducer"]),
                c_reproducer=crash.get("c-reproducer") or None,
                kernel_config=str(crash["kernel-config"]),
                kernel_source_git=str(crash["kernel-source-git"]),
                kernel_source_commit=str(crash["kernel-source-commit"]),
                syzkaller_git=str(crash["syzkaller-git"]),
                syzkaller_commit=str(crash["syzkaller-commit"]),
                compiler_description=str(crash["compiler-description"]),
                architecture=str(crash["architecture"]),
                crash_report_link=str(crash["crash-report-link"]),
            ),
            fix_commits=fix_commits,
            subsystems=[str(item) for item in data.get("subsystems", [])],
            parent_of_fix_commit=data.get("parent_of_fix_commit"),
            raw=data,
        )

    @property
    def safe_id(self) -> str:
        return safe_identifier(self.vuln_id)
