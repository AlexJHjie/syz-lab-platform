from __future__ import annotations

import logging
import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from ..cache import WorkspaceLayout
from ..metadata import Vulnerability
from ..utils.command import run
from ..utils.git import ensure_mirror_commit, ensure_worktree_commit
from .toolchain import target_from_arch

DEFAULT_SYZKALLER_REPO = "https://github.com/google/syzkaller.git"


@dataclass(frozen=True)
class SyzkallerArtifacts:
    tree: Path
    execprog: Path
    executor: Path
    symbolizer: Path | None = None


class SyzkallerBuilder:
    def __init__(self, layout: WorkspaceLayout, vuln: Vulnerability, *, timeout: int | None = None) -> None:
        self.layout = layout
        self.vuln = vuln
        self.timeout = timeout
        self.target = target_from_arch(vuln.crash.architecture)
        self.log_git = layout.logs_dir / "syzkaller-git.log"
        self.log_build = layout.logs_dir / "syzkaller-build.log"

    def build(self) -> SyzkallerArtifacts:
        if not shutil.which("go"):
            raise FileNotFoundError("go is required to build syzkaller, but it was not found in PATH")
        self._ensure_mirror()
        self._ensure_tree()
        build_tree, env = self._make_tools()
        symbolizer = self._prepare_symbolizer(build_tree, env)
        artifacts = SyzkallerArtifacts(
            tree=self.layout.syzkaller_tree,
            execprog=(
                self.layout.syzkaller_tree / "bin" / f"linux_{self.target.syzkaller_arch}" / "syz-execprog"
            ),
            executor=self.layout.syzkaller_tree / "bin" / f"linux_{self.target.syzkaller_arch}" / "syz-executor",
            symbolizer=symbolizer,
        )
        if not artifacts.execprog.is_file() or not artifacts.executor.is_file():
            raise FileNotFoundError("syzkaller build did not produce syz-execprog and syz-executor")
        return artifacts

    def _ensure_mirror(self) -> None:
        repo = os.environ.get("PLATFORM_SYZKALLER_REPO", DEFAULT_SYZKALLER_REPO)
        ensure_mirror_commit(
            repo=repo,
            mirror=self.layout.syzkaller_mirror,
            commit=self.vuln.crash.syzkaller_commit,
            log_path=self.log_git,
            timeout=self.timeout,
        )

    def _ensure_tree(self) -> None:
        ensure_worktree_commit(
            mirror=self.layout.syzkaller_mirror,
            tree=self.layout.syzkaller_tree,
            commit=self.vuln.crash.syzkaller_commit,
            log_path=self.log_git,
            timeout=self.timeout,
        )

    def _make_tools(self) -> tuple[Path, dict[str, str]]:
        build_tree = self.layout.syzkaller_tree
        env = {
            "TARGETOS": "linux",
            "TARGETARCH": self.target.syzkaller_arch,
        }

        if not (self.layout.syzkaller_tree / "go.mod").is_file():
            build_tree = self._prepare_legacy_gopath()
            env.update(
                {
                    "GO111MODULE": "off",
                    "GOPATH": str(self.layout.syzkaller_dir / "gopath"),
                    "PWD": str(build_tree),
                }
            )

        targets = _select_make_targets(self.layout.syzkaller_tree / "Makefile")
        run(
            ["make", *targets],
            cwd=build_tree,
            env=env,
            timeout=self.timeout,
            log_path=self.log_build,
        )
        return build_tree, env

    def _prepare_symbolizer(self, build_tree: Path, env: dict[str, str]) -> Path | None:
        symbolizer = self.layout.syzkaller_tree / "bin" / "syz-symbolize"
        if symbolizer.is_file() and os.access(symbolizer, os.X_OK):
            return symbolizer

        makefile = self.layout.syzkaller_tree / "Makefile"
        targets = _make_targets(makefile)
        try:
            if "symbolize" in targets:
                args = ["make", "symbolize"]
            elif "syz-symbolize" in targets:
                args = ["make", "syz-symbolize"]
            elif (self.layout.syzkaller_tree / "tools" / "syz-symbolize").is_dir():
                package = (
                    "github.com/google/syzkaller/tools/syz-symbolize"
                    if env.get("GO111MODULE") == "off"
                    else "./tools/syz-symbolize"
                )
                symbolizer.parent.mkdir(parents=True, exist_ok=True)
                args = ["go", "build", "-o", str(symbolizer), package]
            else:
                logging.warning(
                    "syz-symbolize source is unavailable in syzkaller commit %s",
                    self.vuln.crash.syzkaller_commit,
                )
                return None

            run(
                args,
                cwd=build_tree,
                env=env,
                timeout=self.timeout,
                log_path=self.log_build,
            )
        except Exception as exc:
            logging.warning("failed to build syz-symbolize: %s", exc)
            return None

        if not symbolizer.is_file() or not os.access(symbolizer, os.X_OK):
            logging.warning("syz-symbolize build did not produce an executable: %s", symbolizer)
            return None
        return symbolizer

    def _prepare_legacy_gopath(self) -> Path:
        gopath = self.layout.syzkaller_dir / "gopath"
        build_tree = gopath / "src" / "github.com" / "google" / "syzkaller"
        if gopath.exists():
            shutil.rmtree(gopath)
        build_tree.parent.mkdir(parents=True, exist_ok=True)
        build_tree.symlink_to(self.layout.syzkaller_tree, target_is_directory=True)
        return build_tree


def _select_make_targets(makefile: Path) -> tuple[str, str]:
    targets = _make_targets(makefile)
    if {"syz-execprog", "syz-executor"}.issubset(targets):
        return "syz-execprog", "syz-executor"
    if {"execprog", "executor"}.issubset(targets):
        return "execprog", "executor"
    raise RuntimeError(f"unsupported syzkaller Makefile targets: {makefile}")


def _make_targets(makefile: Path) -> set[str]:
    text = makefile.read_text(encoding="utf-8", errors="replace")
    return {
        line.split(":", 1)[0].strip()
        for line in text.splitlines()
        if line and not line[0].isspace() and ":" in line
    }
