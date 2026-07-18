from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from ..cache import WorkspaceLayout
from ..fetcher import FetchedArtifacts
from ..metadata import Vulnerability
from ..runtime_profile import RuntimeProfile
from ..utils.command import CommandError, run
from ..utils.git import ensure_mirror_commit, ensure_worktree_commit
from .toolchain import Toolchain, ensure_toolchain, make_jobs, target_from_arch

DEFAULT_LINUX_REPO = "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"


@dataclass(frozen=True)
class KernelArtifacts:
    tree: Path
    bz_image: Path
    vmlinux: Path
    config: Path
    toolchain: Toolchain | None = None


class KernelBuilder:
    def __init__(
        self,
        layout: WorkspaceLayout,
        vuln: Vulnerability,
        fetched: FetchedArtifacts,
        *,
        patch_file: Path | None = None,
        runtime_profile: RuntimeProfile | None = None,
        timeout: int | None = None,
    ) -> None:
        self.layout = layout
        self.vuln = vuln
        self.fetched = fetched
        self.patch_file = patch_file
        self.runtime_profile = runtime_profile or RuntimeProfile.empty()
        self.timeout = timeout
        self.target = target_from_arch(vuln.crash.architecture)
        self.log_git = layout.logs_dir / "kernel-git.log"
        self.log_build = layout.logs_dir / "kernel-build.log"
        self.log_patch = layout.logs_dir / "kernel-patch.log"
        self.toolchain: Toolchain | None = None

    def build(self) -> KernelArtifacts:
        self.toolchain = ensure_toolchain(
            self.vuln.crash.compiler_description,
        )
        self._ensure_mirror()
        self._ensure_tree()
        self._install_config()
        if self.patch_file:
            apply_external_patch(self.layout.linux_tree, self.patch_file, self.log_patch, self.timeout)
        self._olddefconfig()
        self._make_kernel()
        return KernelArtifacts(
            tree=self.layout.linux_tree,
            bz_image=self.layout.linux_tree / "arch" / "x86" / "boot" / "bzImage",
            vmlinux=self.layout.linux_tree / "vmlinux",
            config=self.layout.linux_tree / ".config",
            toolchain=self.toolchain,
        )

    def _ensure_mirror(self) -> None:
        repo = os.environ.get("PLATFORM_LINUX_REPO", DEFAULT_LINUX_REPO)
        ensure_mirror_commit(
            repo=repo,
            mirror=self.layout.linux_mirror,
            commit=self.vuln.crash.kernel_source_commit,
            log_path=self.log_git,
            timeout=self.timeout,
        )

    def _ensure_tree(self) -> None:
        ensure_worktree_commit(
            mirror=self.layout.linux_mirror,
            tree=self.layout.linux_tree,
            commit=self.vuln.crash.kernel_source_commit,
            log_path=self.log_git,
            timeout=self.timeout,
        )

    def _install_config(self) -> None:
        shutil.copy2(self.fetched.kernel_config, self.layout.linux_tree / ".config")

    def _olddefconfig(self) -> None:
        if self.toolchain is None:
            raise RuntimeError("kernel toolchain was not prepared")
        env = self.toolchain.environment()
        env.update(self.runtime_profile.build_env)
        run(
            [
                "make",
                f"ARCH={self.target.kernel_arch}",
                *self.toolchain.make_variables(),
                "olddefconfig",
            ],
            cwd=self.layout.linux_tree,
            env=env,
            timeout=self.timeout,
            log_path=self.log_build,
        )

    def _make_kernel(self) -> None:
        if self.toolchain is None:
            raise RuntimeError("kernel toolchain was not prepared")
        env = self.toolchain.environment()
        env.update(self.runtime_profile.build_env)
        jobs = make_jobs()
        run(
            [
                "make",
                f"ARCH={self.target.kernel_arch}",
                f"-j{jobs}",
                *self.runtime_profile.make_args,
                *self.toolchain.make_variables(),
                "bzImage",
            ],
            cwd=self.layout.linux_tree,
            env=env,
            timeout=self.timeout,
            log_path=self.log_build,
        )

        bz_image = self.layout.linux_tree / "arch" / "x86" / "boot" / "bzImage"
        if not bz_image.is_file():
            raise FileNotFoundError(f"kernel build did not produce bzImage: {bz_image}")


def apply_external_patch(kernel_tree: Path, patch_file: Path, log_path: Path, timeout: int | None) -> None:
    if not patch_file.is_file():
        raise FileNotFoundError(f"patch file does not exist: {patch_file}")

    dst = kernel_tree.parent.parent / "input" / "user.patch"
    shutil.copy2(patch_file, dst)

    try:
        run(["git", "apply", "--check", str(dst)], cwd=kernel_tree, timeout=timeout, log_path=log_path)
        run(["git", "apply", str(dst)], cwd=kernel_tree, timeout=timeout, log_path=log_path)
    except CommandError:
        run(["patch", "-p1", "--forward", "-i", str(dst)], cwd=kernel_tree, timeout=timeout, log_path=log_path)
