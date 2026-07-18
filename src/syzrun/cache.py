from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class WorkspaceLayout:
    root: Path
    vuln_id: str

    @classmethod
    def create(cls, root: Path, vuln_id: str) -> "WorkspaceLayout":
        layout = cls(root=root.resolve(), vuln_id=vuln_id)
        layout.ensure()
        return layout

    def ensure(self) -> None:
        for path in [
            self.cache_dir,
            self.download_cache_dir,
            self.run_dir,
            self.input_dir,
            self.kernel_dir,
            self.syzkaller_dir,
            self.logs_dir,
            self.report_dir,
        ]:
            ensure_dir(path)

    def reset_logs(self) -> None:
        if self.logs_dir.exists():
            shutil.rmtree(self.logs_dir)
        ensure_dir(self.logs_dir)

    @property
    def cache_dir(self) -> Path:
        return self.root / "cache"

    @property
    def download_cache_dir(self) -> Path:
        return self.cache_dir / "downloads"

    @property
    def linux_mirror(self) -> Path:
        return self.cache_dir / "linux.git"

    @property
    def syzkaller_mirror(self) -> Path:
        return self.cache_dir / "syzkaller.git"

    @property
    def rootfs_dir(self) -> Path:
        return self.cache_dir / "rootfs"

    @property
    def run_dir(self) -> Path:
        return self.root / "runs" / self.vuln_id

    @property
    def input_dir(self) -> Path:
        return self.run_dir / "input"

    @property
    def kernel_dir(self) -> Path:
        return self.run_dir / "kernel"

    @property
    def linux_tree(self) -> Path:
        return self.kernel_dir / "linux"

    @property
    def syzkaller_dir(self) -> Path:
        return self.run_dir / "syzkaller"

    @property
    def syzkaller_tree(self) -> Path:
        return self.syzkaller_dir / "src"

    @property
    def logs_dir(self) -> Path:
        return self.run_dir / "logs"

    @property
    def report_dir(self) -> Path:
        return self.run_dir


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path
