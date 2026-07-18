from __future__ import annotations

import os
import time
from pathlib import Path

from .command import CommandError, run


def ensure_mirror_commit(
    *,
    repo: str,
    mirror: Path,
    commit: str,
    log_path: Path,
    timeout: int | None,
) -> None:
    if not mirror.exists():
        run(["git", "clone", "--mirror", repo, str(mirror)], timeout=timeout, log_path=log_path)
    else:
        run(["git", "remote", "set-url", "origin", repo], cwd=mirror, log_path=log_path)

    cached = mirror_has_commit(mirror, commit)
    refresh = os.environ.get("PLATFORM_REFRESH_REPOS") == "1"
    if cached and not refresh:
        return

    if refresh:
        _fetch_with_retries(
            ["git", "fetch", "--prune", "origin"],
            cwd=mirror,
            timeout=timeout,
            log_path=log_path,
        )
    else:
        try:
            _fetch_with_retries(
                ["git", "fetch", "origin", commit],
                cwd=mirror,
                timeout=timeout,
                log_path=log_path,
            )
        except CommandError:
            _fetch_with_retries(
                ["git", "fetch", "--prune", "origin"],
                cwd=mirror,
                timeout=timeout,
                log_path=log_path,
            )

    if not mirror_has_commit(mirror, commit):
        raise RuntimeError(f"repository does not contain commit {commit}: {repo}")


def ensure_worktree_commit(
    *,
    mirror: Path,
    tree: Path,
    commit: str,
    log_path: Path,
    timeout: int | None,
) -> None:
    if not tree.exists():
        tree.parent.mkdir(parents=True, exist_ok=True)
        run(["git", "clone", str(mirror), str(tree)], timeout=timeout, log_path=log_path)

    run(["git", "fetch", "origin", commit], cwd=tree, timeout=timeout, log_path=log_path)
    run(["git", "checkout", "--force", commit], cwd=tree, timeout=timeout, log_path=log_path)
    run(["git", "reset", "--hard", commit], cwd=tree, timeout=timeout, log_path=log_path)
    run(["git", "clean", "-fdx"], cwd=tree, timeout=timeout, log_path=log_path)


def mirror_has_commit(mirror: Path, commit: str) -> bool:
    result = run(
        ["git", "cat-file", "-e", f"{commit}^{{commit}}"],
        cwd=mirror,
        check=False,
    )
    return result.returncode == 0


def _fetch_with_retries(
    args: list[str],
    *,
    cwd: Path,
    timeout: int | None,
    log_path: Path,
) -> None:
    attempts = max(1, int(os.environ.get("PLATFORM_GIT_RETRIES", "3")))
    for attempt in range(1, attempts + 1):
        try:
            run(args, cwd=cwd, timeout=timeout, log_path=log_path)
            return
        except CommandError:
            if attempt == attempts:
                raise
            time.sleep(2)
