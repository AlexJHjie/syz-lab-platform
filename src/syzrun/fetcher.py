from __future__ import annotations

import hashlib
import shutil
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin

from .cache import WorkspaceLayout
from .metadata import Vulnerability

DEFAULT_SYZBOT_BASE_URL = "https://syzkaller.appspot.com"


@dataclass(frozen=True)
class FetchedArtifacts:
    metadata_json: Path
    kernel_config: Path
    syz_reproducer: Path
    crash_report: Path


def resolve_syzbot_url(ref: str, base_url: str = DEFAULT_SYZBOT_BASE_URL) -> str:
    if ref.startswith("http://") or ref.startswith("https://"):
        return ref
    if ref.startswith("/"):
        return urljoin(base_url.rstrip("/") + "/", ref.lstrip("/"))
    return ref


def fetch_artifacts(
    vuln: Vulnerability,
    layout: WorkspaceLayout,
    *,
    syzbot_base_url: str = DEFAULT_SYZBOT_BASE_URL,
) -> FetchedArtifacts:
    metadata_dst = layout.input_dir / "vuln.json"
    shutil.copy2(vuln.source_path, metadata_dst)

    kernel_config = _download_cached(
        vuln.crash.kernel_config,
        layout,
        "kernel.config",
        syzbot_base_url,
    )
    syz_reproducer = _download_cached(
        vuln.crash.syz_reproducer,
        layout,
        "repro.syz",
        syzbot_base_url,
    )
    crash_report = _download_cached(
        vuln.crash.crash_report_link,
        layout,
        "crash.report",
        syzbot_base_url,
    )
    return FetchedArtifacts(
        metadata_json=metadata_dst,
        kernel_config=kernel_config,
        syz_reproducer=syz_reproducer,
        crash_report=crash_report,
    )


def _download_cached(ref: str, layout: WorkspaceLayout, filename: str, base_url: str) -> Path:
    url = resolve_syzbot_url(ref, base_url)
    cache_key = hashlib.sha256(url.encode("utf-8")).hexdigest()
    cache_path = layout.download_cache_dir / cache_key
    dst = layout.input_dir / filename

    if not cache_path.exists():
        request = urllib.request.Request(url, headers={"User-Agent": "syzrun/0.1"})
        with urllib.request.urlopen(request, timeout=60) as response:
            data = response.read()
        cache_path.write_bytes(data)

    shutil.copy2(cache_path, dst)
    return dst
