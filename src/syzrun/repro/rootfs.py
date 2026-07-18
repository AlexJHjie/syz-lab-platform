from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..cache import WorkspaceLayout
from ..runtime_profile import RuntimeProfile


@dataclass(frozen=True)
class Rootfs:
    image: Path
    ssh_key: Path
    ssh_user: str


class RootfsLocator:
    def __init__(self, layout: WorkspaceLayout, runtime_profile: RuntimeProfile | None = None) -> None:
        self.layout = layout
        self.runtime_profile = runtime_profile or RuntimeProfile.empty()

    def locate(self) -> Rootfs:
        profile = self.runtime_profile.rootfs
        default_image = self.layout.rootfs_dir / "rootfs.img"
        default_ssh_key = self.layout.rootfs_dir / "id_rsa"

        image = _configured_path(profile.image if profile else None, default_image, self.layout.root)
        ssh_key = _configured_path(profile.ssh_key if profile else None, default_ssh_key, self.layout.root)
        ssh_user = profile.ssh_user if profile else "root"

        if not image.is_file():
            raise FileNotFoundError(
                f"rootfs image not found: {image}. Configure rootfs.image for this vulnerability "
                "or run scripts/create_rootfs.sh"
            )
        if not ssh_key.is_file():
            raise FileNotFoundError(
                f"SSH private key not found: {ssh_key}. Configure rootfs.ssh_key for this vulnerability "
                "or run scripts/create_rootfs.sh"
            )
        return Rootfs(image=image.resolve(), ssh_key=ssh_key.resolve(), ssh_user=ssh_user)


def _configured_path(profile: str | None, default: Path, work_dir: Path) -> Path:
    if profile is not None:
        path = Path(profile).expanduser()
        return path if path.is_absolute() else work_dir / path
    return default
