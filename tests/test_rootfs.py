from pathlib import Path
import tempfile
import unittest

from syzrun.cache import WorkspaceLayout
from syzrun.repro.rootfs import RootfsLocator
from syzrun.runtime_profile import RootfsProfile, RuntimeProfile


class RootfsLocatorTests(unittest.TestCase):
    def test_uses_default_rootfs_without_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            layout = self._layout(Path(tmp))
            image, key = self._touch_rootfs(layout.root / "cache/rootfs")

            rootfs = RootfsLocator(layout).locate()

        self.assertEqual(rootfs.image, image.resolve())
        self.assertEqual(rootfs.ssh_key, key.resolve())
        self.assertEqual(rootfs.ssh_user, "root")

    def test_uses_profile_paths_relative_to_work_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            layout = self._layout(Path(tmp))
            image, key = self._touch_rootfs(layout.root / "cache/rootfs-firmware")
            profile = RuntimeProfile(
                rootfs=RootfsProfile(
                    image="cache/rootfs-firmware/rootfs.img",
                    ssh_key="cache/rootfs-firmware/id_rsa",
                    ssh_user="profile-user",
                )
            )

            rootfs = RootfsLocator(layout, profile).locate()

        self.assertEqual(rootfs.image, image.resolve())
        self.assertEqual(rootfs.ssh_key, key.resolve())
        self.assertEqual(rootfs.ssh_user, "profile-user")

    def test_missing_profile_image_reports_resolved_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            layout = self._layout(Path(tmp))
            profile = RuntimeProfile(
                rootfs=RootfsProfile(
                    image="cache/rootfs-firmware/rootfs.img",
                    ssh_key="cache/rootfs-firmware/id_rsa",
                )
            )

            with self.assertRaisesRegex(FileNotFoundError, str(layout.root / profile.rootfs.image)):
                RootfsLocator(layout, profile).locate()

    @staticmethod
    def _layout(root: Path) -> WorkspaceLayout:
        work_dir = root / "work"
        return WorkspaceLayout.create(work_dir, "test-vulnerability")

    @staticmethod
    def _touch_rootfs(directory: Path) -> tuple[Path, Path]:
        directory.mkdir(parents=True, exist_ok=True)
        image = directory / "rootfs.img"
        key = directory / "id_rsa"
        image.touch()
        key.touch()
        return image, key
