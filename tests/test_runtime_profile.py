from pathlib import Path
import tempfile
import unittest

from syzrun.metadata import Vulnerability
from syzrun.runtime_profile import RuntimeProfileError, load_runtime_profile


def make_vuln(vuln_id: str = "abc123") -> Vulnerability:
    return Vulnerability.from_dict(
        {
            "version": 1,
            "title": "KASAN: test crash",
            "display-title": "KASAN: test crash",
            "id": vuln_id,
            "status": "fixed",
            "crashes": [
                {
                    "syz-reproducer": "/text?tag=ReproSyz&x=1",
                    "kernel-config": "/text?tag=KernelConfig&x=2",
                    "kernel-source-git": "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
                    "kernel-source-commit": "deadbeef",
                    "syzkaller-git": "https://github.com/google/syzkaller",
                    "syzkaller-commit": "cafebabe",
                    "compiler-description": "gcc (Debian 10.2.1-6) 10.2.1",
                    "architecture": "amd64",
                    "crash-report-link": "/text?tag=CrashReport&x=3",
                }
            ],
        }
    )


class RuntimeProfileTests(unittest.TestCase):
    def test_missing_config_returns_empty_profile(self) -> None:
        profile = load_runtime_profile(make_vuln(), Path("does-not-exist.json"))

        self.assertEqual(profile.build_env, {})
        self.assertEqual(profile.make_args, [])
        self.assertEqual(profile.qemu_append, [])
        self.assertEqual(profile.qemu_args, [])
        self.assertEqual(profile.repro_env, {})
        self.assertEqual(profile.execprog_args, [])
        self.assertIsNone(profile.rootfs)

    def test_unmatched_vulnerability_returns_empty_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profiles.json"
            path.write_text('{"vulnerabilities": {"other": {"qemu_append": ["foo=1"]}}}', encoding="utf-8")

            profile = load_runtime_profile(make_vuln("abc123"), path)

        self.assertEqual(profile.qemu_append, [])

    def test_loads_matching_vulnerability_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profiles.json"
            path.write_text(
                """
                {
                  "vulnerabilities": {
                    "abc123": {
                      "build_env": {"KCFLAGS": "-fcf-protection=none"},
                      "make_args": ["LLVM=1"],
                      "qemu_append": ["systemd.unified_cgroup_hierarchy=0"],
                      "qemu_args": ["-no-reboot"],
                      "repro_env": {"FOO": "bar"},
                      "execprog_args": ["-disable=cgroups"],
                      "rootfs": {
                        "image": "cache/rootfs-firmware/rootfs.img",
                        "ssh_key": "cache/rootfs-firmware/id_rsa",
                        "ssh_user": "admin"
                      }
                    }
                  }
                }
                """,
                encoding="utf-8",
            )

            profile = load_runtime_profile(make_vuln("abc123"), path)

        self.assertEqual(profile.build_env, {"KCFLAGS": "-fcf-protection=none"})
        self.assertEqual(profile.make_args, ["LLVM=1"])
        self.assertEqual(profile.qemu_append, ["systemd.unified_cgroup_hierarchy=0"])
        self.assertEqual(profile.qemu_args, ["-no-reboot"])
        self.assertEqual(profile.repro_env, {"FOO": "bar"})
        self.assertEqual(profile.execprog_args, ["-disable=cgroups"])
        self.assertIsNotNone(profile.rootfs)
        self.assertEqual(profile.rootfs.image, "cache/rootfs-firmware/rootfs.img")
        self.assertEqual(profile.rootfs.ssh_key, "cache/rootfs-firmware/id_rsa")
        self.assertEqual(profile.rootfs.ssh_user, "admin")

    def test_rejects_invalid_field_type(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profiles.json"
            path.write_text('{"vulnerabilities": {"abc123": {"qemu_append": "bad"}}}', encoding="utf-8")

            with self.assertRaises(RuntimeProfileError):
                load_runtime_profile(make_vuln("abc123"), path)

    def test_rejects_incomplete_rootfs_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profiles.json"
            path.write_text(
                '{"vulnerabilities": {"abc123": {"rootfs": {"image": "rootfs.img"}}}}',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(RuntimeProfileError, "rootfs.ssh_key"):
                load_runtime_profile(make_vuln("abc123"), path)

    def test_rejects_invalid_execprog_args(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profiles.json"
            path.write_text(
                '{"vulnerabilities": {"abc123": {"execprog_args": "-disable=cgroups"}}}',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(RuntimeProfileError, "execprog_args"):
                load_runtime_profile(make_vuln("abc123"), path)


if __name__ == "__main__":
    unittest.main()
