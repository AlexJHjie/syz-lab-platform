from pathlib import Path
import tempfile
import unittest
from unittest import mock

from syzrun.builder.syzkaller import SyzkallerArtifacts
from syzrun.repro.syz_execprog import start_syz_repro


class FakeVM:
    def __init__(self, logs_dir: Path) -> None:
        self.logs_dir = logs_dir
        self.copied: list[tuple[Path, str]] = []
        self.commands: list[str] = []

    def scp_to(self, local: Path, remote: str) -> None:
        self.copied.append((local, remote))

    def ssh(self, remote_command: str, *, timeout: int | None, log_path: Path) -> int:
        self.commands.append(remote_command)
        return 0

    def start_ssh(self, remote_command: str, *, log_path: Path):
        self.commands.append(remote_command)
        return mock.Mock()


class SyzExecprogTests(unittest.TestCase):
    def test_start_syz_repro_includes_runtime_environment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repro = root / "repro.syz"
            repro.write_text('# {"threaded": false, "procs": 2}\n', encoding="utf-8")
            syzkaller = SyzkallerArtifacts(
                tree=root / "syzkaller",
                execprog=root / "syz-execprog",
                executor=root / "syz-executor",
            )
            vm = FakeVM(root / "logs")

            _, remote_command = start_syz_repro(
                vm=vm,
                syzkaller=syzkaller,
                repro_file=repro,
                timeout=30,
                env={"FOO": "bar baz", "ALPHA": "1"},
            )

        self.assertIn("timeout 30s env ALPHA=1 'FOO=bar baz' /root/syz-execprog", remote_command)
        self.assertIn("-threaded=0", remote_command)
        self.assertIn("-procs=2", remote_command)
        self.assertEqual(vm.commands[-1], remote_command)


if __name__ == "__main__":
    unittest.main()
