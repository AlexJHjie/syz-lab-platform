from __future__ import annotations

import os
import socket
import subprocess
import time
from pathlib import Path

from ..builder.kernel import KernelArtifacts
from ..runtime_profile import RuntimeProfile
from ..utils.command import run
from .rootfs import Rootfs


class QemuVM:
    def __init__(
        self,
        *,
        kernel: KernelArtifacts,
        rootfs: Rootfs,
        logs_dir: Path,
        timeout: int | None,
        runtime_profile: RuntimeProfile | None = None,
    ) -> None:
        self.kernel = kernel
        self.rootfs = rootfs
        self.logs_dir = logs_dir
        self.runtime_profile = runtime_profile or RuntimeProfile.empty()
        self.timeout = timeout
        self.ssh_port = _free_tcp_port()
        self.process: subprocess.Popen[bytes] | None = None
        self.qemu_log = logs_dir / "qemu.log"

    def start(self) -> None:
        args = self._qemu_args()
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        qemu_log = self.qemu_log.open("ab")
        qemu_log.write((" ".join(str(arg) for arg in args) + "\n").encode("utf-8"))
        qemu_log.flush()
        self.process = subprocess.Popen(
            args,
            stdout=qemu_log,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )

    def wait_for_ssh(self, timeout: int = 180) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process and self.process.poll() is not None:
                raise RuntimeError(f"qemu exited before SSH became ready: {self.process.returncode}")
            result = run(self._ssh_base() + ["true"], timeout=10, log_path=self.logs_dir / "ssh.log", check=False)
            if result.returncode == 0:
                return
            time.sleep(2)
        raise TimeoutError(f"SSH did not become ready on port {self.ssh_port}")

    def scp_to(self, local: Path, remote: str) -> None:
        run(
            [
                "scp",
                "-P",
                str(self.ssh_port),
                "-i",
                str(self.rootfs.ssh_key),
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                str(local),
                f"{self.rootfs.ssh_user}@127.0.0.1:{remote}",
            ],
            timeout=self.timeout,
            log_path=self.logs_dir / "scp.log",
        )

    def ssh(self, remote_command: str, *, timeout: int | None, log_path: Path) -> int:
        result = run(self._ssh_base() + [remote_command], timeout=timeout, log_path=log_path, check=False)
        return result.returncode

    def start_ssh(self, remote_command: str, *, log_path: Path) -> subprocess.Popen[str]:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log = log_path.open("a", encoding="utf-8", errors="replace")
        log.write(f"\n$ {' '.join(self._ssh_base() + [remote_command])}\n")
        log.flush()
        try:
            return subprocess.Popen(
                self._ssh_base() + [remote_command],
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
                start_new_session=True,
            )
        finally:
            log.close()

    def stop(self) -> None:
        if not self.process:
            return
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)

    def _ssh_base(self) -> list[str]:
        return [
            "ssh",
            "-p",
            str(self.ssh_port),
            "-i",
            str(self.rootfs.ssh_key),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=5",
            f"{self.rootfs.ssh_user}@127.0.0.1",
        ]

    def _qemu_args(self) -> list[str]:
        append_items = [
            "console=ttyS0",
            "root=/dev/vda",
            "rw",
            "earlyprintk=serial",
            "net.ifnames=0",
            "oops=panic",
            "panic_on_warn=1",
            "panic=0",
            "kasan_multi_shot=1",
        ]
        append_items.extend(self.runtime_profile.qemu_append)
        append = " ".join(append_items)
        args: list[str] = [
            "qemu-system-x86_64",
            "-m",
            os.environ.get("PLATFORM_QEMU_MEM", "2048"),
            "-smp",
            os.environ.get("PLATFORM_QEMU_SMP", "2"),
            "-kernel",
            str(self.kernel.bz_image),
            "-append",
            append,
            "-drive",
            f"file={self.rootfs.image},format=raw,if=virtio",
            "-netdev",
            f"user,id=net0,hostfwd=tcp:127.0.0.1:{self.ssh_port}-:22",
            "-device",
            "e1000,netdev=net0",
            "-nographic",
            "-snapshot",
        ]
        if Path("/dev/kvm").exists() and not os.environ.get("PLATFORM_DISABLE_KVM"):
            args[1:1] = ["-enable-kvm", "-cpu", "host"]
        args.extend(self.runtime_profile.qemu_args)
        return args


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
