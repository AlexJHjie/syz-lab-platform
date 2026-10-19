from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path

from .toolchain import ToolchainError

HOST_MAKE_VARIABLES = (
    "HOSTCC=/usr/bin/gcc -B/usr/bin/ -Wno-error=format-truncation -Wno-error=redundant-decls",
    "HOSTCXX=/usr/bin/g++ -B/usr/bin/",
    "HOSTLD=/usr/bin/ld",
    "HOSTAR=/usr/bin/ar",
)


@dataclass(frozen=True)
class ContainerBuild:
    image: str
    build_env: dict[str, str]
    timeout: int | None = None
    helper_warning_flags: tuple[str, ...] = ()

    @classmethod
    def from_environment(cls, build_env: dict[str, str], timeout: int | None = None,
                         image: str | None = None) -> ContainerBuild:
        image = (image or os.environ.get("PLATFORM_KERNEL_BUILD_IMAGE", "")).strip()
        if not image:
            raise ToolchainError("PLATFORM_KERNEL_BUILD_IMAGE is required; configure a kernel build container image in .env or the environment")
        return cls(image, dict(build_env), timeout)

    def command(self, args: list[str], root: Path, library_dir: Path | None,
                cwd: Path | None = None) -> list[str]:
        root = root.resolve()
        command = ["docker", "run", "--rm", "--init", "--network=none",
                   "--user", f"{os.getuid()}:{os.getgid()}",
                   "--volume", f"{root}:{root}:ro"]
        if cwd is not None:
            cwd = cwd.resolve()
            command.extend(["--volume", f"{cwd}:{cwd}", "--workdir", str(cwd)])
        else:
            command.extend(["--workdir", "/tmp"])
        env = {"HOME": "/tmp", "PATH": f"{root / 'bin'}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
        if library_dir:
            env["LD_LIBRARY_PATH"] = str(library_dir.resolve())
        env.update(self.build_env)
        for name, value in env.items():
            command.extend(["--env", f"{name}={value}"])
        return [*command, self.image, *args]

    def version(self, executable: Path, args: list[str], library_dir: Path | None) -> str:
        command = self.command([str(executable), *args], executable.parent.parent, library_dir)
        try:
            result = subprocess.run(command, check=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, timeout=self.timeout)
        except subprocess.CalledProcessError as exc:
            raise ToolchainError(f"tool version check failed in container {self.image}: {executable}:\n{exc.stdout or exc}") from exc
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ToolchainError(f"tool version check failed in container {self.image}: {executable}: {exc}") from exc
        return result.stdout.strip()

    def make_command(self, args: list[str], root: Path, library_dir: Path | None,
                     cwd: Path) -> list[str]:
        # -B selects system assembler/linker even with the target bin directory
        # first in PATH. Keep target CC/LD and the target search path intact.
        variables = list(HOST_MAKE_VARIABLES)
        for index in (0, 1):
            if self.helper_warning_flags:
                variables[index] += " " + " ".join(self.helper_warning_flags)
        return self.command([*args, *variables], root, library_dir, cwd)

    def configure_helper_warnings(self, root: Path, library_dir: Path | None,
                                  log_path: Path) -> ContainerBuild:
        from ..utils.command import run

        flag = "-Wno-error=use-after-free"
        # Feature-test both host compilers so older build images remain usable.
        # Do not apply this flag to target CC or globally disable -Werror.
        script = '''
set -eu
if /usr/bin/gcc -B/usr/bin/ "$1" -Werror -x c -fsyntax-only /dev/null &&
   /usr/bin/g++ -B/usr/bin/ "$1" -Werror -x c++ -fsyntax-only /dev/null; then
    printf 'Build helper warning policy: %s (warnings remain visible)\n' "$1"
else
    printf 'Build helper warning policy: compiler does not support %s\n' "$1"
    exit 1
fi
'''
        command = self.command(["/bin/sh", "-ec", script, "helper-warning-check", flag], root, library_dir)
        result = run(command, timeout=self.timeout, log_path=log_path, check=False)
        if result.returncode == 0:
            return replace(self, helper_warning_flags=(flag,))
        if result.returncode != 1:
            from ..utils.command import CommandError
            raise CommandError("failed to check build helper compiler warning support", result)
        return self
