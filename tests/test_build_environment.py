import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from syzrun.builder.container import ContainerBuild, HOST_MAKE_VARIABLES
from syzrun.builder.kernel import KernelBuilder
from types import SimpleNamespace
from syzrun.builder.toolchain import ToolchainError, ensure_toolchain
from syzrun.config import load_project_env


class BuildEnvironmentTests(unittest.TestCase):
    def test_dotenv_defaults_and_no_shell_expansion(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {"EXISTING": "terminal"}, clear=True):
            path = Path(tmp) / ".env"
            path.write_text('EXISTING=file\nexport IMAGE="build:v1" # comment\nLITERAL=$(whoami)\nEMPTY=\n')
            load_project_env(path)
            self.assertEqual(os.environ["EXISTING"], "terminal")
            self.assertEqual(os.environ["IMAGE"], "build:v1")
            self.assertEqual(os.environ["LITERAL"], "$(whoami)")
            self.assertEqual(os.environ["EMPTY"], "")

    def test_version_checks_execute_in_container_and_reject_wrong_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "gcc-10.2.1"
            (root / "bin").mkdir(parents=True)
            compiler = root / "bin/gcc"
            compiler.write_text("unused")
            compiler.chmod(0o755)
            container = ContainerBuild("build:v1", {"CUSTOM": "yes"}, 10)
            with mock.patch("syzrun.builder.container.subprocess.run") as run:
                run.return_value.stdout = "10.2.1\n"
                ensure_toolchain("gcc 10.2.1", toolchains_dir=Path(tmp), version_runner=container.version)
                command = run.call_args.args[0]
                self.assertEqual(command[:3], ["docker", "run", "--rm"])
                self.assertEqual(command[-3:], ["build:v1", str(compiler), "-dumpfullversion"])
                self.assertIn(f"{root}:{root}:ro", command)
                self.assertIn("CUSTOM=yes", command)
                run.return_value.stdout = "11.2.0\n"
                with self.assertRaisesRegex(ToolchainError, "expected 10.2.1, got 11.2.0"):
                    ensure_toolchain("gcc 10.2.1", toolchains_dir=Path(tmp), version_runner=container.version)

    def test_build_without_image_stops_before_tool_checks(self):
        builder = KernelBuilder.__new__(KernelBuilder)
        builder.runtime_profile = SimpleNamespace(build_env={})
        builder.timeout = 10
        with mock.patch.dict(os.environ, {"PLATFORM_KERNEL_BUILD_IMAGE": ""}):
            with mock.patch("syzrun.builder.kernel.ensure_toolchain") as ensure:
                with self.assertRaisesRegex(ToolchainError, "PLATFORM_KERNEL_BUILD_IMAGE"):
                    builder.build()
                ensure.assert_not_called()

    def test_compiler_falls_back_to_banner_in_same_container(self):
        from syzrun.builder.toolchain import _compiler_version
        runner = mock.Mock(side_effect=[ToolchainError("unsupported option"), "clang version 11.0.0"])
        self.assertEqual(_compiler_version(Path("/tools/bin/clang"), None, runner), "11.0.0")
        self.assertEqual(runner.call_args.args[1], ["--version"])

    def test_container_failure_preserves_loader_error(self):
        with mock.patch("syzrun.builder.container.subprocess.run", side_effect=subprocess.CalledProcessError(1, ["docker"], output="GLIBC_2.38 not found")):
            with self.assertRaisesRegex(ToolchainError, "GLIBC_2.38 not found"):
                ContainerBuild("build:v1", {}).version(Path("/tools/bin/ld"), ["--version"], None)


class HelperToolSelectionTests(unittest.TestCase):
    def test_helper_settings_preserve_explicit_kernel_tools(self):
        root = Path("/tmp/exact-toolchain")
        args = ["make", "CC=/tmp/exact-toolchain/bin/gcc", "LD=/tmp/exact-toolchain/bin/ld", "olddefconfig"]
        command = ContainerBuild("build:v2", {}).make_command(args, root, None, Path("/tmp/kernel"))
        self.assertIn(args[1], command)
        self.assertIn(args[2], command)
        self.assertEqual(command[-len(HOST_MAKE_VARIABLES):], list(HOST_MAKE_VARIABLES))
        self.assertIn("PATH=/tmp/exact-toolchain/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", command)

    @unittest.skipUnless(Path("/usr/bin/gcc").is_file(), "system GCC required")
    def test_host_gcc_ignores_incompatible_linker_first_in_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            linker = root / "ld"
            linker.write_text("#!/bin/sh\necho wrong-linker >&2\nexit 97\n")
            linker.chmod(0o755)
            env = {**os.environ, "PATH": f"{root}:/usr/bin:/bin"}
            selected = subprocess.run(["/usr/bin/gcc", "-B/usr/bin/", "-print-prog-name=ld"], env=env, capture_output=True, text=True, check=True)
            self.assertTrue(Path(selected.stdout.strip()).samefile("/usr/bin/ld"))
            result = subprocess.run(["/usr/bin/gcc", "-B/usr/bin/", "-x", "c", "-", "-o", str(root / "helper")], input="int main(void) { return 0; }\n", env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_warning_policy_only_changes_helper_compiler_commands(self):
        container = ContainerBuild("build:v2", {}, helper_warning_flags=("-Wno-error=use-after-free",))
        args = ["make", "CC=/target/bin/gcc", "LD=/target/bin/ld", "bzImage"]
        command = container.make_command(args, Path("/target"), None, Path("/kernel"))
        self.assertIn("CC=/target/bin/gcc", command)
        self.assertIn("LD=/target/bin/ld", command)
        self.assertIn("HOSTCC=/usr/bin/gcc -B/usr/bin/ -Wno-error=use-after-free", command)
        self.assertIn("HOSTCXX=/usr/bin/g++ -B/usr/bin/ -Wno-error=use-after-free", command)
        self.assertNotIn("-Wno-error", " ".join(command).split("-Wno-error=use-after-free")[0])
        self.assertFalse(any(arg.startswith(("CFLAGS=", "KBUILD_CFLAGS=", "WERROR=")) for arg in command))

    def test_warning_policy_is_feature_detected(self):
        for code in (0, 1, 125):
            with self.subTest(code=code):
                from syzrun.utils.command import CommandError
                with mock.patch("syzrun.utils.command.run", return_value=SimpleNamespace(returncode=code)):
                    container = ContainerBuild("build:test", {})
                    if code == 125:
                        with self.assertRaises(CommandError):
                            container.configure_helper_warnings(Path("/target"), None, Path("/tmp/build.log"))
                    else:
                        configured = container.configure_helper_warnings(Path("/target"), None, Path("/tmp/build.log"))
                        self.assertEqual(configured.helper_warning_flags, ("-Wno-error=use-after-free",) if code == 0 else ())
