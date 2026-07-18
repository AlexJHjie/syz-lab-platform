from pathlib import Path
import tempfile
import unittest
from unittest import mock

from syzrun.builder.toolchain import (
    ToolchainError,
    ensure_toolchain,
    parse_toolchain_requirement,
)


class ToolchainRequirementTests(unittest.TestCase):
    def test_parses_exact_gcc_and_binutils_versions(self) -> None:
        requirement = parse_toolchain_requirement(
            "gcc (Debian 10.2.1-6) 10.2.1 20210110, "
            "GNU ld (GNU Binutils for Debian) 2.35.2"
        )

        self.assertEqual(requirement.compiler, "gcc")
        self.assertEqual(requirement.version, "10.2.1")
        self.assertEqual(requirement.binutils_version, "2.35.2")
        self.assertEqual(requirement.key, "gcc-10.2.1-binutils-2.35.2")

    def test_parses_snapshot_gcc_without_binutils(self) -> None:
        requirement = parse_toolchain_requirement("gcc (GCC) 8.0.1 20180413 (experimental)")

        self.assertEqual(requirement.version, "8.0.1")
        self.assertIsNone(requirement.binutils_version)
        self.assertEqual(requirement.key, "gcc-8.0.1")

    def test_rejects_description_without_strict_version(self) -> None:
        with self.assertRaisesRegex(ToolchainError, "cannot parse"):
            parse_toolchain_requirement("gcc")


class ToolchainResolutionTests(unittest.TestCase):
    def test_uses_project_local_exact_toolchain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            toolchains_dir = Path(tmp) / "toolchains"
            root = toolchains_dir / "gcc-10.2.1-binutils-2.35.2"
            bin_dir = root / "bin"
            bin_dir.mkdir(parents=True)
            for name in ("gcc", "ld", "as", "ar", "nm", "objcopy", "objdump", "readelf", "strip", "addr2line"):
                executable = bin_dir / name
                executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                executable.chmod(0o755)

            with mock.patch("syzrun.builder.toolchain._compiler_version", return_value="10.2.1"):
                with mock.patch("syzrun.builder.toolchain._program_version", return_value="2.35.2"):
                    toolchain = ensure_toolchain(
                        "gcc (Debian 10.2.1-6) 10.2.1, GNU ld (GNU Binutils for Debian) 2.35.2",
                        toolchains_dir=toolchains_dir,
                    )
                make_variables = toolchain.make_variables()

        self.assertEqual(toolchain.root, root)
        self.assertEqual(toolchain.cc, bin_dir / "gcc")
        self.assertIn(f"CC={bin_dir / 'gcc'}", make_variables)
        self.assertIn(f"LD={bin_dir / 'ld'}", make_variables)

    def test_does_not_scan_noncanonical_compiler_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            toolchains_dir = Path(tmp) / "toolchains"
            root = toolchains_dir / "gcc-8.0.1"
            nested = root / "original" / "bin"
            nested.mkdir(parents=True)
            compiler = nested / "gcc"
            compiler.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            compiler.chmod(0o755)

            with self.assertRaisesRegex(ToolchainError, "bin/gcc"):
                ensure_toolchain(
                    "gcc (GCC) 8.0.1 20180413 (experimental)",
                    toolchains_dir=toolchains_dir,
                )

    def test_missing_exact_version_does_not_fall_back(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            toolchains_dir = Path(tmp) / "toolchains"

            expected = toolchains_dir.resolve() / "gcc-10.3.0"
            with self.assertRaises(ToolchainError) as raised:
                ensure_toolchain(
                    "gcc (Debian 10.3.0-1) 10.3.0",
                    toolchains_dir=toolchains_dir,
                )
            message = str(raised.exception)

        self.assertIn("Please download and prepare:", message)
        self.assertIn("gcc 10.3.0", message)
        self.assertIn(str(expected / "bin" / "gcc"), message)
        self.assertIn("binutils: not versioned", message)


if __name__ == "__main__":
    unittest.main()
