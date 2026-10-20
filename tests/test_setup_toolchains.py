import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "setup_toolchains.sh"
TOOLS = ("gcc", "ld", "as", "ar", "nm", "objcopy", "objdump", "readelf", "strip", "addr2line")
KEY = "gcc-10.2.1-binutils-2.35.2"


class SetupToolchainsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.installs = self.root / "toolchains"
        self.manifest = self.root / "manifest.json"
        self.executed = self.root / "executed"

    def prepare_archive(self, missing=None, top_level=KEY):
        package = self.root / "package" / top_level
        (package / "bin").mkdir(parents=True)
        for name in TOOLS:
            if name == missing:
                continue
            tool = package / "bin" / name
            tool.write_text(f'#!/bin/sh\ntouch "{self.executed}"\nexit 99\n')
            tool.chmod(0o755)
        archive = self.root / "archive.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            output.add(package, arcname=top_level)
        self.entry = {
            "key": KEY,
            "compiler": "gcc",
            "compiler_version": "10.2.1",
            "binutils_version": "2.35.2",
            "url": archive.as_uri(),
            "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        }
        return archive

    def run_setup(self):
        self.manifest.write_text(json.dumps({"schema_version": 1, "toolchains": [self.entry]}))
        result = subprocess.run(
            ["bash", str(SCRIPT)],
            env={**os.environ, "PLATFORM_TOOLCHAIN_MANIFEST": str(self.manifest),
                 "PLATFORM_TOOLCHAINS_DIR": str(self.installs)},
            capture_output=True, text=True, timeout=20,
        )
        self.assertFalse(self.executed.exists(), "toolchain binaries must never run on the host")
        return result

    def test_install_and_skip_existing_without_executing_binaries(self):
        archive = self.prepare_archive()
        result = self.run_setup()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.installs / KEY / "bin" / "gcc").is_file())
        archive.unlink()  # Existing installs must not require a new download.
        result = self.run_setup()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("already installed:", result.stdout)
        (self.installs / KEY / "bin" / "ld").unlink()
        result = self.run_setup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("executable bin/ld", result.stderr)

    def test_rejects_archive_missing_required_binutil(self):
        self.prepare_archive(missing="addr2line")
        result = self.run_setup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("executable bin/addr2line", result.stderr)
        self.assertFalse((self.installs / KEY).exists())
        self.assertFalse(list(self.installs.glob(".*.install.*")))

    def test_rejects_checksum_mismatch(self):
        self.prepare_archive()
        self.entry["sha256"] = "0" * 64
        result = self.run_setup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SHA256 mismatch", result.stderr)
        self.assertFalse((self.installs / KEY).exists())
        self.assertFalse(list(self.installs.glob(".downloads/*.partial")))

    def test_rejects_wrong_top_level_directory(self):
        self.prepare_archive(top_level="wrong-toolchain")
        result = self.run_setup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly one top-level directory", result.stderr)
        self.assertFalse((self.installs / KEY).exists())
