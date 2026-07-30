from pathlib import Path
import tempfile
import unittest

from syzrun.builder.syzkaller import (
    SYSTEM_CC,
    SYSTEM_CXX,
    _make_targets,
    _select_make_targets,
)


class SyzkallerBuilderTests(unittest.TestCase):
    def test_uses_system_compilers_for_cgo(self) -> None:
        self.assertEqual(SYSTEM_CC, "/usr/bin/gcc")
        self.assertEqual(SYSTEM_CXX, "/usr/bin/g++")

    def test_detects_modern_tools_and_symbolizer_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            makefile = Path(tmp) / "Makefile"
            makefile.write_text(
                "syz-execprog:\n\tgo build\n"
                "syz-executor:\n\tgo build\n"
                "symbolize:\n\tgo build\n",
                encoding="utf-8",
            )

            self.assertEqual(_select_make_targets(makefile), ("syz-execprog", "syz-executor"))
            self.assertIn("symbolize", _make_targets(makefile))

    def test_detects_legacy_exec_targets_without_requiring_make_symbolizer_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            makefile = Path(tmp) / "Makefile"
            makefile.write_text("execprog:\n\tgo build\nexecutor:\n\tgo build\n", encoding="utf-8")

            self.assertEqual(_select_make_targets(makefile), ("execprog", "executor"))
            self.assertNotIn("symbolize", _make_targets(makefile))


if __name__ == "__main__":
    unittest.main()
