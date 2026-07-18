from pathlib import Path
import tempfile
import unittest

from syzrun.metadata import Vulnerability


class MetadataTests(unittest.TestCase):
    def test_load_minimal_metadata(self) -> None:
        raw = """
        {
          "version": 1,
          "title": "KASAN: test crash",
          "display-title": "KASAN: test crash",
          "id": "abc123",
          "status": "fixed",
          "fix-commits": [{"hash": "fix", "repo": "repo", "branch": "master"}],
          "crashes": [{
            "syz-reproducer": "/text?tag=ReproSyz&x=1",
            "kernel-config": "/text?tag=KernelConfig&x=2",
            "kernel-source-git": "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/log/?id=deadbeef",
            "kernel-source-commit": "deadbeef",
            "syzkaller-git": "https://github.com/google/syzkaller/commits/cafebabe",
            "syzkaller-commit": "cafebabe",
            "compiler-description": "gcc (Debian 10.2.1-6) 10.2.1",
            "architecture": "amd64",
            "crash-report-link": "/text?tag=CrashReport&x=3"
          }],
          "subsystems": ["mm"],
          "parent_of_fix_commit": "parent"
        }
        """
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "v.json"
            path.write_text(raw, encoding="utf-8")
            vuln = Vulnerability.from_file(path)
        self.assertEqual(vuln.vuln_id, "abc123")
        self.assertEqual(vuln.crash.kernel_source_commit, "deadbeef")
        self.assertEqual(vuln.crash.architecture, "amd64")


if __name__ == "__main__":
    unittest.main()
