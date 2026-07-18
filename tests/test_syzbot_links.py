import unittest

from syzrun.fetcher import resolve_syzbot_url


class SyzbotLinkTests(unittest.TestCase):
    def test_relative_text_link(self) -> None:
        self.assertEqual(
            resolve_syzbot_url("/text?tag=ReproSyz&x=1"),
            "https://syzkaller.appspot.com/text?tag=ReproSyz&x=1",
        )

    def test_absolute_link_is_preserved(self) -> None:
        self.assertEqual(
            resolve_syzbot_url("https://example.com/text?x=1"),
            "https://example.com/text?x=1",
        )


if __name__ == "__main__":
    unittest.main()
