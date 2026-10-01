"""命令行把文件名当网址（curl README.md）：不进待审（clash_review.filename_host）。

    python -m unittest discover -s tests

只用标准库。设置与数据目录指到临时目录，不碰本机的 clash-review 数据；不读日志，用手写的连接行。
"""
import os, sys, tempfile, unittest

_TMP = tempfile.TemporaryDirectory()
os.environ["APPDATA"] = os.path.join(_TMP.name, "roaming")
os.environ["LOCALAPPDATA"] = os.path.join(_TMP.name, "local")
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import clash_review as cr


def line(host, proc="curl.exe", port=80):
    return f"[2026-10-01 00:25:03.801] 127.0.0.1:5({proc}) --> {host}:{port} match Match using REJECT"


class FilenameHost(unittest.TestCase):
    def test_rule(self):
        f = cr.filename_host
        self.assertTrue(f("README.md", "curl.exe"))
        self.assertTrue(f("Zed.md", "curl.exe"))
        self.assertTrue(f("setup.py", "wget"))
        self.assertTrue(f("notes.txt", "chrome.exe"))           # 不是顶级域：哪个程序都算
        self.assertTrue(f("config.json", ""))
        self.assertFalse(f("point.md", "chrome.exe"))           # 真实顶级域，浏览器连的照常进待审
        self.assertFalse(f("api.example.com", "curl.exe"))
        self.assertFalse(f("x.ai", "curl.exe"))
        self.assertFalse(f("claude", "curl.exe"))                # 单段名本来就不进待审

    def test_classify(self):
        pending = {"domains": {}, "ips": {}}; routed = {"direct": {}, "proxy": {}}
        run = lambda l: cr.classify_line(l, "t", pending, routed, [], [])
        self.assertEqual(run(line("README.md")), (None, False))
        self.assertEqual(run(line("a.json", "python.exe", 443)), (None, False))
        self.assertEqual(run(line("point.md", "msedge.exe", 443)), ("domain", True))
        self.assertEqual(run(line("new.example.com")), ("domain", True))
        self.assertEqual(sorted(pending["domains"]), ["new.example.com", "point.md"])


if __name__ == "__main__":
    unittest.main()
