"""应用包（MSIX）里的数据副本：status 要能报出来（clash_review.container_copies）。

    python -m unittest discover -s tests

只用标准库。设置与数据目录指到临时目录，不碰本机的 clash-review 数据。
"""
import os, sys, tempfile, unittest

_TMP = tempfile.TemporaryDirectory()
os.environ["APPDATA"] = os.path.join(_TMP.name, "roaming")
os.environ["LOCALAPPDATA"] = os.path.join(_TMP.name, "local")
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import clash_review as cr


class Copies(unittest.TestCase):
    def setUp(self):
        # 一起跑时 clash_review 可能已被别的测试先导入，数据目录指向那个测试的临时目录：环境变量跟着它走
        self.env = {k: os.environ.get(k) for k in ("APPDATA", "LOCALAPPDATA")}
        os.environ["APPDATA"] = os.path.dirname(cr.CONF_DIR); os.environ["LOCALAPPDATA"] = os.path.dirname(cr.DATA_DIR)

    def tearDown(self):
        os.environ.update({k: v for k, v in self.env.items() if v is not None})

    def test_none(self):
        self.assertEqual(cr.container_copies(), [])

    def test_found(self):
        pk = os.path.join(os.environ["LOCALAPPDATA"], "Packages")
        data = os.path.join(pk, "Some.App_abc123", "LocalCache", "Local", "clash-review")
        conf = os.path.join(pk, "Other.App_xyz", "LocalCache", "Roaming", "clash-review")
        other = os.path.join(pk, "Third.App_q", "LocalCache", "Local", "another-tool")
        for d in (data, conf, other): os.makedirs(d)
        try:
            got = sorted(cr.container_copies())
            self.assertEqual(got, sorted([("Some.App_abc123", data), ("Other.App_xyz", conf)]))
        finally:
            import shutil; shutil.rmtree(pk)


if __name__ == "__main__":
    unittest.main()
