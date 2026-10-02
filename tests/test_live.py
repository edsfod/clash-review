"""live：从日志行认出被拒的连接与拒绝原因（clash_review.parse_reject / reject_reason）。

    python -m unittest discover -s tests

只用标准库，不连内核。设置与数据目录指到临时目录。
"""
import os, sys, tempfile, unittest

_TMP = tempfile.TemporaryDirectory()
os.environ["APPDATA"] = os.path.join(_TMP.name, "roaming")
os.environ["LOCALAPPDATA"] = os.path.join(_TMP.name, "local")
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import clash_review as cr


class Live(unittest.TestCase):
    def test_parse(self):
        p = cr.parse_reject
        self.assertEqual(p("[TCP] 127.0.0.1:52011(msedge.exe) --> cdn.protect.clerk.com:443 match Match using REJECT"),
                         ("msedge.exe", "cdn.protect.clerk.com", "443", "Match"))
        self.assertEqual(p("[TCP] 127.0.0.1:52012(msedge.exe) --> r.stripe.com:443 match RuleSet(windows-reject) using REJECT"),
                         ("msedge.exe", "r.stripe.com", "443", "RuleSet(windows-reject)"))
        self.assertEqual(p("[TCP] 127.0.0.1:52013 --> 203.0.113.9:8080 match GeoSite(category-ads-all) using REJECT"),
                         ("", "203.0.113.9", "8080", "GeoSite(category-ads-all)"))
        self.assertIsNone(p("[TCP] 127.0.0.1:52014(msedge.exe) --> openrouter.ai:443 match GeoSite(geolocation-!cn) using 节点选择[US-LA-03]"))
        self.assertEqual(p("[TCP] 127.0.0.1:52015(curl.exe) --> a.example:443 match RuleSet(common-reject) using REJECT-DROP"),
                         ("curl.exe", "a.example", "443", "RuleSet(common-reject)"))      # 静默丢弃也是拒绝

    def test_reason(self):
        self.assertIn("兜底", cr.reject_reason("Match"))
        self.assertEqual(cr.reject_reason("RuleSet(common-reject)"), "拉黑规则集 common-reject")
        self.assertEqual(cr.reject_reason("GeoSite(category-ads-all)"), "内置分类 category-ads-all")


if __name__ == "__main__":
    unittest.main()
