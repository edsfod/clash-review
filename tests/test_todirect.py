"""「可改直连」的两道确定的关：候选排除（direct_exclusion）与实测后的国内节点要求（direct_verdict）。

    python -m unittest discover -s tests

只用标准库。设置与数据目录指到临时目录，不碰本机的 clash-review 数据；名单用手写的查询结果代替，不读 var/lists。
"""
import os, sys, tempfile, unittest

_TMP = tempfile.TemporaryDirectory()
os.environ["APPDATA"] = os.path.join(_TMP.name, "roaming")
os.environ["LOCALAPPDATA"] = os.path.join(_TMP.name, "local")
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import clash_review as cr


def lk(owner=(), cats=(), cn=False):
    return {"block": [], "owner": list(owner), "categories": list(cats), "ads_attr": False, "cn_attr": cn}


def ev(cc, asn="TEST-AS（AS1，{}）", direct_ms=100, proxy_ms=1000, with_cc=True):
    e = {"cn_ips": ["192.0.2.1"], "cn_asn": [asn.format(c) for c in cc],
         "speed": {"scheme": "https", "direct_ms": direct_ms, "proxy_ms": proxy_ms, "n": 3, "checked": "2026-10-01T00:00:00"}}
    if with_cc: e["cn_cc"] = list(cc)
    return e


class Exclusion(unittest.TestCase):
    def test_policy_owners_and_categories(self):
        ex = cr.direct_exclusion
        self.assertIn("Google", ex("www.google.com", lk(["alphabet", "google"])))
        self.assertIn("Google", ex("fonts.gstatic.com", lk(["alphabet", "google"], cn=True)))   # 有国内节点也代理
        self.assertIn("GitHub", ex("raw.githubusercontent.com", lk(["github", "microsoft"])))
        self.assertIn("GitHub", ex("someone.github.io", {}))
        self.assertIsNone(ex("registry.npmjs.org", lk(["github", "microsoft", "npmjs"])))     # npm 在 v2fly 的 github 清单里，但不算
        self.assertIn("证书", ex("c.pki.goog.example", lk(cats=["category-cas"])))
        self.assertIn("AI", ex("chatgpt.com", lk(cats=["category-ai-!cn"])))
        self.assertIn("社交", ex("abs.twimg.com", lk(["twitter"], ["category-social-media-!cn"])))
        self.assertIn("流媒体", ex("rufio.hls.live-video.net", lk(["twitch"], ["category-entertainment"])))

    def test_offline_patterns(self):
        ex = cr.direct_exclusion
        self.assertIn("pages.dev", ex("foo.pages.dev", {}))
        self.assertIn("workers.dev", ex("workers.dev", {}))
        self.assertIn("证书", ex("ocsp.sectigo.com", {}))
        self.assertIn("证书", ex("crl3.digicert.com", {}))
        self.assertIn("登录", ex("login.example.com", {}))

    def test_allowed(self):
        ex = cr.direct_exclusion
        self.assertIsNone(ex("avatars.steamstatic.com", lk(["steam"], ["category-entertainment", "category-games-!cn"])))
        self.assertIsNone(ex("a1.mzstatic.com", lk(["apple", "itunes"], ["category-entertainment"], cn=True)))
        self.assertIsNone(ex("download.windowsupdate.com", lk(["microsoft"])))
        self.assertIsNone(ex("cdn.example.org", {}))
        self.assertIsNone(ex("ocspexample.org", {}))          # 前缀必须是完整的一段


class Verdict(unittest.TestCase):
    def test_needs_domestic_node(self):
        self.assertEqual(cr.direct_verdict(ev(["CN"]), "x.example")[0], "direct")
        g, why = cr.direct_verdict(ev(["US"]), "x.example")
        self.assertEqual(g, "keep"); self.assertIn("不是国内节点", why)
        self.assertEqual(cr.direct_verdict(ev(["CN", "HK"]), "x.example")[0], "keep")
        self.assertEqual(cr.direct_verdict(ev([]), "x.example")[0], "keep")

    def test_old_cache_without_cc(self):
        self.assertEqual(cr.direct_verdict(ev(["CN"], with_cc=False), "x.example")[0], "direct")
        self.assertEqual(cr.direct_verdict(ev(["US"], with_cc=False), "x.example")[0], "keep")

    def test_speed_still_applies(self):
        self.assertEqual(cr.direct_verdict(ev(["CN"], direct_ms=900, proxy_ms=1000), "x.example")[0], "keep")
        self.assertIsNone(cr.direct_verdict(dict(ev(["CN"]), speed=None), "x.example")[0])   # 过了节点关、还没测速

    def test_scholar_exempt_from_node(self):
        orig = cr.is_scholar
        cr.is_scholar = lambda host, lk=None: host == "journal.example"
        try:
            self.assertEqual(cr.direct_verdict(ev(["US"]), "journal.example")[0], "direct")
            self.assertEqual(cr.direct_verdict(ev(["US"]), "other.example")[0], "keep")
        finally:
            cr.is_scholar = orig


if __name__ == "__main__":
    unittest.main()
