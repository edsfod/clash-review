"""已忽略可以放回待审（clash_review.ignore_pending / list_ignored / unignore_pending）。

    python -m unittest discover -s tests

只用标准库。设置与数据目录指到临时目录，不碰本机的 clash-review 数据。
"""
import json, os, sys, tempfile, types, unittest

_TMP = tempfile.TemporaryDirectory()
os.environ["APPDATA"] = os.path.join(_TMP.name, "roaming")
os.environ["LOCALAPPDATA"] = os.path.join(_TMP.name, "local")
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import clash_review as cr


def rec(n, procs=(), ctx=()):
    r = cr._new_rec("2026-10-02 14:30:00.000"); r["count"] = n; r["ports"] = {"443"}
    r["procs"] = set(procs); r["ctx"] = list(ctx); return r


class Ignored(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp(dir=_TMP.name)
        self.rules = {"domain": [], "ip": []}
        self.ctx = types.SimpleNamespace(review=d, pending=os.path.join(d, "pending.yaml"),
                                         payloads=lambda kind, cat=None: [("r", self.rules[kind])])
        cr.save_pending(self.ctx.pending, {"domains": {"cdn.protect.clerk.com": rec(8, ["msedge.exe"], ["openrouter.ai"]),
                                                       "keep.example.com": rec(1)},
                                           "ips": {"203.0.113.9": rec(2)}})

    def test_ignore_list_restore(self):
        self.assertEqual(cr.ignore_pending(self.ctx, ["cdn.protect.clerk.com", "203.0.113.9"]),
                         ["203.0.113.9", "cdn.protect.clerk.com"])
        p = cr.load_pending(self.ctx.pending)
        self.assertEqual(list(p["domains"]), ["keep.example.com"]); self.assertEqual(p["ips"], {})
        self.assertEqual(sorted(h for h, _ in cr.list_ignored(self.ctx)), ["203.0.113.9", "cdn.protect.clerk.com"])

        self.assertEqual(cr.unignore_pending(self.ctx, ["cdn.protect.clerk.com", "nope.example"]), ["cdn.protect.clerk.com"])
        r = cr.load_pending(self.ctx.pending)["domains"]["cdn.protect.clerk.com"]
        self.assertEqual((r["count"], r["procs"], r["ctx"], r["ports"]), (8, {"msedge.exe"}, ["openrouter.ai"], {"443"}))
        self.assertEqual([h for h, _ in cr.list_ignored(self.ctx)], ["203.0.113.9"])

    def test_merge_when_back_in_pending(self):
        cr.ignore_pending(self.ctx, ["cdn.protect.clerk.com"])
        p = cr.load_pending(self.ctx.pending); p["domains"]["cdn.protect.clerk.com"] = rec(3, ["chrome.exe"])   # watch 又连到了
        cr.save_pending(self.ctx.pending, p)
        self.assertEqual(cr.list_ignored(self.ctx), [])                     # 已在待审，不再列
        cr.unignore_pending(self.ctx, ["cdn.protect.clerk.com"])
        r = cr.load_pending(self.ctx.pending)["domains"]["cdn.protect.clerk.com"]
        self.assertEqual((r["count"], r["procs"]), (11, {"chrome.exe", "msedge.exe"}))

    def test_covered_not_listed(self):
        cr.ignore_pending(self.ctx, ["cdn.protect.clerk.com"])
        self.rules["domain"] = ["+.clerk.com"]                               # 之后归类进了规则
        self.assertEqual(cr.list_ignored(self.ctx), [])

    def test_seed_from_decisions(self):
        os.makedirs(os.path.join(self.ctx.review, "testcases"))
        with open(cr.decisions_path(self.ctx), "w", encoding="utf-8") as f:
            for host, dec in (("old.example.com", "ignore"), ("again.example.com", "ignore"), ("again.example.com", "proxy")):
                f.write(json.dumps({"time": "2026-09-30T19:14:14", "kind": "pending", "host": host, "decision": dec,
                                    "snapshot": {"count": 2, "procs": ["curl.exe"], "ctx": [], "ports": [443]}}) + "\n")
        self.assertEqual([h for h, _ in cr.list_ignored(self.ctx)], ["old.example.com"])   # 后来又归了类的不算
        self.assertEqual(cr.unignore_pending(self.ctx, ["old.example.com"]), ["old.example.com"])
        self.assertEqual(cr.load_pending(self.ctx.pending)["domains"]["old.example.com"]["ports"], {"443"})
        self.assertTrue(os.path.exists(cr.ignored_path(self.ctx)))


if __name__ == "__main__":
    unittest.main()
