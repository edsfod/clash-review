"""eval_decisions：不作标准答案的裁定、去重、--requery 的多遍统计。模型用假函数代替，不联网。

    python -m unittest discover -s tests
"""
import json, os, tempfile, types, unittest

import test_rulesets                          # 先导入：它把 APPDATA / LOCALAPPDATA 指到临时目录
import eval_decisions as ev

UNTRUSTED = {"groups": [
    {"name": "证书状态", "why": "当时不懂", "patterns": [r"(^|\.)ocsp[0-9a-z-]*\.", r"lencr\.org$"]},
    {"name": "不确定", "hosts": ["wdcp.microsoft.com"]}]}


def dec(kind, host, decision, **snap):
    return {"time": "2026-09-26T10:00:00", "kind": kind, "host": host, "decision": decision, "snapshot": snap, "advice": None}


class Untrusted(unittest.TestCase):
    def setUp(self):
        self.ctx = types.SimpleNamespace(review=tempfile.mkdtemp())

    def test_missing_file_is_empty(self):
        self.assertEqual(ev.load_untrusted(self.ctx), [])

    def test_patterns_and_hosts(self):
        os.makedirs(os.path.join(self.ctx.review, "testcases"))
        with open(ev.untrusted_path(self.ctx), "w", encoding="utf-8") as f: json.dump(UNTRUSTED, f)
        g = ev.load_untrusted(self.ctx)
        self.assertEqual(ev.group_of("ocsp.sectigo.com", g), "证书状态")
        self.assertEqual(ev.group_of("x1.c.lencr.org", g), "证书状态")
        self.assertEqual(ev.group_of("wdcp.microsoft.com", g), "不确定")
        self.assertIsNone(ev.group_of("www.microsoft.com", g))
        self.assertIsNone(ev.group_of("socsp.example.com", g))


class Requery(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp(); os.makedirs(os.path.join(d, "testcases"))
        self.ctx = types.SimpleNamespace(review=d)
        with open(ev.untrusted_path(self.ctx), "w", encoding="utf-8") as f: json.dump(UNTRUSTED, f)
        self.groups = ev.load_untrusted(self.ctx)

    def test_latest_keeps_last_decision_per_page_and_host(self):
        ds = [dec("todirect", "a.com", "direct"), dec("pending", "a.com", "proxy"),
              dec("todirect", "a.com", "proxy"), dec("routed", "b.com", "ok")]
        got = ev.latest(ds)
        self.assertEqual([(d["kind"], d["host"], d["decision"]) for d in got],
                         [("todirect", "a.com", "proxy"), ("pending", "a.com", "proxy")])

    def test_item_of_does_not_send_context(self):
        it = ev.item_of(dec("pending", "a.com", "proxy", count=3, procs=["x.exe"], ctx=["b.com"]))
        self.assertEqual(it, {"kind": "pending", "host": "a.com", "count": 3, "procs": ["x.exe"]})

    def test_outcome(self):
        self.assertIsNone(ev.outcome({"model": None, "recommend": "proxy"}))       # 只有名单结论，不算模型的
        self.assertIsNone(ev.outcome({"model": {}, "model_error": "超时", "recommend": "proxy"}))
        self.assertEqual(ev.outcome({"model": {"decision": "reject"}, "split": True, "recommend": None}), "split")
        self.assertEqual(ev.outcome({"model": {"decision": "direct"}, "recommend": "direct"}), "direct")

    def test_report(self):
        items = [dec("todirect", "a.com", "direct"), dec("todirect", "b.com", "direct"), dec("todirect", "c.com", "proxy"),
                 dec("todirect", "ocsp.sectigo.com", "direct"), dec("pending", "d.com", "ignore"),
                 dec("pending", "e.com", "proxy")]
        answers = [{"a.com": "direct", "b.com": "proxy", "c.com": "direct", "ocsp.sectigo.com": "proxy", "d.com": "reject"},
                   {"a.com": "direct", "b.com": "direct", "c.com": "direct", "ocsp.sectigo.com": "proxy", "d.com": "reject"}]
        n = {"i": 0}
        def ask(it):
            if it["host"] == "e.com": raise RuntimeError("超时")
            return answers[n["i"] // len(items)][it["host"]]
        def ask_counted(it):                  # 每遍 len(items) 次调用：用调用次数分辨第几遍
            try: return ask(it)
            finally: n["i"] += 1
        runs, errors, secs = ev.run_passes(items, ask_counted, 2, 1, log=lambda *a, **k: None)
        self.assertEqual(errors, {("pending", "e.com"): "RuntimeError: 超时"})
        L = "\n".join(ev.requery_report(items, runs, errors, secs, self.groups,
                                        {"time": "t", "prompt_hash": "h", "total": 6}))
        self.assertIn("各遍之间结论不同的：1/6", L)                       # b.com
        self.assertIn("| 可改直连 | 3 | 1/3（33%） | 2/3（66%） |", L)    # 证书状态不计入
        self.assertIn("`c.com`：你选 代理，模型 直连", L)                  # 两遍都不同
        self.assertNotIn("`b.com`：你选", L)
        self.assertIn("### 证书状态", L)
        self.assertIn("`ocsp.sectigo.com`：模型 代理 / 代理；你当时选 直连", L)
        self.assertIn("「忽略」1 项不计", L)
        self.assertIn("`e.com`：RuntimeError: 超时", L)


if __name__ == "__main__":
    unittest.main()
