"""目的地「规则服务」：归类决定经写入接口写进规则服务，上线后让内核重新取（docs/destinations.md）。

    python -m unittest discover -s tests

规则服务用本机上一个假的 HTTP 服务代替（只实现协议里用到的几个接口），内核管道用假函数代替。
设置与数据目录沿用 test_rulesets 的临时目录；settings.json 每个测试写一次、测完删掉，不影响别的测试。
"""
import http.server, json, os, threading, unittest

import test_rulesets as base                   # 先导入：它把 APPDATA / LOCALAPPDATA 指到临时目录
from test_rulesets import Fixture, FakeCore, REMOTE, cr

SERVER_SETS = ["common-reject", "common-direct", "common-proxy", "common-reject-ip", "common-direct-ip", "common-proxy-ip",
               "windows-reject", "windows-proxy"]


class FakeService(http.server.ThreadingHTTPServer):
    """假的规则服务：规则集 {id: [条目]}，路径为 <id>.yaml（与 Fixture 的网址 https://rules.example/<名字>.yaml 对上）。"""

    def __init__(self):
        super().__init__(("127.0.0.1", 0), Handler)
        self.sets = {i: [] for i in SERVER_SETS}
        self.sets["common-proxy"] = ["+.iptoasn.com"]
        self.key = "k" * 40; self.reject_422 = False; self.deploy = "pending"; self.posts = []; self.n = 0
        threading.Thread(target=self.serve_forever, daemon=True).start()

    def version(self, i):
        return "v-" + "|".join(self.sets[i])        # 内容不变，版本就不变（同 git 的 blob 哈希）

    @property
    def endpoint(self):
        return f"http://127.0.0.1:{self.server_address[1]}/api/v1"


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def reply(self, code, body, headers=None):
        data = json.dumps(body).encode()
        self.send_response(code)
        for k, v in {"content-type": "application/json", **(headers or {})}.items(): self.send_header(k, v)
        self.send_header("content-length", str(len(data))); self.end_headers(); self.wfile.write(data)

    def authed(self):
        if self.headers.get("authorization") != f"Bearer {self.server.key}":
            self.reply(401, {"error": "unauthorized"}); return False
        return True

    def do_GET(self):
        if not self.authed(): return
        srv = self.server
        if self.path.startswith("/api/v1/rulesets"):
            rows = [{"id": i, "path": f"{i}.yaml", "version": srv.version(i), "behavior": "ipcidr" if i.endswith("-ip") else "domain",
                     "layer": i.split("-")[0], "category": i.split("-")[1],
                     "count": len(e), **({"entries": list(e)} if "entries=1" in self.path else {})} for i, e in srv.sets.items()]
            return self.reply(200, rows, {"x-head": "a" * 40, "x-credential-expires": "2099-01-01 00:00:00 UTC"})
        if self.path.startswith("/api/v1/deployments/"):
            return self.reply(200, {"state": srv.deploy, "deployed": "b" * 40})
        self.reply(404, {"error": "not_found"})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))   # 先读完请求体，否则回 401 时连接被重置
        if not self.authed(): return
        srv = self.server
        srv.posts.append(body)
        if srv.reject_422: return self.reply(422, {"error": "invalid", "errors": ["common-proxy：坏条目"]})
        stale = {i: srv.version(i) for i, v in (body.get("base") or {}).items() if srv.version(i) != v}
        if stale: return self.reply(409, {"error": "conflict", "versions": stale})
        results = []
        for op in body["ops"]:
            items = srv.sets[op["ruleset"]]
            if op["op"] == "remove":
                if op["entry"] in items: items.remove(op["entry"]); results.append({**op, "result": "done"})
                else: results.append({**op, "result": "unchanged"})
            elif op["entry"] in items: results.append({**op, "result": "unchanged"})
            else: items.append(op["entry"]); results.append({**op, "result": "done"})
        srv.n += 1
        commit = f"{srv.n:040x}"
        touched = {op["ruleset"] for op in body["ops"]}
        self.reply(202, {"commit": commit, "versions": {i: srv.version(i) for i in touched}, "results": results, "notes": ["服务端提示"]},
                   {"location": f"/api/v1/deployments/{commit}"})


class RuleService(unittest.TestCase):
    def setUp(self):
        self.srv = FakeService()
        self.keyfile = os.path.join(base._TMP.name, "write-key.txt")
        with open(self.keyfile, "w") as f: f.write(self.srv.key + "\n")
        self.write_settings(self.srv.endpoint)
        self.fx = Fixture(remote=REMOTE + [("common-direct", "domain", "DIRECT")])
        state = os.path.join(cr.DATA_DIR, "destination.json")                     # 数据目录各测试共用：清掉上一个测试的缓存
        if os.path.exists(state): os.remove(state)
        self.put = []
        self.saved_req = cr.pipe_request
        cr.pipe_request = lambda method, path: self.put.append((method, path)) or 204

    def tearDown(self):
        cr.pipe_request = self.saved_req
        os.remove(cr.SETTINGS)
        self.srv.shutdown(); self.srv.server_close()

    def write_settings(self, endpoint):
        os.makedirs(os.path.dirname(cr.SETTINGS), exist_ok=True)
        conf = {"destination": {"endpoint": endpoint, "key_file": self.keyfile, "admin_url": "https://rules.example/admin/",
                                "rulesets": {"domain": {c: f"common-{c}" for c in cr.CAT_ORDER},
                                             "ip": {c: f"common-{c}-ip" for c in cr.CAT_ORDER}}}}
        with open(cr.SETTINGS, "w", encoding="utf-8") as f: json.dump(conf, f)

    def add_pending(self, ctx, *hosts):
        p = {"domains": {h: cr._new_rec("2026-01-01 00:00:00.000") for h in hosts}, "ips": {}}
        for r in p["domains"].values(): r["count"] = 1
        cr.save_pending(ctx.pending, p)

    def test_promote_writes_service_not_inbox(self):
        ctx = self.fx.ctx(); self.add_pending(ctx, "new.example.com", "keep.example.com")
        out, moved = cr.promote(ctx, {"proxy": ["new.example.com"], "reject": ["1.2.3.4"]})
        self.assertEqual(len(self.srv.posts), 1)                                  # 一次归类一个提交
        self.assertEqual(self.srv.posts[0]["ops"], [{"op": "add", "ruleset": "common-reject-ip", "entry": "1.2.3.4/32"},
                                                     {"op": "add", "ruleset": "common-proxy", "entry": "+.new.example.com"}])
        self.assertNotIn("base", self.srv.posts[0])
        self.assertEqual(moved, ["new.example.com"])
        self.assertIn("keep.example.com", cr.load_pending(ctx.pending)["domains"])
        self.assertEqual(self.fx.read("my-proxy"), [cr.DOMAIN_PLACEHOLDER])       # 收件箱不动
        notes = [n for _, _, _, ns in out for n in ns]
        self.assertIn("服务端提示", notes)
        self.assertTrue(any(n.startswith("已提交到规则服务（0000000）") for n in notes))
        # 刚写的条目马上算作「已有规则」：watch 不会把它放回待审
        dom, ip = cr.load_classified(ctx)
        self.assertIn("+.new.example.com", dom)
        self.assertEqual([r["state"] for r in ctx.dest.load()["submitted"]], ["pending"])

    def test_routed_classify_one_commit(self):
        ctx = self.fx.ctx()
        rec = lambda: dict(cr._new_rec("2026-01-01 00:00:00.000"), count=1)
        cr.save_routed(ctx.routed, {"direct": {}, "proxy": {"cdn.example.com": rec(), "ads.example.net": rec(), "stay.example.org": rec()}})
        added, notes = cr.routed_classify(ctx, {"direct": ["cdn.example.com"], "reject": ["ads.example.net"]})
        self.assertEqual(len(self.srv.posts), 1)                                  # 直连与拉黑一次提交
        self.assertEqual(added, {"direct": ["+.cdn.example.com"], "reject": ["+.ads.example.net"]})
        self.assertEqual(list(cr.load_routed(ctx.routed)["proxy"]), ["stay.example.org"])

    def test_write_patches_cache_without_refetch(self):
        ctx = self.fx.ctx()
        before = ctx.dest.snapshot()                                               # 先有缓存
        self.srv.sets["common-direct"].append("+.changed-elsewhere.example")       # 服务端另有改动：缓存到期前不该看到
        cr.promote(ctx, {"proxy": ["new.example.com"]})
        snap = ctx.dest.load()["snapshot"]
        self.assertEqual(snap["time"], before["time"])                             # 没有重取
        by = {x["id"]: x["entries"] for x in snap["sets"]}
        self.assertIn("+.new.example.com", by["common-proxy"])
        self.assertNotIn("+.changed-elsewhere.example", by["common-direct"])
        self.assertIn("+.new.example.com", cr.load_classified(ctx)[0])

    def test_existing_entry_unchanged(self):
        ctx = self.fx.ctx(); self.add_pending(ctx, "x.iptoasn.com")
        out, moved = cr.promote(ctx, {"proxy": ["iptoasn.com"]})
        self.assertEqual(out[0][2], [])                                            # 服务端说已有，不算新增
        self.assertEqual(moved, ["x.iptoasn.com"])

    def test_rejected_keeps_pending(self):
        self.srv.reject_422 = True
        ctx = self.fx.ctx(); self.add_pending(ctx, "new.example.com")
        with self.assertRaises(cr.DestError) as e: cr.promote(ctx, {"proxy": ["new.example.com"]})
        self.assertIn("坏条目", str(e.exception))
        self.assertIn("new.example.com", cr.load_pending(ctx.pending)["domains"])

    def test_unreachable_keeps_pending(self):
        port = self.srv.server_address[1]; self.srv.shutdown(); self.srv.server_close()
        self.srv = FakeService()                                                   # 给 tearDown 关的
        self.write_settings(f"http://127.0.0.1:{port}/api/v1")                     # 已关掉的端口
        ctx = self.fx.ctx(); self.add_pending(ctx, "new.example.com")
        with self.assertRaises(cr.DestError) as e: cr.promote(ctx, {"direct": ["new.example.com"]})
        self.assertIn("连不上规则服务", str(e.exception))
        self.assertIn("new.example.com", cr.load_pending(ctx.pending)["domains"])

    def test_payloads_use_service_entries(self):
        self.srv.sets["common-reject"] = ["+.only-on-service.example"]
        ctx = self.fx.ctx()
        s, p = cr.first_match(ctx, "domain", "a.only-on-service.example")
        self.assertEqual((s["name"], p), ("common-reject", "+.only-on-service.example"))

    def test_settle_refreshes_kernel(self):
        ctx = self.fx.ctx(); cr.promote(ctx, {"proxy": ["new.example.com"]})
        self.assertEqual(ctx.dest.settle(), [])                                    # 还没上线
        self.srv.deploy = "live"
        counts = {"common-proxy": 2}
        with FakeCore(counts, {}):
            changed = ctx.dest.settle()
        self.assertEqual([r["state"] for r in changed], ["live"])
        self.assertEqual(self.put, [("PUT", "/providers/rules/common-proxy")])
        self.assertIn("条目数一致", changed[0]["kernel"])
        self.assertEqual(ctx.dest.pending(), [])

    def test_status(self):
        ctx = self.fx.ctx()
        with FakeCore({s["name"]: 1 for s in ctx.sets}, {}):
            d = cr.status_data(ctx)
        x = d["dest"]
        self.assertTrue(x["ok"])
        self.assertEqual({t["id"]: t["provider"] for t in x["targets"] if t["kind"] == "domain"},
                         {"common-reject": "common-reject", "common-direct": "common-direct", "common-proxy": "common-proxy"})
        missing = [b for b in d["bad"] if "Clash 配置里没有对应" in b]           # Fixture 里没有 common-direct-ip 等
        self.assertTrue(any("common-direct-ip" in b for b in missing))
        self.assertFalse(any("按默认名猜的" in b for b in d["bad"]))

    def test_routes_follow_clash_provider_proxy(self):
        # Fixture 的 http 规则集在 rules.example 上、写了 proxy: 节点选择：同一主机的服务先经本机代理
        self.write_settings("https://rules.example/api/v1")
        self.assertEqual(self.fx.ctx().dest.routes(), ["proxy", "direct"])
        self.write_settings(self.srv.endpoint)                                     # 127.0.0.1：Clash 里没有它的规则集
        self.assertEqual(self.fx.ctx().dest.routes(), ["direct", "proxy"])

    def test_editor_lists_service_sets(self):
        ctx = self.fx.ctx()
        sets = cr.dest_editor(ctx)
        by = {s["name"]: s for s in sets}
        self.assertEqual(len(sets), len(SERVER_SETS))
        self.assertTrue(all(s["used"] for s in sets[:6]))                          # Clash 用到的排在前面
        self.assertFalse(by["common-direct-ip"]["used"])
        self.assertEqual(by["common-proxy"]["cat"], "proxy")                       # 类别取 Clash 里的去向
        self.assertEqual(by["common-proxy"]["moves"], {"reject": "common-reject", "direct": "common-direct"})
        self.assertEqual(by["common-reject"]["layers"], {"windows": "windows-reject"})
        self.assertEqual(by["common-proxy"]["entries"], ["+.iptoasn.com"])

    def test_edit_move_with_versions(self):
        ctx = self.fx.ctx(); cr.dest_editor(ctx)
        added, notes = cr.dest_edit(ctx, "move", "common-proxy", "+.iptoasn.com", "common-direct")
        post = self.srv.posts[-1]
        self.assertEqual(post["ops"], [{"op": "remove", "ruleset": "common-proxy", "entry": "+.iptoasn.com"},
                                       {"op": "add", "ruleset": "common-direct", "entry": "+.iptoasn.com"}])
        self.assertEqual(set(post["base"]), {"common-proxy", "common-direct"})
        self.assertEqual(added, ["+.iptoasn.com"])
        by = {x["id"]: x for x in ctx.dest.load()["snapshot"]["sets"]}             # 缓存跟着改，版本也更新
        self.assertEqual(by["common-proxy"]["entries"], [])
        self.assertEqual(by["common-direct"]["entries"], ["+.iptoasn.com"])
        self.assertEqual(by["common-direct"]["version"], self.srv.version("common-direct"))
        cr.dest_edit(ctx, "delete", "common-direct", "+.iptoasn.com")               # 用更新后的版本，接着改不冲突
        self.assertEqual(self.srv.sets["common-direct"], [])

    def test_edit_conflict(self):
        ctx = self.fx.ctx(); cr.dest_editor(ctx)
        self.srv.sets["common-proxy"].append("+.added-elsewhere.example")          # 管理页上先改了
        with self.assertRaises(cr.DestError) as e: cr.dest_edit(ctx, "delete", "common-proxy", "+.iptoasn.com")
        self.assertIn("期间被别处改过", str(e.exception))
        self.assertIn("+.iptoasn.com", self.srv.sets["common-proxy"])             # 没有改
        by = {x["id"]: x for x in ctx.dest.load()["snapshot"]["sets"]}             # 已重取
        self.assertIn("+.added-elsewhere.example", by["common-proxy"]["entries"])

    def test_edit_add_exact_and_normalized(self):
        ctx = self.fx.ctx(); cr.dest_editor(ctx)
        cr.dest_edit(ctx, "add", "common-reject", "only.example.com", exact=True)
        cr.dest_edit(ctx, "add", "common-reject", "wide.example.com")
        self.assertEqual(self.srv.sets["common-reject"], ["only.example.com", "+.wide.example.com"])

    def test_wrong_key(self):
        self.srv.key = "x" * 40
        ctx = self.fx.ctx()
        with self.assertRaises(cr.DestError) as e: cr.promote(ctx, {"proxy": ["new.example.com"]})
        self.assertIn("写入密钥不对", str(e.exception))


if __name__ == "__main__":
    unittest.main()
