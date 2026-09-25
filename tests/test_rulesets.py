"""规则集检测与「已有规则」的判断：只有收件箱（type: file）时与旧版一致；有 http 规则集时一并算进去，写入只写收件箱。

    python -m unittest discover -s tests

只用标准库。设置与数据目录指到临时目录，不碰本机的 clash-review 数据；内核接口用假数据代替，不连内核。
"""
import os, sys, tempfile, unittest

_TMP = tempfile.TemporaryDirectory()
os.environ["APPDATA"] = os.path.join(_TMP.name, "roaming")
os.environ["LOCALAPPDATA"] = os.path.join(_TMP.name, "local")
os.environ.pop("CLASH_VERGE_DIR", None)
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import clash_review as cr

INBOX = [("my-reject", "domain", "REJECT"), ("my-reject-ip", "ipcidr", "REJECT"),
         ("my-direct", "domain", "DIRECT"), ("my-direct-ip", "ipcidr", "DIRECT"),
         ("my-proxy", "domain", "节点选择"), ("my-proxy-ip", "ipcidr", "节点选择")]
REMOTE = [("windows-reject", "domain", "REJECT"), ("windows-proxy", "domain", "节点选择"),
          ("common-reject", "domain", "REJECT"), ("common-proxy", "domain", "节点选择"),
          ("common-proxy-ip", "ipcidr", "节点选择")]


def payload(items):
    return "payload:\n" + "".join(f'  - "{x}"\n' for x in items)


class Fixture:
    """临时的 Clash 配置目录：clash-verge.yaml、profiles.yaml 与规则集文件。"""

    def __init__(self, remote=(), files=None, missing=()):
        self.dir = tempfile.mkdtemp(dir=_TMP.name)
        os.makedirs(os.path.join(self.dir, "ruleset", "proxy-rules"))
        open(os.path.join(self.dir, "profiles.yaml"), "w").close()
        prov = ["rule-providers:"]; rules = ["rules:"]
        for name, beh, target in INBOX:
            prov += [f"  {name}:", "    type: file", f"    behavior: {beh}", "    format: yaml", f"    path: ./ruleset/{name}.yaml"]
            rules.append(f"- RULE-SET,{name},{target}")
        for name, beh, target in remote:
            prov += [f"  {name}:", "    type: http", f"    behavior: {beh}", "    format: yaml",
                     f"    url: https://rules.example/{name}.yaml", f"    path: ./ruleset/proxy-rules/{name}.yaml",
                     "    interval: 1800", "    proxy: 节点选择"]
            rules.append(f"- RULE-SET,{name},{target}")
        rules += ["- GEOSITE,cn,DIRECT", "- MATCH,REJECT"]
        with open(os.path.join(self.dir, "clash-verge.yaml"), "w", encoding="utf-8") as f:
            f.write("mixed-port: 7897\n" + "\n".join(prov + rules) + "\n")
        files = files or {}
        for name, beh, _ in INBOX:
            ph = cr.DOMAIN_PLACEHOLDER if beh == "domain" else cr.IP_PLACEHOLDER
            self.write(name, files.get(name) or [ph])
        for name, _, _ in remote:
            if name not in missing: self.write(name, files.get(name, []), remote=True)

    def path(self, name, remote=False):
        return os.path.join(self.dir, "ruleset", *(["proxy-rules"] if remote else []), name + ".yaml")

    def write(self, name, items, remote=False):
        with open(self.path(name, remote), "w", encoding="utf-8", newline="\n") as f: f.write(payload(items))

    def read(self, name):
        return cr.load_payload(self.path(name))

    def ctx(self):
        return cr.Ctx(self.dir)


class FakeCore:
    """代替内核管道：/providers/rules 按给定的条目数返回。"""

    def __init__(self, counts, vehicle):
        self.counts = counts; self.vehicle = vehicle

    def __enter__(self):
        self.saved = (cr.pipe_get, cr.find_core_pipes)
        def get(path):
            if path == "/providers/rules":
                return {"providers": {n: {"ruleCount": c, "vehicleType": self.vehicle.get(n, "File"), "updatedAt": "2026-01-01T00:00:00+08:00"}
                                      for n, c in self.counts.items()}}
            if path == "/configs": return {"mode": "rule", "find-process-mode": "always"}
            return {"version": "test"}
        cr.pipe_get = get; cr.find_core_pipes = lambda: [r"\\.\pipe\verge-mihomo-test"]
        return self

    def __exit__(self, *exc):
        cr.pipe_get, cr.find_core_pipes = self.saved


class FileOnly(unittest.TestCase):
    """只有六个收件箱：检测结果、写入提示与旧版一致。"""

    def test_layout(self):
        ctx = Fixture().ctx()
        self.assertEqual(ctx.guessed, [])
        self.assertEqual([s["name"] for s in ctx.sets], [n for n, _, _ in INBOX])
        self.assertTrue(all(s["inbox"] for s in ctx.sets))
        self.assertEqual(ctx.order["domain"], ("reject", "direct", "proxy"))

    def test_promote_overlap_note(self):
        fx = Fixture(files={"my-reject": ["+.example.org"]})
        out, _ = cr.promote(fx.ctx(), {"proxy": ["a.example.org"]})
        cat, kind, added, notes = out[0]
        self.assertEqual(added, ["+.a.example.org"])
        self.assertIn("重叠：a.example.org 也落在拉黑类的 +.example.org 内，按规则顺序拉黑生效", notes)
        self.assertEqual(fx.read("my-proxy"), ["+.a.example.org"])

    def test_promote_already_covered(self):
        fx = Fixture(files={"my-proxy": ["+.example.org"]})
        out, _ = cr.promote(fx.ctx(), {"proxy": ["b.example.org"]})
        self.assertEqual(out[0][2], [])
        self.assertIn("b.example.org 已被代理类现有条目覆盖，未写入", out[0][3])

    def test_tidy_redundant_within_inbox(self):
        fx = Fixture(files={"my-proxy": ["+.example.org", "a.example.org"]})
        rep = cr.ruleset_audit(fx.ctx())
        self.assertEqual(rep["redundant"], [("domain", "proxy", "a.example.org", "+.example.org")])


class WithHttp(unittest.TestCase):
    """收件箱之后有 http 规则集（本地缓存在 ruleset/proxy-rules/）。"""

    FILES = {"windows-reject": ["+.tracker.example.net"], "windows-proxy": ["+.visualstudio.com"],
             "common-reject": ["+.statsig.anthropic.com"], "common-proxy": ["+.iptoasn.com", "+.anthropic.com"],
             "common-proxy-ip": ["149.154.160.0/20"]}

    def fx(self, **kw):
        files = dict(self.FILES); files.update(kw.pop("files", {}))
        return Fixture(remote=REMOTE, files=files, **kw)

    def test_layout(self):
        ctx = self.fx().ctx()
        self.assertEqual(ctx.names["domain"]["proxy"], "my-proxy")       # 收件箱仍是第一个 type: file
        remote = [s for s in ctx.sets if not s["inbox"]]
        self.assertEqual([s["name"] for s in remote], [n for n, _, _ in REMOTE])
        self.assertTrue(remote[0]["path"].endswith(os.path.join("ruleset", "proxy-rules", "windows-reject.yaml")))

    def test_classified_includes_http(self):
        dom, ip = cr.load_classified(self.fx().ctx())
        self.assertIn("+.iptoasn.com", dom)
        self.assertIn("149.154.160.0/20", ip)
        self.assertNotIn(cr.DOMAIN_PLACEHOLDER, dom)

    def test_leak_covered_by_http_not_pending(self):
        ctx = self.fx().ctx(); dom, ip = cr.load_classified(ctx)
        pending = {"domains": {}, "ips": {}}; routed = {"direct": {}, "proxy": {}}
        line = "[2026-01-01 00:00:00.000] 127.0.0.1:5(curl.exe) --> www.iptoasn.com:443 match Match using REJECT"
        self.assertEqual(cr.classify_line(line, "t", pending, routed, dom, ip), (None, False))
        line2 = line.replace("www.iptoasn.com", "new.example.com")
        self.assertEqual(cr.classify_line(line2, "t", pending, routed, dom, ip), ("domain", True))

    def test_promote_skips_when_http_same_cat_wins(self):
        fx = self.fx()
        out, _ = cr.promote(fx.ctx(), {"proxy": ["x.iptoasn.com"]})
        self.assertEqual(out[0][2], [])
        self.assertIn("x.iptoasn.com 已被代理类 common-proxy 的 +.iptoasn.com 覆盖，未写入", out[0][3])
        self.assertEqual(fx.read("my-proxy"), [cr.DOMAIN_PLACEHOLDER])     # 收件箱不动

    def test_promote_writes_inbox_when_other_cat_would_win(self):
        # statsig.anthropic.com 在 common-reject（排在 common-proxy 前）；改判代理要写收件箱，收件箱在最前所以生效
        fx = self.fx()
        out, _ = cr.promote(fx.ctx(), {"proxy": ["statsig.anthropic.com"]})
        added, notes = out[0][2], out[0][3]
        self.assertEqual(added, ["+.statsig.anthropic.com"])
        self.assertIn("重叠：statsig.anthropic.com 也落在拉黑类 common-reject 的 +.statsig.anthropic.com 内，按规则顺序代理生效", notes)
        self.assertEqual(fx.read("my-proxy"), ["+.statsig.anthropic.com"])
        self.assertEqual(fx.read("my-reject"), [cr.DOMAIN_PLACEHOLDER])

    def test_promote_ip_skips_when_http_covers(self):
        fx = self.fx()
        out, _ = cr.promote(fx.ctx(), {"proxy": ["149.154.167.51"]})
        self.assertEqual(out[0][2], [])
        self.assertIn("149.154.160.0/20 已被代理类 common-proxy-ip 的 149.154.160.0/20 覆盖，未写入", out[0][3])

    def test_missing_cache_degrades(self):
        fx = self.fx(missing=("common-proxy",))
        ctx = fx.ctx()
        out, _ = cr.promote(ctx, {"proxy": ["x.iptoasn.com"]})
        self.assertEqual(out[0][2], ["+.x.iptoasn.com"])                  # 看不到 common-proxy，照常写入收件箱
        self.assertTrue(any(n.startswith("这些规则集读不到，没算进去：common-proxy（本地缓存不在") for n in out[0][3]))

    def test_rejects_regex_covers_http(self):
        rx = cr.rej_hit_re(self.fx().ctx())
        self.assertTrue(rx.search("--> a.tracker.example.net:443 match RuleSet(windows-reject) using REJECT"))
        self.assertTrue(rx.search("--> x.com:443 match RuleSet(my-reject) using REJECT"))
        self.assertFalse(rx.search("--> x.com:443 match RuleSet(common-proxy) using 节点选择"))

    def test_tidy_inbox_entry_already_online(self):
        # 收件箱的条目已在 common-proxy 里，中间的 windows-reject / common-reject 与它不相交：可自动清理
        fx = self.fx(files={"my-proxy": ["+.iptoasn.com"]})
        rep = cr.ruleset_audit(fx.ctx())
        self.assertIn(("domain", "proxy", "+.iptoasn.com", "common-proxy 的 +.iptoasn.com"), rep["redundant"])
        # 中间有拉黑的子域时，删掉收件箱这条会让子域改为拉黑：不算冗余
        fx = self.fx(files={"my-proxy": ["+.iptoasn.com"], "windows-reject": ["dl.iptoasn.com"]})
        rep = cr.ruleset_audit(fx.ctx())
        self.assertFalse([r for r in rep["redundant"] if r[2] == "+.iptoasn.com"])

    def test_tidy_overlap_names_sets(self):
        rep = cr.ruleset_audit(self.fx().ctx())
        self.assertIn("拉黑类 common-reject +.statsig.anthropic.com 落在代理类 common-proxy +.anthropic.com 内 → 该子域common-reject（拉黑）（例外）",
                      rep["overlap"])

    def test_status(self):
        fx = self.fx()
        ctx = fx.ctx()
        counts = {n: 1 for n, _, _ in INBOX}
        counts.update({n: len(self.FILES[n]) for n, _, _ in REMOTE})
        counts["common-reject"] += 1                                     # 内核取到了更新，本地缓存没跟上
        vehicle = {n: "HTTP" for n, _, _ in REMOTE}
        with FakeCore(counts, vehicle):
            d = cr.status_data(ctx)
        by = {s["name"]: s for s in d["sets"]}
        self.assertEqual([s["name"] for s in d["sets"] if s["inbox"]], [n for n, _, _ in INBOX][::2] + [n for n, _, _ in INBOX][1::2])
        self.assertEqual(by["common-proxy"]["state"], "ok")
        self.assertEqual(by["common-proxy"]["vehicle"], "HTTP")
        self.assertEqual(by["common-reject"]["state"], "differ")
        fb = {f["host"]: f for f in d["fallback"]}
        self.assertTrue(fb["iptoasn.com"]["ok"])
        self.assertEqual(fb["iptoasn.com"]["by"], "common-proxy")

    def test_fallback_first_match_wins(self):
        # 回退域名先被拉黑规则集命中：即使后面的代理规则集里有，也算未放行
        fx = self.fx(files={"windows-reject": ["+.iptoasn.com"]})
        with FakeCore({}, {}):
            d = cr.status_data(fx.ctx())
        fb = {f["host"]: f for f in d["fallback"]}["iptoasn.com"]
        self.assertFalse(fb["ok"]); self.assertEqual(fb["by"], "windows-reject")


class ConfigDirArg(unittest.TestCase):
    """--config-dir 写在子命令前后都生效，不退回自动定位的配置目录（那可能是真实的 Clash 配置）。"""

    def run_cli(self, *args):
        import subprocess
        env = dict(os.environ, PYTHONIOENCODING="utf-8")    # APPDATA 已指到临时目录，退回自动定位时找不到配置、以 2 退出
        tool = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "clash_review.py")
        return subprocess.run([sys.executable, "-B", tool, *args], env=env, capture_output=True, text=True, encoding="utf-8")

    def test_before_and_after_subcommand(self):
        fx = Fixture(files={"my-proxy": ["+.example.org", "a.example.org"]})
        for args in (("--config-dir", fx.dir, "tidy"), ("tidy", "--config-dir", fx.dir)):
            r = self.run_cli(*args)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("a.example.org  ← 已被 +.example.org 覆盖", r.stdout)


def tearDownModule():
    _TMP.cleanup()


if __name__ == "__main__":
    unittest.main()
