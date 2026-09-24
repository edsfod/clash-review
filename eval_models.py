"""第 2 层模型评估：同一套题分别交给几个模型（advisor.PROVIDERS），结果存 var/eval/<run>/，可中断续跑。

三套题（都只发主机名与本机已有的少量证据，不发前后连接）：
  A labels     规则集里的人工归类（var/testcases/labels-20260923/），抽样，排除占位、provenance 里改过的、不外发名单里的与 IP。
               检验归类方向：模型推荐与人工归类是否一致。人工归类按旧策略做，只能衡量大体方向。
  B suspicious 地域放行「可疑」24 项（var/testcases/suggest-20260923.json）。没有标准答案，留作盲评，报告里不显示内容。
  C canary     编造的主机（2026-09-23 查过 DoH 均为 NXDOMAIN，父域也未注册），正确回答是不认识；
               另加 statsig.anthropic.com，附本机实测证据，看模型是否以本机证据为准。

用法：python eval_models.py [--run NAME] [--providers a,b] [--sets A,B,C] [--report-only]
      [--from-run NAME]   沿用另一轮冻结的题目（items.json），便于前后比较
      [--half dev|test]   A 套只跑主机名哈希分出的一半（改提示词看 dev，确认看 test）
      [--evidence]        A、B 套附上本机证据（evidence.py：国内视角解析、直连实测、同站归类），结果存 <模型>+ev/
"""
import argparse, concurrent.futures as cf, hashlib, json, os, random, re, sys, threading

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import advisor, evidence
import clash_review as cr

TC   = os.path.join(cr.DATA_DIR, "testcases")
EVAL = os.path.join(cr.DATA_DIR, "eval")
SEED = 20260923
SAMPLE = {"direct": 99, "proxy": 30, "reject": 30}   # 每类最多抽多少（直连不足 99，即全取）
EXCLUDE = {"placeholder.never-match.invalid", "example.com", "disabled.invalid",
           "imageeditor.example", "searchapp.bundleassets.example"}
CANARIES = ["telemetry.trivelta-analytics.com", "log-collect.huanyuxinke.cn", "cdn.stellarquill.net",
            "t.zenmoriq.com", "sync-api.lumetrix-cloud.io"]
STATSIG_NOTE = ("2026-09-23 本机实测：Claude Code 2.1.280 运行约 10 分钟、以及一次完整启动，都没有连接这个主机；"
                "同期调试日志显示功能开关来自 GrowthBook。该主机目前已在 my-reject 里。")
CONCURRENCY = {"claude": 8, "deepseek": 8}   # 每个模型各自的并发数；几个模型同时跑

def run_items(run, from_run=None):
    """一轮评估的题目在第一次运行时冻结为 var/eval/<run>/items.json，之后都从它读。
    build_items() 会随 provenance.json 与不外发名单变化而抽到不同的题，不能每次重建。"""
    p = os.path.join(EVAL, run, "items.json")
    if os.path.exists(p): return json.load(open(p, encoding="utf-8"))
    src = os.path.join(EVAL, from_run, "items.json") if from_run else None
    items = json.load(open(src, encoding="utf-8")) if src else build_items()
    os.makedirs(os.path.dirname(p), exist_ok=True)
    json.dump(items, open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    return items

def build_items():
    no_send = advisor.load_no_send()
    prov = json.load(open(os.path.join(TC, "provenance.json"), encoding="utf-8"))
    changed = {cr._dom_base(c["entry"]) for c in prov["changes"]}
    items = {"A": [], "B": [], "C": []}
    rnd = random.Random(SEED)
    for cat in ("direct", "proxy", "reject"):
        hosts = [cr._dom_base(p) for p in cr.load_payload(os.path.join(TC, "labels-20260923", f"my-{cat}.yaml"))]
        hosts = sorted(h for h in hosts if h not in EXCLUDE and h not in changed
                       and not advisor.blocked(h, no_send) and not cr.is_ip(h))
        for h in rnd.sample(hosts, min(SAMPLE[cat], len(hosts))):
            items["A"].append({"kind": "pending", "host": h, "label": cat})
    for x in json.load(open(os.path.join(TC, "suggest-20260923.json"), encoding="utf-8"))["items"]:
        if advisor.blocked(x["host"], no_send): continue
        items["B"].append({"kind": "suspicious", "host": x["host"], "bucket": x["bucket"],
                           "count": x["record"]["count"], "reasons": x["reasons"], "sites": x["record"].get("sites", [])})
    for h in CANARIES: items["C"].append({"kind": "pending", "host": h, "canary": "fake"})
    items["C"].append({"kind": "pending", "host": "statsig.anthropic.com", "canary": "statsig", "note": STATSIG_NOTE})
    return items

def half(host): return "dev" if int(hashlib.md5(host.encode()).hexdigest(), 16) % 2 == 0 else "test"

def attach_evidence(items):
    """A、B 套附上本机证据。同站归类取冻结的标注规则集，并去掉被问的主机本身（不泄露答案）。
    C 套不附：编造的主机会被「域名不存在」直接揭穿，测不出模型会不会编。"""
    labels = {c: cr.load_payload(os.path.join(TC, "labels-20260923", f"my-{c}.yaml")) for c in ("proxy", "direct", "reject")}
    todo = [it for s in ("A", "B") for it in items.get(s, [])]
    with cf.ThreadPoolExecutor(16) as ex:
        evs = list(ex.map(lambda it: evidence.collect(it["host"]), todo))
    for it, ev in zip(todo, evs):
        it["evidence_lines"] = evidence.describe(ev)
        it["same_site"] = evidence.same_site(it["host"], labels)
    return items

def _path(run, prov, s, host):
    return os.path.join(EVAL, run, prov, s, re.sub(r"[^A-Za-z0-9._-]", "_", host) + ".json")

def run_all(run, providers, sets, items, tag=""):
    sysmsg = advisor.system_prompt()
    os.makedirs(os.path.join(EVAL, run), exist_ok=True)
    with open(os.path.join(EVAL, run, "system_prompt.txt"), "w", encoding="utf-8") as f: f.write(sysmsg)
    lock = threading.Lock(); done = [0]
    def one(prov, s, it):
        p = _path(run, prov + tag, s, it["host"])
        if os.path.exists(p): return
        r = advisor.ask(prov, it, sysmsg=sysmsg)
        r["item"] = it; r["provider"] = prov + tag
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f: json.dump(r, f, ensure_ascii=False, indent=1)
        with lock:
            done[0] += 1
            print(f"  [{prov}{tag}] {s} {it['host']}: {'ok' if r['ok'] else 'FAIL ' + r['error'][:80]} ({r['seconds']}s)", flush=True)
    def per_provider(prov):
        fam = "claude" if prov.startswith("claude") else "deepseek"
        jobs = [(prov, s, it) for s in sets for it in items[s]]
        print(f"{prov}: {len(jobs)} 项", flush=True)
        with cf.ThreadPoolExecutor(CONCURRENCY[fam]) as ex:
            list(ex.map(lambda j: one(*j), jobs))
    with cf.ThreadPoolExecutor(len(providers)) as ex:
        list(ex.map(per_provider, providers))

def load_results(run, prov, s):
    d = os.path.join(EVAL, run, prov, s)
    if not os.path.isdir(d): return []
    return [json.load(open(os.path.join(d, f), encoding="utf-8")) for f in sorted(os.listdir(d)) if f.endswith(".json")]

def report(run, providers):
    L = [f"# 模型评估 {run}", ""]
    L += ["## A 与人工归类的一致性", "",
          "人工归类是旧策略下做的，只看大体方向。「不选 / 忽略」算弃权，不计入一致率。", "",
          "| 模型 | 题数 | 失败 | 弃权 | 作答 | 一致 | 一致率 | 直连 | 代理 | 拉黑 | 平均秒 | 费用 |", "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for prov in providers:
        rs = load_results(run, prov, "A")
        if not rs: continue
        fail = [r for r in rs if not r["ok"]]; okr = [r for r in rs if r["ok"]]
        abst = [r for r in okr if r["result"]["recommend"] in ("keep", "ignore")]
        ans = [r for r in okr if r["result"]["recommend"] not in ("keep", "ignore")]
        agree = [r for r in ans if r["result"]["recommend"] == r["item"]["label"]]
        per = {}
        for cat in ("direct", "proxy", "reject"):
            a = [r for r in ans if r["item"]["label"] == cat]
            per[cat] = f"{sum(1 for r in a if r['result']['recommend']==cat)}/{len(a)}"
        secs = sum(r["seconds"] for r in rs) / len(rs)
        cost = sum((r.get("meta") or {}).get("cost_usd") or 0 for r in rs)
        L.append(f"| {prov} | {len(rs)} | {len(fail)} | {len(abst)} | {len(ans)} | {len(agree)} | "
                 f"{len(agree)/len(ans):.0%} | {per['direct']} | {per['proxy']} | {per['reject']} | {secs:.1f} | "
                 f"{'$%.2f' % cost if cost else '—'} |" if ans else f"| {prov} | {len(rs)} | {len(fail)} | … |")
    L += ["", "「直连 / 代理 / 拉黑」列：人工归为该类、模型也作答的题中，模型给出同类的比例。", ""]
    L += ["## C 编造主机与本机证据", "", "| 模型 | 编造主机：说不认识 | 编造主机：给出归属 | statsig：recommend / confidence / 拉黑影响 |", "|---|---|---|---|"]
    for prov in providers:
        rs = {r["item"]["host"]: r for r in load_results(run, prov, "C")}
        if not rs: continue
        fake = [rs[h] for h in CANARIES if h in rs and rs[h]["ok"]]
        honest = [r for r in fake if r["result"]["owner_basis"] == "unknown" and not r["result"]["owner"].strip()]
        claimed = [f"{r['item']['host']}→{r['result']['owner']}（{r['result']['owner_basis']}）" for r in fake if r not in honest]
        st = rs.get("statsig.anthropic.com")
        sts = (f"{st['result']['recommend']} / {st['result']['confidence']} / {st['result']['block_impact'][:60] or '（空）'}"
               if st and st["ok"] else "失败")
        L.append(f"| {prov} | {len(honest)}/{len(fake)} | {'；'.join(claimed) or '无'} | {sts} |")
    L += ["", "## B 地域放行「可疑」24 项", "", "留作盲评，这里只报完成情况。", ""]
    for prov in providers:
        rs = load_results(run, prov, "B")
        if rs: L.append(f"- {prov}：{sum(1 for r in rs if r['ok'])}/{len(rs)} 成功")
    txt = "\n".join(L) + "\n"
    with open(os.path.join(EVAL, run, "report.md"), "w", encoding="utf-8") as f: f.write(txt)
    return txt

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", default="run-20260923")
    ap.add_argument("--providers", default=",".join(advisor.PROVIDERS))
    ap.add_argument("--sets", default="A,B,C")
    ap.add_argument("--report-only", action="store_true")
    ap.add_argument("--from-run"); ap.add_argument("--half", choices=["dev", "test"]); ap.add_argument("--evidence", action="store_true")
    a = ap.parse_args()
    provs = [p for p in a.providers.split(",") if p]
    if not a.report_only:
        items = run_items(a.run, a.from_run)
        if a.half: items["A"] = [x for x in items["A"] if half(x["host"]) == a.half]
        if a.evidence: items = attach_evidence(items)
        print("题目：" + "，".join(f"{k} {len(v)} 项" for k, v in items.items()))
        run_all(a.run, provs, [s for s in a.sets.split(",") if s], items, "+ev" if a.evidence else "")
    tag = "+ev" if a.evidence else ""
    print(report(a.run, [p + tag for p in provs]))

if __name__ == "__main__":
    main()
