"""核验模型评估结果（eval_models.py 的输出）：能自动核验的自动核验，其余列成人工清单。

本机证据（缓存到 var/eval/<run>/evidence.json）：
  - DNS：国内视角（腾讯 DoH 1.12.12.12，即直连时会拿到的地址）与境外视角（Google DoH 8.8.8.8，经代理）各解析一次
  - 每个地址的 ASN、组织、国家（var/ipdata 的 ip2asn 数据）
  - 模型给出的网址是否真的能打开（这一轮模型都不联网，给出网址本身就可疑）

自动核验：
  A  与人工归类不一致的题，按类型处理：
     - 直连 / 代理之争：看国内视角解析到的地址是否在中国（策略第二节）。能判定的给出结论，判定不了的进人工清单
     - 拉黑与否之争：本机数据判断不了，进人工清单；三个模型都与人工归类相反的单独标出（可能是旧归类不符合新策略）
     - 两个视角都解析不到的主机：已失效，归类无关紧要
  C  编造主机：必须说不认识；statsig：拉黑影响不得与本机证据相反（关键词粗查，结果也列给人看）
  策略遵守（三套题都查）：免费子域平台不许写父域、ignore 只能用于一次性噪声、不认识的主机不许高置信度
  B  三个模型一致且没有违反策略的，列为「一致，未独立核验」；不一致的进人工清单，按模型匿名（甲乙丙，顺序每题随机）

A 按主机名哈希分成 dev / test 两半：改提示词只看 dev，test 用来确认改进不是只对这批题有效。

用法：python verify_eval.py [--run NAME] [--providers a,b,c] [--no-net]
"""
import argparse, concurrent.futures as cf, hashlib, json, os, random, re, subprocess, sys, urllib.request, urllib.parse
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)   # 在 pythonw（没有控制台）下调 curl 等命令行程序，不加这个每次都会弹出一个 cmd 窗口

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import clash_review as cr
import eval_models as em

FREE_SUBDOMAIN = ("workers.dev", "pages.dev", "github.io", "vercel.app", "netlify.app", "supabase.co", "qzz.io",
                  "us.ci", "cc.cd", "trafficmanager.net", "cloudfront.net", "azureedge.net", "herokuapp.com")
CN_NAME = {"direct": "直连", "proxy": "代理", "reject": "拉黑", "keep": "不选", "ignore": "忽略", "ok": "正常"}

def half(host): return "dev" if int(hashlib.md5(host.encode()).hexdigest(), 16) % 2 == 0 else "test"

# ---------------- 本机证据 ----------------
def _doh(url):
    req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
    with urllib.request.urlopen(req, timeout=10) as r: d = json.load(r)
    if d.get("Status") == 3: return "NXDOMAIN"
    return [a["data"] for a in d.get("Answer", []) if a.get("type") == 1]

def resolve(host):
    out = {}
    for view, url in (("cn", "https://1.12.12.12/dns-query?type=A&name="), ("global", "https://8.8.8.8/resolve?type=A&name=")):
        try: out[view] = _doh(url + urllib.parse.quote(host))
        except Exception as e: out[view] = f"ERR {type(e).__name__}"
    return out

def _curl_code(url, direct):
    args = ["curl", "-s", "-o", "NUL", "-L", "-m", "12", "-A", "Mozilla/5.0", "-w", "%{http_code}"]
    args += ["--noproxy", "*", "--doh-url", "https://1.12.12.12/dns-query"] if direct else ["-x", cr.local_proxy()]
    try: return subprocess.run(args + [url], capture_output=True, text=True, timeout=20, creationflags=_NO_WINDOW).stdout.strip() or "000"
    except Exception: return "000"

def url_check(u):
    """返回 exists（域名能解析）/ page（经代理取到的 HTTP 状态码）。
    经 Clash 取不到不等于网址是编的：主机可能正被自己的规则拒绝（MATCH,REJECT）。"""
    host = urllib.parse.urlsplit(u).hostname or ""
    try: exists = _doh("https://8.8.8.8/resolve?type=A&name=" + urllib.parse.quote(host)) != "NXDOMAIN"
    except Exception: exists = None
    return {"exists": exists, "page": _curl_code(u, direct=False)}

def direct_ok(host):
    """直连（不经 Clash，用腾讯 DoH 解析）能否取到 https 首页，用于核对「境外但直连可达」的例外。"""
    return _curl_code("https://" + host + "/", direct=True)

def gather_evidence(run, hosts, urls, net=True):
    p = os.path.join(em.EVAL, run, "evidence.json")
    ev = json.load(open(p, encoding="utf-8")) if os.path.exists(p) else {"dns": {}, "urls": {}}
    ev.setdefault("direct", {})
    ev["urls"] = {u: r for u, r in ev["urls"].items() if isinstance(r, dict)}   # 旧格式（只有真假）重查
    if net:
        todo = [h for h in hosts if h not in ev["dns"]]
        with cf.ThreadPoolExecutor(16) as ex:
            for h, r in zip(todo, ex.map(resolve, todo)): ev["dns"][h] = r
        todo = [u for u in urls if u not in ev["urls"]]
        with cf.ThreadPoolExecutor(16) as ex:
            for u, r in zip(todo, ex.map(url_check, todo)): ev["urls"][u] = r
        json.dump(ev, open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    return ev

def asn_view(ips, table):
    if not isinstance(ips, list): return ips, set()
    info = [cr.ip2asn_lookup(table, ip) for ip in ips]
    ccs = {i["cc"] for i in info if i}
    descs = sorted({f"AS{i['asn']} {i['desc']} [{i['cc']}]" for i in info if i})
    return "；".join(descs) or "—", ccs

# ---------------- 策略遵守 ----------------
def violations(item, res):
    v = []
    sc = (res.get("scope") or "").strip().lower()
    if sc.startswith("+."):
        base = sc[2:]
        if any(base == s for s in FREE_SUBDOMAIN): v.append(f"对免费子域平台写了父域 {sc}")
    if res["recommend"] == "ignore": v.append("用了 ignore（只应用于一次性噪声）")
    if res["owner_basis"] == "unknown" and res["confidence"] == "high": v.append("不认识却给高置信度")
    if res["owner_basis"] == "known" and not res["owner"].strip(): v.append("说已知但没写归属")
    return v

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", default="run-20260923")
    ap.add_argument("--providers", default="deepseek-flash,claude-haiku,claude-sonnet")
    ap.add_argument("--no-net", action="store_true")
    a = ap.parse_args()
    provs = a.providers.split(",")
    R = {p: {s: {r["item"]["host"]: r for r in em.load_results(a.run, p, s)} for s in "ABC"} for p in provs}
    hosts = sorted({h for p in provs for s in "AB" for h in R[p][s]})
    urls = sorted({u.split()[0].rstrip("，,;；") for p in provs for s in "ABC" for r in R[p][s].values() if r["ok"]
                   for u in r["result"]["sources"] if u.startswith("http")})
    ev = gather_evidence(a.run, hosts, urls, net=not a.no_net)
    table = cr.load_ip2asn()
    need = [h for h in hosts if any(R[p]["A"].get(h, {}).get("item", {}).get("label") == "direct" for p in provs)
            and h not in ev["direct"]]
    if need and not a.no_net:
        with cf.ThreadPoolExecutor(16) as ex:
            for h, c in zip(need, ex.map(direct_ok, need)): ev["direct"][h] = c
        json.dump(ev, open(os.path.join(em.EVAL, a.run, "evidence.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    rnd = random.Random(20260923)

    out = [f"# 评估核验 {a.run}", ""]
    manual = [f"# 人工标记清单 {a.run}", "",
              "模型匿名为甲乙丙，每题顺序随机。每题写下你的结论（直连 / 代理 / 拉黑 / 不选，或 拉黑 / 正常），可附一句理由。", ""]

    # ---- 策略遵守 ----
    out += ["## 策略遵守（三套题）", "", "| 模型 | 作答 | 违反条数 | 类型 |", "|---|---|---|---|"]
    viol_detail = {}
    for p in provs:
        cnt = {}; n = 0
        for s in "ABC":
            for h, r in R[p][s].items():
                if not r["ok"]: continue
                n += 1
                for v in violations(r["item"], r["result"]):
                    k = re.sub(r" \+\..*", "", v); cnt[k] = cnt.get(k, 0) + 1
                    viol_detail.setdefault(p, []).append(f"{h}：{v}")
        out.append(f"| {p} | {n} | {sum(cnt.values())} | {'；'.join(f'{k} {c}' for k, c in cnt.items()) or '无'} |")
    for p, L in viol_detail.items():
        out += ["", f"{p} 的违反明细："] + [f"- {x}" for x in L[:30]]
    out.append("")

    # ---- C ----
    out += ["## C 编造主机与本机证据", ""]
    for p in provs:
        fakes = [(h, r["result"]) for h, r in R[p]["C"].items() if r["ok"] and r["item"].get("canary") == "fake"]
        fake_bad = [f"{h}（{x['owner']} / {x['owner_basis']} / 置信度 {x['confidence']} / {CN_NAME[x['recommend']]}）"
                    for h, x in fakes if x["owner_basis"] == "known" or (x["owner_basis"] == "inferred" and x["confidence"] == "high")]
        fake_inf = [f"{h}（{x['owner_basis']} / 置信度 {x['confidence']} / {CN_NAME[x['recommend']]}）"
                    for h, x in fakes if x["owner_basis"] == "inferred" and x["confidence"] != "high"]
        fake_fmt = [h for h, x in fakes if x["owner_basis"] == "unknown" and x["owner"].strip()]
        st = R[p]["C"].get("statsig.anthropic.com")
        if st and st["ok"]:
            bi = st["result"]["block_impact"]
            contra = bool(re.search(r"功能开关|feature flag|失效|无法使用|异常", bi)) and not re.search(r"本机|实测|GrowthBook|未连接|没有连接", bi)
            sts = f"{CN_NAME[st['result']['recommend']]}，影响写「{bi or '（空）'}」" + ("　**与本机证据相反**" if contra else "")
        else: sts = "失败"
        out.append(f"- **{p}**：编造主机 {len(fakes)} 个，" + ("没有冒充已知" if not fake_bad else "**冒充已知或高置信度**：" + "；".join(fake_bad))
                   + (f"；按名称推断（置信度不高）：{'；'.join(fake_inf)}" if fake_inf else "")
                   + (f"；格式问题（不认识却在 owner 里写了字）：{len(fake_fmt)} 个" if fake_fmt else "")
                   + f"。statsig：{sts}")
    out.append("")

    # ---- A ----
    out += ["## A 与人工归类不一致的题", ""]
    auto_rows = []; manual_A = []; dead = []; all_against = []
    for h in sorted({h for p in provs for h in R[p]["A"]}):
        item = next(R[p]["A"][h]["item"] for p in provs if h in R[p]["A"])
        label = item["label"]
        recs = {p: R[p]["A"][h]["result"]["recommend"] for p in provs if h in R[p]["A"] and R[p]["A"][h]["ok"]}
        dis = {p: r for p, r in recs.items() if r not in (label, "keep", "ignore")}
        if not dis: continue
        d = ev["dns"].get(h, {}); cn_desc, cn_cc = asn_view(d.get("cn"), table); gl_desc, _ = asn_view(d.get("global"), table)
        if d.get("cn") == "NXDOMAIN" and d.get("global") == "NXDOMAIN":
            dead.append(h); continue
        if all(recs.get(p) == next(iter(dis.values())) for p in provs if p in recs) and len(recs) == len(provs):
            all_against.append((h, label, next(iter(dis.values()))))
        pair = {label} | set(dis.values())
        if pair <= {"direct", "proxy"} and cn_cc:
            verdict = "direct" if cn_cc == {"CN"} else ("proxy" if "CN" not in cn_cc else None)
            note = f"国内视角 {cn_desc}"
            if verdict == "proxy" and label == "direct":
                code = ev["direct"].get(h, "000")
                note += f"；直连实测 HTTP {code}"
                if code != "000" and code[0] in "234":
                    verdict = "direct"; note += "（境外但直连可达，合第二节第 2 条例外）"
            if verdict:
                auto_rows.append(f"| {h} | {CN_NAME[label]} | {'，'.join(f'{p} {CN_NAME[r]}' for p, r in dis.items())} | "
                                 f"{note} → {CN_NAME[verdict]} | {'人工对' if verdict == label else '模型对'} |")
                continue
        manual_A.append((h, label, recs, cn_desc, gl_desc, half(h)))
    out += [f"两个视角都解析不到（已失效，归类无关紧要）：{len(dead)} 个 {', '.join(dead)}", ""]
    out += ["### 直连 / 代理之争，按国内视角解析地址自动判定", "", "| 主机 | 人工 | 不同意的模型 | 本机证据 | 判定 |", "|---|---|---|---|---|"] + auto_rows + [""]
    out += ["### 三个模型都与人工归类相反", "", "可能是旧归类不符合新策略（如第一方遥测），也可能是模型共同出错。已列入人工清单。", ""]
    out += [f"- {h}：人工 {CN_NAME[l]}，三个模型都说 {CN_NAME[m]}" for h, l, m in all_against] + [""]

    manual += ["## 一、规则集旧归类与模型不一致（本机证据判定不了）", "",
               "这些是你以前的归类。看模型理由后，决定维持还是改。", ""]
    for h, label, recs, cn_desc, gl_desc, hf in manual_A:
        manual.append(f"### {h}（{hf}）")
        manual.append(f"- 你原来的归类：{CN_NAME[label]}")
        manual.append(f"- 本机证据：国内视角 {cn_desc}；境外视角 {gl_desc}")
        order = [p for p in provs if p in recs]; rnd.shuffle(order)
        for tag, p in zip("甲乙丙", order):
            r = R[p]["A"][h]["result"]
            manual.append(f"- {tag}：**{CN_NAME[r['recommend']]}**（{r['confidence']}）{r['owner'] or '不认识'}；{r['purpose']}；理由：{'；'.join(r['reasons'])}"
                          + (f"；拉黑影响：{r['block_impact']}" if r["block_impact"] else ""))
        manual += ["- 你的结论：", ""]

    # ---- B ----
    agree_B = []; manual_B = []
    for h in sorted({h for p in provs for h in R[p]["B"]}, key=lambda x: [i["host"] for i in em.run_items(a.run)["B"]].index(x)):
        recs = {p: R[p]["B"][h]["result"]["recommend"] for p in provs if h in R[p]["B"] and R[p]["B"][h]["ok"]}
        bad = [v for p in recs for v in violations(R[p]["B"][h]["item"], R[p]["B"][h]["result"])]
        if len(recs) == len(provs) and len(set(recs.values())) == 1 and not bad: agree_B.append((h, next(iter(recs.values())))); continue
        manual_B.append(h)
    out += ["## B 地域放行「可疑」", "", f"三个模型一致、且没有违反策略：{len(agree_B)} 项（互相印证，但未经独立核验）；其余 {len(manual_B)} 项进人工清单。", ""]
    manual += ["## 二、地域放行「可疑」：三个模型意见不一的", "", "结论从 拉黑 / 正常 中选。", ""]
    items_B = {i["host"]: i for i in em.run_items(a.run)["B"]}
    # 同一类主机（只差数字或 cn-<地区>- 前缀，如 B 站的 cn-sdqd-ccc-live-tracker-04）合成一题，以第一个为代表
    groups = {}
    for h in manual_B:
        groups.setdefault(re.sub(r"^cn-[a-z]+-", "cn-*-", re.sub(r"\d+", "N", h)), []).append(h)
    for members in groups.values():
        h = members[0]
        d = ev["dns"].get(h, {}); cn_desc, _ = asn_view(d.get("cn"), table)
        it = items_B[h]
        manual.append(f"### {h}" + (f"（同类共 {len(members)} 个，结论对全部适用：{', '.join(members[1:])}）" if len(members) > 1 else ""))
        manual.append(f"- 现在：{'直连' if it['bucket']=='direct' else '代理'}，{it['count']} 次；排序理由：{'；'.join(it['reasons'])}；国内视角 {cn_desc}")
        order = [p for p in provs if p in R and h in R[p]["B"] and R[p]["B"][h]["ok"]]; rnd.shuffle(order)
        for tag, p in zip("甲乙丙", order):
            r = R[p]["B"][h]["result"]
            manual.append(f"- {tag}：**{CN_NAME[r['recommend']]}**（{r['confidence']}）{r['owner'] or '不认识'}；{r['purpose']}；理由：{'；'.join(r['reasons'])}"
                          + (f"；拉黑影响：{r['block_impact']}" if r["block_impact"] else ""))
        manual += ["- 你的结论：", ""]
    manual += ["## 三、地域放行「可疑」：三个模型一致的（未独立核验，可快速过一遍）", ""]
    for h, rec in agree_B:
        r = R[provs[-1]]["B"][h]["result"]
        manual.append(f"- {h}：三家都说 **{CN_NAME[rec]}**。{r['owner'] or '不认识'}；{r['purpose']}　你的结论：")
    manual.append("")

    # ---- 来源网址 ----
    urlev = {u: ev["urls"][u] for u in urls if u in ev["urls"]}
    fake_dom = [u for u, r in urlev.items() if r["exists"] is False]
    no_page = [f"{u}（HTTP {r['page']}）" for u, r in urlev.items() if r["exists"] and not r["page"].startswith(("2", "3"))]
    out += ["## 模型给出的网址", "", f"共 {len(urlev)} 个（这一轮模型都不联网，全凭记忆）。域名根本不存在：{len(fake_dom)} 个；"
            f"域名存在但经代理取不到页面：{len(no_page)} 个（可能是路径记错，也可能是被自己的规则拒绝，不算编造）。", ""]
    out += [f"- 域名不存在：{u}" for u in fake_dom] + [f"- 取不到页面：{u}" for u in no_page] + [""]

    d = os.path.join(em.EVAL, a.run)
    open(os.path.join(d, "verify.md"), "w", encoding="utf-8").write("\n".join(out) + "\n")
    open(os.path.join(d, "manual.md"), "w", encoding="utf-8").write("\n".join(manual) + "\n")
    print("\n".join(out))
    print(f"\n人工清单：{len(manual_A)} + {len(groups)} 题（地域放行 {len(manual_B)} 个主机合成 {len(groups)} 题；另 {len(agree_B)} 项三家一致，供快速过目）→ {os.path.join(d, 'manual.md')}")

if __name__ == "__main__":
    main()
