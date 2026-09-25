"""三层并排：第 1 层本机事实（evidence.py、流量）、第 2 层模型（advisor.py）、第 3 层外部资料（external.py）。
各层独立给出结果，推荐只由下面写明的规则汇总，只作提示，从不自动选择；各层意见冲突时标「有分歧」，由人定。

汇总规则的依据（2026-09-23，A 套 78 题 × 三次运行回放）：
  - 模型与名单都说拉黑：58 次，全部与人工归类一致 → 「拉黑，模型与名单一致」
  - 只有名单说拉黑：2 次，都对；名单另在全部 124 个人工放行的主机里只误收 1 个 → 「拉黑，名单收录」
  - 只有模型说拉黑：19 次，15 次对、4 次把在用的站判拉黑（误拉黑全部出在这一格）→ 「有分歧：仅模型认为该拉黑」
  - 模型说放行、名单没收录：106 次，102 次对 → 按模型给直连或代理
用法：python layers.py <主机> [--model] [--rdap] [--cert] [--search]
"""
import json, os, sys

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import clash_review as cr, evidence, external

CN = {"direct": "直连", "proxy": "代理", "reject": "拉黑", "keep": "不选", "ignore": "忽略", "ok": "正常"}

def layer1(host, ctx=None, payloads=None):
    ev = evidence.collect(host)
    lines = evidence.describe(ev)
    if ctx is not None:
        t = cr.load_traffic(ctx)["hosts"].get(host)
        tl = cr.traffic_line(t)
        if tl: lines.append(tl)
        payloads = payloads or {c: ctx.entries("domain", c) for c in ("proxy", "direct", "reject")}
    ss = evidence.same_site(host, payloads) if payloads else []
    if ss: lines.append("同站主机在规则集里的归类：" + "，".join(ss[:8]))
    return {"evidence": ev, "lines": lines, "same_site": ss}

def layer3(host, rdap=False, cert=False, search=False, ip=None):
    lk = external.lookup(host)
    out = {"lookup": lk, "verdict": external.verdict(lk), "lines": external.describe(lk)}
    if rdap:
        r = external.rdap(host); out["rdap"] = r
        out["lines"].append(f"RDAP（{r['domain']}）：" + (f"注册于 {r['registered']}，注册商 {r['registrar'] or '—'}" if not r.get("error") else "查不到（该后缀可能不提供 RDAP）"))
    if cert:
        c = external.cert(host, ip); out["cert"] = c
        out["lines"].append("证书：" + (f"{c['subject_org'] or '（证书没写机构）'}，CN={c['subject_cn']}，签发 {c['issuer']}" if not c.get("error") else f"取不到（{c['error']}）"))
    if search:
        s = external.search(host); out["search"] = s
        if s.get("error"): out["lines"].append(f"搜索：失败 {s['error']}")
        elif not s.get("found"): out["lines"].append("搜索：没找到可靠出处")
        else:
            for src in s.get("sources", [])[:4]:
                out["lines"].append(f"搜索出处：{src['title']}（{src['url']}{'，' + src['date'] if src.get('date') else ''}）：{src['says']}")
    return out

def combine(model_decision, list_verdict, kind="pending"):
    """返回 (推荐, 说明, 是否有分歧)。推荐只作提示。"""
    m, l = model_decision, list_verdict
    if m == "reject" and l == "reject": return "reject", "拉黑：模型与名单一致", False
    if l == "reject" and m != "reject":
        return "reject", f"拉黑：名单收录（模型认为{CN.get(m, '无结论')}）", m in ("direct", "proxy", "ok")
    if m == "reject": return None, "有分歧：仅模型认为该拉黑，名单都没收录", True
    if m in ("direct", "proxy", "ok"): return m, f"{CN[m]}：模型建议，名单没有收录", False
    if m is None: return None, "只有本机与名单信息，没有模型意见", False
    return None, "模型没有结论", False

def explain(host, kind="pending", model=False, **kw):
    ctx = cr.Ctx(cr.resolve_config_dir())
    l1 = layer1(host, ctx)
    ips = (l1["evidence"] or {}).get("cn_ips")
    l3 = layer3(host, ip=ips[0] if isinstance(ips, list) and ips else None, **kw)
    l2 = None
    if model:
        import advisor
        # 模型只看第 1 层（本机事实），不看名单：两者要各自独立，「一致」才有意义
        item = {"kind": kind, "host": host, "evidence_lines": [x for x in l1["lines"] if not x.startswith("同站")], "same_site": l1["same_site"]}
        l2 = advisor.ask_checked("deepseek-flash", item)
    md = l2["result"]["decision"] if l2 and l2.get("ok") else None
    rec, why, split = combine(md, l3["verdict"], kind)
    return {"host": host, "layer1": l1["lines"], "layer3": l3["lines"], "layer2": l2, "recommend": rec, "why": why, "split": split}

if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]; flags = {a[2:] for a in sys.argv[1:] if a.startswith("--")}
    for h in args:
        r = explain(h, model="model" in flags, rdap="rdap" in flags, cert="cert" in flags, search="search" in flags)
        print(f"== {h}\n推荐：{r['why']}" + ("　【有分歧，由你定】" if r["split"] else ""))
        print("  本机：" + "\n        ".join(r["layer1"] or ["（无）"]))
        print("  资料：" + "\n        ".join(r["layer3"]))
        if r["layer2"] and r["layer2"].get("ok"):
            x = r["layer2"]["result"]
            print(f"  模型：{CN[x['decision']]}" + (f"（{len(x.get('votes', []))} 次：{'、'.join(CN[v] for v in x['votes'])}）" if x.get("votes") else "") + f"　{x['owner'] or '不认识'}；{x['function']}")
            for o in sorted(x["options"], key=lambda o: -o["confidence"]): print(f"        {CN[o['choice']]} {o['confidence']:>3}：{o['reason']}")

# ---------------- 给网页用：带发起进程、前后连接的一项 ----------------
def explain_item(item, ctx, payloads, model=True, include_ctx=False):
    """item：{kind: pending|suspicious|todirect, host, count?, procs?, ctx?, bucket?, reasons?, sites?}。
    include_ctx：是否把前后连接（站点名）发给模型。按外发规则，只有单行「理由」时才发，「为本页全部生成」不发。"""
    import datetime
    host = item["host"]; kind = item.get("kind", "pending"); is_ip = cr.is_ip(host)
    if is_ip:
        l1 = {"evidence": None, "lines": [], "same_site": []}
        t = cr.load_traffic(ctx)["hosts"].get(host); tl = cr.traffic_line(t)
        if tl: l1["lines"].append(tl)
    else:
        l1 = layer1(host, ctx, payloads)
    ips = (l1["evidence"] or {}).get("cn_ips")
    l3 = layer3(host) if not is_ip else {"lookup": None, "verdict": None, "lines": ["名单：只收域名，IP 不查"]}
    out = {"host": host, "kind": kind, "layer1": l1["lines"], "layer3": l3["lines"], "list_verdict": l3["verdict"],
           "owner_lists": (l3["lookup"] or {}).get("owner", []), "model": None, "model_error": "",
           "checked": datetime.datetime.now().isoformat(timespec="seconds"), "ctx_sent": bool(include_ctx)}
    md = None
    if model:
        import advisor
        m = {"kind": kind, "host": host, "count": item.get("count"), "procs": item.get("procs", []),
             "ctx": item.get("ctx", []) if include_ctx else [],
             "bucket": item.get("bucket"), "reasons": item.get("reasons", []), "sites": item.get("sites", []) if include_ctx else [],
             "evidence_lines": [x for x in l1["lines"] if not x.startswith("同站")], "same_site": l1["same_site"]}
        try:
            r = advisor.ask_checked("deepseek-flash", m)
        except ValueError as e:                      # 不外发名单里的主机
            r = {"ok": False, "error": str(e)}
        if r.get("ok"):
            x = r["result"]; md = x["decision"]
            advisor.identity_put(host, x, "deepseek-flash", kind)        # 身份与页面无关，顺带缓存（见 advisor「缓存规则」）
            out["prompt_hash"] = advisor.prompt_hash()
            out["model"] = {k: x.get(k) for k in ("decision", "votes", "owner", "owner_basis", "function", "trigger", "reason",
                                                   "confidence", "scope", "block_impact", "options")}
        else: out["model_error"] = r.get("error", "")
    rec, why, split = combine(md, l3["verdict"], kind)
    if kind == "suspicious" and rec in ("direct", "proxy"): rec = "ok"
    out.update(recommend=rec, why=why, split=split)
    return out
