#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
clash_review_web —— clash_review 的本地网页界面（仅标准库）

启动一个只监听 127.0.0.1 的 HTTP 服务，提供 web/ 下的单页面与 /api/*，并打开浏览器。
三页：待审（漏网归类）/ 地域放行（可疑排序与全表）/ 规则管理（六个自定义规则集与体检；名字取自 Clash 配置）。
所有读写都调用 clash_review.py 里的同一套函数，命令行与网页行为一致。

安全：只绑定 127.0.0.1；校验 Host 头（防 DNS 重绑定）；写操作要求自定义头 X-Clash-Review
（跨站页面带不了这个头而不触发预检，本服务不应答预检），并校验 Origin。

服务外壳（后台运行的日志与失败对话框、单实例、--stop、空闲退出、安全校验、/api/display、/api/prefs、
配色与显示设置 /kit/*）来自本目录的 web-kit/（随工具带的副本，见本工具 README）。本文件只写业务接口。

用法：pythonw clash_review_web.py [--port 8765] [--no-browser] [--config-dir PATH] [--stop]
已有实例在同一端口运行时，只打开浏览器后退出。--stop 停止正在运行的实例。

在后台运行、不开控制台窗口（ui-style 第 3 节「后台运行」）：review-gui.bat 用 pythonw 启动后立即返回。
没有控制台时，输出写到 var/web.log；启动失败（端口被占、找不到配置目录）弹系统对话框告知。
没人用时自己退出，不一直占着端口：打开的页面每分钟报一次到，连续 IDLE_MINUTES 分钟没有任何请求、且没有后台任务在跑，就退出。
"""
import os, sys, json, argparse, webbrowser

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "web-kit"))      # 随本工具带的副本（来历见 vendor.json）
import clash_review as cr
import webkit

WEB = os.path.join(HERE, "web")
SIGNATURE = "clash-review-web"


IDLE_MINUTES = 30


ApiError = webkit.ApiError


# ---------------- 数据组装 ----------------
_ip2asn = {"loaded": False, "table": None}

def ip_table():
    if not _ip2asn["loaded"]:
        _ip2asn["table"] = cr.load_ip2asn(); _ip2asn["loaded"] = True
    return _ip2asn["table"]

def _rec(host, r, kind):
    d = {"host": host, "kind": kind, "count": r["count"], "first": r["first"], "last": r["last"],
         "ports": sorted(r["ports"], key=lambda p: (len(p), p)), "procs": sorted(r.get("procs") or []),
         "ctx": list(r.get("ctx") or [])}
    if kind == "ip":
        d["info"] = cr.enrich_ip(host, ip_table())
    return d

def _written_to(ctx, kind, cat):
    """提示里写进了哪个规则集：规则服务的规则集 id，或本机收件箱的名字。"""
    return ((ctx.dest.rulesets.get(kind) or {}).get(cat) or "?") if ctx.dest else ctx.names[kind][cat]

def api_status(ctx, q):
    d = cr.status_data(ctx)
    d["log"] = cr.scanlog_tail(ctx, 3)
    return d

def api_pending(ctx, q):
    pending = cr.load_pending(ctx.pending)
    groups = []
    for g in cr.context_groups(pending):
        items = [_rec(h, pending["domains"][h], "domain") if h in pending["domains"]
                 else _rec(h, pending["ips"][h], "ip") for h in g]
        groups.append({"items": items, "last": max(i["last"] for i in items)})
    groups.sort(key=lambda g: g["last"], reverse=True)
    return {"groups": groups, "domains": len(pending["domains"]), "ips": len(pending["ips"])}

# 人工裁定日志：应用前先取快照（应用后条目就从清单里移除了），连同模型当时的推荐一起记下（见 clash_review「人工裁定日志」）
def _advice_brief(adv, kind, host):
    a = adv.get(f"{kind}:{host}")
    if not a: return None
    m = a.get("model") or {}
    return {"recommend": a.get("recommend"), "split": a.get("split"), "model_decision": m.get("decision"), "votes": m.get("votes"),
            "list_verdict": a.get("list_verdict"), "prompt_hash": a.get("prompt_hash"), "checked": a.get("checked"),
            "model_error": a.get("model_error") or None}

def _decision(kind, host, decision, snap, adv):
    import datetime
    return {"time": datetime.datetime.now().isoformat(timespec="seconds"), "kind": kind, "host": host, "decision": decision,
            "snapshot": snap, "advice": _advice_brief(adv, kind, host)}

def api_pending_apply(ctx, body):
    targets = {c: [h for h in body.get(c, []) if isinstance(h, str)] for c in cr.CAT_ORDER}
    ignore = [h for h in body.get("ignore", []) if isinstance(h, str)]
    if not any(targets.values()) and not ignore: raise ApiError("没有选择任何条目")
    p = cr.load_pending(ctx.pending); adv = _advice_load(ctx); log = []
    for dec, hosts in list(targets.items()) + [("ignore", ignore)]:
        for h in hosts:
            r = p["domains"].get(h) or p["ips"].get(h) or {}
            snap = {"count": r.get("count"), "procs": sorted(r.get("procs") or []), "ctx": list(r.get("ctx") or []), "ports": sorted(r.get("ports") or [])}
            log.append(_decision("pending", h, dec, snap, adv))
    out, moved = cr.promote(ctx, targets) if any(targets.values()) else ([], [])
    notes = []
    if ignore:
        gone = cr.ignore_pending(ctx, ignore)
        notes += [{"k": "忽略", "cat": "", "t": f"{h}（移出待审，未写规则；再出现会回来）"} for h in gone]
    for cat, kind, added, ns in out:
        name = _written_to(ctx, kind, cat)
        notes += [{"k": "写入", "cat": cat, "t": f"{name}  {e}"} for e in added]
        notes += [{"k": "提示", "cat": "", "t": n} for n in ns]
    cr.append_decisions(ctx, log)
    return {"notes": notes, "removed": moved}

def api_suggest(ctx, q):
    rows = cr.suggest_routed(ctx)
    return {"rows": [{"host": h, "bucket": b, "score": round(sc, 1), "why": why, "count": rec["count"]}
                     for h, b, sc, why, rec in rows],
            "reviewed": len(cr.load_reviewed(ctx)), "min": cr.SUGGEST_MIN}

def api_routed(ctx, q):
    routed = cr.load_routed(ctx.routed)
    bucket = q.get("bucket", "all"); flt = q.get("q", "").strip().lower()
    try: limit = max(1, min(2000, int(q.get("limit", "200"))))
    except ValueError: limit = 200
    rows = []
    for b in ("direct", "proxy"):
        if bucket not in ("all", b): continue
        for h, r in routed[b].items():
            if flt and flt not in h.lower(): continue
            rows.append({"host": h, "bucket": b, "count": r["count"], "last": r["last"],
                         "ports": sorted(r["ports"], key=lambda p: (len(p), p))})
    rows.sort(key=lambda x: -x["count"])
    return {"rows": rows[:limit], "matched": len(rows),
            "totals": {"all": len(routed["direct"]) + len(routed["proxy"]),
                       "direct": len(routed["direct"]), "proxy": len(routed["proxy"])}}

def api_routed_apply(ctx, body):
    pick = lambda k: [h for h in body.get(k, []) if isinstance(h, str) and h.strip()]
    rej, ok, dr, keep = pick("reject"), pick("ok"), pick("direct"), pick("keep")
    if not (rej or ok or dr or keep): raise ApiError("没有标记任何条目")
    views = body.get("views") if isinstance(body.get("views"), dict) else {}      # 每项是在哪个视图里标的
    kind_of = {"sus": "suspicious", "dir": "todirect"}
    routed = cr.load_routed(ctx.routed); adv = _advice_load(ctx); log = []
    for dec, hosts in (("reject", rej), ("ok", ok), ("direct", dr), ("keep", keep)):
        for h in hosts:
            kind = kind_of.get(views.get(h), "routed")
            b = "proxy" if h in routed["proxy"] else "direct" if h in routed["direct"] else None
            r = routed[b][h] if b else {}
            snap = {"bucket": b, "count": r.get("count"), "sites": list(r.get("sites") or []), "ports": sorted(r.get("ports") or [])}
            log.append(_decision(kind, h, "proxy" if dec == "keep" else dec, snap, adv))
    notes = []
    if dr:
        added, ns = cr.routed_classify(ctx, "direct", dr)
        notes += [{"k": "写入", "cat": "direct", "t": _written_to(ctx, "ip" if cr.is_ip_token(e) else "domain", "direct") + "  " + e} for e in added]
        notes += [{"k": "提示", "cat": "", "t": n} for n in ns]
    if keep:
        cr.save_keepproxy(ctx, cr.load_keepproxy(ctx) | set(keep))
        notes.append({"k": "看过", "cat": "", "t": f"{len(keep)} 项保持代理，不再出现在「可改直连」里"})
    if rej:
        added, ns = cr.routed_classify(ctx, "reject", rej)
        notes += [{"k": "写入", "cat": "reject", "t": _written_to(ctx, "ip" if cr.is_ip_token(e) else "domain", "reject") + "  " + e} for e in added]
        notes += [{"k": "提示", "cat": "", "t": n} for n in ns]
    if ok:
        cr.save_reviewed(ctx, cr.load_reviewed(ctx) | set(ok))
        notes.append({"k": "看过", "cat": "", "t": f"{len(ok)} 项标为正常，不再出现在可疑排序里"})
    cr.append_decisions(ctx, log)
    return {"notes": notes}

def _set_of(ctx, name):
    for kind in ("domain", "ip"):
        for cat, n in ctx.names[kind].items():
            if name == n: return kind, cat
    raise ApiError(f"未知规则集 {name}")

def api_rules(ctx, q):
    if ctx.dest:     # 规则在规则服务上：列出服务端能写的全部规则集，经写入接口直接改（见 docs/destinations.md）
        return {"sets": cr.dest_editor(ctx), "dest": {"endpoint": ctx.dest.endpoint, "admin_url": ctx.dest.admin_url},
                "default": (ctx.dest.rulesets.get("domain") or {}).get("proxy")}     # 默认选中新条目写进去的代理规则集
    sets = []
    for kind in ("domain", "ip"):
        for cat in cr.CAT_ORDER:
            sets.append({"name": ctx.names[kind][cat], "kind": kind, "cat": cat,
                         "entries": cr.load_ruleset(ctx, kind, cat)})
    return {"sets": sets}

def api_rules_add(ctx, body):
    v = str(body.get("value", "")).strip()
    if not v: raise ApiError("条目为空")
    if ctx.dest:
        added, notes = cr.dest_edit(ctx, "add", body.get("set", ""), v, exact=bool(body.get("exact")))
        return {"added": added, "notes": notes}
    kind, cat = _set_of(ctx, body.get("set", ""))
    if kind == "ip" and not cr.is_ip_token(v): raise ApiError(f"{v} 不是 IP 或 CIDR")
    if kind == "domain" and (cr.is_ip_token(v) or not cr.is_domain(cr._dom_base(v))): raise ApiError(f"{v} 不是域名")
    notes = []; added = cr.move_entry(ctx, kind, None, cat, v, notes)
    return {"added": added, "notes": notes}

def api_rules_delete(ctx, body):
    if ctx.dest:
        entry = str(body.get("entry", "")); _, notes = cr.dest_edit(ctx, "delete", body.get("set", ""), entry)
        return {"removed": [entry], "notes": notes}
    kind, cat = _set_of(ctx, body.get("set", ""))
    removed = cr.remove_from(ctx, kind, cat, [str(body.get("entry", ""))])
    if not removed: raise ApiError("条目不存在（可能已被改动，刷新后再试）")
    return {"removed": removed}

def api_rules_move(ctx, body):
    if ctx.dest:     # to 是目标规则集（网页从 moves / layers 里取）
        added, notes = cr.dest_edit(ctx, "move", body.get("set", ""), str(body.get("entry", "")), body.get("to", ""))
        return {"added": added, "notes": notes}
    kind, cat = _set_of(ctx, body.get("set", "")); dst = body.get("to", "")
    if dst not in cr.CAT_ORDER or dst == cat: raise ApiError("目标分类无效")
    entry = str(body.get("entry", ""))
    if entry not in cr.load_ruleset(ctx, kind, cat): raise ApiError("条目不存在（可能已被改动，刷新后再试）")
    notes = []; added = cr.move_entry(ctx, kind, cat, dst, entry, notes)
    return {"added": added, "notes": notes}

def api_tidy(ctx, q):
    if ctx.dest:     # 体检只管本机收件箱；规则服务的冗余与重叠由服务端在写入时提示
        return {"redundant": [], "placeholder": [], "reserved": [], "overlap": [], "merge": []}
    rep = cr.ruleset_audit(ctx)
    return {"redundant": [{"kind": k, "cat": c, "entry": p, "by": by} for k, c, p, by in rep["redundant"]],
            "placeholder": [{"kind": k, "cat": c} for k, c in rep["placeholder"]],
            "reserved": [{"cat": c, "entry": p} for c, p in rep["reserved"]],
            "overlap": rep["overlap"],
            "merge": [{"cat": c, "parent": par, "hosts": hs} for c, par, hs in rep["merge"]]}

def api_tidy_apply(ctx, body):
    return {"notes": cr.tidy_apply(ctx)}

def api_tidy_merge(ctx, body):
    """合并候选：把父域写入该类，add_domains 会移除本类中被它覆盖的子域。只接受体检当前列出的候选。"""
    cat = body.get("cat", ""); parent = str(body.get("parent", "")).strip().lower()
    if not any(c == cat and par == parent for c, par, _ in cr.ruleset_audit(ctx)["merge"]):
        raise ApiError("不是当前的合并候选（刷新后再试）")
    notes = []; added = cr.add_domains(ctx, cat, [parent], notes)
    return {"added": added, "notes": notes}

# ---------------- 推荐与理由（三层并排，只作提示，从不自动选择；见 layers.py）----------------
# 名单（第 3 层离线部分）很快，列表一加载就查；模型要几十秒，在后台线程里跑，页面轮询进度。
# 结果缓存到 var/advice.json（按 类型:主机），再打开页面直接显示上次的结论与查询时间。
import threading, uuid
_ADV_LOCK = threading.Lock()
_JOBS = {}

def _advice_path(ctx): return os.path.join(ctx.review, "advice.json")

def _advice_load(ctx):
    try:
        with open(_advice_path(ctx), encoding="utf-8") as f: return json.load(f)
    except (OSError, ValueError): return {}

def api_lists(ctx, q):
    import external
    hosts = [h for h in q.get("hosts", "").split(",") if h][:500]
    out = {}
    for h in hosts:
        if cr.is_ip(h): continue
        lk = external.lookup(h)
        if lk is None: return {"missing": True, "hosts": {}}
        out[h] = {"verdict": external.verdict(lk), "block": sorted({n.split("（")[0] for n, _ in lk["block"]}),
                  "owner": lk["owner"][:3]}
    return {"missing": False, "hosts": out}

def _stale(a, ph):
    """推荐理由是否过期（规则见 advisor「缓存规则」）：只看提示词改没改过，不按时间过期。返回原因或空字符串。"""
    return "" if a.get("prompt_hash") == ph else "提示词改过"

def api_advice(ctx, q):
    import advisor
    kind = q.get("kind", "pending"); hosts = [h for h in q.get("hosts", "").split(",") if h]
    adv = _advice_load(ctx); ph = advisor.prompt_hash()
    return {"advice": {h: dict(adv[f"{kind}:{h}"], stale=_stale(adv[f"{kind}:{h}"], ph)) for h in hosts if f"{kind}:{h}" in adv}}

def _advice_save(ctx, kind, host, r):
    with _ADV_LOCK:
        adv = _advice_load(ctx); adv[f"{kind}:{host}"] = r
        cr._atomic_write_text(_advice_path(ctx), json.dumps(adv, ensure_ascii=False))

def _pending_item(ctx, host):
    p = cr.load_pending(ctx.pending)
    r = p["domains"].get(host) or p["ips"].get(host)
    if not r: return None
    return {"kind": "pending", "host": host, "count": r["count"], "procs": sorted(r.get("procs") or []), "ctx": list(r.get("ctx") or [])}

def _suspicious_item(ctx, host):
    for h, b, sc, why, rec in cr.suggest_routed(ctx, include_reviewed=True):
        if h == host:
            return {"kind": "suspicious", "host": h, "bucket": b, "count": rec["count"], "reasons": why, "sites": list(rec.get("sites") or [])}
    return None

def _todirect_item(ctx, host):
    rec = cr.load_routed(ctx.routed)["proxy"].get(host)
    return {"kind": "todirect", "host": host, "count": rec["count"]} if rec else None

def api_advice_run(ctx, body):
    """body：{kind: pending|suspicious|todirect, hosts: [...]}。一项时算「单行理由」，把前后连接发给模型；多项时不发。"""
    import layers
    kind = body.get("kind"); hosts = [h for h in body.get("hosts", []) if isinstance(h, str)][:300]
    make = {"pending": _pending_item, "suspicious": _suspicious_item, "todirect": _todirect_item}.get(kind)
    if not make or not hosts: raise ApiError("参数不对")
    items = [it for it in (make(ctx, h) for h in hosts) if it]
    if not items: raise ApiError("这些主机已不在清单里（刷新后再试）")
    jid = uuid.uuid4().hex[:12]; single = len(items) == 1
    job = {"total": len(items), "done": 0, "results": {}, "errors": {}, "running": True}
    _JOBS[jid] = job
    payloads = {c: ctx.entries("domain", c) for c in ("proxy", "direct", "reject")}
    def one(it):
        try:
            r = layers.explain_item(it, ctx, payloads, model=True, include_ctx=single)
            _advice_save(ctx, kind, it["host"], r)
            job["results"][it["host"]] = dict(r, stale="")
        except Exception as e:
            job["errors"][it["host"]] = f"{type(e).__name__}: {e}"
        job["done"] += 1
    def run():
        import concurrent.futures as cf
        with cf.ThreadPoolExecutor(4) as ex: list(ex.map(one, items))
        job["running"] = False
    threading.Thread(target=run, daemon=True).start()
    return {"job": jid, "total": len(items), "ctx_sent": single}

# ---------------- 地域放行：代理改直连的候选（见 clash_review.direct_candidates）----------------
# 两道关：
#   1. 测速（直连与代理各测 3 次首字节，cr.direct_verdict）：直连连不上、不比代理快、国内解析不到的，隐藏，不问模型。
#   2. 过了测速的，按提示词里的策略问模型（kind=todirect，结论 direct / proxy / reject），结果存 advice.json 的 todirect:主机。
#      模型建议保持代理的也隐藏；列表只剩没测的、待问模型的、建议直连或拉黑的（含分歧），最多 TO_DIRECT_TOP 个。
# 隐藏的连同原因一起返回，页面可展开查看。「实测」在后台跑，进度沿用 /api/advice/job 轮询。
def _direct_row(ctx, h, rec, t, owner, ev, a, ph):
    import advisor
    gate, speed = cr.direct_verdict(ev)
    ident = advisor.identity_get(h)
    ips = (ev or {}).get("cn_ips")
    adv = dict(a, stale=_stale(a, ph)) if a else None
    if gate is None: state, why = "untested", "还没实测"
    elif gate == "keep": state, why = "hidden", speed
    elif not adv or adv.get("model_error") or adv["stale"]: state, why = "ask", (adv or {}).get("model_error") or speed
    elif adv["recommend"] == "proxy" and not adv["split"]: state, why = "hidden", "模型建议保持代理"
    else: state, why = "shown", speed
    return {"host": h, "count": rec["count"], "ports": sorted(rec["ports"], key=lambda p: (len(p), p)),
            "down": t.get("down", 0), "conns": t.get("conns", 0), "owner": owner,
            "resolve": (f"{ips[0]}（{(ev.get('cn_asn') or ['运营商未知'])[0]}）" if isinstance(ips, list) and ips else ""),
            "checked": ((ev or {}).get("speed") or {}).get("checked", ""), "speed": speed if gate else "",
            "state": state, "why": why, "advice": adv,
            "identity": {k: ident[k] for k in ("owner", "owner_basis", "function")} if ident else None}

def _direct_rows(ctx):
    import evidence, advisor
    rows, hidden = [], []
    adv = _advice_load(ctx); ph = advisor.prompt_hash()
    for h, rec, t, own in cr.direct_candidates(ctx):
        ev = evidence.collect(h, net=False)
        if ev: ev = dict(ev, speed=evidence.collect_speed(h, cr.speed_scheme(rec["ports"]), None, net=False))
        r = _direct_row(ctx, h, rec, t, own, ev, adv.get(f"todirect:{h}"), ph)
        if r["state"] == "hidden": hidden.append(r)
        elif len(rows) < cr.TO_DIRECT_TOP: rows.append(r)
    return rows, hidden

def api_todirect(ctx, q):
    rows, hidden = _direct_rows(ctx)
    return {"rows": rows, "hidden": hidden, "kept": len(cr.load_keepproxy(ctx)), "top": cr.TO_DIRECT_TOP}

def api_todirect_test(ctx, body):
    """对每项：本机证据 → 测速 → 过了测速且还没有有效的模型结论，按策略问模型。"""
    import evidence, advisor, layers
    want = {h for h in body.get("hosts", []) if isinstance(h, str)}
    items = [x for x in cr.direct_candidates(ctx) if x[0] in want]
    if not items: raise ApiError("这些主机已不在候选里（刷新后再试）")
    proxy = cr.mixed_port_url(ctx); ph = advisor.prompt_hash()
    payloads = {c: ctx.entries("domain", c) for c in ("proxy", "direct", "reject")}
    jid = uuid.uuid4().hex[:12]
    job = {"total": len(items), "done": 0, "results": {}, "errors": {}, "running": True}
    _JOBS[jid] = job
    # 两段流水线：测速与问模型分开两个线程池。原先同一个线程里「测速 → 问模型」串着做，模型一答几十秒，
    # 占着 6 个测速线程，下一项的测速也开不了（2026-09-26：60 项跑了好几分钟）。
    lock = threading.Lock()                                  # 两个线程池都会记结果
    def finish(x, ev, a):
        h, rec, t, own = x
        row = _direct_row(ctx, h, rec, t, own, ev, a, ph)
        with lock: job["results"][h] = row; job["done"] += 1
    def fail(x, e):
        with lock: job["errors"][x[0]] = f"{type(e).__name__}: {e}"; job["done"] += 1
    def ask(x, ev):
        h, rec, _, _ = x
        try:
            a = layers.explain_item({"kind": "todirect", "host": h, "count": rec["count"]}, ctx, payloads, model=True)
            _advice_save(ctx, "todirect", h, a)
            finish(x, ev, a)
        except Exception as e: fail(x, e)
    def measure(x, models):
        h, rec, _, _ = x
        try:
            ev = evidence.collect(h)
            if ev and isinstance(ev.get("cn_ips"), list) and ev["cn_ips"]:   # 解析不到的不用测速
                ev = dict(ev, speed=evidence.collect_speed(h, cr.speed_scheme(rec["ports"]), proxy))
            a = _advice_load(ctx).get(f"todirect:{h}")
            if cr.direct_verdict(ev)[0] == "direct" and (not a or a.get("model_error") or _stale(a, ph)):
                return models.submit(ask, x, ev)      # 测速过了、还没有有效结论的，交给问模型的线程池
            finish(x, ev, a)
        except Exception as e: fail(x, e)
    def run():
        import concurrent.futures as cf
        try:
            with cf.ThreadPoolExecutor(12) as models:        # 问模型只是等回话，不占带宽，多开几个
                with cf.ThreadPoolExecutor(6) as speeds:     # 测速要准，别开太多并发挤占带宽
                    list(speeds.map(lambda x: measure(x, models), items))
        finally:
            job["running"] = False
    threading.Thread(target=run, daemon=True).start()
    return {"job": jid, "total": len(items)}

def api_advice_job(ctx, q):
    job = _JOBS.get(q.get("id", ""))
    if not job: raise ApiError("任务不存在（服务重启过？）")
    res = job["results"]; job["results"] = {}     # 每次只返回新完成的
    return {"total": job["total"], "done": job["done"], "running": job["running"], "results": res, "errors": job["errors"]}

GET = {"/api/status": api_status, "/api/pending": api_pending, "/api/suggest": api_suggest,
       "/api/routed": api_routed, "/api/rules": api_rules, "/api/tidy": api_tidy,
       "/api/lists": api_lists, "/api/advice": api_advice, "/api/advice/job": api_advice_job,
       "/api/todirect": api_todirect}
POST = {"/api/pending/apply": api_pending_apply, "/api/routed/apply": api_routed_apply, "/api/advice/run": api_advice_run, "/api/todirect/test": api_todirect_test,
        "/api/rules/add": api_rules_add, "/api/rules/delete": api_rules_delete,
        "/api/rules/move": api_rules_move, "/api/tidy/apply": api_tidy_apply, "/api/tidy/merge": api_tidy_merge}


# ---------------- HTTP（外壳在 web-kit）----------------
class Handler(webkit.Handler):
    signature = SIGNATURE; header = "X-Clash-Review"; web_dir = WEB
    get_routes = GET; post_routes = POST
    ctx = None
    server_version = "clash-review-web"

    def call(self, fn, arg):
        try:
            return fn(self.ctx, arg)
        except cr.DestError as e:          # 写不进规则服务：原因给人看，待审不变
            raise ApiError(f"没有写入：{e}")


def main():
    webkit.setup_log(cr.DATA_DIR)
    ap = argparse.ArgumentParser(prog="clash_review_web", description="clash_review 本地网页界面")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--config-dir", dest="config_dir")
    ap.add_argument("--stop", action="store_true", help="停止正在运行的实例")
    args = ap.parse_args()
    url = f"http://127.0.0.1:{args.port}/"
    if args.stop:
        print("已停止" if webkit.stop(args.port, Handler.header) else "没有在运行"); return
    if webkit.already_running(args.port, SIGNATURE):
        print(f"已在运行：{url}")
        if not args.no_browser: webbrowser.open(url)
        return
    cfg = cr.resolve_config_dir(args.config_dir)
    if not os.path.isfile(os.path.join(cfg, "profiles.yaml")):
        webkit.fail(f"未定位到 Clash Verge 配置目录(缺 profiles.yaml)。当前推断: {cfg}", "Clash Review")
    Handler.ctx = cr.Ctx(cfg); Handler.port = args.port
    Handler.prefs = webkit.Prefs(os.path.join(Handler.ctx.review, "ui_prefs.json"))
    # 空闲退出：推荐、实测等后台任务在跑时不退
    Handler.idle = webkit.IdleWatch(IDLE_MINUTES, busy=lambda: any(j["running"] for j in _JOBS.values()))
    try:
        srv = webkit.bind(args.port, Handler)   # 多线程：推荐任务在后台跑，轮询与其它请求不能被单线程堵住
    except OSError as e:
        webkit.fail(f"端口 {args.port} 用不了（{e}）。换一个：--port 8766", "Clash Review")
    Handler.idle.start(srv)
    if Handler.ctx.dest:                   # 已提交到规则服务的决定：上线后让内核重新取（watch 也在做，重复无害）
        threading.Thread(target=cr.dest_settler, args=(Handler.ctx, threading.Event()), daemon=True).start()
    webkit.log(f"Clash Review 网页已启动：{url}（停止：clash_review_web.py --stop）")
    if not args.no_browser: webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    srv.server_close()
    os._exit(0)      # 停止或空闲退出后立即结束进程：后台任务的工作线程（测速、问模型）不是守护线程，否则会拖着进程继续跑

if __name__ == "__main__":
    main()
