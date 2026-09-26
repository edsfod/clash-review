"""评估：模型推荐与人工裁定是否一致（数据来自网页「应用」时追加的 var/testcases/decisions.jsonl，见 clash_review「人工裁定日志」）。

按页面分开统计：待审（pending）、地域放行「可疑」（suspicious）、「可改直连」（todirect）。两种评法：

- 默认：比应用时已记下的模型推荐。没有推荐的（没点过「理由」或「为本页生成」）单独计数，不算对错；「分歧」项模型本来就不给推荐，单独列出。
  推荐来自哪版提示词各不相同，提示词改过之后，旧推荐说明不了现在的提示词。
- --requery：按现在的提示词把全部裁定重问一遍模型（同一主机取最后一次决定），默认跑两遍。同一提示词两遍之间结论不同的项，
  是模型自身的波动（2026-09-26，DeepSeek：118 项里 9～13 项，134 项里 26 项）；一致率的变化小于这个幅度，说明不了提示词变好还是变坏。
  重问不写网页的推荐缓存与身份缓存，不把前后连接发给模型（同「为本页生成」）。

不作标准答案的裁定：var/testcases/decisions_untrusted.json 里列的主机（组名、理由、主机名或正则）。你当时拿不准、照着模型推荐选的，
拿来当标准答案只会把模型往它自己原先的结论上拉（2026-09-26：证书状态服务与 GitHub 的裁定，用户说明当时不懂）。
这些不计入一致率，单独列出模型的结论与你当时的选择。「忽略」不是归类，也不计。

报告：默认写 var/eval/decisions-<日期>.md；--requery 写 var/eval/requery-<日期时间>/（report.md、逐项结果 result.json、所用提示词 prompt.md）。
跑完把「已评估条数」记到 var/testcases/decisions_eval.json，status 与网页顶栏据此提醒下一次评估。

用法：python eval_decisions.py                  只评上次之后的新裁定
      python eval_decisions.py --all            全部重评
      python eval_decisions.py --requery        按现在的提示词重问全部裁定，跑两遍（--passes 改遍数）
"""
import argparse, collections, concurrent.futures as cf, datetime, json, os, re, sys, time

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import clash_review as cr

CN = {"proxy": "代理", "direct": "直连", "reject": "拉黑", "ignore": "忽略", "keep": "不选", "ok": "正常"}
KIND_CN = {"pending": "待审", "suspicious": "可疑", "todirect": "可改直连", "routed": "地域放行其它视图"}
REQUERY_KINDS = ("pending", "suspicious", "todirect")
NOT_A_CLASS = {"ignore"}             # 「忽略」不是归类，模型不会推荐它

def untrusted_path(ctx): return os.path.join(ctx.review, "testcases", "decisions_untrusted.json")

def load_untrusted(ctx):
    """[(组名, 理由, 主机集合, [正则])]。文件没有就是空；格式见 README「人工裁定日志与评估」。"""
    p = untrusted_path(ctx)
    if not os.path.exists(p): return []
    with open(p, encoding="utf-8") as f: d = json.load(f)
    return [(g["name"], g.get("why", ""), set(g.get("hosts", [])), [re.compile(x) for x in g.get("patterns", [])])
            for g in d.get("groups", [])]

def group_of(host, groups):
    for name, _, hosts, rx in groups:
        if host in hosts or any(r.search(host) for r in rx): return name
    return None

def cn(x): return CN.get(x, x or "—")

def pct(a, n): return f"{a}/{n}（{a * 100 // n}%）" if n else "—"

def excluded_lines(groups, rows):
    """rows：[(主机, 模型结论文字, 你的决定)]，按组列出。"""
    L = []
    for name, why, _, _ in groups:
        mine = sorted(r for r in rows if group_of(r[0], groups) == name)
        if not mine: continue
        L += [f"### {name}", ""] + ([why, ""] if why else [])
        L += [f"- `{h}`：模型 {m}；你当时选 {cn(dec)}" for h, m, dec in mine] + [""]
    return L

# ---------------- 默认：比应用时记下的推荐 ----------------

def recorded_report(ds, batch, groups, all_, cur_hash):
    L = [f"# 模型推荐与人工裁定（{datetime.date.today()}）", "",
         f"本次评估 {len(batch)} 条（{'全部' if all_ else '上次评估之后的新裁定'}；累计 {len(ds)} 条）。", ""]
    counted = [d for d in batch if d["decision"] not in NOT_A_CLASS and not group_of(d["host"], groups)]
    skipped = [d for d in batch if d not in counted]
    if skipped:
        L += [f"不作标准答案、不计入的 {len(skipped)} 条（「忽略」与 `decisions_untrusted.json` 里的主机），列在最后。", ""]
    old = [d for d in counted if (d.get("advice") or {}).get("recommend") and d["advice"].get("prompt_hash") != cur_hash]
    if old:
        L += [f"其中 {len(old)} 条的推荐不是现在的提示词给的（提示词改过），说明不了现在的提示词；要按现在的提示词评估，用 `--requery`。", ""]
    by_kind = collections.defaultdict(list)
    for d in counted: by_kind[d["kind"]].append(d)
    for kind, items in by_kind.items():
        with_rec = [d for d in items if d.get("advice") and d["advice"].get("recommend") and not d["advice"].get("split")]
        split = [d for d in items if d.get("advice") and d["advice"].get("split")]
        none = [d for d in items if not d.get("advice") or (not d["advice"].get("recommend") and not d["advice"].get("split"))]
        agree = [d for d in with_rec if d["advice"]["recommend"] == d["decision"]]
        L += [f"## {KIND_CN.get(kind, kind)}", "",
              f"- 裁定 {len(items)} 条：有模型推荐 {len(with_rec)} 条，其中与你一致 {len(agree)} 条"
              + (f"（{len(agree) * 100 // len(with_rec)}%）" if with_rec else "") + f"；分歧 {len(split)} 条；没有推荐 {len(none)} 条。"]
        conf = collections.Counter((d["advice"]["recommend"], d["decision"]) for d in with_rec)
        if conf:
            L += ["", "| 模型推荐 → 你的决定 | 条数 |", "|---|---|"]
            L += [f"| {cn(a)} → {cn(b)} | {n} |" for (a, b), n in conf.most_common()]
        bad = [d for d in with_rec if d["advice"]["recommend"] != d["decision"]]
        if bad:
            L += ["", "不一致的："]
            L += [f"- `{d['host']}`：模型 {cn(d['advice']['recommend'])}（模型本身 {cn(d['advice'].get('model_decision'))}，名单 {d['advice'].get('list_verdict') or '没收录'}），你选 {cn(d['decision'])}" for d in bad]
        if split:
            L += ["", "分歧项（模型说拉黑、名单没收录）你的决定："]
            L += [f"- `{d['host']}`：你选 {cn(d['decision'])}" for d in split]
        L.append("")
    ex = [d for d in skipped if d["decision"] not in NOT_A_CLASS]
    if ex:
        L += ["## 不作标准答案的（应用时的模型推荐；你当时的选择）", ""]
        L += excluded_lines(groups, [(d["host"], cn((d.get("advice") or {}).get("recommend")), d["decision"]) for d in ex])
    return L

# ---------------- --requery：按现在的提示词重问 ----------------

def latest(ds):
    """同一页面同一主机只留最后一次决定（改过主意以最后为准），保持首次出现的顺序。"""
    last = {}
    for d in ds:
        if d["kind"] in REQUERY_KINDS: last[(d["kind"], d["host"])] = d
    return list(last.values())

def item_of(d):
    """裁定时的快照 → explain_item 的输入（同网页「为本页生成」：前后连接不发）。"""
    s = d.get("snapshot") or {}
    it = {"kind": d["kind"], "host": d["host"], "count": s.get("count") or 1}
    if d["kind"] == "pending": it["procs"] = s.get("procs") or []
    if d["kind"] == "suspicious": it["bucket"] = s.get("bucket")
    return it

def outcome(a):
    """explain_item 的结果 → 一遍里这一项的结论：推荐（proxy/direct/reject/ok）、"split"（分歧）或 None（没有模型结论）。"""
    if a.get("model_error") or not a.get("model"): return None
    return "split" if a.get("split") else a.get("recommend")

def run_passes(items, ask, passes, workers, log=print):
    """ask(item) → 结论。返回 (每遍的 {键: 结论}, {键: 出错信息}, 每遍秒数)。"""
    runs, errors, secs = [], {}, []
    for i in range(passes):
        out = {}; t = time.time(); done = 0
        def one(d):
            try: return d, ask(item_of(d)), None
            except Exception as e: return d, None, f"{type(e).__name__}: {e}"
        with cf.ThreadPoolExecutor(workers) as ex:
            for fut in cf.as_completed([ex.submit(one, d) for d in items]):
                d, rec, err = fut.result(); k = (d["kind"], d["host"])
                out[k] = rec; done += 1
                if err: errors[k] = err
                if done % 20 == 0 or done == len(items): log(f"  第 {i + 1} 遍 {done}/{len(items)}", flush=True)
        runs.append(out); secs.append(time.time() - t)
    return runs, errors, secs

def requery_report(items, runs, errors, secs, groups, meta):
    """items：去重后的裁定；runs：每遍 {(页面, 主机): 结论}。"""
    key = lambda d: (d["kind"], d["host"])
    trusted = [d for d in items if d["decision"] not in NOT_A_CLASS and not group_of(d["host"], groups)]
    excluded = [d for d in items if d["decision"] not in NOT_A_CLASS and group_of(d["host"], groups)]
    show = lambda r: "分歧" if r == "split" else cn(r) if r else "没有结论"
    L = [f"# 按现在的提示词重问（{meta['time']}）", "",
         f"模型 `{meta.get('model', '?')}`；提示词指纹 `{meta['prompt_hash']}`；裁定 {meta['total']} 条，按页面与主机去重后 {len(items)} 项（同一主机取最后一次决定）；"
         f"跑 {len(runs)} 遍，每遍 " + "、".join(f"{s:.0f} 秒" for s in secs) + "。",
         f"计入一致率的 {len(trusted)} 项；不作标准答案的 {len(excluded)} 项（`decisions_untrusted.json`），列在最后；"
         f"「忽略」{len(items) - len(trusted) - len(excluded)} 项不计。", ""]
    if len(runs) > 1:
        flip = [d for d in items if len({r.get(key(d)) for r in runs}) > 1]
        L += ["## 模型自身的波动", "",
              f"同一提示词各遍之间结论不同的：{len(flip)}/{len(items)}。一致率的变化小于这个幅度，说明不了提示词变好还是变坏。", ""]
        L += [f"- {KIND_CN[d['kind']]} `{d['host']}`：" + " / ".join(show(r.get(key(d))) for r in runs) for d in flip]
        L.append("")
    L += ["## 一致率（只算计入的裁定）", "", "| 页面 | 计入 | " + " | ".join(f"第 {i + 1} 遍" for i in range(len(runs))) + " |",
          "|---|---|" + "---|" * len(runs)]
    for kind in REQUERY_KINDS:
        ks = [d for d in trusted if d["kind"] == kind]
        if not ks: continue
        cells = []
        for r in runs:
            got = [d for d in ks if r.get(key(d)) not in (None, "split")]
            cells.append(pct(sum(r[key(d)] == d["decision"] for d in got), len(got)))
        L.append(f"| {KIND_CN[kind]} | {len(ks)} | " + " | ".join(cells) + " |")
    L += ["", "每格是「与你一致 / 有推荐」；没有模型结论与分歧项不在分母里。", ""]
    stuck = [d for d in trusted if len({r.get(key(d)) for r in runs}) == 1 and runs[0].get(key(d)) not in (None, "split", d["decision"])]
    if stuck:
        L += ["## 每遍都与你不同的", "",
              "这些才值得看：要么提示词的策略没写到，要么当时的决定与别处的决定不一致。", ""]
        L += [f"- {KIND_CN[d['kind']]} `{d['host']}`：你选 {cn(d['decision'])}，模型 {cn(runs[0][key(d)])}" for d in stuck]
        L.append("")
    if excluded:
        L += ["## 不作标准答案的（模型每遍的结论；你当时的选择）", ""]
        L += excluded_lines(groups, [(d["host"], " / ".join(show(r.get(key(d))) for r in runs), d["decision"]) for d in excluded])
    if errors:
        L += ["## 出错的", ""] + [f"- {KIND_CN[k[0]]} `{k[1]}`：{e}" for k, e in sorted(errors.items())] + [""]
    return L

def requery(ctx, ds, groups, passes, workers):
    import advisor, layers
    items = latest(ds)
    if not items: print("没有可重问的裁定。"); return None
    payloads = {c: ctx.entries("domain", c) for c in ("proxy", "direct", "reject")}
    def ask(it):
        a = layers.explain_item(it, ctx, payloads, model=True, remember=False)
        if a.get("model_error"): raise RuntimeError(a["model_error"])
        return outcome(a)
    now = datetime.datetime.now()
    prompt = advisor.system_prompt()
    meta = {"time": now.isoformat(timespec="minutes"), "prompt_hash": advisor.prompt_hash(prompt), "model": advisor.model_name(), "total": len(ds)}
    print(f"用 {meta['model']} 重问 {len(items)} 项，跑 {passes} 遍（每遍几分钟）…", flush=True)
    runs, errors, secs = run_passes(items, ask, passes, workers)
    L = requery_report(items, runs, errors, secs, groups, meta)
    out = os.path.join(ctx.review, "eval", f"requery-{now:%Y%m%d-%H%M}")
    os.makedirs(out, exist_ok=True)
    cr._atomic_write_text(os.path.join(out, "report.md"), "\n".join(L))
    cr._atomic_write_text(os.path.join(out, "prompt.md"), prompt)
    cr._atomic_write_text(os.path.join(out, "result.json"), json.dumps(dict(meta, items=[
        {"kind": d["kind"], "host": d["host"], "decision": d["decision"], "group": group_of(d["host"], groups),
         "runs": [r.get((d["kind"], d["host"])) for r in runs], "error": errors.get((d["kind"], d["host"]))} for d in items]),
        ensure_ascii=False, indent=1))
    return L, os.path.join(out, "report.md")

def main():
    ap = argparse.ArgumentParser(description="模型推荐与人工裁定的一致性")
    ap.add_argument("--all", action="store_true", help="全部重评，不只评上次之后的新裁定")
    ap.add_argument("--requery", action="store_true", help="按现在的提示词重问全部裁定（不看应用时记下的推荐）")
    ap.add_argument("--passes", type=int, default=2, help="--requery 跑几遍（默认 2，用来估计模型自身的波动）")
    ap.add_argument("--workers", type=int, default=12, help="--requery 同时问几项（默认 12）")
    args = ap.parse_args()
    ctx = cr.Ctx(cr.resolve_config_dir())
    ds = cr.load_decisions(ctx)
    groups = load_untrusted(ctx)
    if args.requery:
        got = requery(ctx, ds, groups, max(1, args.passes), max(1, args.workers))
        if not got: return
        L, out = got
    else:
        import advisor
        st = cr.decisions_status(ctx)
        batch = ds if args.all else ds[len(ds) - st["new"]:]
        if not batch:
            print("没有新的裁定。"); return
        L = recorded_report(ds, batch, groups, args.all, advisor.prompt_hash())
        out = os.path.join(ctx.review, "eval", f"decisions-{datetime.date.today():%Y%m%d}.md")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        cr._atomic_write_text(out, "\n".join(L))
    cr._atomic_write_text(cr.decisions_eval_path(ctx), json.dumps(
        {"evaluated": len(ds), "time": datetime.datetime.now().isoformat(timespec="seconds")}, ensure_ascii=False))
    print("\n".join(L)); print(f"\n报告：{out}")

if __name__ == "__main__":
    main()
