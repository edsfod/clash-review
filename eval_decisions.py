"""评估：模型推荐与人工裁定是否一致（数据来自网页「应用」时追加的 var/testcases/decisions.jsonl，见 clash_review「人工裁定日志」）。

按页面分开统计：待审（pending）、地域放行「可疑」（suspicious）、「可改直连」（todirect）。只统计应用时已有模型推荐的项；
没有推荐的（没点过「理由」或「为本页生成」）单独计数，不算对错。「分歧」项模型本来就不给推荐，单独列出。
报告写到 var/eval/decisions-<日期>.md；跑完把「已评估条数」记到 var/testcases/decisions_eval.json，status 与网页顶栏据此提醒下一次评估。

用法：python eval_decisions.py            只评上次之后的新裁定
      python eval_decisions.py --all      全部重评（不改「已评估条数」以外的东西）
"""
import argparse, collections, datetime, json, os, sys

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import clash_review as cr

CN = {"proxy": "代理", "direct": "直连", "reject": "拉黑", "ignore": "忽略", "keep": "不选", "ok": "正常"}
KIND_CN = {"pending": "待审", "suspicious": "可疑", "todirect": "可改直连", "routed": "地域放行其它视图"}

def main():
    ap = argparse.ArgumentParser(description="模型推荐与人工裁定的一致性")
    ap.add_argument("--all", action="store_true", help="全部重评，不只评上次之后的新裁定")
    args = ap.parse_args()
    ctx = cr.Ctx(cr.resolve_config_dir())
    ds = cr.load_decisions(ctx)
    st = cr.decisions_status(ctx)
    batch = ds if args.all else ds[len(ds) - st["new"]:]
    if not batch:
        print("没有新的裁定。"); return
    L = [f"# 模型推荐与人工裁定（{datetime.date.today()}）", "",
         f"本次评估 {len(batch)} 条（{'全部' if args.all else '上次评估之后的新裁定'}；累计 {len(ds)} 条）。", ""]
    by_kind = collections.defaultdict(list)
    for d in batch: by_kind[d["kind"]].append(d)
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
            L += [f"| {CN.get(a, a)} → {CN.get(b, b)} | {n} |" for (a, b), n in conf.most_common()]
        bad = [d for d in with_rec if d["advice"]["recommend"] != d["decision"]]
        if bad:
            L += ["", "不一致的："]
            L += [f"- `{d['host']}`：模型 {CN.get(d['advice']['recommend'])}（模型本身 {CN.get(d['advice'].get('model_decision'), '—')}，名单 {d['advice'].get('list_verdict') or '没收录'}），你选 {CN.get(d['decision'])}" for d in bad]
        if split:
            L += ["", "分歧项（模型说拉黑、名单没收录）你的决定："]
            L += [f"- `{d['host']}`：你选 {CN.get(d['decision'])}" for d in split]
        L.append("")
    out = os.path.join(ctx.review, "eval", f"decisions-{datetime.date.today():%Y%m%d}.md")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    cr._atomic_write_text(out, "\n".join(L))
    cr._atomic_write_text(cr.decisions_eval_path(ctx), json.dumps(
        {"evaluated": len(ds), "time": datetime.datetime.now().isoformat(timespec="seconds")}, ensure_ascii=False))
    print("\n".join(L)); print(f"\n报告：{out}")

if __name__ == "__main__":
    main()
