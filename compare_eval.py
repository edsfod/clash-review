"""比较几种提示词 / 证据组合在 A 套（人工归类）上的表现，按 var/testcases/acceptable-20260923.json 的口径计分。

口径：
  - any 里的主机：任何答案都算对；exclude 里的不计分；override 给出改判后的可接受答案
  - 作答 = 给出 直连 / 代理 / 拉黑；不选、忽略算弃权
  - 错误按代价分三级：
      严重 = 人工放行（直连或代理）的主机被判拉黑，用得到的服务会打不开
      中等 = 人工拉黑的主机被判放行，广告、遥测会放进来
      轻微 = 直连与代理互换，两边都能用。其中「直连实测可达」的，按策略第二节第 2 条例外本来就两可，另计

用法：python compare_eval.py [--half dev|test]
"""
import argparse, json, os, re, sys

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import eval_models as em, evidence

ACC = json.load(open(os.path.join(em.TC, "acceptable-20260923.json"), encoding="utf-8"))
BASE = "run-20260923"
OLD_MAP = {"拉黑": "reject", "代理": "proxy", "直连": "direct", "跳过": "keep"}

def old_prompt(host):
    """旧提示词的自由文本答案：取「推荐策略」之后第一个选项。"""
    p = os.path.join(em.EVAL, BASE, "deepseek-flash-oldprompt", re.sub(r"[^A-Za-z0-9._-]", "_", host) + ".json")
    if not os.path.exists(p): return None
    t = json.load(open(p, encoding="utf-8"))["text"]
    i = t.find("推荐策略"); seg = t[i:] if i >= 0 else t
    f = re.findall(r"【(拉黑|代理|直连|跳过)】", seg) or re.findall(r"推荐[^：:\n]{0,4}[：:]\s*\**\s*(拉黑|代理|直连|跳过)", seg)
    return OLD_MAP.get(f[0]) if f else None

def from_run(run, prov, field="recommend"):
    rs = {r["item"]["host"]: r["result"].get(field) for r in em.load_results(run, prov, "A") if r["ok"]}
    return lambda h: rs.get(h)

VARIANTS = [
    ("旧提示词", old_prompt),
    ("第一版", from_run(BASE, "deepseek-flash")),
    ("第二版", from_run("run-20260923-v2", "deepseek-flash")),
    ("第二版+本机证据", from_run("run-20260923-v2", "deepseek-flash+ev")),
    ("第三版+本机证据（模型自选）", from_run("run-20260923-v3", "deepseek-flash+ev")),
    ("第三版+本机证据（按代价定）", from_run("run-20260923-v3", "deepseek-flash+ev", "decision")),
]

def score(items, get):
    s = {"n": 0, "ans": 0, "ok": 0, "harm": 0, "leak": 0, "swap": 0, "swap_ok": 0, "abst": 0, "miss": 0, "bad": []}
    for x in items:
        h = x["host"]
        if h in ACC["exclude"]["hosts"]: continue
        r = get(h)
        if r is None: s["miss"] += 1; continue
        s["n"] += 1
        if r not in ("direct", "proxy", "reject"): s["abst"] += 1; continue
        s["ans"] += 1
        good = ACC["override"].get(h, [x["label"]])
        if h in ACC["any"]["hosts"] or r in good: s["ok"] += 1; continue
        lab = good[0]
        if lab in ("direct", "proxy") and r == "reject": s["harm"] += 1; tag = "严重"
        elif lab == "reject": s["leak"] += 1; tag = "中等"
        else:
            d = (evidence.collect(h, net=False) or {}).get("direct") or {}
            reach = isinstance(d, dict) and any(v != "000" for v in d.values())
            s["swap"] += 1; s["swap_ok"] += reach; tag = "轻微" + ("·直连可达" if reach else "")
        s["bad"].append(f"{h}:{lab}→{r}（{tag}）")
    return s

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--half", choices=["dev", "test"]); a = ap.parse_args()
    items = [x for x in em.run_items(BASE)["A"] if not a.half or em.half(x["host"]) == a.half]
    print(f"A 套{('（' + a.half + ' 一半）') if a.half else ''}：{len(items)} 题，不计分 {sum(x['host'] in ACC['exclude']['hosts'] for x in items)} 题")
    print("| 版本 | 计分题 | 作答 | 对 | 严重（误拉黑） | 中等（放进该拉黑的） | 轻微（直连代理互换；其中直连可达） | 弃权 |\n|---|---|---|---|---|---|---|---|")
    bad = {}
    for name, get in VARIANTS:
        s = score(items, get)
        if not s["n"]: continue
        print(f"| {name} | {s['n']} | {s['ans']} | {s['ok']} | {s['harm']} | {s['leak']} | {s['swap']}；{s['swap_ok']} | {s['abst']} |")
        bad[name] = s["bad"]
    for name, L in bad.items():
        print(f"\n{name} 答错：{'；'.join(L) or '无'}")

if __name__ == "__main__":
    main()
