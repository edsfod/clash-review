"""按新策略复查规则集：用地域放行的可疑打分（clash_review.score_host）给已放行的条目打分，挑出像广告、遥测的候选。

只读，不改规则集。默认用 var/testcases/ 下冻结的基准（labels-20260923/ 与 routed-20260923.yaml），
结果可重复。打分时对每一条做「留一」：先把它从学习数据里去掉再打分，否则「与已拉黑相似」
与学出来的词会用到这一条自己的归类。

同时对拉黑条目做同样的留一打分，报告其中有多少能被打分挑出来（召回），作为算法本身的检验。

用法：python audit_candidates.py [--labels DIR] [--routed FILE] [--min 3]
"""
import argparse, collections, os, sys

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import clash_review as cr

# 占位与保留域名，不是真实归类，不参与学习与评估
EXCLUDE = {"placeholder.never-match.invalid", "example.com", "disabled.invalid",
           "imageeditor.example", "searchapp.bundleassets.example"}

def load_labels(d):
    out = {}
    for cat in ("proxy", "direct", "reject"):
        ps = cr.load_payload(os.path.join(d, f"my-{cat}.yaml"))
        out[cat] = [b for b in (cr._dom_base(p) for p in ps) if b not in EXCLUDE]
    return out

def learned_from(rej, alw, seen_site_n, st):
    """与 clash_review._learned 相同的统计，但拉黑 / 放行列表由调用方给出（用于留一）。"""
    rej_sites = collections.defaultdict(list)
    for b in rej: rej_sites[cr.site_of(b)].append(b)
    alw_site_n = collections.Counter(cr.site_of(b) for b in alw)
    rt = collections.Counter(t for b in rej for t in set(cr._tokens(b)))
    at = collections.Counter(t for b in alw for t in set(cr._tokens(b)))
    return rej_sites, alw_site_n, seen_site_n, rt, at, st

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--labels", default=os.path.join(cr.DATA_DIR, "testcases", "labels-20260923"))
    ap.add_argument("--routed", default=os.path.join(cr.DATA_DIR, "testcases", "routed-20260923.yaml"))
    ap.add_argument("--min", type=float, default=cr.SUGGEST_MIN)
    a = ap.parse_args()

    lab = load_labels(a.labels)
    routed = cr.load_routed(a.routed)
    seen = [h for b in ("direct", "proxy") for h in routed[b] if not cr.is_ip(h)]
    seen_site_n = collections.Counter(cr.site_of(h) for h in seen)
    st = collections.Counter(t for h in seen for t in set(cr._tokens(h)))

    def loo_score(cat, i):
        host = lab[cat][i]
        rej = [x for j, x in enumerate(lab["reject"]) if not (cat == "reject" and j == i)]
        alw = [x for c in ("proxy", "direct") for j, x in enumerate(lab[c]) if not (c == cat and j == i)]
        return cr.score_host(host, {}, learned_from(rej, alw, seen_site_n, st))

    cands = []; near = []
    for cat in ("proxy", "direct"):
        for i, h in enumerate(lab[cat]):
            sc, why = loo_score(cat, i)
            if sc >= a.min: cands.append((sc, cat, h, why))
            elif sc > 0: near.append((sc, cat, h, why))
    hit = 0; miss = []
    for i, h in enumerate(lab["reject"]):
        sc, why = loo_score("reject", i)
        if sc >= a.min: hit += 1
        else: miss.append(h)

    n_alw = len(lab["proxy"]) + len(lab["direct"])
    print(f"基准：{a.labels}")
    print(f"放行条目 {n_alw} 条（代理 {len(lab['proxy'])}、直连 {len(lab['direct'])}），留一打分 ≥ {a.min:g} 的候选 {len(cands)} 条：")
    for sc, cat, h, why in sorted(cands, key=lambda x: (-x[0], x[2])):
        print(f"  {sc:4.1f}  {'代理' if cat=='proxy' else '直连'}  {h}\n              {'；'.join(why)}")
    print(f"\n分数在 0 与 {a.min:g} 之间的 {len(near)} 条（不算候选，只列出供参考）：")
    for sc, cat, h, why in sorted(near, key=lambda x: (-x[0], x[2])):
        print(f"  {sc:4.1f}  {'代理' if cat=='proxy' else '直连'}  {h}   {'；'.join(why)}")
    print(f"\n算法检验：拉黑条目 {len(lab['reject'])} 条，留一打分 ≥ {a.min:g} 的 {hit} 条（{hit/len(lab['reject']):.0%}）。"
          f"其余 {len(miss)} 条靠名称与相似度看不出来。")

if __name__ == "__main__":
    main()
