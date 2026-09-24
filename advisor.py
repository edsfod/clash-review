"""第 2 层：调模型给出归类建议与理由（见 README 第五节「设想」）。

系统提示取自本目录 prompt.md 的「背景与策略」与「工具输出格式」两节。改策略直接改 prompt.md（对话里也可以直接用它，
见其头部）。
每次只问一项；返回模型给的 JSON（字段见该笔记「工具输出格式」）。

模型（PROVIDERS）：
- deepseek-flash：DeepSeek API（DeepSeek-V4.1-Flash）（OpenAI 兼容接口，JSON 模式），密钥取环境变量 DEEPSEEK_API_KEY，
  没有则读 settings.json 的 deepseek_key_file 所指的文件
- claude-haiku / claude-sonnet：本机 Claude Code 命令行 `claude -p`，用订阅登录。用自己的系统提示替换 Claude Code 默认提示、
  关掉全部工具、不读设置与 CLAUDE.md，在空目录里运行。残留：Claude Code 仍会在系统提示前加一句
  「You are a Claude agent...」，并附一段运行环境说明（工作目录、系统版本），2026-09-23 实测无法关掉。

不外发名单 no_send.txt（个人文件，不进仓库；样例 no_send.example.txt）里的主机不会被发送：被问的主机在名单里时直接拒绝；前后连接里的按站点名过滤。
只用标准库。
"""
import concurrent.futures as cf, datetime, hashlib, json, os, re, shutil, subprocess, sys, tempfile, threading, time, urllib.error, urllib.request
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)   # 在 pythonw（没有控制台）下调 curl 等命令行程序，不加这个每次都会弹出一个 cmd 窗口

HERE    = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import clash_review as cr
NOTES   = os.path.join(HERE, "prompt.md")
NO_SEND = os.path.join(cr.CONF_DIR, "no_send.txt")      # 个人名单，放设置目录（与 settings.json 同处）

PENDING_CHOICES    = ["proxy", "direct", "reject", "keep", "ignore"]
SUSPICIOUS_CHOICES = ["reject", "ok"]
TODIRECT_CHOICES   = ["direct", "proxy", "reject"]      # 地域放行「可改直连」：proxy 即保持现状
CHOICES = {"pending": PENDING_CHOICES, "suspicious": SUSPICIOUS_CHOICES, "todirect": TODIRECT_CHOICES}
STATUS_QUO = {"pending": "keep", "suspicious": "ok", "todirect": "proxy"}   # 拉黑理由不够时退回的结论

SCHEMA = {
    "type": "object",
    "properties": {
        "owner":        {"type": "string"},
        "owner_basis":  {"type": "string", "enum": ["known", "inferred", "unknown"]},
        "function":     {"type": "string"},
        "trigger":      {"type": "string"},
        "recommend":    {"type": "string", "enum": PENDING_CHOICES + ["ok"]},
        "scope":        {"type": "string"},
        "confidence":   {"type": "string", "enum": ["high", "medium", "low"]},
        "reason":       {"type": "string"},
        "block_impact": {"type": "string"},
        "sources":      {"type": "array", "items": {"type": "string"}},
        "options":      {"type": "array", "items": {"type": "object", "properties": {
                            "choice": {"type": "string", "enum": PENDING_CHOICES + ["ok"]},
                            "confidence": {"type": "integer", "minimum": 0, "maximum": 100},
                            "reason": {"type": "string"}},
                         "required": ["choice", "confidence", "reason"], "additionalProperties": False}},
    },
    "required": ["owner", "owner_basis", "function", "trigger", "recommend", "scope",
                 "confidence", "reason", "block_impact", "sources", "options"],
    "additionalProperties": False,
}

# ---------------- 提示词 ----------------
def _section(text, title):
    m = re.search(r"^## " + re.escape(title) + r"\s*\n(.*?)(?=^---\s*$|^## )", text, re.S | re.M)
    if not m: raise RuntimeError(f"提示词笔记里找不到「{title}」一节：{NOTES}")
    return m.group(1).strip()

def system_prompt():
    t = open(NOTES, encoding="utf-8").read()
    return _section(t, "提示词：背景与策略") + "\n\n## 输出格式\n\n" + _section(t, "提示词：工具输出格式")

# ---------------- 不外发 ----------------
def load_no_send():
    out = []
    if os.path.exists(NO_SEND):
        for line in open(NO_SEND, encoding="utf-8"):
            s = line.split("#", 1)[0].strip().lower()
            if s: out.append(s.lstrip("."))
    return out

def blocked(host, no_send):
    h = host.lower()
    return any(h == d or h.endswith("." + d) for d in no_send)

def _site(host):
    parts = host.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host

def item_message(item, no_send=None):
    """item: {kind: pending|suspicious, host, procs?, ctx?, bucket?, count?, reasons?, sites?, note?, evidence_lines?, same_site?}"""
    no_send = load_no_send() if no_send is None else no_send
    if blocked(item["host"], no_send):
        raise ValueError(f"{item['host']} 在不外发名单里")
    L = []
    if item["kind"] == "todirect":
        L.append("清单：地域放行「可改直连」（现在走代理，实测直连可用且比代理快）。结论从 direct、proxy、reject 中选。")
        L.append(f"主机：{item['host']}")
        if item.get("count"): L.append(f"累计连接次数：{item['count']}")
    elif item["kind"] == "suspicious":
        L.append("清单：地域放行「可疑」。结论从 reject、ok 中选。")
        L.append(f"主机：{item['host']}")
        if item.get("bucket"): L.append(f"当前去向：{'直连（地域规则判为国内）' if item['bucket']=='direct' else '代理（地域规则判为境外）'}")
        if item.get("count"):  L.append(f"累计连接次数：{item['count']}")
        if item.get("reasons"): L.append("排序程序的打分理由：" + "；".join(item["reasons"]))
        sites = [s for s in item.get("sites", []) if not blocked(s, no_send)]
        if sites: L.append("最初出现时前后连接里的站点：" + ", ".join(sites))
    else:
        L.append("清单：待审（落到最后 MATCH,REJECT 被拒的连接）。结论从 proxy、direct、reject、keep、ignore 中选。")
        L.append(f"主机：{item['host']}")
        if item.get("count"): L.append(f"累计连接次数：{item['count']}")
        if item.get("procs"): L.append("发起进程：" + ", ".join(item["procs"]))
        if item.get("ctx"):
            sites = []
            for h in item["ctx"]:
                s = _site(h)
                if not blocked(h, no_send) and s not in sites and s != _site(item["host"]): sites.append(s)
            if sites: L.append("前后连接里的站点：" + ", ".join(sites[:6]))
    L += item.get("evidence_lines", [])          # 国内视角解析、直连实测（evidence.describe）
    if item.get("same_site"): L.append("同站主机在规则集里的归类：" + "，".join(item["same_site"][:8]))
    if item.get("note"): L.append("本机证据：" + item["note"])
    if not any(x.startswith(("发起进程", "前后连接", "最初出现", "本机证据", "国内视角", "直连实测", "直连与代理", "同站主机")) for x in L):
        L.append("没有其它证据。")
    return "\n".join(L)

# ---------------- 结果校验 ----------------
def _parse_json(text):
    text = text.strip()
    m = re.search(r"\{.*\}", text, re.S)
    if not m: raise ValueError("输出里没有 JSON")
    return json.loads(m.group(0))

def validate(obj, kind):
    miss = [k for k in SCHEMA["required"] if k not in obj]
    if miss: raise ValueError(f"缺字段 {miss}")
    allowed = CHOICES[kind]
    if obj["recommend"] not in allowed: raise ValueError(f"recommend={obj['recommend']} 不在 {allowed}")
    opts = [o for o in obj["options"] if isinstance(o, dict) and o.get("choice") in allowed]
    if not opts: raise ValueError("options 为空或没有合法选项")
    obj["options"] = opts
    obj["decision"] = decide(obj, kind)
    return obj

# ---------------- 由各选项的置信度定结论 ----------------
# 模型给每个选项的把握与理由，最后结论由这里按代价定：把用得到的服务拉黑，代价比多放行一个无害主机大，
# 所以拉黑要比最好的放行选项高出 REJECT_MARGIN 才采用；差距不够时退回 STATUS_QUO：待审项给「不选」（仍被拒，但留给人定），
# 可疑项给「正常」、可改直连项给「代理」（都是维持现状）。
REJECT_MARGIN = 20

def decide(obj, kind):
    conf = {}
    for o in obj["options"]: conf[o["choice"]] = max(conf.get(o["choice"], 0), int(o.get("confidence") or 0))
    best = max(conf, key=conf.get)
    if best != "reject": return best
    allow = max([conf.get(c, 0) for c in CHOICES[kind] if c not in ("reject", "keep", "ignore")] or [0])
    if conf["reject"] - allow >= REJECT_MARGIN: return "reject"
    return STATUS_QUO[kind]

# ---------------- 各家接口 ----------------
def _deepseek_key():
    """环境变量 DEEPSEEK_API_KEY 优先，其次 settings.json 的 deepseek_key_file（密钥文件放在哪由使用者定）。"""
    k = os.environ.get("DEEPSEEK_API_KEY", "").strip()
    if k: return k
    import clash_review as cr
    path = cr.settings().get("deepseek_key_file")
    if not path:
        raise RuntimeError("没有 DeepSeek 密钥：设环境变量 DEEPSEEK_API_KEY，或在 settings.json 里写 deepseek_key_file")
    try:
        with open(path, encoding="utf-8") as f: return f.read().strip()
    except OSError as e:
        raise RuntimeError(f"读不到 DeepSeek 密钥文件 {path}（{e}）")

def _deepseek(model, sysmsg, usermsg, timeout, schema=None):
    body = {"model": model, "messages": [{"role": "system", "content": sysmsg}, {"role": "user", "content": usermsg}],
            "response_format": {"type": "json_object"}, "stream": False}
    req = urllib.request.Request("https://api.deepseek.com/chat/completions", data=json.dumps(body).encode("utf-8"),
                                 headers={"Content-Type": "application/json",
                                          "Authorization": "Bearer " + _deepseek_key()})
    with urllib.request.urlopen(req, timeout=timeout) as r: d = json.load(r)
    return d["choices"][0]["message"]["content"], {"usage": d.get("usage")}

_CLEAN_DIR = None
def _claude(model, sysmsg, usermsg, timeout, schema=None):
    global _CLEAN_DIR
    exe = shutil.which("claude") or os.path.expanduser(r"~\.local\bin\claude.exe")
    if _CLEAN_DIR is None:
        _CLEAN_DIR = tempfile.mkdtemp(prefix="clash-review-claude-")
        with open(os.path.join(_CLEAN_DIR, "system.txt"), "w", encoding="utf-8") as f: f.write(sysmsg)
    cmd = [exe, "-p", usermsg, "--model", model,
           "--system-prompt-file", os.path.join(_CLEAN_DIR, "system.txt"),
           "--exclude-dynamic-system-prompt-sections", "--tools", "", "--setting-sources", "",
           "--no-session-persistence", "--output-format", "json", "--json-schema", json.dumps(schema or SCHEMA)]
    p = subprocess.run(cmd, cwd=_CLEAN_DIR, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout,
                       encoding="utf-8", errors="replace", creationflags=_NO_WINDOW)
    try: d = json.loads(p.stdout)
    except ValueError: raise RuntimeError(f"claude 输出不是 JSON（退出码 {p.returncode}）：{(p.stdout or p.stderr)[:300]}")
    if d.get("is_error"): raise RuntimeError(f"claude 报错：{str(d.get('result'))[:300]}")
    out = d.get("structured_output")
    text = json.dumps(out, ensure_ascii=False) if out is not None else d.get("result", "")
    return text, {"usage": d.get("usage"), "cost_usd": d.get("total_cost_usd"), "models": list(d.get("modelUsage", {}))}

PROVIDERS = {
    "deepseek-flash":  lambda s, u, t, sc=None: _deepseek("deepseek-flash", s, u, t, sc),
    "claude-haiku":    lambda s, u, t, sc=None: _claude("haiku", s, u, t, sc),
    "claude-sonnet":   lambda s, u, t, sc=None: _claude("sonnet", s, u, t, sc),
}

# 同一进程内对每家接口的并发上限：所有调用方（评估、网页、批量）共用。
# DeepSeek 在约 16 个并发时开始返回 429（2026-09-23），这里留余量取 6；claude -p 每次一个本机进程，取 CPU 核数的一半。
_SEMS = {"deepseek": threading.BoundedSemaphore(6), "claude": threading.BoundedSemaphore(max(2, (os.cpu_count() or 8) // 2))}

def ask(provider, item, sysmsg=None, timeout=180, retries=4):
    """返回 {ok, result|error, raw, seconds, meta, message}。
    限流（429）与服务端过载时按 2、4、8、16 秒退避重试；输出不合格时直接再问一次。"""
    sysmsg = sysmsg or system_prompt()
    msg = item_message(item)
    sem = _SEMS["claude" if provider.startswith("claude") else "deepseek"]
    t0 = time.time(); last = None
    for attempt in range(retries + 1):
        try:
            with sem: raw, meta = PROVIDERS[provider](sysmsg, msg, timeout)
            try:
                res = validate(_parse_json(raw), item["kind"])
                return {"ok": True, "result": res, "raw": raw, "seconds": round(time.time() - t0, 1), "meta": meta, "message": msg}
            except ValueError as e:
                last = {"ok": False, "error": f"输出不合格：{e}", "raw": raw, "meta": meta}
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            if "402" in err: err = "DeepSeek 账户余额不足（HTTP 402），充值后再试"   # 2026-09-23 首次遇到；不重试
            last = {"ok": False, "error": err, "raw": ""}
            if "402" in err or "余额" in err: break
            if _retryable(err) and attempt < retries: time.sleep(2 ** (attempt + 1))
    last.update(seconds=round(time.time() - t0, 1), message=msg)
    return last

# ---------------- 缓存规则（2026-09-24）----------------
# 模型的回答分两类，按各自依赖什么来缓存：
# 1. 身份（owner / owner_basis / function）：只取决于主机名本身，与在哪个页面看无关 → 按主机缓存在 var/identity.json，各页面共用；
#    任一页面的查询成功时写入，新的覆盖旧的。
# 2. 推荐与理由（advice.json，见网页服务）：取决于提示词与本机证据。同样的输入再问一遍只是重新抽样（见下面「多次采样投票」），
#    所以不自动重查。只有提示词改过（按 prompt_hash 比对）才标「已过期」，「为本页生成」时重查并覆盖。
# 两类都不按时间过期，一直留到被新结果覆盖（用户 2026-09-24 定）。
IDENTITY = os.path.join(cr.DATA_DIR, "identity.json")
_ID_LOCK = threading.Lock()

def prompt_hash(text=None):
    """提示词指纹：策略一改，旧的推荐就过期。"""
    return hashlib.sha1((text or system_prompt()).encode("utf-8")).hexdigest()[:10]

def _id_load():
    try:
        with open(IDENTITY, encoding="utf-8") as f: return json.load(f)
    except (OSError, ValueError): return {}

def identity_get(host):
    """缓存里的身份，没有返回 None。"""
    return _id_load().get(host)

def identity_put(host, res, model, source):
    """res 含 owner / owner_basis / function。source：查询所在的页面（pending / suspicious / todirect）。"""
    import clash_review as cr
    rec = {"owner": res.get("owner", ""), "owner_basis": res.get("owner_basis", "unknown"), "function": res.get("function", ""),
           "model": model, "source": source, "checked": datetime.datetime.now().isoformat(timespec="seconds")}
    with _ID_LOCK:
        d = _id_load(); d[host] = rec
        cr._atomic_write_text(IDENTITY, json.dumps(d, ensure_ascii=False, indent=1))
    return rec

# ---------------- 多次采样投票 ----------------
# 同一题问几次，严重错误（把在用的服务判成拉黑）并不稳定：2026-09-23 三次相同的评估里，
# prod.do.dsp.mp.microsoft.com 与 polyfill-fastly.io 各只在一次里被误判拉黑。
# 所以问 n 次：拉黑要过半数才采用；否则取非拉黑结论里最多的；全是拉黑以外的弃权就给 keep。
def vote(decisions, kind="pending"):
    ds = [d for d in decisions if d]
    if not ds: return None
    if sum(d == "reject" for d in ds) * 2 > len(ds): return "reject"
    rest = [d for d in ds if d != "reject"]
    if not rest: return STATUS_QUO[kind]
    return max(set(rest), key=lambda d: (rest.count(d), d != "keep"))

def ask_vote(provider, item, n=3, sysmsg=None):
    """同一项并发问 n 次。返回第一次成功的结果，另加 votes（各次结论）与 decision（投票结论）。"""
    sysmsg = sysmsg or system_prompt()
    with cf.ThreadPoolExecutor(n) as ex:
        rs = list(ex.map(lambda _: ask(provider, item, sysmsg), range(n)))
    ok = [r for r in rs if r["ok"]]
    if not ok: return rs[0]
    base = next((r for r in ok if r["result"]["decision"] == vote([x["result"]["decision"] for x in ok], item["kind"])), ok[0])
    base = dict(base); base["result"] = dict(base["result"])
    base["result"]["votes"] = [r["result"]["decision"] for r in ok]
    base["result"]["decision"] = vote(base["result"]["votes"], item["kind"])
    return base

def ask_checked(provider, item, sysmsg=None, extra=2):
    """日常用这个：先问一次；只有结论是拉黑时再问 extra 次并投票。
    2026-09-23 在 A 套三次评估上回放：误拉黑与「每题都问 3 次」一样为 0，调用次数约为后者的 55%。"""
    sysmsg = sysmsg or system_prompt()
    r = ask(provider, item, sysmsg)
    if not r["ok"] or r["result"]["decision"] != "reject": return r
    with cf.ThreadPoolExecutor(extra) as ex:
        more = [x for x in ex.map(lambda _: ask(provider, item, sysmsg), range(extra)) if x["ok"]]
    votes = [r["result"]["decision"]] + [x["result"]["decision"] for x in more]
    final = vote(votes, item["kind"])
    if final == "reject": base = r
    else: base = next((x for x in more if x["result"]["decision"] == final), r)
    base = dict(base); base["result"] = dict(base["result"])
    base["result"]["votes"] = votes; base["result"]["decision"] = final
    return base

# ---------------- 批量：一次调用问多项（「为本页全部生成」用） ----------------
# claude -p 每次调用要启动一个 Claude Code 进程，约 3–6 秒本机开销；批量把它分摊到多项上。
# 单行「理由」仍用 ask()，一次只问一项。
BATCH_SCHEMA = {
    "type": "object",
    "properties": {"items": {"type": "array", "items": {
        "type": "object",
        "properties": dict({"host": {"type": "string"}}, **SCHEMA["properties"]),
        "required": ["host"] + SCHEMA["required"], "additionalProperties": False}}},
    "required": ["items"], "additionalProperties": False,
}
BATCH_NOTE = ("本次一共给你 {n} 项，彼此独立：逐项按策略判断，不要因为它们放在一起就互相类推。"
              "输出一个 JSON 对象 {{\"items\": [...]}}，数组里每项一个对象，含 host 字段（与题目里的主机名完全一致），其余字段同上。")

def ask_batch(provider, items, sysmsg=None, timeout=600):
    """一次问多项。返回 [ask() 同样格式的结果]，顺序与 items 一致；缺项或不合格的单独标失败。"""
    sysmsg = sysmsg or system_prompt()
    no_send = load_no_send()
    msgs = [item_message(it, no_send) for it in items]
    usermsg = BATCH_NOTE.format(n=len(items)) + "\n\n" + "\n\n".join(f"【第 {i+1} 项】\n{m}" for i, m in enumerate(msgs))
    t0 = time.time()
    try:
        raw, meta = PROVIDERS[provider](sysmsg, usermsg, timeout, BATCH_SCHEMA)
        got = {x.get("host", "").strip().lower(): x for x in _parse_json(raw).get("items", []) if isinstance(x, dict)}
    except Exception as e:
        sec = round(time.time() - t0, 1)
        return [{"ok": False, "error": f"{type(e).__name__}: {e}", "raw": "", "seconds": sec, "message": m, "batch": len(items)} for m in msgs]
    sec = round(time.time() - t0, 1); out = []
    for it, m in zip(items, msgs):
        x = got.get(it["host"].lower())
        try:
            if x is None: raise ValueError("批量结果里缺这一项")
            x = {k: v for k, v in x.items() if k != "host"}
            out.append({"ok": True, "result": validate(x, it["kind"]), "raw": json.dumps(x, ensure_ascii=False),
                        "seconds": sec, "meta": meta, "message": m, "batch": len(items)})
        except ValueError as e:
            out.append({"ok": False, "error": f"输出不合格：{e}", "raw": raw, "seconds": sec, "message": m, "batch": len(items)})
    return out

# ---------------- 自适应并发 ----------------
# 订阅额度与 DeepSeek 都没有公开的固定并发上限，按「加性增、乘性减」自己找：
# 从 start 起，每连续成功「当前并发数」个任务就 +1，直到 cap；遇到限流、超时、服务端错误，并发减半、稍等再试。
# claude 另受本机 CPU 限制（每个调用一个进程），cap 默认取逻辑核数。
def _retryable(err):
    return bool(re.search(r"429|rate.?limit|overload|529|503|502|timed? ?out|Timeout|ECONNRESET", err or "", re.I))

class AdaptivePool:
    def __init__(self, start=4, cap=None):
        self.cap = cap or (os.cpu_count() or 8); self.limit = min(start, self.cap)
        self.running = 0; self.ok_streak = 0; self.peak = self.limit
        self.cv = threading.Condition()
    def acquire(self):
        with self.cv:
            while self.running >= self.limit: self.cv.wait()
            self.running += 1
    def release(self, ok, retryable=False):
        with self.cv:
            self.running -= 1
            if ok:
                self.ok_streak += 1
                if self.ok_streak >= self.limit and self.limit < self.cap:
                    self.limit += 1; self.ok_streak = 0; self.peak = max(self.peak, self.limit)
            elif retryable:
                self.limit = max(1, self.limit // 2); self.ok_streak = 0
            self.cv.notify_all()

def run_many(provider, items, batch=8, start=4, cap=None, sysmsg=None, on_result=None, max_retries=3):
    """把 items 按每批 batch 项切开，自适应并发地问。返回与 items 同序的结果列表。batch=1 即逐项问。
    on_result(item, result) 每得到一项结果就回调一次（用于边跑边落盘）。"""
    sysmsg = sysmsg or system_prompt()
    fam_cap = cap or ((os.cpu_count() or 8) if provider.startswith("claude") else 32)
    pool = AdaptivePool(start=start, cap=fam_cap)
    chunks = [list(range(i, min(i + batch, len(items)))) for i in range(0, len(items), batch)]
    results = [None] * len(items)
    def work(idx):
        for attempt in range(max_retries + 1):
            pool.acquire()
            sub = [items[i] for i in idx]
            try:
                rs = ask_batch(provider, sub, sysmsg) if len(sub) > 1 else [ask(provider, sub[0], sysmsg, retries=0)]
            except Exception as e:   # ask / ask_batch 自己会接住调用错误，这里只防 item_message 之类的意外
                rs = [{"ok": False, "error": f"{type(e).__name__}: {e}", "raw": "", "seconds": 0} for _ in sub]
            bad = [r for r in rs if not r["ok"]]
            retry = bool(bad) and len(bad) == len(rs) and _retryable(bad[0].get("error"))
            pool.release(ok=not bad, retryable=retry)
            if retry and attempt < max_retries:
                time.sleep(2 * (attempt + 1)); continue
            for i, r in zip(idx, rs):
                results[i] = r
                if on_result: on_result(items[i], r)
            return
    with cf.ThreadPoolExecutor(max(len(chunks), 1)) as ex:
        list(ex.map(work, chunks))
    return results, pool.peak

if __name__ == "__main__":
    # 手动试一项：python advisor.py <provider> <host> [pending|suspicious]
    prov, host = sys.argv[1], sys.argv[2]
    kind = sys.argv[3] if len(sys.argv) > 3 else "pending"
    print(json.dumps(ask(prov, {"kind": kind, "host": host}), ensure_ascii=False, indent=1))
