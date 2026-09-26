"""第 2 层：调模型给出归类建议与理由（见 README 第五节「设想」）。

系统提示取自本目录 prompt.md 的「背景与策略」与「工具输出格式」两节。改策略直接改 prompt.md（对话里也可以直接用它，
见其头部）。
每次只问一项；返回模型给的 JSON（字段见该笔记「工具输出格式」）。

模型：settings.json 的 "model" 选（见下面「各家接口」），默认 Codex（ChatGPT 订阅）的 gpt-6-sol。评估脚本另可按 PROVIDERS 的名字指定：
- codex-sol：见「各家接口」里 Codex 一段
- deepseek-flash：DeepSeek API（OpenAI 兼容接口，JSON 模式），密钥取环境变量 DEEPSEEK_API_KEY，
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
# 用哪个模型由 settings.json 的 "model" 定（网页顶栏「模型」也能改），三种：
#   {"provider": "codex", "model": "gpt-6-sol", "effort": "low"}   ChatGPT 订阅，经 Codex 命令行（默认）
#   {"provider": "claude", "model": "haiku"}                        Claude 订阅，经 Claude Code 命令行 claude -p
#   {"provider": "openai", "base_url": "https://api.deepseek.com", "model": "deepseek-flash", "key_file": "..."}
#                                                                   任何 OpenAI 兼容接口（DeepSeek、OpenAI、Gemini 等），按用量付费
# 评估脚本仍可按 PROVIDERS 里的名字指定模型。
DEFAULT_MODEL = {"provider": "codex", "model": "gpt-6-sol", "effort": "low"}

def model_conf():
    m = cr.settings().get("model")
    if not isinstance(m, dict) or m.get("provider") not in ("codex", "claude", "openai"):
        if cr.settings().get("deepseek_key_file") and m is None:      # 1.4.0 之前的设置：只写了 DeepSeek 密钥
            return {"provider": "openai", "base_url": "https://api.deepseek.com", "model": "deepseek-flash",
                    "key_file": cr.settings()["deepseek_key_file"]}
        return dict(DEFAULT_MODEL)
    return m

def model_name(conf=None):
    """记在推荐与身份缓存里的模型名，如 codex:gpt-6-sol。换了模型，旧推荐标「已过期」。"""
    c = conf or model_conf()
    return f"{c['provider']}:{c.get('model') or DEFAULT_MODEL['model']}"

def _read_key(path, what):
    try:
        with open(path, encoding="utf-8") as f: return f.read().strip()
    except OSError as e:
        raise RuntimeError(f"读不到{what}密钥文件 {path}（{e}）")

def _openai(base_url, model, key, sysmsg, usermsg, timeout, schema=None):
    """OpenAI 兼容的 /chat/completions，JSON 模式。"""
    body = {"model": model, "messages": [{"role": "system", "content": sysmsg}, {"role": "user", "content": usermsg}],
            "response_format": {"type": "json_object"}, "stream": False}
    req = urllib.request.Request(base_url.rstrip("/") + "/chat/completions", data=json.dumps(body).encode("utf-8"),
                                 headers={"Content-Type": "application/json", "Authorization": "Bearer " + key})
    with urllib.request.urlopen(req, timeout=timeout) as r: d = json.load(r)
    return d["choices"][0]["message"]["content"], {"usage": d.get("usage")}

def _deepseek_key():
    """环境变量 DEEPSEEK_API_KEY 优先，其次 settings.json 的 deepseek_key_file。"""
    k = os.environ.get("DEEPSEEK_API_KEY", "").strip()
    if k: return k
    path = cr.settings().get("deepseek_key_file")
    if not path:
        raise RuntimeError("没有 DeepSeek 密钥：设环境变量 DEEPSEEK_API_KEY，或在 settings.json 里写 deepseek_key_file")
    return _read_key(path, " DeepSeek ")

def _deepseek(model, sysmsg, usermsg, timeout, schema=None):
    return _openai("https://api.deepseek.com", model, _deepseek_key(), sysmsg, usermsg, timeout, schema)

_CLEAN_DIR = None
def _claude(model, sysmsg, usermsg, timeout, schema=None):
    global _CLEAN_DIR
    exe = shutil.which("claude") or os.path.expanduser(r"~\.local\bin\claude.exe")
    if _CLEAN_DIR is None:
        _CLEAN_DIR = tempfile.mkdtemp(prefix="clash-review-claude-")
    sysfile = os.path.join(_CLEAN_DIR, f"system-{prompt_hash(sysmsg)}.txt")      # 同一进程里提示词可能改过（评估对比新旧提示词）
    if not os.path.exists(sysfile):
        with open(sysfile, "w", encoding="utf-8") as f: f.write(sysmsg)
    cmd = [exe, "-p", usermsg, "--model", model,
           "--system-prompt-file", sysfile,
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

# Codex（ChatGPT 订阅）：codex exec 本是写代码的 agent，这里尽量把它当成裸模型用（2026-09-26 实测）：
# - 单独的数据目录 CODEX_HOME = var/codex，单独登录一次（python clash_review.py codex-login）。
#   不用 ~/.codex：那里的全局 AGENTS.md 会被带进每次调用，也没有开关能关掉（project_doc_max_bytes 只管项目里的）；
#   单独登录是另一套凭据，不影响 Codex 桌面版的登录。
# - 系统提示用 model_instructions_file 换掉 Codex 自带的；不读用户设置与规则；只读沙箱；关掉能关的功能（插件、浏览器、
#   电脑操作、生成图片、多 agent、命令行工具等），基础开销从约 11600 token 降到约 4800；仍剩几个关不掉的内置工具，只占 token。
# - 输出格式用 --output-schema 固定，最终回答写到 -o 指定的文件。
CODEX_HOME = os.path.join(cr.DATA_DIR, "codex")
CODEX_OFF = ["apps", "browser_use", "browser_use_external", "computer_use", "image_generation", "multi_agent", "plugins",
             "shell_tool", "unified_exec", "view_image", "skill_search", "tool_suggest", "hooks", "goals", "sleep_tool",
             "in_app_browser", "shell_snapshot", "workspace_dependencies", "memories", "remote_plugin", "code_mode_host"]
_CODEX = {}     # 进程内缓存：exe 路径、这个版本认得的功能开关

def codex_exe():
    """settings.json 的 codex_exe 优先；其次 Codex 桌面版自带的命令行（%LOCALAPPDATA%\\OpenAI\\Codex\\bin\\<随机目录>\\codex.exe，
    桌面版更新会换目录，取最新的）；再次 PATH 上的 codex。"""
    p = cr.settings().get("codex_exe")
    if p: return p
    import glob
    found = glob.glob(os.path.join(os.environ.get("LOCALAPPDATA", ""), "OpenAI", "Codex", "bin", "*", "codex.exe"))
    if found: return max(found, key=os.path.getmtime)
    p = shutil.which("codex")
    if p: return p
    raise RuntimeError("找不到 Codex 命令行：装 Codex 桌面版，或在 settings.json 里写 codex_exe")

def codex_logged_in(): return os.path.exists(os.path.join(CODEX_HOME, "auth.json"))

def _codex_features(exe):
    """这个版本认得的功能开关名（codex features list）；认不得的 --disable 会让 codex 报错，所以只关认得的。"""
    if _CODEX.get("exe") != exe:
        try:
            out = subprocess.run([exe, "features", "list"], capture_output=True, encoding="utf-8", errors="replace",
                                 timeout=30, creationflags=_NO_WINDOW).stdout
            names = {l.split()[0] for l in out.splitlines() if l.strip() and "removed" not in l}
        except Exception: names = set()
        _CODEX.update(exe=exe, features=names)
    return _CODEX["features"]

def codex_models():
    """ChatGPT 账号能用的模型（Codex 缓存的清单，隐藏的不列）。清单在 Codex 数据目录，第一次调用后才有。"""
    for home in (CODEX_HOME, os.path.expanduser(r"~\.codex")):
        try:
            with open(os.path.join(home, "models_cache.json"), encoding="utf-8") as f: d = json.load(f)
            ms = d.get("models", d) if isinstance(d, dict) else d
            return [m["slug"] for m in sorted(ms, key=lambda m: m.get("priority", 99)) if m.get("visibility") == "list"]
        except (OSError, ValueError, KeyError, TypeError): continue
    return []

def _codex(model, effort, sysmsg, usermsg, timeout, schema=None):
    if not codex_logged_in():
        raise RuntimeError("Codex 还没登录：在工具目录运行 python clash_review.py codex-login，按提示用 ChatGPT 账号登录")
    exe = codex_exe(); known = _codex_features(exe)
    d = tempfile.mkdtemp(prefix="clash-review-codex-")
    try:
        files = {"sys": os.path.join(d, "system.txt"), "schema": os.path.join(d, "schema.json"), "out": os.path.join(d, "out.txt")}
        with open(files["sys"], "w", encoding="utf-8") as f: f.write(sysmsg)
        with open(files["schema"], "w", encoding="utf-8") as f: json.dump(schema or SCHEMA, f)
        cmd = [exe, "exec", "--skip-git-repo-check", "--ephemeral", "--sandbox", "read-only", "--ignore-user-config", "--ignore-rules",
               "-m", model, "-c", f'model_reasoning_effort="{effort}"',
               "-c", "model_instructions_file=" + json.dumps(files["sys"]), "-c", "project_doc_max_bytes=0",
               "-c", 'web_search="disabled"',
               *[a for x in CODEX_OFF if x in known for a in ("--disable", x)],
               "--output-schema", files["schema"], "-o", files["out"], "-"]
        p = subprocess.run(cmd, cwd=d, env=dict(os.environ, CODEX_HOME=CODEX_HOME), input=usermsg, capture_output=True,
                           timeout=timeout, encoding="utf-8", errors="replace", creationflags=_NO_WINDOW)
        log = (p.stderr or "") + (p.stdout or "")
        try:
            with open(files["out"], encoding="utf-8") as f: text = f.read()
        except OSError: text = ""
        if not text.strip():
            errs = [l.strip() for l in log.splitlines() if "ERROR" in l or "error" in l.lower()]
            raise RuntimeError(f"codex 没有给出回答（退出码 {p.returncode}）：{(errs[-1] if errs else log[-300:])[:300]}")
        m = re.search(r"tokens used\s*\n\s*([\d,]+)", log)
        return text, {"tokens": int(m.group(1).replace(",", "")) if m else None, "model": model}
    finally:
        shutil.rmtree(d, ignore_errors=True)

PROVIDERS = {
    "deepseek-flash":  lambda s, u, t, sc=None: _deepseek("deepseek-flash", s, u, t, sc),
    "claude-haiku":    lambda s, u, t, sc=None: _claude("haiku", s, u, t, sc),
    "claude-sonnet":   lambda s, u, t, sc=None: _claude("sonnet", s, u, t, sc),
    "codex-sol":       lambda s, u, t, sc=None: _codex("gpt-6-sol", "low", s, u, t, sc),
}

def resolve(provider=None):
    """provider：PROVIDERS 里的名字，或 None（用 settings.json 选的模型）。返回 (调用函数, 并发族, 模型名)。"""
    if provider:
        fam = "claude" if provider.startswith("claude") else "codex" if provider.startswith("codex") else "api"
        return PROVIDERS[provider], fam, provider
    c = model_conf(); name = model_name(c); p = c["provider"]
    if p == "codex":
        return (lambda s, u, t, sc=None: _codex(c.get("model") or DEFAULT_MODEL["model"], c.get("effort") or "low", s, u, t, sc)), "codex", name
    if p == "claude":
        return (lambda s, u, t, sc=None: _claude(c.get("model") or "haiku", s, u, t, sc)), "claude", name
    if not c.get("base_url") or not c.get("model"):
        raise RuntimeError("settings.json 的 model 缺 base_url 或 model（OpenAI 兼容接口）")
    def call(s, u, t, sc=None):
        key = os.environ.get(c["key_env"], "").strip() if c.get("key_env") else ""
        if not key:
            if not c.get("key_file"): raise RuntimeError("settings.json 的 model 缺 key_file（接口密钥文件）")
            key = _read_key(c["key_file"], "接口")
        return _openai(c["base_url"], c["model"], key, s, u, t, sc)
    return call, "api", name

# 同一进程内对每家接口的并发上限：所有调用方（评估、网页、批量）共用。
# DeepSeek 在约 16 个并发时开始返回 429（2026-09-23），接口类留余量取 6；claude -p 与 codex exec 每次一个本机进程，
# claude 取 CPU 核数的一半；codex 一次约 10～30 秒、多是等模型，取 8。
_SEMS = {"api": threading.BoundedSemaphore(6), "claude": threading.BoundedSemaphore(max(2, (os.cpu_count() or 8) // 2)),
         "codex": threading.BoundedSemaphore(8)}

def ask(provider, item, sysmsg=None, timeout=180, retries=4):
    """provider：PROVIDERS 里的名字，None 为 settings.json 选的模型。返回 {ok, result|error, raw, seconds, meta, message, model}。
    限流（429）与服务端过载时按 2、4、8、16 秒退避重试；输出不合格时直接再问一次。"""
    sysmsg = sysmsg or system_prompt()
    msg = item_message(item)
    fn, fam, name = resolve(provider)
    t0 = time.time(); last = None
    for attempt in range(retries + 1):
        try:
            with _SEMS[fam]: raw, meta = fn(sysmsg, msg, timeout)
            try:
                res = validate(_parse_json(raw), item["kind"])
                return {"ok": True, "result": res, "raw": raw, "seconds": round(time.time() - t0, 1), "meta": meta, "message": msg, "model": name}
            except ValueError as e:
                last = {"ok": False, "error": f"输出不合格：{e}", "raw": raw, "meta": meta}
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            if "402" in err: err = "接口账户余额不足（HTTP 402），充值后再试"   # 2026-09-23 DeepSeek 首次遇到；不重试
            last = {"ok": False, "error": err, "raw": ""}
            if "402" in err or "余额" in err or "还没登录" in err or "找不到 Codex" in err or "settings.json 的 model 缺" in err: break
            if _retryable(err) and attempt < retries: time.sleep(2 ** (attempt + 1))
    last.update(seconds=round(time.time() - t0, 1), message=msg, model=name)
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

def advice_version():
    """(提示词指纹, 模型名)：两者任一变了，已有的推荐标「已过期」。"""
    return prompt_hash(), model_name()

def _id_load():
    try:
        with open(IDENTITY, encoding="utf-8") as f: return json.load(f)
    except (OSError, ValueError): return {}

def identity_get(host, table=None):
    """缓存里的身份，没有返回 None。table：identity_all() 的结果，逐个主机查时传进来，免得每次重读整个文件。"""
    return (_id_load() if table is None else table).get(host)

def identity_all(): return _id_load()

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
        fn, fam, _ = resolve(provider)
        with _SEMS[fam]: raw, meta = fn(sysmsg, usermsg, timeout, BATCH_SCHEMA)
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
    fam = resolve(provider)[1]
    fam_cap = cap or {"claude": os.cpu_count() or 8, "codex": 8}.get(fam, 32)
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
