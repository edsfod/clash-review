"""第 3 层：外部资料。与第 1 层（本机事实，evidence.py）、第 2 层（模型，advisor.py）并排，各自独立给出结果。

离线部分（var/lists/，每月由 update-lists 下载一次，查询不联网）：
  - 拦截名单：EasyPrivacy、EasyList（只取整域名规则 ||example.com^）、HaGeZi Pro、anti-AD。按域名后缀匹配。
  - v2fly domain-list-community（geosite 的源数据）：按公司或类别分的域名清单，回答「是谁家的」。
    沿 include 关系向上追溯（如 msn 被 microsoft 包含），条目上的 @ads 属性单独标出。
按需联网部分（结果缓存到 var/external_cache.json，30 天内不重查）：
  - RDAP：注册时间、注册商（经 rdap.org）
  - 证书：TLS 证书上的机构名与签发者
  - 搜索：本机 claude -p 带网页搜索找厂商文档等出处（用订阅额度，只在按需时调用）
只用标准库。
"""
import datetime, gzip, io, json, os, re, socket, ssl, subprocess, sys, threading, time, urllib.parse, urllib.request, zipfile
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)   # 在 pythonw（没有控制台）下调 curl 等命令行程序，不加这个每次都会弹出一个 cmd 窗口

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import clash_review as cr

LISTS = os.path.join(cr.DATA_DIR, "lists")
INDEX = os.path.join(LISTS, "index.json.gz")
CACHE = os.path.join(cr.DATA_DIR, "external_cache.json")
CACHE_DAYS = 30
SOURCES = {   # 文件名: (下载地址, 说明)
    "easyprivacy.txt":     ("https://easylist.to/easylist/easyprivacy.txt", "EasyPrivacy（追踪）"),
    "easylist.txt":        ("https://easylist.to/easylist/easylist.txt", "EasyList（广告）"),
    "hagezi-pro.txt":      ("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt", "HaGeZi Pro（广告、追踪、遥测）"),
    "anti-ad-domains.txt": ("https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-domains.txt", "anti-AD（国内广告、追踪）"),
    "v2fly-dlc.zip":       ("https://codeload.github.com/v2fly/domain-list-community/zip/refs/heads/master", "v2fly 域名分类（归属）"),
}
BLOCKLISTS = ["easyprivacy.txt", "easylist.txt", "hagezi-pro.txt", "anti-ad-domains.txt"]

# ---------------- 下载 ----------------
def update(proxy="http://127.0.0.1:7897"):
    """下载全部名单（先直连，失败回退本机代理），再重建索引。返回 [(文件, 字节数或错误)]。"""
    os.makedirs(LISTS, exist_ok=True); out = []
    for fn, (url, _) in SOURCES.items():
        data = None
        for px in (None, proxy):
            try: data = cr._download(url, proxy=px, timeout=120); break
            except Exception as e: err = f"{type(e).__name__}: {e}"
        if data is None: out.append((fn, err)); continue
        tmp = os.path.join(LISTS, fn + ".tmp")
        with open(tmp, "wb") as f: f.write(data)
        os.replace(tmp, os.path.join(LISTS, fn)); out.append((fn, len(data)))
    build_index()
    return out

# ---------------- 解析与索引 ----------------
ABP_RE = re.compile(r"^\|\|([a-z0-9.-]+\.[a-z0-9-]+)\^(?:\$(.*))?$")

def _parse_blocklist(fn, text):
    doms = set()
    for line in text.splitlines():
        s = line.strip().lower()
        if not s or s[0] in "#!@[": continue
        if fn.startswith("easy"):
            m = ABP_RE.match(s)
            if not m: continue                              # 带路径、元素隐藏等规则不适用于分流
            opts = m.group(2) or ""
            if "domain=" in opts or "denyallow" in opts or "~third-party" in opts: continue   # 只在特定网站生效的
            doms.add(m.group(1))
        else:
            s = s.split()[0].lstrip("*.").lstrip(".")
            if "." in s and re.match(r"^[a-z0-9._-]+$", s): doms.add(s)
    return doms

def _parse_v2fly(zpath):
    """返回 files{名: {"domain": {域: [属性]}, "full": {...}, "include": [名]}}。"""
    z = zipfile.ZipFile(zpath); files = {}
    for n in z.namelist():
        if "/data/" not in n or n.endswith("/"): continue
        name = n.rsplit("/", 1)[1]; d = {"domain": {}, "full": {}, "include": []}
        for line in z.read(n).decode("utf-8", "ignore").splitlines():
            line = line.split("#", 1)[0].strip()
            if not line: continue
            toks = line.split(); rule = toks[0]; attrs = [t[1:] for t in toks[1:] if t.startswith("@")]
            if rule.startswith("include:"): d["include"].append([rule[8:], attrs])   # include:x @ads 只含 x 里标了 @ads 的条目
            elif rule.startswith("full:"): d["full"][rule[5:].lower()] = attrs
            elif rule.startswith(("keyword:", "regexp:")): continue
            else: d["domain"][rule.split(":", 1)[-1].lower()] = attrs
        files[name] = d
    return files

def build_index():
    block = {}
    for fn in BLOCKLISTS:
        p = os.path.join(LISTS, fn)
        if not os.path.exists(p): continue
        for dom in _parse_blocklist(fn, open(p, encoding="utf-8", errors="ignore").read()):
            block.setdefault(dom, []).append(fn)
    v2 = {"domain": {}, "full": {}, "parents": {}}
    zp = os.path.join(LISTS, "v2fly-dlc.zip")
    if os.path.exists(zp):
        files = _parse_v2fly(zp)
        for name, d in files.items():
            for k in ("domain", "full"):
                for dom, attrs in d[k].items(): v2[k].setdefault(dom, []).append([name, attrs])
            for inc, need in d["include"]: v2["parents"].setdefault(inc, []).append([name, need])
    meta = {"built": datetime.datetime.now().isoformat(timespec="seconds"),
            "files": {fn: datetime.datetime.fromtimestamp(os.path.getmtime(os.path.join(LISTS, fn))).isoformat(timespec="seconds")
                      for fn in SOURCES if os.path.exists(os.path.join(LISTS, fn))}}
    with gzip.open(INDEX, "wt", encoding="utf-8") as f: json.dump({"meta": meta, "block": block, "v2fly": v2}, f)
    return meta

_IDX = None
def _index():
    global _IDX
    if _IDX is None:
        if not os.path.exists(INDEX):
            if not os.path.exists(os.path.join(LISTS, BLOCKLISTS[0])): return None
            build_index()
        with gzip.open(INDEX, "rt", encoding="utf-8") as f: _IDX = json.load(f)
    return _IDX

def _suffixes(host):
    parts = host.lower().strip(".").split(".")
    return [".".join(parts[i:]) for i in range(len(parts))]

def _ancestors(name, attrs, parents, seen=None):
    """沿 include 向上找包含 name 的清单；带属性过滤的 include（如 include:microsoft @ads）只在条目有该属性时成立。
    属性过滤中的 @!x 表示条目不能有 x。"""
    seen = seen if seen is not None else set()
    for p, need in parents.get(name, []):
        ok = all((a[1:] not in attrs) if a.startswith("!") else (a in attrs) for a in need)
        if ok and p not in seen: seen.add(p); _ancestors(p, attrs, parents, seen)
    return seen

def lookup(host):
    """离线查询。返回 {block: [(名单说明, 命中的域)], owner: [清单名], categories: [...], ads_attr: bool}；没有名单时返回 None。"""
    idx = _index()
    if idx is None: return None
    sfx = _suffixes(host)
    block = []
    for s in sfx:
        for fn in idx["block"].get(s, []): block.append((SOURCES[fn][1], s))
    v2 = idx["v2fly"]; direct = []
    if host.lower() in v2["full"]: direct += [(n, a, host.lower()) for n, a in v2["full"][host.lower()]]
    for s in sfx:
        if s in v2["domain"]: direct += [(n, a, s) for n, a in v2["domain"][s]]; break   # 只取最具体的一级
    allnames = {n for n, _, _ in direct}
    for n, a, _ in direct: allnames |= _ancestors(n, a, v2["parents"])
    cats = sorted(n for n in allnames if n.startswith("category-") or n.startswith("geolocation-"))
    owners = sorted(n for n in allnames if not (n.startswith("category-") or n.startswith("geolocation-")))
    ads_attr = any("ads" in a for _, a, _ in direct) or any(n.startswith("category-ads") for n in allnames)
    return {"block": block, "owner": owners, "categories": cats, "ads_attr": ads_attr,
            "v2fly_match": sorted({f"{n}:{s}" for n, _, s in direct})}

def verdict(lk):
    """名单这一层自己的结论（只作一票，不自动执行）：命中任一拦截名单或 v2fly 标了广告 → 像广告/追踪；否则无结论。"""
    if not lk: return None
    if lk["block"] or lk["ads_attr"]: return "reject"
    return None

def describe(lk):
    if lk is None: return ["名单：尚未下载（update-lists）"]
    L = []
    if lk["block"]:
        by = {}
        for name, s in lk["block"]: by.setdefault(name, s)
        L.append("拦截名单命中：" + "；".join(f"{n}（{s}）" for n, s in by.items()))
    else: L.append("拦截名单：五份都没有收录")
    if lk["owner"] or lk["categories"]:
        L.append("v2fly 分类：" + "，".join(lk["owner"] + lk["categories"]) + ("（条目标了 @ads）" if lk["ads_attr"] else ""))
    else: L.append("v2fly 分类：没有收录")
    return L

# ---------------- 按需联网：RDAP、证书、搜索 ----------------
_LOCK = threading.Lock()
_SLD = {"com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn", "com.hk", "com.tw", "co.uk", "org.uk", "ac.uk",
        "co.jp", "ne.jp", "or.jp", "com.au", "net.au", "co.nz", "ac.nz", "com.br", "co.kr", "com.sg"}

def registrable(host):
    p = host.lower().split(".")
    return ".".join(p[-3:]) if len(p) >= 3 and ".".join(p[-2:]) in _SLD else ".".join(p[-2:])

def _read_cache():   # 读完立即关文件，否则 Windows 上别的线程替换缓存文件会「拒绝访问」（同 evidence._read）
    if not os.path.exists(CACHE): return {}
    with open(CACHE, encoding="utf-8") as f: return json.load(f)

def _cached(key, fn):
    with _LOCK: cache = _read_cache()
    c = cache.get(key)
    if c and (datetime.datetime.now() - datetime.datetime.fromisoformat(c["checked"])).days < CACHE_DAYS: return c["data"]
    data = fn()
    with _LOCK:
        cache = _read_cache()
        cache[key] = {"checked": datetime.datetime.now().isoformat(timespec="seconds"), "data": data}
        cr._atomic_write_text(CACHE, json.dumps(cache, ensure_ascii=False, indent=1))
    return data

def rdap(host):
    dom = registrable(host)
    def q():
        d = None; err = ""
        for px in (None, cr.local_proxy()):     # 先直连，失败回退本机代理（rdap.org 与各注册局未必被规则放行）
            try:
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": px, "https": px} if px else {}))
                req = urllib.request.Request("https://rdap.org/domain/" + dom, headers={"Accept": "application/rdap+json"})
                with opener.open(req, timeout=20) as r: d = json.load(r); break
            except Exception as e: err = f"{type(e).__name__}"
        if d is None: return {"domain": dom, "error": err}
        ev = {e.get("eventAction"): e.get("eventDate", "")[:10] for e in d.get("events", [])}
        ents = []
        for e in d.get("entities", []):
            vc = e.get("vcardArray", [None, []])[1]
            fn = next((x[3] for x in vc if x and x[0] in ("fn", "org") and x[3]), "")
            ents.append({"roles": e.get("roles", []), "name": fn})
        return {"domain": dom, "registered": ev.get("registration", ""), "expires": ev.get("expiration", ""),
                "registrar": next((e["name"] for e in ents if "registrar" in e["roles"]), ""),
                "registrant": next((e["name"] for e in ents if "registrant" in e["roles"]), "")}
    return _cached("rdap:" + dom, q)

def cert(host, ip=None):
    """取 TLS 证书（验证通过才记机构名）。ip 为空时直连解析；连不上返回 error。"""
    def q():
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((ip or host, 443), timeout=8) as s:
                with ctx.wrap_socket(s, server_hostname=host) as t: c = t.getpeercert()
        except Exception as e: return {"error": f"{type(e).__name__}"}
        get = lambda seq, k: next((v for rdn in seq for (kk, v) in rdn if kk == k), "")
        return {"subject_org": get(c.get("subject", ()), "organizationName"), "subject_cn": get(c.get("subject", ()), "commonName"),
                "issuer": get(c.get("issuer", ()), "organizationName"), "not_before": c.get("notBefore", "")}
    return _cached("cert:" + host, q)

SEARCH_SCHEMA = {"type": "object", "properties": {
    "summary": {"type": "string"},
    "sources": {"type": "array", "items": {"type": "object", "properties": {
        "url": {"type": "string"}, "title": {"type": "string"}, "date": {"type": "string"}, "says": {"type": "string"}},
        "required": ["url", "title", "date", "says"], "additionalProperties": False}},
    "found": {"type": "boolean"}}, "required": ["summary", "sources", "found"], "additionalProperties": False}

def search(host, model="haiku", timeout=240):
    """用本机 claude -p 带网页搜索找出处（优先厂商官方文档）。只按需调用。"""
    def q():
        import shutil, tempfile
        exe = shutil.which("claude") or os.path.expanduser(r"~\.local\bin\claude.exe")
        d = tempfile.mkdtemp(prefix="clash-review-search-")
        sysmsg = ("你是资料查找员。用网页搜索查这个主机名是谁的、做什么用。优先找厂商官方文档，其次是知名技术站点。"
                  "只写搜到的网页里确实写着的内容，每条出处写网址、标题、页面日期（看不出写空）和它说了什么。找不到就 found=false，不要推测。")
        cmd = [exe, "-p", f"主机名：{host}", "--model", model, "--system-prompt", sysmsg,
               "--exclude-dynamic-system-prompt-sections", "--tools", "WebSearch,WebFetch", "--allowed-tools", "WebSearch,WebFetch",
               "--setting-sources", "", "--no-session-persistence", "--output-format", "json", "--json-schema", json.dumps(SEARCH_SCHEMA)]
        try:
            p = subprocess.run(cmd, cwd=d, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, encoding="utf-8", errors="replace", creationflags=_NO_WINDOW)
            o = json.loads(p.stdout); r = o.get("structured_output") or {}
            r["cost_usd"] = o.get("total_cost_usd"); return r
        except Exception as e: return {"error": f"{type(e).__name__}: {e}"}
    return _cached(f"search:{model}:{host}", q)

if __name__ == "__main__":
    for h in sys.argv[1:]:
        lk = lookup(h); print(h, "→", verdict(lk)); print("  " + "\n  ".join(describe(lk)))
