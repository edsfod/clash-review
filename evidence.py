"""本机证据（第 1 层的一部分）：给一个主机收集本机能查到的事实，供模型判断与界面显示。

- 国内视角解析：用腾讯 DoH（1.12.12.12）解析，即直连时会连到的地址；再用 var/ipdata 的 ip2asn 数据查运营商与国家
- 直连实测：不经 Clash，用腾讯 DoH 解析后直接访问 https://<主机>/ 与 http://<主机>/，各记 HTTP 状态码（000 为连不上）。
  两个都要测：有的只走 HTTP（如 download.windowsupdate.com），只测 HTTPS 会误报「连不上」
- 同站归类：同一站点（最后两段）的其它主机在六个规则集里归了哪类

「可改直连」另测直连与代理的首字节时间（speed，见文件末尾）。
联网只有 DoH 查询与直连实测两项（加上「可改直连」的对比测速）。结果缓存到 var/evidence_cache.json（按主机，含查询时间），默认 7 天内不重查。
只用标准库，另调用系统自带的 curl。
"""
import datetime, json, os, subprocess, sys, threading, time, urllib.parse, urllib.request
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)   # 在 pythonw（没有控制台）下调 curl 等命令行程序，不加这个每次都会弹出一个 cmd 窗口

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import clash_review as cr

CACHE = os.path.join(cr.DATA_DIR, "evidence_cache.json")
MAX_AGE_DAYS = 7
_LOCK = threading.Lock()

def _read_nolock():
    if not os.path.exists(CACHE): return {}
    with open(CACHE, encoding="utf-8") as f: return json.load(f)

def _read():
    # 读完立即关文件：Windows 上文件开着时别的线程无法用 os.replace 替换它（2026-09-24 并发实测时报过「拒绝访问」）
    with _LOCK: return _read_nolock()

def _doh_cn(host):
    req = urllib.request.Request("https://1.12.12.12/dns-query?type=A&name=" + urllib.parse.quote(host),
                                 headers={"accept": "application/dns-json"})
    with urllib.request.urlopen(req, timeout=10) as r: d = json.load(r)
    if d.get("Status") == 3: return "NXDOMAIN"
    return [a["data"] for a in d.get("Answer", []) if a.get("type") == 1]

def direct_code(host, scheme="https"):
    args = ["curl", "-s", "-o", "NUL", "-m", "12", "-A", "Mozilla/5.0", "-w", "%{http_code}",
            "--noproxy", "*", "--doh-url", "https://1.12.12.12/dns-query", f"{scheme}://{host}/"]
    try: return subprocess.run(args, capture_output=True, text=True, timeout=20, creationflags=_NO_WINDOW).stdout.strip() or "000"
    except Exception: return "000"

def direct_test(host):
    return {"https": direct_code(host, "https"), "http": direct_code(host, "http")}

_TABLE = None
def _asn(ips):
    global _TABLE
    if _TABLE is None: _TABLE = cr.load_ip2asn() or False
    info = [cr.ip2asn_lookup(_TABLE, ip) for ip in ips] if _TABLE else []
    return sorted({f"{i['desc']}（AS{i['asn']}，{i['cc']}）" for i in info if i}), sorted({i["cc"] for i in info if i})

def snapshot():
    """整个缓存读一次，传给 collect / collect_speed 的 cache 参数：逐个主机只读缓存时不必每次重读整个文件
    （2026-09-26：「可改直连」812 个候选各读两次 140 KB 的缓存，刷新一次 3～5 秒）。"""
    return _read()

def collect(host, net=True, cache=None):
    """返回 {cn_ips, cn_asn, cn_cc, direct, checked}；net=False 时只读缓存。cache：snapshot() 的结果，不给就现读。"""
    cache = _read() if cache is None else cache
    c = cache.get(host)
    fresh = c and (datetime.datetime.now() - datetime.datetime.fromisoformat(c["checked"])).days < MAX_AGE_DAYS
    if c and not isinstance(c.get("direct"), dict): fresh = False      # 旧格式（只测了 HTTPS）重查
    if fresh or not net: return c
    ips = None
    for attempt in range(3):                                          # 并发查询时 DoH 偶尔失败，重试
        try: ips = _doh_cn(host); break
        except Exception as e: ips = f"ERR {type(e).__name__}"; time.sleep(1 + attempt)
    asn, cc = _asn(ips) if isinstance(ips, list) else ([], [])
    c = {"cn_ips": ips, "cn_asn": asn, "cn_cc": cc,
         "direct": direct_test(host) if isinstance(ips, list) and ips else {"https": "000", "http": "000"},
         "checked": datetime.datetime.now().isoformat(timespec="seconds")}
    if isinstance(ips, str) and ips.startswith("ERR"): return c      # 查询失败不写缓存，下次重查
    with _LOCK:   # 并发时重读再写
        cache = _read_nolock()
        if (cache.get(host) or {}).get("speed"): c["speed"] = cache[host]["speed"]   # 对比测速单独过期，重查证据时保留
        cache[host] = c
        cr._atomic_write_text(CACHE, json.dumps(cache, ensure_ascii=False, indent=1))
    return c

# ---------------- 直连与代理对比（「可改直连」用）----------------
# 同一个网址直连、走代理交替各测 SPEED_N 次首字节时间，取中位数。直连扣掉本机 DoH 解析（Clash 直连时解析有缓存）；
# 代理走 Clash 的 mixed-port，含 Clash 自己的解析与节点往返——就是现在实际走的那条路。
# 为什么不看握手时间或 ASN 登记国家：2026-09-24 实测 edge.microsoft.com 握手一次 292 ms，按阈值判成「节点较远」，
# 但首字节直连 0.2–0.6 s、代理 1.1–1.3 s，直连快得多；单次握手抖动也大（同一家的 x1 / x2.c.lencr.org 测出 264 与 56 ms）。
SPEED_N = 3

def _ttfb(url, proxy=None):
    args = ["curl", "-s", "-o", "NUL", "-m", "10", "-A", "Mozilla/5.0", "-w", "%{http_code} %{time_namelookup} %{time_starttransfer}"]
    args += ["-x", proxy] if proxy else ["--noproxy", "*", "--doh-url", "https://1.12.12.12/dns-query"]
    try: out = subprocess.run(args + [url], capture_output=True, text=True, timeout=15, creationflags=_NO_WINDOW).stdout.split()
    except Exception: return None
    try:
        if out[0] == "000" or float(out[2]) <= 0: return None
        return round((float(out[2]) - (0 if proxy else float(out[1]))) * 1000)
    except (IndexError, ValueError): return None

def speed(host, scheme, proxy):
    url = f"{scheme}://{host}/"; d, p = [], []
    for _ in range(SPEED_N):
        x = _ttfb(url); y = _ttfb(url, proxy)
        if x is not None: d.append(x)
        if y is not None: p.append(y)
    med = lambda v: sorted(v)[len(v) // 2] if v else None
    return {"scheme": scheme, "direct_ms": med(d), "proxy_ms": med(p), "direct_ok": len(d), "proxy_ok": len(p), "n": SPEED_N,
            "checked": datetime.datetime.now().isoformat(timespec="seconds")}

def collect_speed(host, scheme, proxy, net=True, cache=None):
    """对比测速结果，缓存在证据缓存该主机的 speed 字段，MAX_AGE_DAYS 内不重测；net=False 时只读缓存。cache 同 collect。"""
    cache = _read() if cache is None else cache
    s = (cache.get(host) or {}).get("speed")
    fresh = s and s.get("scheme") == scheme and (datetime.datetime.now() - datetime.datetime.fromisoformat(s["checked"])).days < MAX_AGE_DAYS
    if fresh or not net: return s if fresh else None
    s = speed(host, scheme, proxy)
    with _LOCK:
        cache = _read_nolock()
        if host in cache:                      # 只挂在已有证据的主机上（collect 先跑）；没有就不缓存
            cache[host]["speed"] = s
            cr._atomic_write_text(CACHE, json.dumps(cache, ensure_ascii=False, indent=1))
    return s

def same_site(host, payloads, exclude=()):
    """payloads: {cat: [条目...]}。返回同站其它条目的归类，如 ["api.x.com（代理）"]。"""
    site = cr.site_of(host); out = []
    for cat, ents in payloads.items():
        for e in ents:
            b = cr._dom_base(e)
            if b != host and b not in exclude and cr.site_of(b) == site:
                out.append(f"{b}（{cr.CAT_CN[cat]}）")
    return sorted(out)

def describe(ev):
    """证据转成给模型看的几行文字。"""
    if not ev: return []
    L = []
    ips = ev.get("cn_ips")
    if ips == "NXDOMAIN": L.append("国内视角解析：域名不存在")
    elif isinstance(ips, list) and ips:
        L.append(f"国内视角解析：{', '.join(ips[:3])}；{'；'.join(ev['cn_asn']) or '运营商未知'}")
    elif isinstance(ips, list): L.append("国内视角解析：没有 A 记录（这个名字本身不直接提供服务，常见于只有子域在用的父域）")
    else: L.append("国内视角解析：查询失败，没有结果")
    d = ev.get("direct") or {}
    if isinstance(ips, list) and ips:
        hs, hp = d.get("https", "000"), d.get("http", "000")
        if hs == "000" and hp == "000": L.append("直连实测：HTTPS 与 HTTP 都连不上")
        else: L.append("直连实测：可达（" + "，".join(f"{k.upper()} {'连不上' if v == '000' else '返回 ' + v}" for k, v in (("https", hs), ("http", hp))) + "）")
    s = ev.get("speed")
    if s:
        f = lambda ms: "连不上" if ms is None else f"{ms} ms"
        L.append(f"直连与代理对比（{s['scheme'].upper()} 首字节，各 {s['n']} 次取中位数）：直连 {f(s['direct_ms'])}，代理 {f(s['proxy_ms'])}")
    return L
