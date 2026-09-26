#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
clash_review —— Clash Verge (mihomo) 漏网审查工具（独立可运行，仅标准库）

从 mihomo 核心连接日志提取「命中最终 MATCH→REJECT 的漏网连接」，去重累计到待审清单
(pending.yaml)，审查后归类写入配置目录的 ruleset/my-*.yaml（域名）或 my-*-ip.yaml（IP 段）。

两类漏网：
  · 域名漏网：写 ruleset/my-{proxy,direct,reject}.yaml      (behavior: domain)
  · IP   漏网：写 ruleset/my-{proxy,direct,reject}-ip.yaml   (behavior: ipcidr)
            —— Telegram 等客户端按 IP 直连(无域名)，域名规则集匹配不到，必须按 IP 放行。

子命令：
  scan           增量扫描核心日志（只处理上次之后的新行），更新待审清单（域名+IP）与地域放行清单 routed.yaml，
                 向 scan.log 追加摘要（保留最近 500 行）；--baseline 只推进高水位不计数
  watch          常驻：经内核命名管道订阅实时日志流，每 --every 条（默认 200）连接日志落盘一次；
                 由计划任务在登录时启动。2.5.4 起 service 日志文件不可读，日常采集靠它
  list           打印待审清单（域名表 + IP 表；IP 自动标注 ASN/组织/国家/已知服务）
  routed         打印地域放行清单（被 GeoSite(cn)/GeoIP(CN)/geolocation-!cn 直接路由、进不了漏网审查的域名/IP）
  promote        归类：--proxy/--direct/--reject，逗号分隔；自动识别 IP/CIDR 与域名分别写入
  update-ipdata  （唯一联网命令）从 iptoasn.com 下载 IP→ASN 数据集到 var/ipdata/，供 list 离线标注

网页界面 clash_review_web.py（本地 127.0.0.1）提供三页：待审归类 / 地域放行（可疑排序与全表，一键拉黑）/
规则管理（查看·新增·删除·改分类六个 my-*.yaml，含 tidy 体检）。它调用本文件的同一套函数。

删除/改分类/写入均为原子写（先写临时文件再 os.replace），杜绝历史上因写入中断产生的截断损坏。

配置目录定位（优先级从高到低）：
  1) --config-dir PATH   2) 环境变量 CLASH_VERGE_DIR   3) settings.json 的 config_dir
  4) 脚本父目录          5) %APPDATA%\\io.github.clash-verge-rev.clash-verge-rev

设计：除 update-ipdata 外全程离线、仅标准库；只读核心日志，只写 var/ 下的 pending.yaml / routed.yaml /
scan.log / ipdata/，以及 my-*.yaml / my-*-ip.yaml。幂等可反复运行。归类后需在 Clash Verge【右键→重新激活】生效。
"""
import os, sys, re, glob, gzip, bisect, argparse, datetime, ipaddress, tempfile, json, hashlib, time, collections, threading, math
import urllib.request, urllib.parse, urllib.error

# ---------------- 设置与运行数据放在哪（web-kit 的 tooldirs）----------------
# 设置（settings.json、no_send.txt）在 %APPDATA%\clash-review\，运行数据在 %LOCALAPPDATA%\clash-review\；
# 工具目录里有 portable 文件时都在工具目录（数据在 var/）。代码与文档里说的「var/」都指数据目录 DATA_DIR。
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "web-kit"))      # 随本工具带的副本（来历见 vendor.json）
import tooldirs
CONF_DIR, DATA_DIR = tooldirs.dirs(HERE, "clash-review")

def var_dir(*sub):
    d=os.path.join(DATA_DIR, *sub)
    os.makedirs(d, exist_ok=True)
    return d

# ---------------- 配置目录定位 ----------------
def resolve_config_dir(cli_dir=None):
    cands = []
    if cli_dir: cands.append(cli_dir)
    if os.environ.get("CLASH_VERGE_DIR"): cands.append(os.environ["CLASH_VERGE_DIR"])
    if settings().get("config_dir"): cands.append(settings()["config_dir"])
    here = os.path.dirname(os.path.abspath(__file__))
    cands.append(os.path.dirname(here))
    appdata = os.environ.get("APPDATA")
    if appdata: cands.append(os.path.join(appdata, "io.github.clash-verge-rev.clash-verge-rev"))
    for d in cands:
        if d and os.path.isfile(os.path.join(d, "profiles.yaml")):
            return os.path.abspath(d)
    return os.path.dirname(here)

# ---------------- 使用者的设置（settings.json，可选）----------------
# 与本机、本人有关的东西不写死在代码里：能从 Clash 配置读到的就读（见下面 detect_layout），
# 读不到或要改的写在设置目录 CONF_DIR 的 settings.json 里（格式见 settings.example.json）。文件不在就全用自动检测。
SETTINGS = os.path.join(CONF_DIR, "settings.json")

def settings():
    try:
        with open(SETTINGS, encoding="utf-8") as f: d=json.load(f)
        return d if isinstance(d, dict) else {}
    except FileNotFoundError: return {}
    except (OSError, ValueError) as e:
        raise SystemExit(f"settings.json 读不了（{e}）：{SETTINGS}")

# ---------------- 规则集、代理组、内核管道（从 Clash 生成的 clash-verge.yaml 读）----------------
# 规则集的名字、先后顺序、代理组名因人而异，不写死。Clash Verge 每次激活配置都会把合并后的完整配置写到
# 配置目录的 clash-verge.yaml，其中：
#   rules:           - RULE-SET,<名字>,<去向>   去向 REJECT / REJECT-DROP → 拉黑，DIRECT → 直连，其它（代理组名）→ 代理
#                    - MATCH,<去向>             漏网审查的前提是它为 REJECT
#   rule-providers:  <名字>: behavior domain / ipcidr，type file / http，path 为文件（http 的是内核取来的本地缓存）
#   external-controller-pipe / mixed-port
# 写入的地方（收件箱）：每类（域名 / IP × 拉黑 / 直连 / 代理）取规则里第一个 type: file 的规则集。settings.json 的
# rulesets / proxy_group 可覆盖；两处都没有的按默认名 my-<类>[-ip] 猜，status 会报出来。
# 「已有规则」（漏网是否已覆盖、写入前的冗余与重叠、体检、回退域名是否放行）看规则里全部 domain / ipcidr 规则集，
# 按规则顺序：收件箱之外的（http 规则集、其它 file 规则集）只读不写，http 的读 path 处的本地缓存，读不到的跳过并提示。
CATS = ("reject", "direct", "proxy")
DEFAULT_NAMES = {"domain": {c: f"my-{c}" for c in CATS}, "ip": {c: f"my-{c}-ip" for c in CATS}}

def _yaml_scalar(v):
    v=v.split(" #")[0].strip()
    if len(v)>=2 and v[0]==v[-1] and v[0] in "'\"": v=v[1:-1]
    return v

def detect_layout(cfg):
    out={"sets":{"domain":{}, "ip":{}}, "order":{"domain":[], "ip":[]}, "proxy_group":None, "match":None,
         "pipe":None, "mixed_port":None, "found":False, "all":[]}
    try:
        with open(os.path.join(cfg, "clash-verge.yaml"), encoding="utf-8") as f: text=f.read()
    except OSError:
        return out
    out["found"]=True
    m=re.search(r"^external-controller-pipe:\s*(.+)$", text, re.M)
    if m: out["pipe"]=_yaml_scalar(m.group(1)) or None
    m=re.search(r"^mixed-port:\s*(\d+)", text, re.M)
    if m: out["mixed_port"]=int(m.group(1))
    provs={}; cur=None; sect=None; rules=[]
    for line in text.splitlines():
        if re.match(r"^[^\s-]", line):         # 顶层键；列表项（- …）在 Clash 的输出里也顶格写，不算
            sect=line.split(":", 1)[0].strip(); cur=None; continue
        if sect=="rule-providers":
            m=re.match(r"^  (['\"]?)([^\s'\":]+)\1:\s*$", line)
            if m: cur=provs.setdefault(m.group(2), {}); continue
            m=re.match(r"^    ([a-z-]+):\s*(.*)$", line)
            if m and cur is not None: cur[m.group(1)]=_yaml_scalar(m.group(2))
        elif sect=="rules":
            m=re.match(r"^\s*-\s*['\"]?([^'\"]+?)['\"]?\s*$", line)
            if m: rules.append([x.strip() for x in m.group(1).split(",")])
    for rank, r in enumerate(rules):
        if r[0].upper()=="MATCH" and len(r)>1: out["match"]=r[1]
        if r[0].upper()!="RULE-SET" or len(r)<3: continue
        name, target = r[1], r[2]
        p=provs.get(name) or {}
        kind={"domain":"domain", "ipcidr":"ip"}.get(p.get("behavior", "").lower())
        typ=p.get("type", "file").lower()
        if not kind or typ not in ("file", "http"): continue
        cat="reject" if target.upper() in ("REJECT", "REJECT-DROP") else "direct" if target.upper()=="DIRECT" else "proxy"
        path=p.get("path") or None
        if path and not os.path.isabs(path): path=os.path.normpath(os.path.join(cfg, path))
        out["all"].append({"name":name, "kind":kind, "cat":cat, "type":typ, "path":path, "url":p.get("url") or "", "proxy":p.get("proxy") or "",
                           "format":(p.get("format") or "yaml").lower(), "rank":rank})
        if typ!="file" or not path or cat in out["sets"][kind]: continue
        out["sets"][kind][cat]={"name":name, "path":path}
        out["order"][kind].append(cat)
        if cat=="proxy" and not out["proxy_group"]: out["proxy_group"]=target
    return out

LOCAL_PROXY = None      # Clash 的 mixed-port，建 Ctx 时读出；联网命令经代理回退时用

def local_proxy():
    return LOCAL_PROXY or "http://127.0.0.1:7897"

# ---------------- 日志行解析 ----------------
# 目标地址：域名 / IPv4 为 host:port，IPv6 为 [addr]:port
HOST_RE  = re.compile(r'-->\s*(?:\[([0-9A-Fa-f:.%]+)\]|([A-Za-z0-9_.-]+)):(\d+)')
MATCH_RE = re.compile(r'match\s+([A-Za-z0-9_-]+)', re.I)
USING_RE = re.compile(r'using\s+([A-Za-z0-9_.\-]+)', re.I)
DIAL_RE  = re.compile(r'dial\s+([A-Za-z0-9_.\-]+)', re.I)
IPV4_RE  = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
# 规则+出口一次抓取（含括号/叹号/点/连字符的规则名，如 GeoSite(geolocation-!cn)）。
# 出口 \S+ 可含中文与方括号（如「节点选择[US-LA-03]」）。用于「地域放行」发现。
RULE_USING_RE = re.compile(r'match\s+([A-Za-z0-9_()!.\-]+)\s+using\s+(\S+)', re.I)

def is_ipv4(h): return bool(IPV4_RE.match(h))
def is_ipv6(h):
    if ":" not in h: return False
    try: return ipaddress.ip_address(h.split("%")[0]).version==6
    except ValueError: return False
def is_ip(h): return is_ipv4(h) or is_ipv6(h)
def is_domain(h): return bool(h) and not is_ipv4(h) and "." in h and ":" not in h

def parse_host(line):
    """取连接日志的目标 (host, port)；不是连接行返回 None。"""
    m=HOST_RE.search(line)
    if not m: return None
    return (m.group(1) or m.group(2)), m.group(3)

def region_bucket(rule_token):
    """判断某条连接是否由「地域规则」直接路由；是则返回其去向桶，否则 None。
      · GeoSite(cn) / GeoIP(CN)      -> 'direct'（地域判为国内，直连）
      · GeoSite(geolocation-!cn)     -> 'proxy' （地域判为境外，走代理）
    自定义 RuleSet(...)、去广告 category-ads-all、兜底 Match 一律不计入（它们不是
    "被地域直接放行"，无需在此发现）。这些连接不会落到 MATCH,REJECT，故进不了 pending，
    本函数是让它们「进得了审查」的依据（见 scan 的地域放行采集）。"""
    t = rule_token.lower()
    if "ruleset(" in t: return None
    if "category-ads-all" in t: return None
    if "geolocation-!cn" in t: return "proxy"
    if "geosite(cn)" in t: return "direct"
    if "geoip(cn)" in t: return "direct"
    return None

# 不纳入审查的 IP（私有/保留/回环/组播/fake-ip 段等）
_SKIP_NETS = [ipaddress.ip_network(x) for x in
    ("0.0.0.0/8","10.0.0.0/8","100.64.0.0/10","127.0.0.0/8","169.254.0.0/16",
     "172.16.0.0/12","192.168.0.0/16","198.18.0.0/15","224.0.0.0/4","240.0.0.0/4")]
def skip_ip(ip):
    try: a = ipaddress.ip_address(ip)
    except ValueError: return True
    if a.is_private or a.is_loopback or a.is_reserved or a.is_multicast or a.is_link_local:
        return True
    return any(a in n for n in _SKIP_NETS)

# ---------------- 内置已知服务段（离线兜底标注；未下载 ip2asn 时也能识别要害服务）----------------
_BUILTIN = [
    ("Telegram",   ["149.154.160.0/20","91.108.0.0/16","91.105.192.0/23","185.76.151.0/24","95.161.64.0/20"]),
    ("Cloudflare", ["104.16.0.0/13","172.64.0.0/13","1.1.1.0/24","1.0.0.0/24"]),
    ("Google",     ["8.8.8.0/24","8.8.4.0/24","142.250.0.0/15","172.217.0.0/16","216.58.192.0/19"]),
    ("Akamai",     ["23.32.0.0/11","104.64.0.0/10"]),
    ("Fastly",     ["151.101.0.0/16"]),
]
_BUILTIN = [(name, [ipaddress.ip_network(c) for c in cidrs]) for name, cidrs in _BUILTIN]
def builtin_service(ip):
    try: a = ipaddress.ip_address(ip)
    except ValueError: return None, None
    for name, nets in _BUILTIN:
        for n in nets:
            if a in n: return name, n
    return None, None

# ---------------- 域名规则集 payload 读写（沿用旧逻辑，不依赖 pyyaml）----------------
def load_payload(path):
    items=[]
    if not os.path.exists(path): return items
    inpayload=False
    with open(path, encoding="utf-8") as f:
        for line in f:
            s=line.rstrip("\n")
            if re.match(r'^\s*payload\s*:', s): inpayload=True; continue
            if inpayload:
                m=re.match(r'\s*-\s*["\']?([^"\'#]+?)["\']?\s*$', s)
                if m: items.append(m.group(1).strip())
                elif s.strip() and not s.strip().startswith("#") and not s.startswith(" "):
                    inpayload=False
    return items

def norm_domain(domain):
    d=domain.lower().lstrip(".")
    return d if d.startswith("+.") else "+."+d

def domain_covered(domain, payload):
    d=domain.lower().lstrip(".").replace("+.","",1)
    for p in payload:
        base=p.lower().strip().replace("+.","",1)
        if p.strip().startswith("+."):
            if d==base or d.endswith("."+base): return True
        elif d==base:
            return True
    return False

# ---------------- IP 规则集 payload（ipcidr，纯 CIDR）----------------
def parse_net(tok):
    """把 IP / CIDR 解析为 ip_network；非法返回 None。'1.2.3.4' -> /32。"""
    try: return ipaddress.ip_network(tok.strip(), strict=False)
    except ValueError: return None

def is_ip_token(tok):
    return parse_net(tok) is not None

def ip_covered(tok, cidr_payload):
    net = parse_net(tok)
    if net is None: return False
    for c in cidr_payload:
        cn = parse_net(c)
        if cn is not None and net.version==cn.version and net.subnet_of(cn):
            return True
    return False

# ---------------- pending.yaml 读写（domains + ips 两段，自带去重）----------------
# 记录字段：count / first / last / ports，漏网项另有两个可选字段：
#   procs  发起连接的进程名（内核开启 find-process-mode 时日志才带，形如 "127.0.0.1:5(curl.exe) -->"）
#   ctx    该漏网连接前后各 CTX_K 条连接的目标主机，最多 CTX_MAX 个，用于判断「当时在访问什么网页」
def _new_rec(ts): return {"count":0,"first":ts,"last":ts,"ports":set(),"procs":set(),"ctx":[]}

def _list_field(line, key):
    m=re.search(key+r':\s*\[([^\]]*)\]', line)
    return None if m is None else [x.strip() for x in m.group(1).split(",") if x.strip()]

def load_pending(path):
    return _load_sections(path, ("domains","ips"))

def save_pending(path, data):
    # 原子写：watch 常驻后 scan 与 GUI/手动命令可能交错，不能留下半截文件
    txt=("# 漏网待审清单（自动去重累计）。审查后：python clash_review.py promote --proxy/--direct/--reject 目标\n"
         "# 目标可为域名或 IP/CIDR，promote 自动分流到 my-*.yaml 或 my-*-ip.yaml。\n"
         + _section_text("domains", data["domains"])
         + _section_text("ips",     data["ips"]))
    _atomic_write_text(path, txt)

# ---------------- routed.yaml：地域放行清单（direct + proxy 两段，供发现应拉黑的域名/IP）----------------
def _load_sections(path, sections):
    """通用小解析器（pending 与 routed 共用）：读取 path 中给定顶层 section，返回 {section:{host:rec}}。"""
    data={s:{} for s in sections}
    if not os.path.exists(path): return data
    secset=set(sections); section=None; cur=None
    with open(path, encoding="utf-8", errors="ignore") as f: lines=f.readlines()
    for line in lines:
        m0=re.match(r'^(\w+):\s*$', line)
        if m0 and m0.group(1) in secset:
            section=m0.group(1); cur=None; continue
        if section is None: continue
        m=re.match(r'^\s{2}(\S+):\s*$', line)
        if m:
            cur=m.group(1); data[section][cur]=_new_rec(""); continue
        if cur:
            rec=data[section][cur]
            for key,rx in (("count",r'count:\s*(\d+)'),("first",r'first:\s*"([^"]*)"'),("last",r'last:\s*"([^"]*)"')):
                mm=re.search(rx,line)
                if mm: rec[key]=int(mm.group(1)) if key=="count" else mm.group(1)
            for key in ("ports","procs"):
                v=_list_field(line, key)
                if v is not None: rec[key]=set(v)
            for key in ("ctx","sites"):
                v=_list_field(line, key)
                if v is not None: rec[key]=v
    return data

def load_routed(path):
    return _load_sections(path, ("direct","proxy"))

def _section_text(title, d):
    lines=[f"{title}:"]
    for k in sorted(d, key=lambda x:-d[x]["count"]):
        v=d[k]
        lines += [f"  {k}:", f"    count: {v['count']}", f"    first: \"{v['first']}\"",
                  f"    last: \"{v['last']}\"", f"    ports: [{','.join(sorted(v['ports']))}]"]
        if v.get("procs"): lines.append(f"    procs: [{','.join(sorted(v['procs']))}]")
        if v.get("ctx"):   lines.append(f"    ctx: [{','.join(v['ctx'])}]")
        if v.get("sites"): lines.append(f"    sites: [{','.join(v['sites'])}]")
    return "\n".join(lines)+"\n"

def save_routed(path, data):
    txt=("# 地域放行清单：命中「地域规则」被直接路由的连接（不会落到 MATCH,REJECT，故不进 pending）。\n"
         "# direct = GeoSite(cn)/GeoIP(CN) -> 直连；proxy = GeoSite(geolocation-!cn) -> 代理。\n"
         "# 用途：在此发现「本该拉黑」的广告/追踪域名或 IP（它们被地域规则放行、进不了漏网审查），一键归类。\n"
         + _section_text("direct", data["direct"])
         + _section_text("proxy",  data["proxy"]))
    _atomic_write_text(path, txt)

# ---------------- ip2asn 数据（var/ipdata/ 子文件夹；离线读，update-ipdata 才联网）----------------
IP2ASN_URL  = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"   # Frank Denis 维护，公有领域，逐时更新，非国内来源
IP2ASN_NAME = "ip2asn-v4.tsv.gz"

def ipdata_dir():
    return var_dir("ipdata")

def load_ip2asn():
    path=os.path.join(ipdata_dir(), IP2ASN_NAME)
    if not os.path.exists(path): return None
    starts=[]; rows=[]
    try:
        with gzip.open(path, "rt", encoding="utf-8", errors="ignore") as f:
            for line in f:
                p=line.rstrip("\n").split("\t")
                if len(p)<5: continue
                try:
                    s=int(ipaddress.ip_address(p[0])); e=int(ipaddress.ip_address(p[1]))
                except ValueError: continue
                starts.append(s); rows.append((e, p[2], p[3], p[4]))
    except OSError:
        return None
    return (starts, rows)

def ip2asn_lookup(table, ip):
    if not table: return None
    starts, rows = table
    try: x=int(ipaddress.ip_address(ip))
    except ValueError: return None
    i=bisect.bisect_right(starts, x)-1
    if i<0: return None
    end, asn, cc, desc = rows[i]
    if x>end: return None
    if asn in ("0","",None) and desc in ("Not routed","",None): return None
    return {"asn":asn, "cc":cc, "desc":desc}

def enrich_ip(ip, table):
    svc, net = builtin_service(ip)
    info = ip2asn_lookup(table, ip)
    bits=[]
    if svc:  bits.append(svc)
    if info:
        a = f"AS{info['asn']} {info['desc']}".strip()
        cc = info.get("cc") or ""
        bits.append(a + (f" [{cc}]" if cc and cc!="None" else ""))
    if not bits:
        return "—（未识别；下载 ip2asn 后更全：update-ipdata）" if table is None else "—"
    return " · ".join(bits)

# ---------------- 上下文 ----------------
class Ctx:
    def __init__(self, cfg):
        self.cfg=cfg
        self.logdirs=[os.path.join(cfg,"logs","service"), os.path.join(cfg,"logs","sidecar")]
        self.ruleset=os.path.join(cfg,"ruleset")
        self.review=var_dir()
        self.pending=os.path.join(self.review,"pending.yaml")
        self.routed=os.path.join(self.review,"routed.yaml")
        self.scanlog=os.path.join(self.review,"scan.log")
        self.state=os.path.join(self.review,"scan_state.json")
        # 六个规则集：先按 Clash 配置检测，再用 settings.json 覆盖，都没有的按默认名猜（guessed 里记下，status 报）
        st=settings(); lay=detect_layout(cfg); self.layout=lay
        self.names={"domain":{}, "ip":{}}; files={"domain":{}, "ip":{}}; self.guessed=[]
        for kind in ("domain", "ip"):
            over=(st.get("rulesets") or {}).get(kind) or {}
            for cat in CATS:
                if over.get(cat):
                    name=over[cat]; path=os.path.join(self.ruleset, name+".yaml")
                elif cat in lay["sets"][kind]:
                    name=lay["sets"][kind][cat]["name"]; path=lay["sets"][kind][cat]["path"]
                else:
                    name=DEFAULT_NAMES[kind][cat]; path=os.path.join(self.ruleset, name+".yaml"); self.guessed.append(name)
                self.names[kind][cat]=name; files[kind][cat]=path
        # 绝对路径：os.path.join(ctx.ruleset, 绝对路径) 仍得到该绝对路径，沿用各处的写法
        self.dom_files=files["domain"]; self.ip_files=files["ip"]
        # 先后顺序（同一目标落在多类时谁生效）：按规则里的顺序，检测不全时退回 拉黑 → 直连 → 代理
        self.order={k: (tuple(lay["order"][k]) if len(lay["order"][k])==3 else CAT_ORDER) for k in ("domain", "ip")}
        self.proxy_group=st.get("proxy_group") or lay["proxy_group"]
        # 全部规则集（收件箱 + 只读的 http / 其它 file 规则集），按规则顺序
        self.sets=self._all_sets(lay); self.unreadable={}
        # 目的地：settings.json 有 destination 时，归类决定写进规则服务（见下文「目的地」一节），否则写收件箱
        self.dest=Destination(st["destination"], self) if st.get("destination") else None
        global LOCAL_PROXY, PIPE_HINT
        LOCAL_PROXY=f"http://127.0.0.1:{lay['mixed_port']}" if lay["mixed_port"] else None
        PIPE_HINT=lay["pipe"]

    def _all_sets(self, lay):
        """[{name, kind, cat, type, path, format, rank, inbox}]，按 rank（规则里的位置）排序。
        收件箱在规则里找全了就用规则里的位置；找不全（按默认名猜的、settings.json 指定的）就按 self.order 排在最前，与只看收件箱时的先后一致。"""
        inbox={(k, c): (self.names[k][c], (self.dom_files if k=="domain" else self.ip_files)[c]) for k in ("domain", "ip") for c in CATS}
        out=[]; seen=set()
        for s in lay["all"]:
            if s["name"] in seen: continue       # 同一规则集在规则里出现多次，以第一次为准
            seen.add(s["name"])
            mine=inbox[(s["kind"], s["cat"])][0]==s["name"]
            out.append(dict(s, inbox=mine, path=inbox[(s["kind"], s["cat"])][1] if mine else s["path"]))
        for kind in ("domain", "ip"):
            if sum(1 for s in out if s["inbox"] and s["kind"]==kind)==len(CATS): continue
            out=[s for s in out if not (s["inbox"] and s["kind"]==kind)]
            for i, cat in enumerate(self.order[kind]):
                name, path = inbox[(kind, cat)]
                out=[s for s in out if s["name"]!=name]
                out.append({"name":name, "kind":kind, "cat":cat, "type":"file", "path":path, "format":"yaml",
                            "rank":-len(CATS)+i, "inbox":True})
        return sorted(out, key=lambda s: s["rank"])

    def sets_of(self, kind, cat=None):
        return [s for s in self.sets if s["kind"]==kind and (cat is None or s["cat"]==cat)]

    def payloads(self, kind, cat=None):
        """[(规则集, 条目)]，按规则顺序，占位已去掉。只读规则集读不到的记进 self.unreadable（名字 → 原因）并跳过。"""
        out=[]
        for s in self.sets_of(kind, cat):
            got=self.dest.items_for(s) if self.dest else None     # 规则服务的规则集：用写入接口取来的条目
            items, err = got if got is not None else read_set(s)
            if err and not s["inbox"]: self.unreadable[s["name"]]=err; continue
            self.unreadable.pop(s["name"], None)      # 网页与 watch 常驻：缓存后来有了就不再提示
            out.append((s, items))
        return out

    def entries(self, kind, cat):
        """某一类在全部规则集里的条目（收件箱在内），占位已去掉。"""
        return [p for _, items in self.payloads(kind, cat) for p in items]

    def unreadable_note(self, kind=None):
        bad=[f"{n}（{why}）" for n, why in self.unreadable.items() if kind is None or any(s["name"]==n and s["kind"]==kind for s in self.sets)]
        return "这些规则集读不到，没算进去：" + "；".join(bad) if bad else None

def read_set(s):
    """读一个规则集的条目，去掉占位。返回 (条目, 读不到的原因或 None)。收件箱文件不在时返回空表（与旧版一致，写入时新建）。"""
    path=s.get("path")
    if not path: return [], "profile 里没写 path，找不到本地缓存"
    if not os.path.exists(path):
        return [], (f"文件不在：{path}" if s["type"]=="file" else f"本地缓存不在：{path}")
    fmt=s.get("format") or "yaml"
    if fmt not in ("yaml", "text"): return [], f"{fmt} 格式读不了"
    try:
        if fmt=="yaml": items=load_payload(path)
        else:
            with open(path, encoding="utf-8") as f:
                items=[l.strip() for l in f if l.strip() and not l.lstrip().startswith("#")]
    except (OSError, UnicodeDecodeError) as e:
        return [], f"读不了：{e}"
    return strip_placeholder(items, s["kind"]), None

def strip_placeholder(items, kind):
    if kind=="domain": return [p for p in items if p!=DOMAIN_PLACEHOLDER]
    ph=ipaddress.ip_network(IP_PLACEHOLDER)
    return [p for p in items if not ((n:=parse_net(p)) is not None and n.version==ph.version and n.subnet_of(ph))]

def first_match(ctx, kind, host):
    """按规则顺序，第一个覆盖 host 的规则集与条目：(规则集, 条目)；都不覆盖返回 (None, None)。"""
    for s, items in ctx.payloads(kind):
        for p in items:
            if (domain_covered(host, [p]) if kind=="domain" else ip_covered(host, [p])): return s, p
    return None, None

# ---------------- 数据锁（watch 落盘与网页/命令的「读-改-写」互斥）----------------
# pending.yaml / routed.yaml 都是整文件重写：watch 落盘和网页归类若交错，后写者会把前者的改动覆盖掉。
class data_lock:
    def __init__(self, ctx, timeout=10.0, name="data.lock"):
        self.path=os.path.join(ctx.review, name); self.timeout=timeout; self.f=None
    def __enter__(self):
        try:
            import msvcrt
        except ImportError:
            return self
        self.f=open(self.path, "a")
        end=time.time()+self.timeout
        while True:
            try:
                self.f.seek(0); msvcrt.locking(self.f.fileno(), msvcrt.LK_NBLCK, 1); return self
            except OSError:
                if time.time()>end: self.f.close(); self.f=None; raise TimeoutError("数据锁超时（watch 正在落盘？）")
                time.sleep(0.05)
    def __exit__(self, *exc):
        if self.f is not None:
            import msvcrt
            try: self.f.seek(0); msvcrt.locking(self.f.fileno(), msvcrt.LK_UNLCK, 1)
            finally: self.f.close()

# ---------------- 目的地：规则服务（写入接口）----------------
# 归类决定默认写本机文件（收件箱）。settings.json 里有 destination 时，改为经写入接口直接写进规则服务的线上正本
# （协议见 docs/destinations.md 第三节）：
#   {"endpoint": "https://…/api/v1", "key_file": "写入密钥文件", "admin_url": "管理页（可选，规则页给链接）",
#    "rulesets": {"domain": {"reject": "<id>", "direct": "<id>", "proxy": "<id>"}, "ip": {…}}}
# 写入前的检查（冗余、重叠、写法）由服务端做，提示原样显示。服务端的条目经 GET /rulesets?entries=1 取来，缓存在
# var/destination.json，作为 Clash 里对应 http 规则集（网址以服务端给的 path 结尾）的「已有规则」。
# 已提交的决定也记在那里；上线后（GET /deployments/<提交>）让内核立即重新取对应的规则集，不用等它的更新间隔。
DEST_TTL = 600          # 秒：服务端条目的缓存多久重取一次（watch 每次落盘都读）
DEST_GIVE_UP = 1800     # 秒：提交后这么久仍未上线，不再等
DEST_KEEP = 86400       # 秒：已结束的提交记录保留多久（status 里看得到）
DEST_DIRECT_TIMEOUT = 8 # 秒：直连最多等这么久，再改经本机代理（先后见 Destination.routes）

class DestError(Exception):
    """写到规则服务失败。消息给人看；待审里的条目不动。"""

class Destination:
    def __init__(self, conf, ctx):
        if not isinstance(conf, dict) or not conf.get("endpoint"):
            raise SystemExit("settings.json 的 destination 要写 endpoint（规则服务的写入接口地址）")
        self.ctx=ctx; self.endpoint=conf["endpoint"].rstrip("/"); self.key_file=conf.get("key_file") or ""
        self.rulesets=conf.get("rulesets") or {}; self.admin_url=conf.get("admin_url") or ""
        self.path=os.path.join(ctx.review, "destination.json")
        self.retry_at=0.0; self.last_error=""

    # -- 状态文件：{"snapshot": {time, head, expires, sets: [{id, path, version, behavior, entries}]}, "submitted": [...]} --
    def load(self):
        try:
            with open(self.path, encoding="utf-8") as f: d=json.load(f)
        except (OSError, ValueError): d={}
        d.pop("route", None); d.setdefault("snapshot", None); d.setdefault("submitted", [])     # route：v1.2.0 记过线路，已不用
        return d

    def update(self, fn):
        with data_lock(self.ctx, name="destination.lock"):
            d=self.load(); fn(d); _atomic_write_text(self.path, json.dumps(d, ensure_ascii=False, indent=1))

    def key(self):
        p=os.path.expandvars(os.path.expanduser(self.key_file)) if self.key_file else ""
        if not p: raise DestError("settings.json 的 destination 没写 key_file（写入密钥文件）")
        try:
            with open(p, encoding="utf-8") as f: k=f.read().strip()
        except OSError as e: raise DestError(f"写入密钥文件读不了：{e}")
        if not k: raise DestError(f"写入密钥文件是空的：{p}")
        return k

    def routes(self):
        """先走哪条线路。Clash 里对应这个服务的 http 规则集写了 proxy（内核自己也经代理组取它），就先经本机代理；
        否则先直连。不按「上次成功」记：直连 pages.dev 这类地址有时 0.2 秒、有时 40 秒才回，成功一次不代表能用（2026-09-26）。"""
        host=urllib.parse.urlsplit(self.endpoint).hostname
        via=any(s.get("proxy") and s["proxy"].upper()!="DIRECT" for s in self.ctx.sets
                if s.get("url") and urllib.parse.urlsplit(s["url"]).hostname==host)
        return ["proxy", "direct"] if via else ["direct", "proxy"]

    def call(self, method, path, body=None, timeout=30):
        """(状态码, 响应头, JSON 或 None)。按 routes() 的顺序试，直连最多等 DEST_DIRECT_TIMEOUT 秒。"""
        data=json.dumps(body).encode() if body is not None else None
        hdr={"Authorization": f"Bearer {self.key()}", "User-Agent": "clash-review", "Accept": "application/json"}
        if data is not None: hdr["Content-Type"]="application/json"
        errs=[]
        for r in self.routes():
            px={} if r=="direct" else {"http": local_proxy(), "https": local_proxy()}
            opener=urllib.request.build_opener(urllib.request.ProxyHandler(px))
            req=urllib.request.Request(self.endpoint+path, data=data, method=method, headers=hdr)
            try:
                with opener.open(req, timeout=DEST_DIRECT_TIMEOUT if r=="direct" else timeout) as res:
                    status, headers, raw = res.status, res.headers, res.read()
            except urllib.error.HTTPError as e:
                status, headers, raw = e.code, e.headers, e.read()
            except OSError as e:          # URLError、超时、连接被拒都是 OSError
                errs.append(f"{'直连' if r=='direct' else '经代理'}：{getattr(e, 'reason', e)}"); continue
            try: js=json.loads(raw.decode("utf-8")) if raw else None
            except ValueError: js=None
            return status, headers, js
        raise DestError("连不上规则服务（" + "；".join(errs) + "）")

    def target(self, kind, cat):
        rid=(self.rulesets.get(kind) or {}).get(cat)
        if not rid:
            raise DestError(f"settings.json 的 destination.rulesets 没有指定{CAT_CN[cat]}{'IP' if kind=='ip' else '域名'}写进哪个规则集")
        return rid

    def snapshot(self, max_age=DEST_TTL):
        """服务端全部规则集（带条目）。缓存没过期就用缓存；取不到时用旧缓存（没有就是 None），旧缓存里记下原因。"""
        snap=self.load()["snapshot"]
        if snap and time.time()-snap.get("time", 0) < max_age: return snap
        if max_age and time.time()<self.retry_at: return snap and dict(snap, stale=self.last_error)
        try:
            status, headers, js = self.call("GET", "/rulesets?entries=1")
            if status!=200 or not isinstance(js, list):
                raise DestError(f"读取规则集失败（HTTP {status}）：{(js or {}).get('detail', '') if isinstance(js, dict) else ''}")
        except DestError as e:
            # 取不到时两分钟内不再试：payloads 调用很频繁，断网时每次都等超时，网页和 watch 会被拖住
            self.retry_at=time.time()+120; self.last_error=str(e)
            return snap and dict(snap, stale=str(e))
        snap={"time": time.time(), "head": headers.get("x-head", ""), "expires": headers.get("x-credential-expires", ""),
              "sets": [{k: s.get(k) for k in ("id", "path", "version", "behavior", "entries", "layer", "category")} for s in js]}
        self.update(lambda d: d.update(snapshot=snap))
        return snap

    @staticmethod
    def match(url, snap):
        """Clash 里一个 http 规则集的网址对应服务端的哪个规则集：网址（去掉查询串）以 /<path> 结尾。"""
        if not url or not snap: return None
        u=url.split("#")[0].split("?")[0]
        return next((x for x in snap["sets"] if x.get("path") and u.endswith("/"+x["path"])), None)

    def items_for(self, s):
        """Ctx.payloads 用：这个规则集若属于规则服务，返回 (条目, None)；不属于返回 None，照旧读本地。"""
        if s.get("type")!="http" or not s.get("url"): return None
        m=self.match(s["url"], self.snapshot())
        return None if m is None else (strip_placeholder(list(m.get("entries") or []), s["kind"]), None)

    def write(self, adds):
        """adds: [(kind, cat, 条目)]，一批提交（只加，不带 base：只加不改，不怕别处的改动）。
        返回 (提交号或 None, {(kind, cat): 真正新增的条目}, 服务端提示)。失败抛 DestError。"""
        ops=[{"op": "add", "ruleset": self.target(k, c), "entry": e} for k, c, e in adds]
        if not ops: return None, {}, []
        commit, results, notes = self.change(ops)
        done={}
        for (k, c, e), r in zip(adds, results):
            if r.get("result")=="done": done.setdefault((k, c), []).append(e)
        return commit, done, notes

    def change(self, ops, base=None):
        """一批改动（op 为 add / remove），整批原子。base（{规则集: version}）给了就先核对版本，期间被别处改过返回 409。
        成功后把改动与新版本直接写进缓存（马上算作「已有规则」，不为此再读一次服务端），并记下提交等它上线。
        返回 (提交号或 None, 逐条结果, 服务端提示)。失败抛 DestError；409 时先重取缓存。"""
        status, _, js = self.call("POST", "/changes", {"ops": ops, **({"base": base} if base else {})})
        js=js if isinstance(js, dict) else {}
        if status==401: raise DestError("规则服务说写入密钥不对")
        if status==422: raise DestError("规则服务拒绝了这批改动：" + "；".join(js.get("errors") or [js.get("detail", "")]))
        if status==409:
            self.snapshot(0)
            raise DestError("规则服务上的规则期间被别处改过，已重新读取，请再操作一次")
        if status not in (200, 202): raise DestError(f"写入失败（HTTP {status}）：{js.get('detail', '')}")
        commit=js.get("commit"); versions=js.get("versions") or {}; results=js.get("results") or []
        done=[(r["ruleset"], r["op"], r["entry"]) for r in results if r.get("result")=="done"]
        rec={"commit": commit, "time": time.time(), "rulesets": sorted({o["ruleset"] for o in ops}),
             "entries": [o["entry"] for o in ops], "state": "pending"}
        def apply(d):
            # 缓存的时间不变，到期照常重取服务端的真实内容
            for x in (d["snapshot"] or {}).get("sets", []):
                es=list(x.get("entries") or [])
                for rid, op, e in done:
                    if rid!=x["id"]: continue
                    if op=="add" and e not in es: es.append(e)
                    elif op=="remove": es=[v for v in es if v!=e]
                x["entries"]=es
                if versions.get(x["id"]): x["version"]=versions[x["id"]]
            if commit: d["submitted"].append(rec)
        self.update(apply)
        return commit, results, list(js.get("notes") or [])

    def pending(self):
        return [r for r in self.load()["submitted"] if r["state"]=="pending"]

    def settle(self):
        """查已提交的决定上线没有；上线的让内核立即重新取对应的规则集。返回这次状态有变化的记录。"""
        now=time.time(); changed=[]
        for rec in self.pending():
            rec=dict(rec)
            if now-rec["time"]>DEST_GIVE_UP: rec["state"]="timeout"; changed.append(rec); continue
            try: status, _, js = self.call("GET", f"/deployments/{rec['commit']}")
            except DestError: continue
            st=(js or {}).get("state") if isinstance(js, dict) else None
            if status!=200 or st not in ("live", "failed"): continue
            rec["state"]=st; rec["run"]=js.get("run", "")
            if st=="live": rec["kernel"]=self.refresh_kernel(rec["rulesets"])
            changed.append(rec)
        if changed:
            by={r["commit"]: r for r in changed}
            def apply(d):
                merged=[by.get(r["commit"], r) for r in d["submitted"]]
                d["submitted"]=[r for r in merged if r["state"]=="pending" or now-r["time"]<DEST_KEEP]
            self.update(apply)
        return changed

    def refresh_kernel(self, ids):
        """让内核重新取 Clash 配置里对应这些规则集的 http 规则集，再核对条目数。返回一句说明。"""
        snap=self.snapshot(0)
        pairs=[(s["name"], m) for s in self.ctx.sets
               if s["type"]=="http" and (m:=self.match(s.get("url"), snap)) is not None and m["id"] in ids]
        if not pairs: return "Clash 配置里没有对应的规则集，内核会按自己的间隔取到"
        try:
            for name, _ in pairs:
                code=pipe_request("PUT", f"/providers/rules/{urllib.parse.quote(name)}")
                if code not in (200, 204): return f"让内核重新取 {name} 失败：HTTP {code}"
            provs=pipe_get("/providers/rules").get("providers", {})
        except Exception as e:
            return f"没能让内核重新取（{e}）；内核会按自己的间隔取到"
        diff=[f"{n} 内核 {provs.get(n, {}).get('ruleCount')} 条、服务端 {max(1, len(m.get('entries') or []))} 条"
              for n, m in pairs if provs.get(n, {}).get("ruleCount")!=max(1, len(m.get("entries") or []))]
        return ("内核已重新取，但条目数不符：" + "；".join(diff)) if diff else f"内核已重新取 {len(pairs)} 个规则集，条目数一致"

def dest_editor(ctx):
    """规则页（规则服务目的地）：服务端能写的全部规则集，带条目。这台电脑的 Clash 用到的排在前面（按规则顺序），
    类别取 Clash 里那一行的去向；没用到的取服务端给的 category（协议之外的附加字段，没有就不能改类）。
    moves：改到别的类时写进哪个规则集（同层、同为域名或 IP）；layers：换到别的层时写进哪个规则集（服务端给了 layer 才有）。"""
    snap=ctx.dest.snapshot(0)                     # 编辑要最新的条目与版本
    if not snap or snap.get("stale"): raise DestError((snap or {}).get("stale") or ctx.dest.last_error or "读不到规则服务上的规则集")
    used={}
    for s in ctx.sets:
        m=Destination.match(s.get("url"), snap) if s["type"]=="http" else None
        if m and m["id"] not in used: used[m["id"]]=s
    out=[]
    for i, x in enumerate(snap["sets"]):
        u=used.get(x["id"])
        out.append({"name": x["id"], "kind": "ip" if x.get("behavior")=="ipcidr" else "domain",
                    "cat": u["cat"] if u else (x.get("category") if x.get("category") in CAT_ORDER else None),
                    "layer": x.get("layer") or "", "entries": list(x.get("entries") or []),
                    "used": bool(u), "clash": u["name"] if u else "", "order": u["rank"] if u else 10**6+i})
    for o in out:
        o["moves"]={c: t["name"] for c in CAT_ORDER if o["cat"] and c!=o["cat"]
                    for t in out if t["kind"]==o["kind"] and t["cat"]==c and t["layer"]==o["layer"]}
        o["layers"]={t["layer"]: t["name"] for t in out if o["layer"] and t["layer"] and t["layer"]!=o["layer"]
                     and t["kind"]==o["kind"] and t["cat"]==o["cat"]}
    return sorted(out, key=lambda o: o["order"])

def dest_edit(ctx, op, rid, entry, to=None, exact=False):
    """规则页在规则服务上的改动。op：add（新增到 rid）、delete（从 rid 删）、move（从 rid 移到 to）。
    exact：新增时按原样写（撤销删除时用），否则同收件箱：域名加 +.，单个 IP 写成 /32。
    改动与删除带上版本号，期间别处改过就报错（缓存已重取）。返回 (新增条目, 提示)。失败抛 DestError。"""
    snap=ctx.dest.snapshot()
    sets={x["id"]: x for x in (snap or {}).get("sets", [])}
    if rid not in sets or (to is not None and to not in sets): raise DestError("规则服务上没有这个规则集（刷新后再试）")
    notes=[]
    if op=="add":
        kind="ip" if sets[rid].get("behavior")=="ipcidr" else "domain"
        e=entry.strip() if exact else _dest_form(kind, entry, notes)
        if not e: raise DestError(f"{entry} 不是{'IP 或 CIDR' if kind=='ip' else '域名'}")
        commit, results, server = ctx.dest.change([{"op": "add", "ruleset": rid, "entry": e}])
    else:
        if entry not in (sets[rid].get("entries") or []): raise DestError("条目不存在（可能已被改动，刷新后再试）")
        ops=[{"op": "remove", "ruleset": rid, "entry": entry}] + ([{"op": "add", "ruleset": to, "entry": entry}] if op=="move" else [])
        commit, results, server = ctx.dest.change(ops, {i: sets[i].get("version") for i in {o["ruleset"] for o in ops}})
    notes+=server
    notes.append(f"已提交到规则服务（{commit[:7]}），上线后自动让 Clash 重新取，一般一两分钟" if commit else "没有变化")
    return [r["entry"] for r in results if r.get("op")=="add" and r.get("result")=="done"], notes

def dest_settler(ctx, stop, every=15):
    """常驻进程（watch、网页）里的后台线程：有已提交未上线的决定时，每隔一会儿查一次。"""
    while not stop.wait(every):
        try:
            if ctx.dest and ctx.dest.pending():
                for r in ctx.dest.settle():
                    _append_scanlog(ctx, f"destination {r['commit'][:7]} {r['state']}" + (f": {r.get('kernel')}" if r.get("kernel") else ""))
        except Exception as e:
            _append_scanlog(ctx, f"destination settle error: {type(e).__name__}: {e}")

# ---------------- 增量状态（var/scan_state.json，仅 scan 读文件时用）----------------
# 核心日志文件每行以 "[YYYY-MM-DD HH:MM:SS.mmm]" 开头。以已处理的最大行首时间戳为高水位，
# 只处理其后的行 —— 轮转时 *_latest.log 会被改名，按文件名记账会重读同一批内容。
# 与高水位同一毫秒的行记其摘要，避免边界上重复或遗漏。
SCANLOG_KEEP = 500   # scan.log 只保留最近这么多行

def load_state(ctx):
    try:
        with open(ctx.state, encoding="utf-8") as f: return json.load(f)
    except (OSError, ValueError):
        return {"watermark":"", "at_mark":[]}

def save_state(ctx, st):
    _atomic_write_text(ctx.state, json.dumps(st, ensure_ascii=False, indent=1))

def _line_ts(line):
    return line[1:24] if line.startswith("[") and line[24:25]=="]" else None

def _line_key(line):
    return hashlib.md5(line.rstrip("\r\n").encode("utf-8","ignore")).hexdigest()[:16]

def list_logs(ctx):
    logs=[]
    for d in ctx.logdirs: logs+=sorted(glob.glob(os.path.join(d,"*.log")))
    return logs

def _append_scanlog(ctx, text):
    lines=[]
    if os.path.exists(ctx.scanlog):
        with open(ctx.scanlog, encoding="utf-8", errors="ignore") as f: lines=f.read().splitlines()
    lines.append(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {text}")
    _atomic_write_text(ctx.scanlog, "\n".join(lines[-SCANLOG_KEEP:])+"\n")

# ---------------- 单行归类（scan 与 watch 共用）----------------
def load_classified(ctx):
    """全部规则集（收件箱与只读的 http 等）里的域名与 IP 条目：已被覆盖的主机不进待审与地域放行。"""
    dom=[p for _, items in ctx.payloads("domain") for p in items]
    ip =[p for _, items in ctx.payloads("ip") for p in items]
    return dom, ip

def _bump(rec_map, key, ts, port):
    new = key not in rec_map
    if new: rec_map[key]=_new_rec(ts)
    rec_map[key]["count"]+=1; rec_map[key]["last"]=ts; rec_map[key]["ports"].add(port)
    return new

def classify_line(line, ts, pending, routed, dom_classified, ip_classified):
    """把一条连接日志计入 pending（漏网）或 routed（地域放行）。
    返回 (kind, is_new)：kind 为 'domain'/'ip'（漏网）、'routed' 或 None。"""
    hp=parse_host(line)
    if not hp: return None, False
    host,port=hp
    # ---- 漏网 (最终 MATCH -> REJECT)：口径与原实现一致 ----
    if "REJECT" in line:
        mm=MATCH_RE.search(line); rule=mm.group(1) if mm else ""
        um=USING_RE.search(line); dm=DIAL_RE.search(line)
        outp=um.group(1) if um else (dm.group(1) if dm else "")
        if outp.upper()=="REJECT" and (not rule or rule.upper()=="MATCH"):
            if is_domain(host):
                if domain_covered(host, dom_classified): return None, False
                return "domain", _bump(pending["domains"], host, ts, port)
            if is_ip(host):
                if skip_ip(host) or ip_covered(host, ip_classified): return None, False
                return "ip", _bump(pending["ips"], host, ts, port)
            return None, False
    # ---- 地域放行发现：被 GeoSite(cn)/GeoIP(CN)/geolocation-!cn 直接路由的连接 ----
    # 内核自身的连接（DoH 等，日志为 "mihomo --> ..."）不是用户流量，不计入
    if SELF_RE.search(line): return None, False
    ru=RULE_USING_RE.search(line)
    if not ru: return None, False
    bucket=region_bucket(ru.group(1))
    if not bucket: return None, False
    if is_domain(host):
        if domain_covered(host, dom_classified): return None, False   # 已在自定义规则里就不再提示
    elif is_ip(host):
        if skip_ip(host) or ip_covered(host, ip_classified): return None, False
    else:
        return None, False
    _bump(routed[bucket], host, ts, port)
    return "routed", False

# ---------------- 漏网项的上下文：进程名 + 前后连接 ----------------
# 审查时要回答「当时在访问什么网页、用什么软件」（见 notes/clash-review-域名评估提示词.md）。
# 同一次页面加载带出的连接在日志里是相邻的，故按连接顺序取前后各 CTX_K 条（按条数，不按时间）。
CTX_K   = 8
CTX_MAX = 12
PROC_RE = re.compile(r'\(([^()]+)\)\s*-->')       # "127.0.0.1:5(curl.exe) -->"
SELF_RE = re.compile(r'\]\s+mihomo\s+-->')         # 内核自身的连接（DoH 等），不作上下文

# 地域放行项另记 sites：前后相邻连接所属的站点（取最后两段），用于「跨站出现」这一追踪器特征。
# 窗口比漏网项的 ctx 窄（前后各 SITES_K 条，基本只覆盖同一次页面加载），且只在该主机最初出现的
# SITES_OCC 次里收集：否则高频主机（第一方 CDN 等）的邻居会随时间一直积累到上限，失去区分度。
SITES_MAX = 20
SITES_K   = 3
SITES_OCC = 40

def site_of(host):
    """粗略的站点归属：IP 原样返回，域名取最后两段。只用于计数「出现在几个不同站点附近」。"""
    if is_ip(host): return host
    parts=host.lower().split(".")
    return ".".join(parts[-2:]) if len(parts)>=2 else host

def _ctx_add(rec, host, field="ctx"):
    cap=CTX_MAX if field=="ctx" else SITES_MAX
    c=rec.setdefault(field, [])
    if host not in c and len(c)<cap: c.append(host)

class ContextTracker:
    """按连接顺序给记录补上前后 k 条连接的信息。field="ctx" 记主机（漏网项），field="sites" 记站点（地域放行项）。"""
    def __init__(self, k=CTX_K):
        self.k=k; self.recent=collections.deque(maxlen=k); self.waiting=[]   # waiting: [rec, host, 剩余条数, field]
    @staticmethod
    def _add(rec, field, own, other):
        if field=="ctx":
            if other!=own: _ctx_add(rec, other, "ctx")
        else:
            s=site_of(other)
            if s!=site_of(own): _ctx_add(rec, s, "sites")
    def observe(self, host, rec=None, field="ctx"):
        for w in self.waiting:
            self._add(w[0], w[3], w[1], host); w[2]-=1
        self.waiting=[w for w in self.waiting if w[2]>0]
        if rec is not None:
            k=self.k if field=="ctx" else SITES_K
            for h in list(self.recent)[-k:]: self._add(rec, field, host, h)
            self.waiting.append([rec, host, k, field])
        if not self.recent or self.recent[-1]!=host: self.recent.append(host)
    def idle(self):
        """漏网项的后续上下文是否已收齐（地域放行项的 sites 丢几条无妨，不等）。"""
        return not any(w[3]=="ctx" for w in self.waiting)

def record_line(line, ts, pending, routed, dom_c, ip_c, tracker=None):
    """classify_line，另为漏网项记下进程名与上下文、为地域放行项记下相邻站点。返回值同 classify_line。"""
    kind,new=classify_line(line, ts, pending, routed, dom_c, ip_c)
    hp=parse_host(line)
    if hp is None or SELF_RE.search(line): return kind,new
    host=hp[0]; rec=None; field="ctx"
    if kind in ("domain","ip"):
        rec=pending["domains" if kind=="domain" else "ips"][host]
        pm=PROC_RE.search(line)
        if pm: rec.setdefault("procs", set()).add(pm.group(1))
    elif kind=="routed":
        d=routed["direct"].get(host)
        rec=d if d is not None and d["last"]==ts else routed["proxy"].get(host)
        if rec is not None and rec["count"]>SITES_OCC: rec=None   # 只在最初 SITES_OCC 次出现里收集
        field="sites"
    if tracker is not None: tracker.observe(host, rec, field)
    return kind,new

def context_groups(pending):
    """把互相出现在对方上下文里的漏网项并成一组（并查集）。返回 [[host, ...], ...]，按组内总次数降序。"""
    recs={**pending.get("domains",{}), **pending.get("ips",{})}
    parent={h:h for h in recs}
    def find(x):
        while parent[x]!=x: parent[x]=parent[parent[x]]; x=parent[x]
        return x
    for h,r in recs.items():
        for o in r.get("ctx",[]):
            if o in parent: parent[find(o)]=find(h)
    groups=collections.defaultdict(list)
    for h in recs: groups[find(h)].append(h)
    out=[sorted(g, key=lambda x:-recs[x]["count"]) for g in groups.values()]
    return sorted(out, key=lambda g:-sum(recs[x]["count"] for x in g))

# ---------------- 地域放行的可疑度排序 ----------------
# 地域放行清单是未经审核的原始池（上千项），此处打分把可能的广告/追踪排到前面，并给出理由。
# 四类信号：名称关键词、与已拉黑条目相似、跨站出现、名字像随机生成。分数只用于排序与提示，不自动拉黑。
# 看过、确认正常的记在 var/routed_reviewed.txt，排序时不再列出。
SUGGEST_MIN = 3.0
KW_SUBSTR = ("analytics","track","telemetry","pixel","beacon","doubleclick","adservice","adserver","adsystem",
             "advert","sentry","bugsnag","datadog","amplitude","mixpanel","hotjar","optimizely","criteo",
             "taboola","outbrain","prebid","adnxs","pubmatic","rubicon","scorecardresearch","quantserve",
             "chartbeat","newrelic","nr-data","appsflyer","adjust","branch.io","clarity","tongji","umeng","cnzz")
KW_STRONG = {"ad","ads","adv","stat","stats","rum","bid","bidder","rtb","metrics","metric","collect","collector"}
# 有歧义的缩写放弱关键词：dsp 在 dsp.mp.microsoft.com 里是 Windows 更新分发，不是广告需求方平台
KW_WEAK   = {"log","logs","event","events","tag","tags","sdk","sync","count","counter","cm","tj","insight","insights",
             "monitor","report","reporting","measure","id","uid","match","dsp","ssp","hm","mta"}
RAND_RE   = re.compile(r'^(?=.*\d)(?=.*[a-z])[a-z0-9]{12,}$|^[0-9a-f]{8,}(-[0-9a-f]{4,}){1,}$|^[a-z]\d{6,}$|^[0-9a-f]{16,}$')

def _tokens(host):
    """域名的词：按 . 与 - 切分，去掉最后一段（顶级域）。"""
    labels=host.lower().split(".")[:-1]
    out=[]
    for l in labels: out+= [t for t in l.split("-") if t]
    return out

def routed_reviewed_path(ctx): return os.path.join(ctx.review, "routed_reviewed.txt")

def load_reviewed(ctx):
    p=routed_reviewed_path(ctx)
    if not os.path.exists(p): return set()
    with open(p, encoding="utf-8") as f: return {l.strip() for l in f if l.strip() and not l.startswith("#")}

def save_reviewed(ctx, hosts):
    _atomic_write_text(routed_reviewed_path(ctx),
        "# 地域放行中看过、确认正常的主机，suggest 排序时不再列出。一行一个。\n" + "".join(h+"\n" for h in sorted(hosts)))

def _learned(ctx, routed):
    """从现有规则集与地域放行清单学出打分用的统计：
    拉黑条目按站点归组；每个站点下「拉黑 / 放行 / 地域放行」各有多少主机；各词在拉黑、放行、地域放行中出现的次数。"""
    rej=[_dom_base(p) for p in ctx.entries("domain", "reject")]
    alw=[_dom_base(p) for c in ("proxy","direct") for p in ctx.entries("domain", c)]
    seen=[h for b in ("direct","proxy") for h in routed[b] if not is_ip(h)]
    rej_sites=collections.defaultdict(list)
    for b in rej: rej_sites[site_of(b)].append(b)
    alw_site_n=collections.Counter(site_of(b) for b in alw)
    seen_site_n=collections.Counter(site_of(h) for h in seen)
    rt=collections.Counter(t for b in rej  for t in set(_tokens(b)))
    at=collections.Counter(t for b in alw  for t in set(_tokens(b)))
    st=collections.Counter(t for h in seen for t in set(_tokens(h)))
    return rej_sites, alw_site_n, seen_site_n, rt, at, st

def score_host(host, rec, learned):
    """返回 (分数, [理由])。"""
    rej_sites, alw_site_n, seen_site_n, rt, at, st = learned
    score=0.0; why=[]
    if is_ip(host): return 0.0, []
    toks=_tokens(host); low=host.lower()
    # 1. 名称关键词
    hit=[k for k in KW_SUBSTR if k in low]
    if hit: score+=3; why.append("关键词 " + "/".join(hit[:3]))
    strong=[t for t in toks if t in KW_STRONG]
    if strong: score+=3; why.append("关键词 " + "/".join(dict.fromkeys(strong)))
    weak=[t for t in toks if t in KW_WEAK]
    if weak and not (hit or strong): score+=1.5; why.append("弱关键词 " + "/".join(dict.fromkeys(weak)))
    # 2. 与已拉黑条目相似
    # 同站只在「该站已知主机里拉黑占比高」时才算：拉黑一个 ogads-pa.clients6.google.com 不代表 google.com 都可疑
    s=site_of(host)
    if s in rej_sites:
        rn=len(rej_sites[s]); ratio=rn/(rn+alw_site_n[s]+seen_site_n[s])
        ex=rej_sites[s][0]
        if ratio>=0.5:   score+=3; why.append(f"与已拉黑的 {ex} 同站（该站已知主机 {ratio:.0%} 被拉黑）")
        elif ratio>=0.2: score+=1; why.append(f"与已拉黑的 {ex} 同站（该站 {ratio:.0%} 被拉黑）")
    # 学出来的词：只出现在拉黑条目里，且在地域放行里不普遍（排除 edge/static/data 这类通用词）
    learned_toks=[t for t in set(toks) if len(t)>=3 and rt[t]>=2 and at[t]==0 and st[t]<=2*rt[t]
                  and t not in KW_STRONG and t not in KW_WEAK]
    if learned_toks:
        score+=min(3, 1.5*len(learned_toks))
        why.append("词 " + "/".join(sorted(learned_toks)[:3]) + " 只出现在你拉黑的条目里")
    # 3. 跨站出现（辅助证据：权重低，单靠它到不了 SUGGEST_MIN）
    n=len(rec.get("sites", []))
    if n>=12:  score+=1.5; why.append(f"最初 {SITES_OCC} 次出现里跟着 {n}{'+' if n>=SITES_MAX else ''} 个不同站点")
    elif n>=8: score+=1;   why.append(f"最初 {SITES_OCC} 次出现里跟着 {n} 个不同站点")
    # 4. 名字像随机生成
    if any(RAND_RE.match(l) for l in host.lower().split(".")[:-2]):
        score+=1.5; why.append("子域像随机串")
    return score, why

def suggest_routed(ctx, routed=None, include_reviewed=False):
    """返回 [(host, bucket, score, reasons, rec)]，按分数降序，只含分数 ≥ SUGGEST_MIN 的。"""
    routed=routed if routed is not None else load_routed(ctx.routed)
    learned=_learned(ctx, routed); reviewed=set() if include_reviewed else load_reviewed(ctx)
    out=[]
    for bucket in ("direct","proxy"):
        for h, rec in routed[bucket].items():
            if h in reviewed: continue
            sc, why=score_host(h, rec, learned)
            if sc>=SUGGEST_MIN: out.append((h, bucket, sc, why, rec))
    out.sort(key=lambda x:(-x[2], -x[4]["count"]))
    return out

# ---------------- 地域放行：代理改直连的候选 ----------------
# geolocation-!cn 按域名归属分，不看在国内能不能直连：微软/苹果/Steam 的下载 CDN、Office 更新等在国内有节点，直连更快也省代理流量。
# 候选先离线筛：走代理的域名，去掉登录/账号类（改直连会换地区、可能触发验证）、v2fly 标为 category-ai-!cn 的（AI 服务限制中国地区，
# 直连可能触发地区限制；2026-09-24 实测 bridge.claudeusercontent.com 直连 40 ms 能通，但不该推荐）、同站已人工归到代理的、拦截名单收录的（那是「可疑」视图的事）、
# 标过「保持代理」的，按流量与次数取前 TO_DIRECT_TOP 个。实测（腾讯 DoH 解析 + curl 直连）按需跑，与待审证据共用 var/evidence_cache.json。
# Clash 的 direct-nameserver 也是 223.5.5.5 / 1.12.12.12，所以实测解析到的就是改直连后实际会连的节点。
# 推荐规则：在它实际用的端口上，直连与走代理各测 3 次首字节取中位数（evidence.speed），直连 ≤ 代理 × FASTER 才推荐直连。
# 测完不值得改的（直连连不上、不比代理快）不再列出，名额由后面的候选补上；7 天后缓存过期会重测。只作提示，不替你选。
TO_DIRECT_TOP = 60
FASTER = 0.8          # 留两成余量，免得测量抖动把差不多的也推荐成直连
LOGIN_KW = {"login","logon","signin","signup","account","accounts","auth","oauth","sso","passport","identity","id","myaccount"}

def keepproxy_path(ctx): return os.path.join(ctx.review, "routed_keepproxy.txt")

def load_keepproxy(ctx):
    p=keepproxy_path(ctx)
    if not os.path.exists(p): return set()
    with open(p, encoding="utf-8") as f: return {l.strip() for l in f if l.strip() and not l.startswith("#")}

def save_keepproxy(ctx, hosts):
    _atomic_write_text(keepproxy_path(ctx),
        "# 地域放行中走代理、看过后决定保持代理的主机，「可改直连」不再列出。一行一个。\n" + "".join(h+"\n" for h in sorted(hosts)))

def speed_scheme(ports):
    """对比测速用哪个协议：它实际用 443 就测 HTTPS，只用 80 就测 HTTP。"""
    ports={str(p) for p in ports}
    return "http" if "80" in ports and "443" not in ports else "https"

def direct_verdict(ev):
    """(推荐, 理由)。推荐为 direct / keep；没测过为 (None, ...)。ev 为证据缓存的一项（含 speed）。"""
    if not ev: return None, "还没实测"
    ips=ev.get("cn_ips")
    if ips=="NXDOMAIN": return "keep", "国内 DNS 解析不到"
    if not isinstance(ips, list) or not ips: return "keep", "国内 DNS 解析没有结果"
    s=ev.get("speed")
    if not s: return None, "还没实测"
    d, p = s["direct_ms"], s["proxy_ms"]
    if d is None: return "keep", "直连连不上"
    if p is None: return "direct", f"直连 {d} ms，代理连不上"
    if d<=p*FASTER: return "direct", f"直连 {d} ms，代理 {p} ms"
    return "keep", f"直连 {d} ms，代理 {p} ms，直连不比代理快"

def mixed_port_url(ctx):
    """Clash 的 mixed-port（对比测速走代理用）。读不到时用 Clash Verge 的默认值 7897。"""
    mp=ctx.layout["mixed_port"]
    return f"http://127.0.0.1:{mp}" if mp else local_proxy()

def direct_candidates(ctx, routed=None, top=None):
    """返回 [(host, rec, traffic, owner)]，按流量与次数排序。只离线筛，不联网；top=None 返回全部。"""
    import external
    routed=routed if routed is not None else load_routed(ctx.routed)
    keep=load_keepproxy(ctx)
    proxied={site_of(_dom_base(p)) for p in ctx.entries("domain", "proxy")}
    T=load_traffic(ctx)["hosts"]; out=[]
    for h, rec in routed["proxy"].items():
        if is_ip(h) or h in keep or set(_tokens(h)) & LOGIN_KW or site_of(h) in proxied: continue
        lk=external.lookup(h)
        if lk and (external.verdict(lk)=="reject" or "category-ai-!cn" in lk["categories"]): continue
        t=T.get(h) or {}
        score=math.log10(t.get("up", 0)+t.get("down", 0)+1)+math.log10(rec["count"]+1)
        out.append((score, h, rec, t, (lk or {}).get("owner", [])[:3]))
    out.sort(key=lambda x: -x[0])
    return [x[1:] for x in (out[:top] if top else out)]

def _summary(tag, extra, td, newd, ti, newi, pending, routed):
    rd_n=len(routed["direct"])+len(routed["proxy"])
    # scan.log 摄要一律纯 ASCII：该行可能经非 UTF-8 控制台/重定向落盘，有中文就会被代码页损为 '?'。
    # （与本项目“对外脚本尽量纯 ASCII”的约定一致。）
    return (f"{tag}: {extra} | domain-leak={td}(new {newd}) pending={len(pending['domains'])} | "
            f"ip-leak={ti}(new {newi}) pending={len(pending['ips'])} | routed={rd_n}")

# ---------------- scan（读日志文件；2.5.4 起 service 日志已不可读，主要用于旧日志 / sidecar 模式）----------------
def cmd_scan(ctx, args):
    logs=list_logs(ctx)
    st=load_state(ctx)
    wm=st.get("watermark",""); at_mark=set(st.get("at_mark",[]))
    new_wm=wm; new_at=set(at_mark) if wm else set()
    nlines=0
    if getattr(args, "baseline", False):
        # 只推进高水位、不计数：用于日志已被旧版全量扫过、或恢复备份后避免重复累计
        for lg in logs:
            for line in open(lg, encoding="utf-8", errors="ignore"):
                ts=_line_ts(line)
                if not ts: continue
                if ts>new_wm: new_wm=ts; new_at={_line_key(line)}
                elif ts==new_wm: new_at.add(_line_key(line))
        save_state(ctx, {"watermark":new_wm, "at_mark":sorted(new_at)})
        _append_scanlog(ctx, f"baseline: logs={len(logs)} | watermark={new_wm}")
        try: print(f"baseline: 高水位推进到 {new_wm}（未计数）")
        except Exception: pass
        return
    dom_classified, ip_classified = load_classified(ctx)
    pending=load_pending(ctx.pending)
    routed=load_routed(ctx.routed)
    td=ti=newd=newi=0
    tracker=ContextTracker()
    for lg in logs:
        for line in open(lg, encoding="utf-8", errors="ignore"):
            ts=_line_ts(line)
            if not ts: continue
            if ts<wm: continue
            key=_line_key(line)
            if ts==wm and key in at_mark: continue
            if ts>new_wm: new_wm=ts; new_at={key}
            elif ts==new_wm: new_at.add(key)
            nlines+=1
            kind,new=record_line(line, ts, pending, routed, dom_classified, ip_classified, tracker)
            if kind=="domain": td+=1; newd+=new
            elif kind=="ip":   ti+=1; newi+=new
    save_pending(ctx.pending, pending)
    save_routed(ctx.routed, routed)
    save_state(ctx, {"watermark":new_wm, "at_mark":sorted(new_at)})
    line_ascii=_summary("scan", f"logs={len(logs)} new-lines={nlines}", td, newd, ti, newi, pending, routed)
    try:
        print(line_ascii)
    except Exception:
        pass  # pythonw / 无控制台时 stdout 可能为 None，不影响日志落盘
    _append_scanlog(ctx, line_ascii)

# ---------------- watch（常驻，订阅内核日志流，按条数落盘）----------------
# Clash Verge 2.5.4 起 service 模式的核心日志写在 C:\ProgramData\clash-verge-service\users\<hash>\logs\，
# 仅 SYSTEM 可读，且按 service 重启轮转。故改为经内核命名管道 \\.\pipe\verge-mihomo-*（普通用户可连、
# 无需 secret）订阅 GET /logs?level=info 的实时流。每条 payload 与日志文件中 msg= 部分同格式。
# 每累计 --every 条连接日志合并落盘一次（默认 200）；断流时先落盘再重连。
# 落盘时重读 pending/routed 与规则集，只合并增量，不覆盖 GUI/手动命令在此期间做的改动。
PIPE_PREFIX = "verge-mihomo-"
PIPE_HINT = None        # clash-verge.yaml 的 external-controller-pipe，建 Ctx 时读出；优先用它

def find_core_pipes():
    try: names=os.listdir("\\\\.\\pipe\\")
    except OSError: return []
    out=["\\\\.\\pipe\\"+n for n in sorted(names) if n.startswith(PIPE_PREFIX)]
    if PIPE_HINT and PIPE_HINT.rsplit("\\", 1)[-1] in names:
        out=[PIPE_HINT]+[p for p in out if p.lower()!=PIPE_HINT.lower()]
    return out

def no_pipe_message():
    """找不到内核管道时说清楚找了什么、可能的原因（本工具按 Clash Verge 2.5.4 的布局写）。"""
    want=f"clash-verge.yaml 里的 external-controller-pipe（{PIPE_HINT}）" if PIPE_HINT else "clash-verge.yaml 里没有 external-controller-pipe"
    return (f"找不到内核管道：{want}，也没有 \\\\.\\pipe\\{PIPE_PREFIX}*。"
            "Clash Verge 没在运行，或不是 2.5.x（本工具按 2.5.4 的布局写：内核经命名管道提供控制接口）。")

def pipe_request(method, path):
    """经内核命名管道发一次没有请求体的请求（如 PUT /providers/rules/<名字>），返回状态码。
    用 HTTP/1.0：响应不分块、读到连接关闭为止。"""
    pipes=find_core_pipes()
    if not pipes: raise RuntimeError(no_pipe_message())
    with open(pipes[0], "r+b", buffering=0) as f:
        f.write(f"{method} {path} HTTP/1.0\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n".encode())
        data=b""
        while True:
            c=f.read(65536)
            if not c: break
            data+=c
    parts=data.split(b"\r\n", 1)[0].split(b" ")
    return int(parts[1]) if len(parts)>1 and parts[1].isdigit() else 0

def pipe_get(path):
    """经内核命名管道发一次 GET，返回解析后的 JSON。找不到管道或请求失败时抛异常。"""
    pipes=find_core_pipes()
    if not pipes: raise RuntimeError(no_pipe_message())
    with open(pipes[0], "r+b", buffering=0) as f:
        f.write(f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode())
        data=b""
        while True:
            c=f.read(65536)
            if not c: break
            data+=c
    head,_,body=data.partition(b"\r\n\r\n")
    if b" 200 " not in head.split(b"\r\n",1)[0]:
        raise RuntimeError("HTTP " + head.split(b"\r\n",1)[0].decode("ascii","replace"))
    if b"transfer-encoding: chunked" in head.lower():
        out=b""
        while body:
            size_s,_,rest=body.partition(b"\r\n"); n=int(size_s.split(b";")[0].strip() or b"0", 16)
            if n==0: break
            out+=rest[:n]; body=rest[n+2:]
        body=out
    return json.loads(body.decode("utf-8"))

def _merge_recs(dst, src):
    for k, r in src.items():
        if k not in dst: dst[k]=r; continue
        d=dst[k]; d["count"]+=r["count"]; d["ports"]|=r["ports"]
        if r["first"] and (not d["first"] or r["first"]<d["first"]): d["first"]=r["first"]
        if r["last"] and r["last"]>d["last"]: d["last"]=r["last"]
        d.setdefault("procs", set()).update(r.get("procs", ()))
        for h in r.get("ctx", []):   _ctx_add(d, h, "ctx")
        for s in r.get("sites", []): _ctx_add(d, s, "sites")

def iter_log_stream(pipe, on_warn=None):
    """连接内核管道，逐条产出 /logs 流中的 payload 文本；连接断开时返回。
    on_warn(type, payload)：warning / error 级别的日志另外交给它（watch 用来记内核报错，见 KERNEL_WARN）。"""
    raw=open(pipe, "r+b", buffering=0)
    try:
        raw.write(b"GET /logs?level=info HTTP/1.1\r\nHost: localhost\r\n\r\n")
        buf=b""
        def need(pred):
            nonlocal buf
            while not pred():
                c=raw.read(65536)
                if not c: raise EOFError
                buf+=c
        need(lambda: b"\r\n\r\n" in buf)
        head,buf=buf.split(b"\r\n\r\n",1)
        status=head.split(b"\r\n",1)[0]
        if b" 200 " not in status:
            raise RuntimeError("HTTP " + status.decode("ascii","replace"))
        while True:                      # Transfer-Encoding: chunked
            need(lambda: b"\r\n" in buf)
            size_s,buf=buf.split(b"\r\n",1)
            size=int(size_s.split(b";")[0].strip() or b"0", 16)
            if size==0: return
            need(lambda: len(buf)>=size+2)
            chunk,buf=buf[:size],buf[size+2:]
            for part in chunk.splitlines():
                if not part.strip(): continue
                try: obj=json.loads(part)
                except ValueError: continue
                if on_warn and obj.get("type") in ("warning", "error"): on_warn(obj["type"], obj.get("payload",""))
                yield obj.get("payload","")
    except EOFError:
        return
    finally:
        raw.close()

# ---------------- 内核警告与错误、代理线路探测（var/kernel_warn.log）----------------
# 代理线路间歇卡住时（2026-09-24：Claude 应用的长连接多次心跳超时、请求超时，线路事后测却正常），
# 要知道那一刻内核报了什么：连不上节点、握手超时，还是被对端重置。watch 本来就收着内核日志流，
# 这里把 warning / error 级别的原样存下，带时间；超过 KERNEL_WARN_MAX 字节时转存为 .1（只留一份旧的）。
KERNEL_WARN_MAX = 4*1024*1024

def kernel_warn_path(ctx): return os.path.join(ctx.review, "kernel_warn.log")

def append_kernel_warn(ctx, typ, payload):
    p=kernel_warn_path(ctx)
    try:
        if os.path.exists(p) and os.path.getsize(p)>KERNEL_WARN_MAX: os.replace(p, p+".1")
        with open(p, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.datetime.now():%Y-%m-%d %H:%M:%S}] {typ:7} {payload}\n")
    except OSError: pass

# 代理线路探测：走 VLESS 节点时，卡在「节点到目标」这一段内核不报任何警告（2026-09-24 实测：经 MyVPS 连
# github.com:81 超时，日志里只有一条正常的 info 连接记录），光存内核报错抓不到。所以另外每 PROBE_EVERY 秒经
# mixed-port 请求一次 generate_204（几十字节），失败或慢于 PROBE_SLOW 秒时记一行（含当时的节点），恢复时再记一行。
PROBE_EVERY = 30
PROBE_SLOW  = 3.0
PROBE_URL   = "https://www.gstatic.com/generate_204"

def _current_node(ctx):
    """代理规则集所指的代理组当前选中的节点（组名取自 Clash 配置，见 detect_layout）。"""
    if not ctx.proxy_group: return "?"
    try:
        g=pipe_get("/proxies/"+urllib.parse.quote(ctx.proxy_group, safe=""))
        return g.get("now") or "?"
    except Exception: return "?"

def link_probe(ctx, stop):
    proxy=None; bad=False
    while not stop.wait(PROBE_EVERY):
        try:
            proxy=proxy or mixed_port_url(ctx)
            op=urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
            t0=time.time(); err=""
            try:
                with op.open(PROBE_URL, timeout=10) as r: r.read()
            except Exception as e: err=f"{type(e).__name__}: {e}"
            dt=time.time()-t0
            if err or dt>PROBE_SLOW:
                append_kernel_warn(ctx, "probe", f"代理探测{'失败' if err else '慢'} {dt:.1f}s 节点={_current_node(ctx)} {err}".rstrip()); bad=True
            elif bad:
                append_kernel_warn(ctx, "probe", f"代理探测恢复 {dt:.1f}s 节点={_current_node(ctx)}"); bad=False
        except Exception: pass

def cmd_watch(ctx, args):
    try:
        import msvcrt
        lockf=open(os.path.join(ctx.review,"watch.lock"),"w")
        msvcrt.locking(lockf.fileno(), msvcrt.LK_NBLCK, 1)
    except ImportError:
        pass
    except OSError:
        try: print("watch 已在运行，退出。")
        except Exception: pass
        return
    st={"p":{"domains":{}, "ips":{}}, "r":{"direct":{}, "proxy":{}}, "h":{}, "lines":0, "td":0, "ti":0}
    cls=list(load_classified(ctx)); rej=list(load_reject_payloads(ctx)); rej_rx=rej_hit_re(ctx)
    sampler=TrafficSampler(); threading.Thread(target=sampler.run, daemon=True).start()
    threading.Thread(target=link_probe, args=(ctx, threading.Event()), daemon=True).start()
    if ctx.dest: threading.Thread(target=dest_settler, args=(ctx, threading.Event()), daemon=True).start()
    tracker=ContextTracker()
    def flush(reason):
        if not st["lines"]: return
        with data_lock(ctx):
            pending=load_pending(ctx.pending); routed=load_routed(ctx.routed)
            cls[:]=load_classified(ctx)             # 期间可能已归类：已覆盖的不再并入
            dom_c, ip_c = cls
            fresh={}
            for sec, covered in (("domains", lambda h: domain_covered(h, dom_c)), ("ips", lambda h: ip_covered(h, ip_c))):
                src={h:r for h,r in st["p"][sec].items() if not covered(h)}
                fresh[sec]=sum(1 for h in src if h not in pending[sec])
                _merge_recs(pending[sec], src)
            for b in ("direct","proxy"): _merge_recs(routed[b], st["r"][b])
            save_pending(ctx.pending, pending); save_routed(ctx.routed, routed)
            merge_reject_hits(ctx, st["h"], datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:23])
            merge_traffic(ctx, sampler.take())
            rej[:]=load_reject_payloads(ctx)
        _append_scanlog(ctx, _summary("watch", f"{reason} lines={st['lines']}", st["td"], fresh["domains"],
                                      st["ti"], fresh["ips"], pending, routed))
        st.update(p={"domains":{}, "ips":{}}, r={"direct":{}, "proxy":{}}, h={}, lines=0, td=0, ti=0)
    _append_scanlog(ctx, f"watch start: stream mode, flush every {args.every} lines")
    backoff=1; last_err=""
    while True:
        pipes=find_core_pipes()
        err="no core pipe (Clash Verge not running?)" if not pipes else ""
        for pipe in pipes:
            try:
                for payload in iter_log_stream(pipe, on_warn=lambda t, pl: append_kernel_warn(ctx, t, pl)):
                    if last_err:
                        _append_scanlog(ctx, f"watch connected: {os.path.basename(pipe)}"); last_err=""
                    backoff=1
                    if not HOST_RE.search(payload): continue
                    ts=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:23]
                    kind,_=record_line(payload, ts, st["p"], st["r"], cls[0], cls[1], tracker)
                    record_reject_hit(payload, ts, st["h"], rej[0], rej[1], rej_rx)
                    st["lines"]+=1
                    if kind=="domain": st["td"]+=1
                    elif kind=="ip":   st["ti"]+=1
                    # 等最近漏网项的后续上下文收齐再落盘，否则落盘后追加的上下文会丢；最多拖到 2 倍
                    if st["lines"]>=args.every and (tracker.idle() or st["lines"]>=2*args.every):
                        flush("flush")
                err=f"stream closed: {os.path.basename(pipe)}"
                break
            except Exception as e:
                err=f"{type(e).__name__}: {e}"
        try: flush("disconnect")
        except Exception as e: _append_scanlog(ctx, f"watch flush error: {type(e).__name__}: {e}")
        if err!=last_err:
            _append_scanlog(ctx, f"watch waiting: {err}"); last_err=err
        time.sleep(backoff); backoff=min(backoff*2, 30)

# ---------------- 拉黑命中统计（var/reject_hits.json）----------------
# watch 只把漏网与地域放行计入清单，被 my-reject / my-reject-ip 拒掉的连接原本不留痕。
# 这里按规则条目计数：哪些拉黑条目一直有流量、哪些早已没人连，以及某个被拉黑的主机以后是否还会被连。
# 日志只写规则集名（match RuleSet(my-reject)），不写命中的是哪一条，故按当前规则集反查最具体的那条。
# 次数是「新建连接」的次数，分不出定时连接、失败重试还是多个进程各自连接，所以另按小时分桶、按进程计数，
# 看规律要看分桶，不能只看总数（2026-09-23：半小时 470 次 Datadog 实为评估时 216 个 claude -p 进程各连 2 次）。
def rej_hit_re(ctx):
    """匹配被拉黑规则集（收件箱与只读的都算）拒绝的连接日志：match RuleSet(<拉黑规则集名>) using REJECT。"""
    names="|".join(re.escape(s["name"]) for s in ctx.sets if s["cat"]=="reject")
    return re.compile(r'match\s+RuleSet\((?:' + names + r')\)\s+using\s+REJECT', re.I)

REJ_HOSTS_MAX  = 10     # 每条记下的不同主机数上限
REJ_PROCS_MAX  = 10
REJ_HOURS_KEEP = 24*14  # 每条保留最近多少个小时桶

def reject_hits_path(ctx): return os.path.join(ctx.review, "reject_hits.json")

def load_reject_hits(ctx):
    p=reject_hits_path(ctx)
    if os.path.exists(p):
        try:
            with open(p, encoding="utf-8") as f: d=json.load(f)
            if isinstance(d.get("entries"), dict): return d
        except (OSError, ValueError): pass
    return {"since": "", "entries": {}}

def save_reject_hits(ctx, data):
    _atomic_write_text(reject_hits_path(ctx), json.dumps(data, ensure_ascii=False, indent=1, sort_keys=True))

def load_reject_payloads(ctx):
    return ctx.entries("domain", "reject"), ctx.entries("ip", "reject")

def reject_entry_for(host, rej_dom, rej_ip):
    """host 命中的最具体的拉黑条目；找不到（如规则集刚改、内核还在用旧副本）返回 None。"""
    if is_ip(host):
        net=parse_net(host); best=None; bl=-1
        for c in rej_ip:
            cn=parse_net(c)
            if cn is not None and net is not None and net.version==cn.version and net.subnet_of(cn) and cn.prefixlen>bl:
                best, bl = c, cn.prefixlen
        return best
    d=host.lower(); best=None; bl=-1
    for p in rej_dom:
        base=_dom_base(p)
        ok = (d==base or d.endswith("."+base)) if p.strip().startswith("+.") else d==base
        if ok and len(base)>bl: best, bl = p, len(base)
    return best

def record_reject_hit(line, ts, hits, rej_dom, rej_ip, rx):
    """若 line 是被拉黑规则集拒绝的连接（rx 为 rej_hit_re(ctx)），计入 hits（{条目: 记录}）。返回是否计入。"""
    if not rx.search(line): return False
    hp=parse_host(line)
    if not hp: return False
    host=hp[0]
    entry=reject_entry_for(host, rej_dom, rej_ip) or host
    r=hits.setdefault(entry, {"count":0, "first":ts, "last":ts, "hosts":[], "procs":{}, "hours":{}})
    r["count"]+=1; r["last"]=ts
    if host not in r["hosts"] and len(r["hosts"])<REJ_HOSTS_MAX: r["hosts"].append(host)
    pm=PROC_RE.search(line); proc=pm.group(1) if pm else "?"
    if proc in r["procs"] or len(r["procs"])<REJ_PROCS_MAX: r["procs"][proc]=r["procs"].get(proc, 0)+1
    hr=ts[:13]; r["hours"][hr]=r["hours"].get(hr, 0)+1
    return True

def merge_reject_hits(ctx, new_hits, ts):
    """把一批命中并入 var/reject_hits.json。调用方须已持有 data_lock。"""
    if not new_hits: return
    data=load_reject_hits(ctx)
    first=min(r["first"] for r in new_hits.values())     # 统计起点取最早一次命中，不取落盘时间
    if not data["since"] or first<data["since"]: data["since"]=first
    ent=data["entries"]
    for e, r in new_hits.items():
        d=ent.get(e)
        if d is None: ent[e]=r; continue
        d["count"]+=r["count"]
        if r["first"] and (not d.get("first") or r["first"]<d["first"]): d["first"]=r["first"]
        if r["last"] > d.get("last", ""): d["last"]=r["last"]
        for x in r["hosts"]:
            if x not in d["hosts"] and len(d["hosts"])<REJ_HOSTS_MAX: d["hosts"].append(x)
        for x, n in r["procs"].items():
            if x in d["procs"] or len(d["procs"])<REJ_PROCS_MAX: d["procs"][x]=d["procs"].get(x, 0)+n
        for h, n in r["hours"].items(): d["hours"][h]=d["hours"].get(h, 0)+n
        for h in sorted(d["hours"])[:-REJ_HOURS_KEEP]: del d["hours"][h]
    save_reject_hits(ctx, data)

def cmd_rejects(ctx, args):
    data=load_reject_hits(ctx); ent=data["entries"]
    rej_dom, rej_ip = load_reject_payloads(ctx)
    current=set(rej_dom)|set(rej_ip)
    if not data["since"]:
        print("还没有拉黑命中记录（watch 运行后才开始统计）。"); return
    print(f"【拉黑命中】统计起点 {data['since'][:19]}；有命中的 {sum(1 for e in ent if e in current)} 条 / 拉黑条目共 {len(current)} 条")
    flt=(args.filter or "").lower()
    rows=[(e, r) for e, r in ent.items() if not flt or flt in e.lower() or any(flt in h.lower() for h in r.get("hosts", []))]
    rows.sort(key=lambda x: -x[1]["count"])
    print(f"{'条目':44} {'次数':>6} {'每小时':>6}  {'最近':19}  进程(次数) | 主机")
    print("-"*110)
    for e, r in rows[:args.top]:
        tag="" if e in current else "  (已不在拉黑规则集)"
        pr=sorted(r.get("procs", {}).items(), key=lambda x:-x[1])
        extra=",".join(f"{p}({n})" for p, n in pr[:3])
        hs=[h for h in r.get("hosts", []) if h!=_dom_base(e)]
        if hs: extra+=" | "+",".join(hs[:3])
        hrs=r.get("hours", {}); rate=f"{r['count']/max(len(hrs),1):.0f}"   # 有命中的小时里平均每小时几次
        print(f"{e:44} {r['count']:>6} {rate:>6}  {r['last'][:19]:19}  {extra}{tag}")
        if args.hours and hrs:
            print("      " + "  ".join(f"{h[5:]}时:{n}" for h, n in sorted(hrs.items())[-args.hours:]))
    if len(rows)>args.top: print(f"  … 其余 {len(rows)-args.top} 条（--top 调大）")
    if args.zero:
        zero=sorted(current-set(ent))
        print(f"\n统计起点以来没有命中的拉黑条目 {len(zero)} 条：")
        for e in zero: print(f"  {e}")

# ---------------- 流量统计（var/traffic.json）----------------
# 日志流不带字节数。watch 另起一个线程每 TRAFFIC_POLL 秒经内核管道取一次 /connections（约 1 毫秒），
# 记下每个连接最近一次的上传 / 下载累计值；连接从列表里消失时，按最后一次看到的值计入该主机。
# 局限：存活不到一个轮询间隔的连接看不到；消失前最后一秒内的字节会少算。被拒绝的连接（漏网项、拉黑）没有流量，
# 所以这项证据只对放行的主机（地域放行、已归类的）有用。
# 用途：看上下行的比例与每个连接的大小。只陈述数字，不下结论（调接口、传文件也会上传多于下载）。
TRAFFIC_POLL = 1.0

def traffic_path(ctx): return os.path.join(ctx.review, "traffic.json")

def load_traffic(ctx):
    p=traffic_path(ctx)
    if os.path.exists(p):
        try:
            with open(p, encoding="utf-8") as f: d=json.load(f)
            if isinstance(d.get("hosts"), dict): return d
        except (OSError, ValueError): pass
    return {"since": "", "hosts": {}}

class TrafficSampler:
    def __init__(self):
        self.live={}; self.agg={}; self.lock=threading.Lock(); self.stop=threading.Event(); self.errors=0
    def _close(self, rec):
        host, up, down, proc, rule, ts = rec
        a=self.agg.setdefault(host, {"conns":0, "up":0, "down":0, "max_down":0, "max_up":0, "procs":{}, "rules":{}, "first":ts, "last":ts})
        a["conns"]+=1; a["up"]+=up; a["down"]+=down; a["max_down"]=max(a["max_down"], down); a["max_up"]=max(a["max_up"], up)
        a["procs"][proc]=a["procs"].get(proc, 0)+1; a["rules"][rule]=a["rules"].get(rule, 0)+1; a["last"]=ts
    def poll_once(self):
        d=pipe_get("/connections"); now=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        seen=set()
        with self.lock:
            for c in d.get("connections") or []:
                m=c.get("metadata", {}); host=m.get("host") or m.get("destinationIP") or ""
                if not host or m.get("type")=="Inner": continue      # 内核自身的连接（如 DoH 上游 8.8.8.8）
                seen.add(c["id"])
                rule=c.get("rule", "")+(f"({c['rulePayload']})" if c.get("rulePayload") else "")
                self.live[c["id"]]=[host, int(c.get("upload") or 0), int(c.get("download") or 0), m.get("process") or "?", rule, now]
            for cid in [k for k in self.live if k not in seen]: self._close(self.live.pop(cid))
    def run(self):
        while not self.stop.wait(TRAFFIC_POLL):
            try: self.poll_once()
            except Exception: self.errors+=1           # 内核重启、管道暂不可用：下一轮再试
    def take(self):
        with self.lock: a=self.agg; self.agg={}; return a

def merge_traffic(ctx, agg):
    """把一批已结束连接的流量并入 var/traffic.json。调用方须已持有 data_lock。"""
    if not agg: return
    data=load_traffic(ctx)
    first=min(a["first"] for a in agg.values())
    if not data["since"] or first<data["since"]: data["since"]=first
    H=data["hosts"]
    for h, a in agg.items():
        d=H.get(h)
        if d is None: H[h]=a; continue
        for k in ("conns", "up", "down"): d[k]+=a[k]
        for k in ("max_down", "max_up"): d[k]=max(d[k], a[k])
        for k in ("procs", "rules"):
            for x, n in a[k].items(): d[k][x]=d[k].get(x, 0)+n
        d["last"]=max(d["last"], a["last"])
    _atomic_write_text(traffic_path(ctx), json.dumps(data, ensure_ascii=False, separators=(",", ":")))

def _size(n):
    for u in ("B", "KB", "MB", "GB"):
        if n<1024 or u=="GB": return f"{n:.0f}{u}" if u=="B" else f"{n:.1f}{u}"
        n/=1024

def traffic_line(t):
    """一个主机的流量摘要，给界面与模型看。"""
    if not t or not t.get("conns"): return ""
    avg_d=t["down"]/t["conns"]; avg_u=t["up"]/t["conns"]
    u, d = t["up"]+1, t["down"]+1     # 只陈述比例，不下结论：调接口、传文件也会上传多
    shape=f"上传是下载的 {u/d:.1f} 倍" if u>=d else f"下载是上传的 {d/u:.1f} 倍"
    return (f"流量：{t['conns']} 个连接，上传 {_size(t['up'])}、下载 {_size(t['down'])}，平均每个连接上传 {_size(avg_u)}、下载 {_size(avg_d)}；{shape}")

def cmd_traffic(ctx, args):
    data=load_traffic(ctx); H=data["hosts"]
    if not H: print("还没有流量记录（watch 运行后才开始统计）。"); return
    flt=(args.filter or "").lower()
    rows=[(h, t) for h, t in H.items() if not flt or flt in h.lower()]
    key={"down": lambda x: -x[1]["down"], "up": lambda x: -x[1]["up"], "conns": lambda x: -x[1]["conns"],
         "ratio": lambda x: -(x[1]["up"]+1)/(x[1]["down"]+1)}[args.sort]
    rows.sort(key=key)
    print(f"【流量】统计起点 {data['since']}；{len(H)} 个主机。按 {args.sort} 排序")
    print(f"{'主机':46} {'连接':>5} {'上传':>9} {'下载':>9}  进程")
    print("-"*100)
    for h, t in rows[:args.top]:
        pr=sorted(t["procs"].items(), key=lambda x:-x[1])
        print(f"{h:46} {t['conns']:>5} {_size(t['up']):>9} {_size(t['down']):>9}  {','.join(p for p,_ in pr[:3])}")

# ---------------- list ----------------
def cmd_list(ctx, args):
    pending=load_pending(ctx.pending)
    dom=pending["domains"]; ips=pending["ips"]
    if not dom and not ips: print("待审清单为空。"); return
    if dom:
        print("【域名待审】（互相出现在对方上下文里的归为一组；ctx 为前后相邻连接，procs 为发起进程）")
        print(f"{'域名':40} {'次数':>5}  {'端口':12} 最近")
        print("-"*80)
        for gi, g in enumerate(context_groups({"domains":dom}), 1):
            if len(g)>1: print(f"── 组 {gi}（{len(g)} 项，同一次访问带出）")
            for d in g:
                v=dom[d]; print(f"{d:40} {v['count']:>5}  {','.join(sorted(v['ports'])):12} {v['last']}")
                if v.get("procs"): print(f"{'':6}procs: {', '.join(sorted(v['procs']))}")
                if v.get("ctx"):   print(f"{'':6}ctx:   {', '.join(v['ctx'])}")
        print()
    if ips:
        table=load_ip2asn()
        if table is None:
            print("（提示：尚未下载 ip2asn 数据，IP 仅用内置表识别；运行 `update-ipdata` 获取完整 ASN/组织/国家）")
        print("【IP 待审】")
        print(f"{'IP':18} {'次数':>5}  {'端口':10} {'最近':19}  识别")
        print("-"*100)
        for ip in sorted(ips, key=lambda x:-ips[x]["count"]):
            v=ips[ip]
            print(f"{ip:18} {v['count']:>5}  {','.join(sorted(v['ports'])):10} {v['last']:19}  {enrich_ip(ip, table)}")
            if v.get("procs"): print(f"{'':6}procs: {', '.join(sorted(v['procs']))}")
            if v.get("ctx"):   print(f"{'':6}ctx:   {', '.join(v['ctx'])}")

# ---------------- routed（地域放行清单）----------------
def cmd_routed(ctx, args):
    if getattr(args, "ok", ""):        # 标记为看过、正常
        hs={h.strip() for h in args.ok.split(",") if h.strip()}
        rv=load_reviewed(ctx); save_reviewed(ctx, rv|hs); print(f"已标记为看过：{', '.join(sorted(hs))}"); return
    if getattr(args, "unok", ""):
        hs={h.strip() for h in args.unok.split(",") if h.strip()}
        rv=load_reviewed(ctx); save_reviewed(ctx, rv-hs); print(f"已取消看过标记：{', '.join(sorted(hs))}"); return
    if getattr(args, "suggest", False):
        rows=suggest_routed(ctx)
        print(f"【地域放行 / 可疑排序】{len(rows)} 项（分数 ≥ {SUGGEST_MIN:g}；已看过 {len(load_reviewed(ctx))} 项不列出）")
        print(f"{'分数':>4}  {'去向':4} {'域名':44} {'次数':>6}")
        print("-"*80)
        for h, bucket, sc, why, rec in rows[:args.top]:
            print(f"{sc:>4.1f}  {'直连' if bucket=='direct' else '代理':4} {h:44} {rec['count']:>6}")
            print(f"{'':12}{'；'.join(why)}")
        if len(rows)>args.top: print(f"  … 其余 {len(rows)-args.top} 项（--top 调大）")
        print("\n看过、确认正常：routed --ok 域名,域名    要拉黑：promote --reject 域名")
        return
    routed=load_routed(ctx.routed)
    flt=(getattr(args,"filter","") or "").lower()
    for bucket,title in (("direct","被地域判为国内→直连"),("proxy","被地域判为境外→代理")):
        d=routed[bucket]
        keys=[k for k in d if flt in k.lower()] if flt else list(d)
        keys.sort(key=lambda x:-d[x]["count"])
        print(f"【地域放行 / {title}】共 {len(keys)} 项" + (f"（过滤: {flt}）" if flt else ""))
        print(f"{'域名/IP':44} {'次数':>6}  最近")
        print("-"*80)
        for k in keys[:args.top]:
            v=d[k]; print(f"{k:44} {v['count']:>6}  {v['last']}")
        if len(keys)>args.top: print(f"  … 其余 {len(keys)-args.top} 项已省略（用 --filter 缩小，或 --top 调大）")
        print()

# ---------------- 写规则集 ----------------
def _read_head(path):
    head=[]
    if os.path.exists(path):
        with open(path,encoding="utf-8") as f:
            for line in f:
                if re.match(r'^\s*payload\s*:', line): break
                head.append(line.rstrip("\n"))
    return head

# ---- 占位条目（清单删空时回填，避免 mihomo 对空 payload 报错）----
DOMAIN_PLACEHOLDER = "placeholder.never-match.invalid"
IP_PLACEHOLDER     = "198.51.100.0/24"   # 文档保留段，永不匹配真实流量

def _atomic_write_text(path, text):
    """原子写：先写临时文件、fsync 落盘，再 os.replace 覆盖目标。
    历史上 my-*.yaml 曾因「边写边被中断」留下截断的 *.corrupt-bak；原子写杜绝此类损坏。"""
    d=os.path.dirname(os.path.abspath(path)) or "."
    fd,tmp=tempfile.mkstemp(dir=d, suffix=".tmp")
    try:
        with os.fdopen(fd,"w",encoding="utf-8",newline="\n") as f:
            f.write(text); f.flush(); os.fsync(f.fileno())
        os.replace(tmp,path)
    except BaseException:
        try: os.remove(tmp)
        except OSError: pass
        raise

def _payload_text(head, items):
    out=[]
    if head: out.append("\n".join(head).rstrip())
    out.append("payload:")
    for p in items: out.append(f'  - "{p}"')
    return "\n".join(out)+"\n"

def _write_payload(path, items, placeholder=None):
    """把 items 作为 payload 原子写回 path，保留 payload 之前的注释头。
    items 为空且给了 placeholder 时写占位，避免空清单报错。"""
    if not items and placeholder is not None:
        items=[placeholder]
    _atomic_write_text(path, _payload_text(_read_head(path), items))

# ---- 写入时的冗余与冲突检查 ----
# 同一目标落在多个规则集时，规则里排在前面的生效。实际顺序按 Clash 配置检测（ctx.sets 的 rank，收件箱的先后即 ctx.order），
# CAT_ORDER 是检测不全时收件箱的默认顺序，也是各处列出三类时的显示顺序。
CAT_ORDER = ("reject", "direct", "proxy")
CAT_CN    = {"reject": "拉黑", "direct": "直连", "proxy": "代理"}

def _dom_base(entry):
    e=entry.strip().lower()
    return e[2:] if e.startswith("+.") else e.lstrip(".")

def _dom_within(entry, base):
    """entry 匹配的范围是否落在 +.base 之内（等于或为其子域）。"""
    b=_dom_base(entry)
    return b==base or b.endswith("."+base)

def _lab(s):
    """提示里怎么称呼一个规则集：收件箱沿用「代理类」，只读的另写出名字，如「代理类 common-proxy」。"""
    return f"{CAT_CN[s['cat']]}类" if s["inbox"] else f"{CAT_CN[s['cat']]}类 {s['name']}"

def _of(s):
    return _lab(s) + ("的" if s["inbox"] else " 的")

def _who(s):
    """提示里「谁生效」：收件箱写「代理」，只读的写「common-proxy（代理）」。"""
    return CAT_CN[s["cat"]] if s["inbox"] else f"{s['name']}（{CAT_CN[s['cat']]}）"

def _inbox(ctx, kind, cat):
    return next(s for s in ctx.sets if s["inbox"] and s["kind"]==kind and s["cat"]==cat)

def _first_cover(ctx, kind, tok, covered):
    """按规则顺序第一个覆盖 tok 的规则集与条目；covered(tok, [条目]) 为判断函数。"""
    for s, items in ctx.payloads(kind):
        hit=[p for p in items if covered(tok, [p])]
        if hit: return s, hit[0]
    return None, None

def _dest_form(kind, tok, notes):
    """写进规则服务的条目写法，与写收件箱时相同：域名一律 +.，单个 IP 写成 /32（落在已知服务段内的扩成整段）。无效返回 None。"""
    if kind=="domain":
        b=_dom_base(tok)
        return norm_domain(b) if b else None
    net=parse_net(tok)
    if net is None: return None
    write=str(net)
    if net.prefixlen==net.max_prefixlen:
        svc, bnet = builtin_service(str(net.network_address))
        if svc and bnet is not None:
            write=str(bnet); notes.append(f"{tok.strip()} 识别为 {svc}，按整段 {write} 写入")
    return write

def dest_add(ctx, items, notes):
    """items: [(kind, cat, 原始写法)]，一批写进规则服务。返回 {(kind, cat): 真正新增的条目}；提交号与服务端的提示追加到 notes。
    写入前的检查由服务端做。失败抛 DestError。"""
    adds=[]
    for k, c, t in items:
        e=_dest_form(k, t, notes)
        if e and (k, c, e) not in adds: adds.append((k, c, e))
    commit, done, server_notes = ctx.dest.write(adds)
    notes+=server_notes
    if commit: notes.append(f"已提交到规则服务（{commit[:7]}），上线后自动让 Clash 重新取，一般一两分钟")
    elif adds: notes.append("规则服务上已经有这些条目，没有改动")
    return done

def add_domains(ctx, cat, domains, notes=None):
    """写入域名收件箱。写入前：已被本类收件箱覆盖、或按规则顺序已先命中本类的只读规则集（如 http 规则集）的跳过；
    收件箱中被新条目覆盖的旧条目一并移除；与另外两类（全部规则集）有重叠时在 notes 里说明哪个生效（只提示，不改别的规则集）。
    配了规则服务（ctx.dest）时改为写进规则服务，检查由服务端做。返回实际新增的条目。"""
    notes=[] if notes is None else notes
    if ctx.dest: return dest_add(ctx, [("domain", cat, d) for d in domains], notes).get(("domain", cat), [])
    me=_inbox(ctx, "domain", cat); path=me["path"]
    payload=[p for p in load_payload(path) if p!=DOMAIN_PLACEHOLDER]; added=[]
    others=[(s, items) for s, items in ctx.payloads("domain") if s["cat"]!=cat]
    for d in domains:
        b=_dom_base(d)
        if not b: continue
        if domain_covered(b, payload):
            notes.append(f"{b} 已被{CAT_CN[cat]}类现有条目覆盖，未写入"); continue
        fs, fp = _first_cover(ctx, "domain", b, domain_covered)
        if fs is not None and not fs["inbox"] and fs["cat"]==cat:
            notes.append(f"{b} 已被{_of(fs)} {fp} 覆盖，未写入"); continue
        e=norm_domain(b)
        inner=[p for p in payload if _dom_within(p, b)]
        if inner:
            payload=[p for p in payload if p not in inner]
            notes.append(f"{e} 覆盖了{CAT_CN[cat]}类已有的 {', '.join(inner)}，已一并移除")
        payload.append(e); added.append(e)
        for os_, op in others:
            outer=[p for p in op if domain_covered(b, [p])]
            inner_o=[p for p in op if _dom_within(p, b) and p not in outer]
            w=_who(os_ if os_["rank"]<me["rank"] else me)
            if outer:   notes.append(f"重叠：{b} 也落在{_of(os_)} {', '.join(outer)} 内，按规则顺序{w}生效")
            if inner_o: notes.append(f"重叠：{_of(os_)} {', '.join(inner_o)} 落在 {e} 内，这些子域按规则顺序{w}生效")
    _write_payload(path, payload, DOMAIN_PLACEHOLDER)
    un=ctx.unreadable_note("domain")
    if un: notes.append(un)
    return added

def add_ips(ctx, cat, tokens, notes=None):
    """写入 IP 收件箱；单个 IP 若落在内置已知服务段内，自动扩成整段并提示。
    冗余与冲突检查同 add_domains；配了规则服务时同样改写到那里。返回 (新增条目, notes)。"""
    notes=[] if notes is None else notes
    if ctx.dest: return dest_add(ctx, [("ip", cat, t) for t in tokens], notes).get(("ip", cat), []), notes
    ph=ipaddress.ip_network(IP_PLACEHOLDER)
    def real(items):
        out=[]
        for c in items:
            n=parse_net(c)
            if n is not None and not (n.version==ph.version and n.subnet_of(ph)): out.append(c)
        return out
    me=_inbox(ctx, "ip", cat); path=me["path"]
    payload=real(load_payload(path)); added=[]
    others=[(s, real(items)) for s, items in ctx.payloads("ip") if s["cat"]!=cat]
    for t in tokens:
        net=parse_net(t)
        if net is None: continue
        write=str(net)   # 规范成 CIDR：单 IP -> x.x.x.x/32。mihomo 的 ipcidr 规则集不接受裸 IP，会报 "invalid Ipcidr" 并跳过
        if net.prefixlen==net.max_prefixlen:  # 单 IP：尝试扩成已知服务整段
            svc, bnet = builtin_service(str(net.network_address))
            if svc and bnet is not None:
                write=str(bnet); notes.append(f"{t.strip()} 识别为 {svc}，按整段 {write} 写入")
        wn=parse_net(write)
        if ip_covered(write, payload):
            notes.append(f"{write} 已被{CAT_CN[cat]}类现有网段覆盖，未写入"); continue
        fs, fp = _first_cover(ctx, "ip", write, ip_covered)
        if fs is not None and not fs["inbox"] and fs["cat"]==cat:
            notes.append(f"{write} 已被{_of(fs)} {fp} 覆盖，未写入"); continue
        inner=[p for p in payload if parse_net(p).version==wn.version and parse_net(p).subnet_of(wn)]
        if inner:
            payload=[p for p in payload if p not in inner]
            notes.append(f"{write} 覆盖了{CAT_CN[cat]}类已有的 {', '.join(inner)}，已一并移除")
        payload.append(write); added.append(write)
        for os_, op in others:
            same=[p for p in op if parse_net(p).version==wn.version]
            outer=[p for p in same if wn.subnet_of(parse_net(p))]
            inner_o=[p for p in same if parse_net(p).subnet_of(wn) and p not in outer]
            w=_who(os_ if os_["rank"]<me["rank"] else me)
            if outer:   notes.append(f"重叠：{write} 也落在{_of(os_)} {', '.join(outer)} 内，按规则顺序{w}生效")
            if inner_o: notes.append(f"重叠：{_of(os_)} {', '.join(inner_o)} 落在 {write} 内，按规则顺序{w}生效")
    _write_payload(path, payload, IP_PLACEHOLDER)
    un=ctx.unreadable_note("ip")
    if un: notes.append(un)
    return added, notes

# ---------------- 规则集：读取 / 删除 / 改分类（供加回误拉黑与规则管理 UI 复用）----------------
def ruleset_path(ctx, kind, cat):
    """kind: 'domain'|'ip'；cat: 'proxy'|'direct'|'reject'。返回对应 my-*.yaml 路径。"""
    files = ctx.dom_files if kind=="domain" else ctx.ip_files
    return os.path.join(ctx.ruleset, files[cat])

def load_ruleset(ctx, kind, cat, hide_placeholder=True):
    """读取某规则集现有条目（原文，用于展示与精确删除）。默认隐藏占位条目。"""
    items=load_payload(ruleset_path(ctx, kind, cat))
    if hide_placeholder:
        ph = DOMAIN_PLACEHOLDER if kind=="domain" else IP_PLACEHOLDER
        items=[x for x in items if x!=ph]
    return items

def remove_from(ctx, kind, cat, entries):
    """按存储原文精确删除 entries；删空则回填占位。返回实际删除的条目列表。"""
    path=ruleset_path(ctx, kind, cat)
    ph = DOMAIN_PLACEHOLDER if kind=="domain" else IP_PLACEHOLDER
    payload=load_payload(path); rm=set(entries)
    removed=[p for p in payload if p in rm]
    if removed:
        _write_payload(path, [p for p in payload if p not in rm], ph)
    return removed

def move_entry(ctx, kind, src_cat, dst_cat, entry, notes=None):
    """把一条 entry 从 src_cat 移到 dst_cat（先删后加）。src_cat 为空/None 时仅新增
    （用于把「地域放行」里发现的域名/IP 直接归类，本无自定义归属）。返回新增条目列表；提示追加到 notes。"""
    if src_cat:
        remove_from(ctx, kind, src_cat, [entry])
    if kind=="domain":
        return add_domains(ctx, dst_cat, [entry], notes)
    added,_ = add_ips(ctx, dst_cat, [entry], notes)
    return added

def routed_classify(ctx, targets):
    """把地域放行里的主机归类（targets：{cat: [主机]}），并从地域放行清单移除（避免重复出现）。返回 ({cat: 新增条目}, notes)。
    规则服务模式下各类一起一次提交：直连与拉黑分开提交时，一次「应用」要等两趟写入接口。"""
    added={}; notes=[]
    hosts=[h for hs in targets.values() for h in hs]
    # 先写规则（规则服务要联网，放在数据锁外面），写成功了再从清单移除
    if ctx.dest:
        done=dest_add(ctx, [("ip" if is_ip(h) else "domain", cat, h) for cat, hs in targets.items() for h in hs], notes)
        for (k, cat), es in done.items(): added.setdefault(cat, []).extend(es)
    else:
        for cat, hs in targets.items():
            for h in hs: added.setdefault(cat, []).extend(move_entry(ctx, "ip" if is_ip(h) else "domain", None, cat, h, notes))
    with data_lock(ctx):
        routed=load_routed(ctx.routed)
        for h in hosts: routed["direct"].pop(h, None); routed["proxy"].pop(h, None)
        save_routed(ctx.routed, routed)
    return added, notes

def promote(ctx, targets):
    """归类并从待审清单移除。targets: {cat: [域名或 IP/CIDR, ...]}。
    返回 [(cat, kind, 新增条目列表, notes)] 与从待审移除的主机列表。命令行与网页共用。"""
    groups=[]
    for cat in CAT_ORDER:
        toks=[x.strip() for x in targets.get(cat, []) if x.strip()]
        dom_toks=[t for t in toks if not is_ip_token(t)]; ip_toks=[t for t in toks if is_ip_token(t)]
        if dom_toks: groups.append((cat, "domain", dom_toks))
        if ip_toks:  groups.append((cat, "ip", ip_toks))
    # 先写规则，再动待审：写入失败（规则服务连不上等）时抛异常，待审不变。
    # 写规则服务要联网，放在数据锁外面，免得 watch 落盘时等锁超时。
    out=[]
    if ctx.dest and groups:
        notes=[]; done=dest_add(ctx, [(k, c, t) for c, k, ts in groups for t in ts], notes)
        out=[(c, k, done.get((k, c), []), notes if i==0 else []) for i, (c, k, _) in enumerate(groups)]
    else:
        for c, k, ts in groups:
            if k=="domain": notes=[]; added=add_domains(ctx, c, ts, notes)
            else: added, notes=add_ips(ctx, c, ts)
            out.append((c, k, added, notes))
    moved=[]
    with data_lock(ctx):
        pending=load_pending(ctx.pending)
        for c, k, ts in groups:
            if k=="domain":
                for d in ts:
                    key=d.lstrip("+.")
                    for pk in list(pending["domains"]):
                        if pk==key or pk.endswith("."+key) or pk==d: pending["domains"].pop(pk,None); moved.append(pk)
            else:
                for t in ts:
                    net=parse_net(t)
                    for pk in list(pending["ips"]):
                        if net is not None and parse_net(pk) is not None and parse_net(pk).subnet_of(net):
                            pending["ips"].pop(pk,None); moved.append(pk)
        save_pending(ctx.pending, pending)
    return out, sorted(set(moved))

def ignore_pending(ctx, hosts):
    """忽略：只从待审清单移除，不写任何规则集，也不记名单——以后再出现会重新进待审。
    用于一次性的噪声（测试站、打错的网址、命令行误把文件名当网址等）。返回实际移除的主机。"""
    want={h.strip() for h in hosts if h.strip()}; removed=[]
    with data_lock(ctx):
        pending=load_pending(ctx.pending)
        for sec in ("domains","ips"):
            for h in list(pending[sec]):
                if h in want: pending[sec].pop(h); removed.append(h)
        if removed: save_pending(ctx.pending, pending)
    return sorted(removed)

def cmd_ignore(ctx, args):
    removed=ignore_pending(ctx, args.hosts.split(","))
    print(f"已从待审移除（未写规则）: {removed}" if removed else "待审里没有这些主机。")

def cmd_promote(ctx, args):
    targets={cat: getattr(args,cat).split(",") for cat in CAT_ORDER if getattr(args,cat)}
    try: out, moved=promote(ctx, targets)
    except DestError as e:
        print(f"没有写入，待审不变：{e}", file=sys.stderr); sys.exit(1)
    for cat, kind, added, notes in out:
        for n in notes: print("  ·", n)
        k="域名" if kind=="domain" else "IP"
        print(f"[{cat}/{k}] 写入{len(added)}条: {added}" if added else f"[{cat}/{k}] 无新增(已覆盖)")
    if moved: print(f"已从待审移除: {moved}")
    if ctx.dest: print("写进了规则服务：上线后常驻的 watch（或打开的网页）会让 Clash 重新取，不用重新激活。")
    else: print("⚠ 归类后请在 Clash Verge 对相应配置【右键→重新激活】(或点🔥)生效。")

# ---------------- status：配置目录与内核实际加载是否一致 ----------------
# 内核读的是 C:\ProgramData\clash-verge-service\users\<hash>\runtime\ruleset\ 下的副本，Clash Verge
# 「重新激活」时才复制过去。副本保留原文件的修改时间，内核 /providers/rules 的 updatedAt 即该时间，
# 故「updatedAt 与配置目录文件的修改时间相同、条目数相同」即已同步。
FALLBACK_HOSTS = {"iptoasn.com": "update-ipdata 下载"}  # 本工具经代理回退时要访问的域名；别的工具的写在 settings.json 的 fallback_hosts

def fallback_hosts():
    return {**FALLBACK_HOSTS, **(settings().get("fallback_hosts") or {})}

def _watch_running(ctx):
    """watch 持有 var/watch.lock；能锁上说明没有 watch 在跑。"""
    try:
        import msvcrt
    except ImportError:
        return None
    p=os.path.join(ctx.review, "watch.lock")
    if not os.path.exists(p): return False
    try:
        with open(p, "a") as f:
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        return False
    except OSError:
        return True

def scanlog_tail(ctx, n=3):
    if not os.path.exists(ctx.scanlog): return []
    with open(ctx.scanlog, encoding="utf-8", errors="ignore") as f: return f.read().splitlines()[-n:]

# ---------------- 人工裁定日志（测试题的来源）----------------
# 网页上每次「应用」，把这一项当时的证据快照、模型当时的推荐与人的决定追加到 var/testcases/decisions.jsonl。
# 真实测试题由日常审查顺带积累，不再手工冻结：待审处理后条目就被移除，事后冻结赶不上。
# 评估（eval_decisions.py）比对模型推荐与人的决定；上次评估后的新裁定达到阈值时，status 与网页顶栏提醒。
DECISIONS_DUE = 20                  # 新裁定达到这么多条就提醒评估
DECISIONS_DUE_SLOW = (10, 7)        # 或者：至少 10 条，且距上次评估（或第一条裁定）已 7 天

def decisions_path(ctx): return os.path.join(ctx.review, "testcases", "decisions.jsonl")
def decisions_eval_path(ctx): return os.path.join(ctx.review, "testcases", "decisions_eval.json")

def append_decisions(ctx, entries):
    if not entries: return
    p=decisions_path(ctx); os.makedirs(os.path.dirname(p), exist_ok=True)
    with data_lock(ctx), open(p, "a", encoding="utf-8") as f:
        for e in entries: f.write(json.dumps(e, ensure_ascii=False)+"\n")

def load_decisions(ctx):
    p=decisions_path(ctx)
    if not os.path.exists(p): return []
    with open(p, encoding="utf-8") as f: return [json.loads(l) for l in f if l.strip()]

def decisions_status(ctx):
    """{total, new, since, due}：new 为上次评估之后的新裁定条数。"""
    ds=load_decisions(ctx)
    try:
        with open(decisions_eval_path(ctx), encoding="utf-8") as f: ev=json.load(f)
    except (OSError, ValueError): ev={"evaluated": 0, "time": ""}
    new=ds[ev.get("evaluated", 0):]
    since=ev.get("time") or (new[0]["time"] if new else "")
    days=(datetime.datetime.now()-datetime.datetime.fromisoformat(since)).days if since else 0
    due=len(new)>=DECISIONS_DUE or (len(new)>=DECISIONS_DUE_SLOW[0] and days>=DECISIONS_DUE_SLOW[1])
    return {"total": len(ds), "new": len(new), "since": since, "due": due}

def status_data(ctx, live=False):
    """status 的数据部分（命令行与网页共用）。bad 为需要处理的问题列表，空即一切正常。
    live：配了规则服务时当场问一次服务端（命令行）；网页顶栏刷新得勤，用缓存。"""
    d={"core":None, "core_error":"", "generated":"", "sets":[], "fallback":[], "watch":None,
       "last_log":"", "pending":{}, "routed":0, "bad":[], "names":ctx.names, "proxy_group":ctx.proxy_group,
       "match":ctx.layout["match"], "guessed":ctx.guessed, "order":list(ctx.order["domain"])}
    bad=d["bad"]; provs=None
    if not ctx.layout["found"]: bad.append("配置目录里没有 clash-verge.yaml，规则集名与代理组读不到（先在 Clash Verge 里激活一次配置）")
    if ctx.guessed and not ctx.dest: bad.append("规则里找不到这些规则集，按默认名猜的：" + "、".join(ctx.guessed) + "（在 settings.json 的 rulesets 里指定）")
    d["dest"]=dest_status(ctx, bad, live) if ctx.dest else None
    if ctx.layout["found"] and (ctx.layout["match"] or "").upper()!="REJECT":
        bad.append(f"规则最后一条是 MATCH,{ctx.layout['match']}，不是 MATCH,REJECT：没有「漏网」，待审清单不会有东西")
    try:
        v=pipe_get("/version"); c=pipe_get("/configs"); provs=pipe_get("/providers/rules").get("providers", {})
        d["core"]={"pipe":os.path.basename(find_core_pipes()[0]), "version":v.get("version"),
                   "mode":c.get("mode"), "find_process_mode":c.get("find-process-mode")}
        if c.get("find-process-mode")!="always": bad.append("find-process-mode 不是 always，漏网项记不到进程名")
    except Exception as e:
        d["core_error"]=str(e); bad.append("连不上内核")
    gen=os.path.join(ctx.cfg, "clash-verge.yaml")
    if os.path.exists(gen):
        d["generated"]=f"{datetime.datetime.fromtimestamp(os.path.getmtime(gen)):%Y-%m-%d %H:%M:%S}"
    # 收件箱（本工具写入）：按类列出，比对条目数与修改时间，与旧版一致
    for kind, files in (("domain", ctx.dom_files), ("ip", ctx.ip_files)):
        for cat in CAT_ORDER:
            path=os.path.join(ctx.ruleset, files[cat]); name=ctx.names[kind][cat]
            n_file=len(load_payload(path))
            mt=datetime.datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M:%S") if os.path.exists(path) else ""
            s={"name":name, "kind":kind, "cat":cat, "count":n_file, "mtime":mt, "core_count":None, "core_mtime":"", "state":"unknown",
               "inbox":True, "type":"file", "vehicle":""}
            if provs is not None:
                p=provs.get(name)
                if p is None:
                    s["state"]="missing"; bad.append(f"{name} 未被内核加载")
                else:
                    s["core_mtime"]=str(p.get("updatedAt",""))[:19].replace("T", " "); s["core_count"]=p.get("ruleCount")
                    s["vehicle"]=p.get("vehicleType") or ""
                    if s["core_mtime"]==mt and s["core_count"]==n_file: s["state"]="ok"
                    else: s["state"]="stale"; bad.append(f"{name} 改动未生效")
            d["sets"].append(s)
    # 只读规则集（http 与收件箱之外的 file）：按规则顺序。http 的由内核按网址取，本工具读 path 处的本地缓存，
    # 只比条目数（内核的 updatedAt 是取线上的时间，不是缓存文件的修改时间）；file 的同收件箱，改了要重新激活
    for rs in ctx.sets:
        if rs["inbox"]: continue
        name=rs["name"]; path=rs["path"]
        got=ctx.dest.items_for(rs) if ctx.dest else None      # 规则服务的规则集：比的是服务端的条目，不是本地缓存
        items, err = got if got is not None else read_set(rs)
        if got is not None: raw=max(1, len(items))            # 空清单在文件里是一条占位，内核也算一条
        else: raw=len(load_payload(path)) if not err and rs["format"]=="yaml" else len(items)     # 与内核比对的条数含占位
        mt=datetime.datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M:%S") if path and os.path.exists(path) else ""
        s={"name":name, "kind":rs["kind"], "cat":rs["cat"], "count":None if err else raw, "mtime":mt, "core_count":None,
           "core_mtime":"", "state":"unknown", "inbox":False, "type":rs["type"], "vehicle":"", "path":path or "", "error":err or ""}
        if err: s["state"]="unreadable"; bad.append(f"{name} {err}：「已有规则」的判断里缺了这一集")
        if provs is not None:
            p=provs.get(name)
            if p is None:
                s["state"]="missing"; bad.append(f"{name} 未被内核加载")
            else:
                s["core_mtime"]=str(p.get("updatedAt",""))[:19].replace("T", " "); s["core_count"]=p.get("ruleCount")
                s["vehicle"]=p.get("vehicleType") or ""
                if err: pass
                elif rs["type"]=="http":
                    if s["core_count"]==raw: s["state"]="ok"
                    else:
                        s["state"]="differ"
                        bad.append(f"{name} 规则服务上 {raw} 条，内核 {s['core_count']} 条：内核还没取到最新（已提交的上线后会自动重取）" if got is not None
                                   else f"{name} 本地缓存 {raw} 条，内核 {s['core_count']} 条：缓存不是内核在用的那份，「已有规则」按缓存判断")
                elif s["core_mtime"]==mt and s["core_count"]==raw: s["state"]="ok"
                else: s["state"]="stale"; bad.append(f"{name} 改动未生效")
        d["sets"].append(s)
    # 回退域名：按规则顺序第一个覆盖它的规则集须是代理类（收件箱或只读的都行）
    for h, why in fallback_hosts().items():
        fs, fp = first_match(ctx, "domain", h)
        ok=fs is not None and fs["cat"]=="proxy"
        d["fallback"].append({"host":h, "why":why, "ok":ok, "by":fs["name"] if fs else "", "by_cat":fs["cat"] if fs else ""})
        if not ok: bad.append(f"{h} 未放行")
    d["watch"]=_watch_running(ctx)
    if d["watch"] is False: bad.append("watch 未运行（计划任务 ClashVerge-LeakScan）")
    last=scanlog_tail(ctx, 1); d["last_log"]=last[0] if last else ""
    pending=load_pending(ctx.pending); routed=load_routed(ctx.routed)
    d["pending"]={"domains":len(pending["domains"]), "ips":len(pending["ips"])}
    d["routed"]=len(routed["direct"])+len(routed["proxy"])
    d["decisions"]=decisions_status(ctx)
    return d

def dest_status(ctx, bad, live=False):
    """规则服务目的地的现状：连得上没有、密钥对不对、每类写进哪个规则集、Clash 里对不对得上、已提交的上线没有。
    live：当场问一次服务端（命令行 status）；否则用缓存的服务端条目判断（网页顶栏常刷新，每次联网要一两秒）。"""
    dest=ctx.dest
    try:
        if dest.pending(): dest.settle()
    except Exception: pass
    out={"endpoint": dest.endpoint, "admin_url": dest.admin_url, "ok": False, "error": "", "head": "", "expires": "",
         "targets": [], "submitted": dest.load()["submitted"]}
    if live:
        try:
            status, headers, js = dest.call("GET", "/rulesets")
            if status==200 and isinstance(js, list):
                out.update(ok=True, head=headers.get("x-head", ""), expires=headers.get("x-credential-expires", ""))
            elif status==401: out["error"]="写入密钥不对"
            else: out["error"]=f"HTTP {status}：{(js or {}).get('detail', '') if isinstance(js, dict) else ''}"
        except DestError as e:
            out["error"]=str(e); js=None
        ids={s["id"]: s for s in js} if out["ok"] else {}
        snap=dest.snapshot()
    else:
        snap=dest.snapshot()
        if snap and not snap.get("stale"): out.update(ok=True, head=snap.get("head", ""), expires=snap.get("expires", ""))
        else: out["error"]=(snap or {}).get("stale") or dest.last_error or "还没取到规则服务上的规则集"
        ids={s["id"]: s for s in snap["sets"]} if out["ok"] else {}
    if not out["ok"]: bad.append(f"规则服务：{out['error']}（归类写不进去）")
    for kind in ("domain", "ip"):
        for cat in CAT_ORDER:
            rid=(dest.rulesets.get(kind) or {}).get(cat)
            prov=next((s["name"] for s in ctx.sets if s["type"]=="http" and (m:=Destination.match(s.get("url"), snap)) and m["id"]==rid), "") if rid else ""
            t={"kind": kind, "cat": cat, "id": rid or "", "exists": bool(rid and rid in ids), "provider": prov}
            out["targets"].append(t)
            what=f"{CAT_CN[cat]}{'IP' if kind=='ip' else '域名'}"
            if not rid: bad.append(f"规则服务：没有指定{what}写进哪个规则集（settings.json 的 destination.rulesets）")
            elif out["ok"] and not t["exists"]: bad.append(f"规则服务上没有规则集 {rid}（{what}）")
            elif snap and not prov: bad.append(f"Clash 配置里没有对应 {rid} 的规则集：写进去后这台电脑用不上")
    if out["expires"]:
        try:
            left=(datetime.datetime.strptime(out["expires"][:19], "%Y-%m-%d %H:%M:%S")-datetime.datetime.now()).days
            if left<30: bad.append(f"规则服务的 GitHub 令牌 {left} 天后到期")
        except ValueError: pass
    for r in out["submitted"]:
        if r["state"] in ("failed", "timeout"):
            bad.append(f"规则服务：提交 {r['commit'][:7]} {'部署失败' if r['state']=='failed' else '超过半小时仍未上线'}（{', '.join(r['entries'][:3])}）")
    return out

def cmd_status(ctx, args):
    d=status_data(ctx, live=True); bad=d["bad"]
    print("【内核】")
    if d["core"]:
        c=d["core"]
        print(f"  管道   {c['pipe']}")
        print(f"  版本   {c['version']}   模式 {c['mode']}   find-process-mode {c['find_process_mode']}")
    else:
        print(f"  ✗ {d['core_error']}")
    if d["generated"]: print(f"  Clash Verge 最近一次生成配置  {d['generated']}")
    print(f"  代理组 {d['proxy_group'] or '（未检测到）'}   兜底 MATCH,{d['match'] or '?'}")

    inbox=[s for s in d["sets"] if s["inbox"]]; ro=[s for s in d["sets"] if not s["inbox"]]
    w=max([13]+[len(s["name"]) for s in d["sets"]])
    print("\n【收件箱（本工具写入，type: file）：配置目录 vs 内核已加载】")
    if d["core"] is None: print("  （连不上内核，无法比对）")
    else:
        for s in inbox:
            if s["state"]=="missing": print(f"  ✗ {s['name']:{w}} 内核未加载该规则集")
            elif s["state"]=="ok":    print(f"  ✓ {s['name']:{w}} {s['count']:>4} 条  {s['mtime']}")
            else: print(f"  ✗ {s['name']:{w}} 配置目录 {s['count']} 条 / {s['mtime']}，内核 {s['core_count']} 条 / {s['core_mtime']}")

    if ro:
        print("\n【其它规则集（只读，一并算作已有规则；http 读本地缓存）：本地 vs 内核已加载】")
        for s in ro:
            tag=f"{s['type']:4} {CAT_CN[s['cat']]}{'IP' if s['kind']=='ip' else '域名'}"
            core=f"内核 {s['vehicle'] or '?'} {s['core_count']} 条 / {'取于 ' if s['type']=='http' else ''}{s['core_mtime']}" \
                 if s["core_count"] is not None else ("内核未加载" if s["state"]=="missing" else "（连不上内核）")
            if s["state"]=="unreadable": print(f"  ✗ {s['name']:{w}} {tag}  {s['error']}；{core}")
            elif s["state"]=="ok":       print(f"  ✓ {s['name']:{w}} {tag}  {s['count']:>4} 条  {core}")
            elif s["state"]=="unknown":  print(f"  · {s['name']:{w}} {tag}  本地 {s['count']} 条  {core}")
            else:                        print(f"  ✗ {s['name']:{w}} {tag}  本地 {s['count']} 条 / {s['mtime']}，{core}")

    if d["dest"]:
        x=d["dest"]
        print("\n【写入目的地：规则服务】")
        print(f"  {'✓' if x['ok'] else '✗'} {x['endpoint']}" + (f"  main {x['head'][:7]}" if x["head"] else "") + (f"  {x['error']}" if x["error"] else ""))
        if x["expires"]: print(f"    GitHub 令牌到期 {x['expires']}")
        for t in x["targets"]:
            what=f"{CAT_CN[t['cat']]}{'IP' if t['kind']=='ip' else '域名'}"
            mark="✓" if t["id"] and (t["exists"] or not x["ok"]) and t["provider"] else "✗"
            print(f"  {mark} {what:6} → {t['id'] or '（未指定）'}" + (f"  Clash 里是 {t['provider']}" if t["provider"] else "  Clash 里没有对应的规则集"))
        for r in x["submitted"][-5:]:
            st={"pending": "等待上线", "live": "已上线", "failed": "部署失败", "timeout": "未上线（已不再等）"}[r["state"]]
            print(f"  · {r['commit'][:7]} {st}  {', '.join(r['entries'][:3])}" + (f"  {r['kernel']}" if r.get("kernel") else ""))
        if x["admin_url"]: print(f"  检索、修改已有规则：{x['admin_url']}")

    print("\n【工具回退所需的代理放行】")
    hw=max([14]+[len(f["host"]) for f in d["fallback"]])
    for f in d["fallback"]:
        if f["ok"]: print(f"  ✓ {f['host']:{hw}} {f['why']}（{f['by']}）")
        elif f["by"]: print(f"  ✗ {f['host']:{hw}} {f['why']}：按规则顺序先命中 {f['by']}（{CAT_CN[f['by_cat']]}），经代理回退"
                            + ("会被拒绝" if f["by_cat"]=="reject" else "不经节点、直接连"))
        else: print(f"  ✗ {f['host']:{hw}} {f['why']}：不在任何代理规则集，经代理回退会落到 MATCH,{d['match'] or 'REJECT'}")

    print("\n【采集】")
    run=d["watch"]
    print(f"  watch  {'运行中' if run else ('未运行' if run is False else '未知')}")
    if d["last_log"]: print(f"  最近   {d['last_log']}")
    print(f"  待审   域名 {d['pending']['domains']}  IP {d['pending']['ips']}    地域放行 {d['routed']}")
    ds=d["decisions"]
    print(f"  裁定   累计 {ds['total']} 条，上次评估后新增 {ds['new']} 条" + ("  → 可以评估：python eval_decisions.py" if ds["due"] else ""))

    print()
    if bad:
        print("需要处理：")
        for b in bad: print("  ·", b)
        if any("未生效" in b for b in bad):
            print("  → 规则集改动未生效：在 Clash Verge 对当前配置【右键→重新激活】。")
        sys.exit(1)
    print("一切正常。")

# ---------------- tidy：体检现有规则集 ----------------
RESERVED_SUFFIXES = (".invalid", ".example", ".test", ".localhost")
RESERVED_NAMES    = {"example.com", "example.net", "example.org"}
MERGE_MIN         = 3     # 同一父域下达到这么多个子主机才列为合并候选

def ruleset_audit(ctx):
    """只读体检。返回 dict：
    redundant  [(kind,cat,entry,by)]  同类中已被更大范围条目覆盖的条目（删除不改变行为）
    placeholder[(kind,cat)]           有真实条目时仍残留的占位条目
    reserved   [(cat,entry)]          保留域名（.invalid/.example 等），多为测试残留
    overlap    [str]                  跨类重叠及生效方
    merge      [(cat,parent,[hosts])] 同一父域下的多个子主机（只作候选，需人工确认）"""
    rep={"redundant":[], "placeholder":[], "reserved":[], "overlap":[], "merge":[]}
    D={c: load_payload(os.path.join(ctx.ruleset, ctx.dom_files[c])) for c in CAT_ORDER}
    I={c: load_payload(os.path.join(ctx.ruleset, ctx.ip_files[c])) for c in CAT_ORDER}
    ph=ipaddress.ip_network(IP_PLACEHOLDER)
    for c in CAT_ORDER:
        real=[p for p in D[c] if p!=DOMAIN_PLACEHOLDER]
        if real and len(real)<len(D[c]): rep["placeholder"].append(("domain", c))
        for p in real:
            by=[o for o in real if o!=p and o.startswith("+.") and _dom_within(p, _dom_base(o))]
            if by: rep["redundant"].append(("domain", c, p, by[0]))
            b=_dom_base(p)
            if b.endswith(RESERVED_SUFFIXES) or b in RESERVED_NAMES: rep["reserved"].append((c, p))
        nets=[(p, parse_net(p)) for p in I[c] if parse_net(p) is not None]
        realn=[(p,n) for p,n in nets if not (n.version==ph.version and n.subnet_of(ph))]
        if realn and len(realn)<len(nets): rep["placeholder"].append(("ip", c))
        for p,n in realn:
            by=[o for o,m in realn if o!=p and m.version==n.version and n.subnet_of(m) and n!=m]
            if by: rep["redundant"].append(("ip", c, p, by[0]))
        parents=collections.defaultdict(list)
        for p in real:
            parts=_dom_base(p).split(".")
            if len(parts)>=3: parents[".".join(parts[-2:])].append(_dom_base(p))
        for par, hs in sorted(parents.items(), key=lambda x:-len(x[1])):
            if len(hs)>=MERGE_MIN and not any(_dom_base(x)==par for x in real):
                rep["merge"].append((c, par, hs))
    # 收件箱条目已被只读规则集（http 等）的同类条目覆盖：在前面的，收件箱这条本来就不起作用；在后面的，
    # 两者之间没有别的类与它范围相交的条目时，删掉它仍落到同一类（典型：收件箱的条目已并入线上规则集）
    _redundant_across(ctx, "domain", rep)
    _redundant_across(ctx, "ip", rep)
    sets=ctx.payloads("domain")     # 全部域名规则集，按规则顺序，前面的先命中
    for i,(sa,A) in enumerate(sets):
        for sb,B in sets[i+1:]:
            if sa["cat"]==sb["cat"]: continue
            for p in B:
                hit=[o for o in A if domain_covered(_dom_base(p), [o])]
                if hit: rep["overlap"].append(f"{_lab(sb)} {p} 落在{_lab(sa)} {', '.join(hit)} 内 → {_who(sa)}生效，该条不起作用")
            for p in A:   # 先命中的里有更窄的条目：在后面的大范围里挖出例外（范围相同的已在上面报过）
                hit=[o for o in B if _dom_base(o)!=_dom_base(p) and domain_covered(_dom_base(p), [o])]
                if hit: rep["overlap"].append(f"{_lab(sa)} {p} 落在{_lab(sb)} {', '.join(hit)} 内 → 该子域{_who(sa)}（例外）")
    return rep

def _scope_covers(kind, o, p):
    """条目 o 匹配的范围是否包含条目 p 的全部范围。"""
    if kind=="ip":
        n, m = parse_net(p), parse_net(o)
        return n is not None and m is not None and n.version==m.version and n.subnet_of(m)
    if o.strip().startswith("+."): return _dom_within(p, _dom_base(o))
    return not p.strip().startswith("+.") and _dom_base(p)==_dom_base(o)

def _scope_meets(kind, a, b):
    """两个条目匹配的范围是否相交。"""
    if kind=="ip":
        n, m = parse_net(a), parse_net(b)
        return n is not None and m is not None and n.version==m.version and n.overlaps(m)
    return domain_covered(_dom_base(a), [b]) or domain_covered(_dom_base(b), [a])

def _redundant_across(ctx, kind, rep):
    sets=ctx.payloads(kind)
    known={(k, c, p) for k, c, p, _ in rep["redundant"]}
    blind=[n for n in ctx.unreadable if any(s["name"]==n and s["kind"]==kind for s in ctx.sets)]
    for s, items in sets:
        if not s["inbox"]: continue
        for p in items:
            if (kind, s["cat"], p) in known: continue
            for t, T in sets:
                if t["inbox"] or t["cat"]!=s["cat"]: continue
                o=next((o for o in T if _scope_covers(kind, o, p)), None)
                if o is None: continue
                if t["rank"]>s["rank"]:
                    lo, hi = s["rank"], t["rank"]
                    if blind and any(x["rank"] in range(lo+1, hi) for x in ctx.sets if x["name"] in blind): continue
                    if any(_scope_meets(kind, p, q) for u, U in sets if lo<u["rank"]<hi and u["cat"]!=s["cat"] for q in U): continue
                rep["redundant"].append((kind, s["cat"], p, f"{t['name']} 的 {o}")); break

def cmd_tidy(ctx, args):
    rep=ruleset_audit(ctx)
    print("【可自动清理（删除后匹配行为不变）】")
    for kind,c,p,by in rep["redundant"]: print(f"  冗余  {CAT_CN[c]}/{'域名' if kind=='domain' else 'IP'}  {p}  ← 已被 {by} 覆盖")
    for kind,c in rep["placeholder"]:    print(f"  占位  {CAT_CN[c]}/{'域名' if kind=='domain' else 'IP'}  已有真实条目，占位条目可删")
    if not rep["redundant"] and not rep["placeholder"]: print("  （无）")
    print("\n【需人工确认】")
    for c,p in rep["reserved"]: print(f"  保留域名  {CAT_CN[c]}  {p}（.invalid/.example 等不会出现在真实流量里，多为测试残留）")
    for s in rep["overlap"]:    print(f"  跨类重叠  {s}")
    for c,par,hs in rep["merge"]:
        print(f"  合并候选  {CAT_CN[c]}  {par} 下 {len(hs)} 个：{', '.join(hs)}")
    if rep["merge"]:
        print("  ↳ 父域可能是大站或公共后缀（如 microsoft.com、免费子域服务），合并前逐个确认；"
              "确认后用 promote --<类> <父域> 写入，本类中被覆盖的子条目会自动移除。")
    if not (rep["reserved"] or rep["overlap"] or rep["merge"]): print("  （无）")
    if not getattr(args, "apply", False):
        if rep["redundant"] or rep["placeholder"]: print("\n加 --apply 执行「可自动清理」部分。")
        return
    for line in tidy_apply(ctx, rep): print(line)
    print("⚠ 请在 Clash Verge 对相应配置【右键→重新激活】(或点🔥)生效。")

def tidy_apply(ctx, rep=None):
    """执行体检里「可自动清理」的部分（冗余条目与残留占位）。返回每个改动文件一行说明。"""
    rep=rep or ruleset_audit(ctx); out=[]
    changed=set((k,c) for k,c,_,_ in rep["redundant"]) | set(rep["placeholder"])
    for kind,c in sorted(changed):
        drop={p for k,cc,p,_ in rep["redundant"] if k==kind and cc==c}
        path=ruleset_path(ctx, kind, c)
        ph=DOMAIN_PLACEHOLDER if kind=="domain" else IP_PLACEHOLDER
        keep=[p for p in load_payload(path) if p not in drop and p!=ph]
        _write_payload(path, keep, ph)
        out.append(f"已清理 {CAT_CN[c]}/{'域名' if kind=='domain' else 'IP'}：移除 {len(drop)} 条冗余" +
                   ("，移除占位" if (kind,c) in rep["placeholder"] else ""))
    return out

# ---------------- update-ipdata（唯一联网命令）----------------
def _download(url, proxy=None, timeout=60):
    handlers=[]
    if proxy: handlers.append(urllib.request.ProxyHandler({"http":proxy,"https":proxy}))
    else:     handlers.append(urllib.request.ProxyHandler({}))   # 显式不走系统代理
    opener=urllib.request.build_opener(*handlers)
    req=urllib.request.Request(url, headers={"User-Agent":"clash-review/ipdata"})
    with opener.open(req, timeout=timeout) as r:
        return r.read()

def cmd_update_lists(ctx, args):
    """(联网) 下载第 3 层用的拦截名单与 v2fly 域名分类到 var/lists/ 并重建索引（见 external.py）。"""
    import external
    for fn, r in external.update(proxy=None if getattr(args, "no_proxy", False) else mixed_port_url(ctx)):
        print(f"  {fn}: " + (f"{r/1024/1024:.1f} MB" if isinstance(r, int) else f"失败 {r}"))
    _append_scanlog(ctx, "update-lists done")

def cmd_update_data(ctx, args):
    """月度任务调用：update-ipdata 与 update-lists 各跑一次，一个失败不影响另一个。"""
    for name, fn in (("update-ipdata", cmd_update_ipdata), ("update-lists", cmd_update_lists)):
        print(f"[{name}]")
        try: fn(ctx, args)
        except Exception as e:
            print(f"  失败：{type(e).__name__}: {e}"); _append_scanlog(ctx, f"{name} failed: {type(e).__name__}")

def cmd_update_ipdata(ctx, args):
    os.makedirs(ipdata_dir(), exist_ok=True)
    dst=os.path.join(ipdata_dir(), IP2ASN_NAME)
    proxy = None if args.no_proxy else mixed_port_url(ctx)
    data=None; via=""
    try:
        data=_download(IP2ASN_URL, proxy=None); via="direct"
    except Exception as e1:
        if proxy:
            try:
                data=_download(IP2ASN_URL, proxy=proxy); via=f"proxy({proxy})"
            except Exception as e2:
                print(f"下载失败：直连 {e1}；代理 {e2}", file=sys.stderr); sys.exit(1)
        else:
            print(f"下载失败：{e1}", file=sys.stderr); sys.exit(1)
    # 原子写
    fd,tmp=tempfile.mkstemp(dir=ipdata_dir(), suffix=".tmp"); os.close(fd)
    with open(tmp,"wb") as f: f.write(data)
    # 校验可解压
    try:
        with gzip.open(tmp,"rt",encoding="utf-8",errors="ignore") as f:
            n=sum(1 for _ in zip(range(3), f))
        assert n>0
    except Exception as e:
        os.remove(tmp); print(f"下载内容非法 gzip：{e}", file=sys.stderr); sys.exit(1)
    os.replace(tmp, dst)
    mb=len(data)/1048576.0
    print(f"ip2asn 已更新 via={via}: {dst} ({mb:.1f} MB, {datetime.datetime.now():%Y-%m-%d %H:%M:%S})")
    print("来源：iptoasn.com（公有领域，非国内）。list 现可离线标注 IP 的 ASN/组织/国家。")

# ---------------- main ----------------
def main():
    parent=argparse.ArgumentParser(add_help=False)
    # 子命令前后都能写。默认值用 SUPPRESS：否则子命令的解析器会用它的默认值 None 盖掉写在子命令前面的值，
    # 悄悄退回自动定位的配置目录（2026-09-25 因此把测试条目写进了真实的规则集）
    parent.add_argument("--config-dir", dest="config_dir", default=argparse.SUPPRESS, help="Clash Verge 配置目录(含 profiles.yaml)；默认自动定位")
    ap=argparse.ArgumentParser(prog="clash_review", parents=[parent], description="Clash Verge 漏网审查工具（域名+IP，独立运行）")
    sub=ap.add_subparsers(dest="cmd")
    sc=sub.add_parser("scan", parents=[parent], help="增量扫描核心日志，更新待审清单(域名+IP)")
    sc.add_argument("--baseline", action="store_true", help="只把高水位推进到现有日志末尾、不计数")
    wt=sub.add_parser("watch", parents=[parent], help="常驻：订阅内核日志流，每 --every 条连接日志落盘一次")
    wt.add_argument("--every", type=int, default=200, help="每累计多少条连接日志合并落盘一次(默认200)")
    sub.add_parser("list", parents=[parent], help="查看待审清单(IP 自动标注)")
    rt=sub.add_parser("routed", parents=[parent], help="查看地域放行清单(被地域规则直接路由、进不了漏网审查的域名/IP)")
    rt.add_argument("--filter", default="", help="按子串过滤(如 ads/track/beacon/stat)")
    rt.add_argument("--top", type=int, default=60, help="每桶最多显示多少项(默认60)")
    rt.add_argument("--suggest", action="store_true", help="按可疑度排序（关键词/与已拉黑相似/跨站出现/随机子域），附理由")
    rt.add_argument("--ok", default="", help="把这些主机标记为看过、正常（逗号分隔），suggest 不再列出")
    rt.add_argument("--unok", default="", help="取消看过标记")
    pp=sub.add_parser("promote", parents=[parent], help="归类待审目标(域名或IP/CIDR自动分流)")
    pp.add_argument("--proxy",default=""); pp.add_argument("--direct",default=""); pp.add_argument("--reject",default="")
    ig=sub.add_parser("ignore", parents=[parent], help="忽略：只从待审移除，不写规则（再出现会回来）")
    ig.add_argument("hosts", help="逗号分隔的主机或 IP，须与待审里的写法一致")
    rj=sub.add_parser("rejects", parents=[parent], help="拉黑命中统计：各拉黑条目被连了多少次（watch 运行时累计）")
    rj.add_argument("--filter", default="", help="按子串过滤条目或主机")
    rj.add_argument("--top", type=int, default=60, help="最多显示多少条(默认60)")
    rj.add_argument("--zero", action="store_true", help="另列出统计起点以来没有命中的拉黑条目")
    rj.add_argument("--hours", type=int, default=0, help="每条下面另列最近 N 个小时的逐时次数")
    tf=sub.add_parser("traffic", parents=[parent], help="流量统计：各主机的连接数与上传 / 下载字节（watch 运行时累计）")
    tf.add_argument("--filter", default=""); tf.add_argument("--top", type=int, default=60)
    tf.add_argument("--sort", choices=["down", "up", "conns", "ratio"], default="down", help="ratio=上传/下载比，从高到低（找上报）")
    sub.add_parser("status", parents=[parent], help="核对：规则集改动是否已被内核加载、watch 是否在跑、回退域名是否放行")
    td=sub.add_parser("tidy", parents=[parent], help="体检六个规则集：冗余、残留占位、保留域名、跨类重叠、合并候选")
    td.add_argument("--apply", action="store_true", help="执行可自动清理的部分（冗余条目与残留占位）")
    up=sub.add_parser("update-ipdata", parents=[parent], help="(联网)下载 IP→ASN 数据集到 var/ipdata/")
    up.add_argument("--no-proxy", action="store_true", help="只直连，不回退本机代理（Clash 的 mixed-port）")
    ul=sub.add_parser("update-lists", parents=[parent], help="(联网)下载拦截名单与 v2fly 域名分类到 var/lists/")
    ul.add_argument("--no-proxy", action="store_true")
    ud=sub.add_parser("update-data", parents=[parent], help="(联网)update-ipdata + update-lists，月度任务用")
    ud.add_argument("--no-proxy", action="store_true")
    args=ap.parse_args()
    cfg=resolve_config_dir(getattr(args, "config_dir", None))
    if args.cmd not in ("update-ipdata", "update-lists", "update-data") and not os.path.isfile(os.path.join(cfg,"profiles.yaml")):
        print(f"未定位到 Clash Verge 配置目录(缺 profiles.yaml)。当前推断: {cfg}\n可用 --config-dir 指定。", file=sys.stderr); sys.exit(2)
    ctx=Ctx(cfg)
    if   args.cmd=="scan":          cmd_scan(ctx,args)
    elif args.cmd=="watch":         cmd_watch(ctx,args)
    elif args.cmd=="list":          cmd_list(ctx,args)
    elif args.cmd=="routed":        cmd_routed(ctx,args)
    elif args.cmd=="promote":       cmd_promote(ctx,args)
    elif args.cmd=="ignore":        cmd_ignore(ctx,args)
    elif args.cmd=="tidy":          cmd_tidy(ctx,args)
    elif args.cmd=="rejects":       cmd_rejects(ctx,args)
    elif args.cmd=="traffic":       cmd_traffic(ctx,args)
    elif args.cmd=="status":        cmd_status(ctx,args)
    elif args.cmd=="update-ipdata": cmd_update_ipdata(ctx,args)
    elif args.cmd=="update-lists":  cmd_update_lists(ctx,args)
    elif args.cmd=="update-data":   cmd_update_data(ctx,args)
    else: ap.print_help()

if __name__=="__main__":
    main()
