# -*- coding: utf-8 -*-
"""
webkit —— 本地网页工具共用的服务端外壳（仅标准库），按 ui-style 第 3 节「后台运行，不留无用的窗口」。

有什么：
  setup_log(var_dir)        pythonw 启动（没有控制台）时把输出写到工具的 var/web.log
  fail(msg, title)          启动失败：有控制台就打印，没有就弹系统对话框，然后退出
  ExclusiveServer / bind()  只绑 127.0.0.1 的多线程服务，独占端口（Windows 上默认的 SO_REUSEADDR 会让两个进程绑同一端口）
  already_running / stop    查同一端口上是否已有本工具；--stop 的客户端（POST /api/shutdown）
  IdleWatch                 连续若干分钟没有任何请求就关服务；busy() 为真时不关（有后台任务在跑）
  read_displays             向 Windows 读各显示器的物理分辨率与系统缩放（per-monitor DPI 感知）
  Prefs                     显示设置的默认值 var/ui_prefs.json 的读写，按 schemes.json 做白名单校验
  kit_asset                 送出 /kit/kit.js、/kit/kit.css：把 schemes.json 注入进去（取值只有一处）
  Handler                   请求处理基类：Host 头校验（防 DNS 重绑定）；写操作要求自定义请求头并校验 Origin；
                            /api/ping、/api/shutdown、/api/display、/api/prefs、/kit/*、静态文件，其余交给工具的路由表

没有什么：页面内容与业务接口（各工具自己的 GET / POST 表）、页面样式。
用法见上游 README「接入清单」。每个工具在自己目录里带一份（<工具目录>/web-kit/），只导入自己那份；副本与上游由比对脚本保证一致。
"""
import os, sys, json, time, datetime, threading, urllib.request, urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

KIT_DIR = os.path.dirname(os.path.abspath(__file__))


class ApiError(Exception):
    """业务接口里抛出：以 400 与这句话回给页面。"""


def log(msg):
    print(f"[{datetime.datetime.now():%Y-%m-%d %H:%M:%S}] {msg}")


# ---------------- 后台运行：输出与失败提示 ----------------
HEADLESS = sys.stdout is None          # pythonw 启动：没有控制台

def setup_log(var_dir):
    """没有控制台时把 stdout / stderr 接到 var/web.log（print 在 pythonw 下会因 stdout 为 None 报错）；有控制台时改用 UTF-8 输出。"""
    if HEADLESS:
        os.makedirs(var_dir, exist_ok=True)
        sys.stdout = sys.stderr = open(os.path.join(var_dir, "web.log"), "a", encoding="utf-8", buffering=1)
    elif hasattr(sys.stdout, "reconfigure"):
        try: sys.stdout.reconfigure(encoding="utf-8")
        except (ValueError, OSError): pass

def fail(msg, title):
    """启动失败：有控制台就打印，没有就弹对话框（否则用户什么也看不到）。"""
    print(msg, file=sys.stderr)
    if HEADLESS:
        import ctypes
        ctypes.windll.user32.MessageBoxW(None, msg, title, 0x10)
    sys.exit(2)


# ---------------- 服务与单实例 ----------------
class ExclusiveServer(ThreadingHTTPServer):
    """HTTPServer 默认开 SO_REUSEADDR，在 Windows 上会让两个进程同时绑定同一端口；改为独占。"""
    allow_reuse_address = False
    daemon_threads = True
    def server_bind(self):
        import socket
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

def bind(port, handler, wait_seconds=0):
    """在 127.0.0.1:port 上建服务。wait_seconds > 0 时端口被占就每 0.25 秒重试（接替正在退出的旧实例用）。失败抛最后一个 OSError。"""
    for i in range(max(1, int(wait_seconds * 4))):
        try:
            return ExclusiveServer(("127.0.0.1", port), handler)
        except OSError as e:
            err = e
            if wait_seconds: time.sleep(0.25)
    raise err

_NOPROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))

def already_running(port, signature):
    try:
        with _NOPROXY.open(urllib.request.Request(f"http://127.0.0.1:{port}/api/ping"), timeout=2) as r:
            return json.loads(r.read().decode("utf-8")).get("app") == signature
    except Exception:
        return False

def stop(port, header):
    """--stop：请正在运行的实例退出。返回是否有实例应答。"""
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/shutdown", data=b"{}", method="POST",
                                 headers={"Content-Type": "application/json", header: "1"})
    try:
        with _NOPROXY.open(req, timeout=3): return True
    except Exception: return False


# ---------------- 空闲退出 ----------------
class IdleWatch:
    """连续 minutes 分钟没有任何请求（页面开着时每 60 秒有一次 /api/ping）就关服务。busy() 为真时不关。"""
    def __init__(self, minutes, busy=None):
        self.minutes = minutes; self.busy = busy or (lambda: False); self.last = time.time()
    def touch(self):
        self.last = time.time()
    def start(self, srv):
        self.last = time.time()
        def watch():
            while True:
                time.sleep(min(30, self.minutes * 60 / 4))
                if time.time() - self.last > self.minutes * 60 and not self.busy():
                    log(f"{self.minutes} 分钟没有请求，自动退出")
                    srv.shutdown(); return
        threading.Thread(target=watch, daemon=True).start()


# ---------------- 本机显示参数（系统层面，与浏览器缩放无关）----------------
# 页面里的 devicePixelRatio = 系统缩放 × 浏览器缩放，两者分不开；由服务直接向 Windows 读系统缩放，
# 页面据此反推浏览器缩放。做法与作者的 display-info 工具相同：须 per-monitor DPI 感知。
def read_displays():
    import ctypes
    from ctypes import wintypes
    user32 = ctypes.windll.user32; shcore = ctypes.windll.shcore
    user32.SetThreadDpiAwarenessContext(ctypes.c_void_p(-4))      # 只影响本线程
    class MONITORINFOEXW(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD), ("rcMonitor", wintypes.RECT), ("rcWork", wintypes.RECT),
                    ("dwFlags", wintypes.DWORD), ("szDevice", wintypes.WCHAR * 32)]
    out = []
    PROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HMONITOR, wintypes.HDC, ctypes.POINTER(wintypes.RECT), wintypes.LPARAM)
    def cb(hmon, hdc, rect, lp):
        mi = MONITORINFOEXW(); mi.cbSize = ctypes.sizeof(mi)
        user32.GetMonitorInfoW(hmon, ctypes.byref(mi))
        dx = ctypes.c_uint(); dy = ctypes.c_uint()
        shcore.GetDpiForMonitor(hmon, 0, ctypes.byref(dx), ctypes.byref(dy))
        r = mi.rcMonitor; w = mi.rcWork; scale = round(dx.value / 96, 2)
        out.append({"name": mi.szDevice, "primary": bool(mi.dwFlags & 1),
                    "physical": [r.right - r.left, r.bottom - r.top], "scale": scale,
                    "css": [round((r.right - r.left) / scale), round((r.bottom - r.top) / scale)],
                    "css_work_area": [round((w.right - w.left) / scale), round((w.bottom - w.top) / scale)]})
        return True
    user32.EnumDisplayMonitors(None, None, PROC(cb), 0)
    return out

def api_display():
    try:
        return {"screens": read_displays()}
    except Exception as e:
        return {"screens": [], "error": f"{type(e).__name__}: {e}"}


# ---------------- 配色与显示设置的取值（schemes.json）----------------
_SCHEMES = None

def schemes():
    global _SCHEMES
    if _SCHEMES is None:
        with open(os.path.join(KIT_DIR, "schemes.json"), encoding="utf-8") as f:
            _SCHEMES = json.load(f)
    return _SCHEMES


class Prefs:
    """显示设置的默认值（「设为默认」写入；文件不在即用页面内置的出厂值）。
    文件格式 {"display": {"scheme", "font", "weight", "ink"}}；旧文件没有 scheme 一项照样读（页面按旧的深浅补上）。
    写入前白名单校验：配色与字体只能是 schemes.json 里列出的，粗细与灰字亮度限定范围，不把任意字符串写进页面样式。"""
    def __init__(self, path):
        self.path = path
    def load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                return {"display": json.load(f).get("display")}
        except (OSError, ValueError, AttributeError):
            return {"display": None}
    def save(self, body):
        d = body.get("display")
        if d is None:   # 清除：回到出厂值
            try: os.remove(self.path)
            except OSError: pass
            return {"display": None}
        S = schemes()
        try:
            font, weight, ink = d["font"], int(d["weight"]), int(d["ink"])
            scheme = d.get("scheme", S["factory"]["scheme"])
        except (KeyError, TypeError, ValueError, AttributeError):
            raise ApiError("设置格式不对")
        lo, hi = S["weight"]
        if (font not in {f for f, _ in S["fonts"]} or scheme not in {s["id"] for s in S["schemes"]}
                or not lo <= weight <= hi or not 0 <= ink <= 3):
            raise ApiError("设置超出范围")
        val = {"scheme": scheme, "font": font, "weight": weight, "ink": ink}
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps({"display": val}, ensure_ascii=False, indent=1))
        os.replace(tmp, self.path)      # 原子写：写到一半中断不会留下截断的文件
        return {"display": val}


# ---------------- /kit/* ----------------
def _scheme_blocks():
    """四个 [data-scheme] 变量块；出厂那套同时挂在 :root 上（页面脚本没跑时也有取值）。"""
    S = schemes(); out = []
    for s in S["schemes"]:
        sel = f':root[data-scheme="{s["id"]}"]'
        if s["id"] == S["factory"]["scheme"]: sel = ":root, " + sel
        body = "; ".join(f"--{k}:{s['tokens'][k]}" for k in S["vars"])
        out.append(f"{sel} {{   /* {s['name']}：{s['desc']}（{s['source']}） */\n  {body};\n  color-scheme: {s['theme']};\n}}")
    return "\n".join(out)

def kit_asset(path):
    """/kit/kit.js 与 /kit/kit.css：每次从盘上读，schemes.json 注入进去。其它路径返回 None。"""
    if path == "/kit/kit.js":
        S = schemes()
        data = {"factory": S["factory"], "fonts": S["fonts"], "weight": S["weight"],
                "schemes": [{k: s[k] for k in ("id", "name", "theme", "pair", "desc", "swatch", "ink")} for s in S["schemes"]]}
        with open(os.path.join(KIT_DIR, "kit.js"), encoding="utf-8") as f:
            text = f.read().replace("/*@@KIT_DATA@@*/null", json.dumps(data, ensure_ascii=False))
        return text.encode("utf-8"), "text/javascript; charset=utf-8"
    if path == "/kit/kit.css":
        with open(os.path.join(KIT_DIR, "kit.css"), encoding="utf-8") as f:
            text = f.read().replace("/*@@SCHEME_BLOCKS@@*/", _scheme_blocks())
        return text.encode("utf-8"), "text/css; charset=utf-8"
    return None


# ---------------- 请求处理基类 ----------------
_STATIC_TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8"}

class Handler(BaseHTTPRequestHandler):
    """工具继承它，设这些类属性：
       signature  /api/ping 回的 app 名（already_running 据此认自己）
       header     写操作要求的自定义请求头名，如 "X-Clash-Review"（跨站页面带不了这个头而不触发预检，本服务不应答预检）
       web_dir    页面文件目录；static 为 {URL: 文件名}，默认 / → index.html、/app.js、/app.css
       get_routes / post_routes  {路径: 函数}；函数的调用方式由 call() 定（默认 fn(arg)）
       prefs      Prefs 实例（有它才提供 /api/prefs）；idle  IdleWatch 实例（有它才计空闲）
       port       监听的端口（Host / Origin 校验用），启动时设"""
    signature = "web-kit"; header = "X-Kit"; web_dir = ""; port = 0
    static = {"/": "index.html", "/app.js": "app.js", "/app.css": "app.css"}
    get_routes = {}; post_routes = {}
    prefs = None; idle = None
    server_version = "web-kit"

    def call(self, fn, arg):
        return fn(arg)

    def log_message(self, fmt, *args):
        pass

    def parse_request(self):
        if self.idle: self.idle.touch()        # 任何请求都算「有人在用」
        return super().parse_request()

    def _host_ok(self):
        return self.headers.get("Host", "") in (f"127.0.0.1:{self.port}", f"localhost:{self.port}")

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-App", self.signature)
        self.end_headers()
        self.wfile.write(data)

    def _run(self, fn, arg):
        try:
            self._send(200, fn(arg))
        except ApiError as e:
            self._send(400, {"error": str(e)})
        except Exception as e:
            log(f"{self.path} 出错：{type(e).__name__}: {e}")
            self._send(500, {"error": f"{type(e).__name__}: {e}"})

    def do_GET(self):
        if not self._host_ok(): return self._send(403, {"error": "bad host"})
        u = urllib.parse.urlsplit(self.path)
        kit = kit_asset(u.path)
        if kit: return self._send(200, kit[0], kit[1])
        if u.path in self.static:
            fn = self.static[u.path]
            with open(os.path.join(self.web_dir, fn), "rb") as f:
                return self._send(200, f.read(), _STATIC_TYPES.get(os.path.splitext(fn)[1], "application/octet-stream"))
        if u.path == "/api/ping": return self._send(200, {"app": self.signature, "pid": os.getpid(), "header": self.header, "kit": "web-kit"})
        if u.path == "/api/display": return self._send(200, api_display())
        if u.path == "/api/prefs" and self.prefs: return self._run(lambda q: self.prefs.load(), None)
        fn = self.get_routes.get(u.path)
        if fn is None: return self._send(404, {"error": "not found"})
        self._run(lambda q: self.call(fn, q), dict(urllib.parse.parse_qsl(u.query)))

    def do_POST(self):
        if not self._host_ok(): return self._send(403, {"error": "bad host"})
        origin = self.headers.get("Origin")
        if self.headers.get(self.header) != "1" or (origin and origin not in
                (f"http://127.0.0.1:{self.port}", f"http://localhost:{self.port}")):
            return self._send(403, {"error": "forbidden"})
        path = urllib.parse.urlsplit(self.path).path
        if path == "/api/shutdown":     # --stop 用；后台运行时没有窗口可关
            self._send(200, {"stopping": True})
            log("收到停止请求，退出")
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return
        if path == "/api/prefs" and self.prefs: fn = self.prefs.save; direct = True
        else:
            fn = self.post_routes.get(path); direct = False
            if fn is None: return self._send(404, {"error": "not found"})
        try:
            n = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(n).decode("utf-8") or "{}") if n else {}
            if not isinstance(body, dict): raise ValueError
        except ValueError:
            return self._send(400, {"error": "bad json"})
        self._run(fn if direct else (lambda b: self.call(fn, b)), body)
