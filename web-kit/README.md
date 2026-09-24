# web-kit —— 本地网页工具共用的配色、显示设置与服务外壳

> 创建/重写：2026-09-24
> 边界：只记 kit 里有什么、怎样接入、哪些故意不放进来。各工具的页面样式与业务不在这里。
> 仓库：https://github.com/edsfod/web-kit 。许可证：MIT（见 `LICENSE`）。用到它的工具各带一份副本，按网址与版本引用，见「副本与比对」。
> 失效判据：不再有工具使用 web-kit 时，本篇整体失效。

几个带网页界面的本机工具（目前是 [clash-review](https://github.com/edsfod/clash-review) 与 [port-monitor](https://github.com/edsfod/port-monitor)）里，**与页面内容无关**的部分放在这里，各工具带一份副本（见「副本与比对」）：四套配色、显示设置面板、本机显示参数检测、心跳，以及后台运行的服务必须有的那层外壳（不开控制台窗口、日志写 `var/`、失败弹对话框、单实例、`--stop`、空闲退出）。页面样式与业务代码不在这里，各工具自己写。仅用 Python 标准库与浏览器原生 JS / CSS，没有构建步骤。另有启动脚本共用的 `find-python.ps1`（找 Python 解释器）。

---

## 一、接入清单

先按「副本与比对」把某个版本取到工具目录的 `web-kit/`，并在工具根目录的 `vendor.json` 里记下来。工具只导入自己的副本，在自己的 README 里写明它是副本。

服务端（Python）：
1. `sys.dont_write_bytecode = True` 之后 `sys.path.insert(0, os.path.join(HERE, "web-kit"))`、`import webkit`（不在副本目录生成 `__pycache__`）。
2. `ApiError = webkit.ApiError`；业务接口照旧写成函数，放进 `GET` / `POST` 两张表。
3. `class Handler(webkit.Handler)`，设 `signature`、`header`（写操作的自定义请求头名）、`web_dir`、`get_routes`、`post_routes`；接口函数要额外参数时覆盖 `call(self, fn, arg)`（clash-review 传 `ctx`）。
4. `main()` 里：`webkit.setup_log(var 目录)`；`--stop` 用 `webkit.stop(port, Handler.header)`；`webkit.already_running(port, signature)`；设 `Handler.port`、`Handler.prefs = webkit.Prefs(<var>/ui_prefs.json)`、`Handler.idle = webkit.IdleWatch(分钟, busy=…)`；`srv = webkit.bind(port, Handler)`，失败时 `webkit.fail(话, 对话框标题)`；`Handler.idle.start(srv)`；`srv.serve_forever()`。
5. 起子进程时照旧自己带 `creationflags=CREATE_NO_WINDOW`（本模块自己不起子进程）。
6. 启动用的 `.bat` 用 `for /f … ('powershell -NoProfile -ExecutionPolicy Bypass -File "%HERE%web-kit\find-python.ps1"')` 取 `pythonw.exe` 的路径，不写死；PowerShell 脚本里 `& web-kit\find-python.ps1`（`-Console` 取 `python.exe`）。

页面（`web/index.html` 与 `app.js`）：
1. `<head>` 里先 `<link rel="stylesheet" href="/kit/kit.css">` 再链自己的 `app.css`，并 `<script src="/kit/kit.js" data-prefix="xx"></script>`（`xx` 是 localStorage 键名前缀；放在 `<head>` 里是为了页面画出来之前就施加配色，不闪）。
2. 顶栏要有 id 为 `settings`（打开显示设置）与 `theme`（深浅切换）的两个按钮；页面样式里要有 `.btn` `.btn-ghost` `.btn-sm` `.link` `.muted` `.grow` `.hidden` 这几个类与变量 `--mono`（面板里的按钮用它们，长相随工具）。
3. 页面脚本末尾 `WebKit.init({ header: 'X-…', onDisplay: renderStatus, onError: (m) => toast(m) })`；状态栏据 `WebKit.display.zoomOff`（浏览器缩放不是 100% 时非 0）与 `WebKit.display.text` 画提示。
4. 页面自己的 `api()` / `guard()` / `toast()` 照旧；不要再写心跳、显示参数、配色切换。

---

## 二、它解决什么问题

- 两个工具各有一份一模一样的配色块、显示设置面板、显示参数检测、心跳，以及服务端的日志、失败对话框、单实例、`--stop`、空闲退出、安全校验、`/api/display`、`/api/prefs`。改一处要记得改另一处，已经出现过两边不一致（`/api/ping` 回不回 PID、`already_running` 走不走系统代理、面板窄屏时的宽度）。
- 配色的取值原来抄在两个 `app.css`、两个 `app.js`（灰字亮度）与两个后端白名单里，一共六处。现在只在 `schemes.json` 一处。

---

## 三、文件与内容

| 文件 | 内容 |
|---|---|
| `schemes.json` | **唯一取值来源**：四套配色（id、名字、深浅、同一对里的另一套、一句说明、色块、全部变量值、灰字亮度四档）、可选字体、粗细范围、出厂值（深青 / Segoe UI Variable Text / 400 / 灰字默认） |
| `kit.css` | 显示设置面板与配色列表的样式；四套 `[data-scheme=…]` 变量块（含 `color-scheme`）**不写在文件里**，由 `webkit.py` 送出时从 `schemes.json` 生成，替换占位注释 |
| `kit.js` | 配色切换（`data-scheme`，顶栏按钮在同一对里切换：深青↔青瓷，暖炭↔象牙；旧版只存了深浅的浏览器按它取同一对里的那套）；显示设置面板（配色、英文字体、英文粗细、灰字亮度；当前值 / 设为默认 / 还原出厂三层）；本机显示参数（`/api/display` 读系统缩放，反推浏览器缩放；高分辨率低缩放时整体放大，上限 1.35 倍）；每 60 秒 `/api/ping`。配色数据由 `webkit.py` 送出时注入（替换占位），不另发请求 |
| `find-python.ps1` | 找 Python 3.8+ 解释器，打印 `pythonw.exe`（`-Console` 打印 `python.exe`）的路径，找不到退出码 1。顺序：环境变量 `TOOL_PYTHON` → 工具目录里的 `python\`（发布包自带的免安装版 Python）→ 注册表登记的安装（PEP 514，新版本优先；python.org 与 Miniforge 的安装程序都会登记）→ `py` 启动器 → 常见安装目录 → PATH（跳过应用商店的占位程序）。PATH 放最后：Inkscape 这类程序会把自带的 Python 放进 PATH。纯 ASCII |
| `tooldirs.py` | 设置与运行数据放在哪：`dirs(工具目录, 工具名)` 返回 (设置目录, 数据目录)，平常是 `%APPDATA%\<工具名>\` 与 `%LOCALAPPDATA%\<工具名>\`；工具目录里有 `portable` 文件时是工具目录与它的 `var/`（便携模式）。只算路径，不建目录。不依赖 `webkit.py`，命令行工具也能用 |
| `pack.py` | 打发布包：工具里 git 跟踪的文件（不含 `.github/`）加 python.org 官方的 Windows 免安装版 Python（版本与 sha256 写在脚本开头，下载后核对），打成 `<工具名>-<标签>-win64.zip`，Python 放 `<工具名>/python/`，并在它的 `._pth` 里加上工具根目录（免安装版默认不把脚本所在目录放进 `sys.path`）。各工具的 GitHub Actions 在打标签时调用它 |
| `webkit.py` | 服务端外壳：`setup_log`、`fail`、`ExclusiveServer` / `bind`（只绑 127.0.0.1，独占端口，可等旧实例让出端口）、`already_running`、`stop`、`IdleWatch`（`busy()` 为真时不退）、`read_displays`、`Prefs`（`{"display": {scheme, font, weight, ink}}`，白名单来自 `schemes.json`，原子写）、`kit_asset`、`Handler` 基类（Host 头校验；写操作要求自定义请求头并校验 Origin；`/api/ping`、`/api/shutdown`、`/api/display`、`/api/prefs`、`/kit/kit.js`、`/kit/kit.css`、静态页面）。`/api/ping` 回 `{app, pid, header, kit}`：`header` 是写操作要的请求头名，port-monitor 据 `pid` 与它认出并停止带 web-kit 的服务 |

四套配色：

| 配色 | 深浅 | 来源 | 观感 |
|---|---|---|---|
| 深青（出厂） | 深 | 作者的界面风格笔记，深色（原「青铜」） | 冷调深蓝绿黑，青绿 + 铜 |
| 青瓷 | 浅 | 作者的界面风格笔记，浅色 | 冷灰青白，墨青 + 赭铜 |
| 暖炭 | 深 | 作者另一个项目的深色配色 | 暖近黑，珊瑚强调 |
| 象牙 | 浅 | 作者另一个项目的浅色配色 | 暖米白，墨字，珊瑚强调 |

后两套的取值按角色映射到这里的变量名，映射写在 `schemes.json` 的 `_说明` 里。

---

## 四、故意不放进来的

- **页面样式**：列表行、按钮、标签、布局、说明弹窗。页面长什么样取决于各工具自己的内容与操作（clash-review 是逐行选择再统一应用，port-monitor 是只读列表加少数操作），统一它会反过来约束页面逻辑。kit 只定变量名，各工具的样式引用变量。
- **`api()` / `guard()` / `toast()`**：出错提示放在页面哪里、长什么样，随各页面的结构走。kit 自己发的请求（显示设置的读写、显示参数）出错时调页面传进来的 `onError`。
- **业务接口与数据**：各工具的 `GET` / `POST` 表、采集、写入。
- **各工具特有的服务行为**：clash-review 停止后 `os._exit(0)`（后台任务的工作线程不是守护线程）；port-monitor 的 `/api/elevate` 与 `--takeover`（以管理员身份接替同一端口，用 `bind(…, wait_seconds=10)`）。

---

## 五、注意事项

- 改配色只改本仓库的 `schemes.json`，推送、打新标签，各工具更新副本后，刷新页面即生效（`kit.css` / `kit.js` 每次请求从盘上读），后端白名单随之更新要重启服务。
- 变量名是约定：四套配色都给出同一组变量（`--ground` … `--n3`），工具样式只能引用这些名字。要加变量，四套都得加。
- 显示设置的默认值文件 `ui_prefs.json` 在各工具自己的数据目录里（`tooldirs.py`），不在本目录。旧文件没有 `scheme` 一项也能读。
- 本仓库没有运行产物；`var/` 不进仓库（`.gitignore`）。

---

## 副本与比对

用到 web-kit 的工具目录要能单独拿走，所以每个工具在自己目录里带一份副本 `<工具>/web-kit/`，运行时只用自己的副本（冗余可以接受，靠校验保证一致）。

- **只改本仓库**，工具里的副本不改。改完推送并打标签（`v<主>.<次>.<修订>`）。
- 副本是本仓库某个标签的**完整内容**（含本 README 与 `.gitignore` 等），不增不减，这样副本的 git tree 哈希就等于本仓库该版本的 tree 哈希。
- 工具根目录的 `vendor.json` 记下副本的来历：

  ```json
  {"web-kit": {"source": "https://github.com/edsfod/web-kit.git", "ref": "v1.0.0",
               "commit": "<提交哈希>", "tree": "swh:1:dir:<git tree 哈希>"}}
  ```

  `tree` 用 SWHID（ISO/IEC 18670）格式，数值就是 git 的 tree 哈希，谁拿到文件都能独立算出，不依赖 GitHub。
- 核对副本没被改过（在工具仓库里）：`git rev-parse HEAD:web-kit` 应等于 `tree` 的哈希部分，`git status web-kit` 应无改动。
- 查有没有新版：`git ls-remote --tags https://github.com/edsfod/web-kit.git`。
- 更新副本：`git clone --depth 1 --branch <标签> <网址>` 到临时目录，删掉其中的 `.git/`，用它整个替换工具里的 `web-kit/`，改 `vendor.json`，重启服务。
- 工具只用已推送的版本，不引用本仓库的本地工作目录（不留本地覆盖的后门）。改了 web-kit 想在工具里试，要先推送。

---

## 六、否定结论

- 统一页面样式不行：页面长什么样取决于各工具的内容与操作，使用者明确不定标准（2026-09-24）；只统一变量名。
- 把 `api()` / `guard()` / `toast()` 放进来不行：它们跟各页面的结构绑在一起，抽出来要加一层配置，得不偿失。
- 配色数据在 CSS、JS、Python 各写一份不行：抽出前两个工具里一共有六处副本；改为只在 `schemes.json`，送出时生成。
- 页面加载后再异步取配色不行：会先按默认配色画一次再闪成用户的配色；改为送出 `kit.js` 时把数据写进去，在 `<head>` 里同步执行。

---

## 修订记录

- 2026-09-24（v1.0.0）：首次公开发布。此前在作者的私有工作区里开发，历史不随公开仓库发布。
