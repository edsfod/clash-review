# clash-review —— Clash Verge 漏网审查工具链（域名 + IP）

> 创建/重写：2026-06-26
> 边界：只记本工具的用法、设计与由来。模型用的策略见本目录 `prompt.md`；网页的配色、显示设置与服务外壳见本目录 `web-kit/`（[web-kit](https://github.com/edsfod/web-kit) 的副本，版本见 `vendor.json`）。Clash Verge 本身怎么配不在这里。
> 仓库：https://github.com/edsfod/clash-review 。许可证：MIT（见 `LICENSE`）。
> 失效判据：Clash Verge 不再提供内核命名管道 `verge-mihomo-*`（采集方式失效），或规则不再以 `MATCH,REJECT` 兜底（「漏网」的定义失效），或不再使用 Clash Verge 时，本篇整体失效。

从 mihomo 内核的连接日志提取「命中最终 `MATCH→REJECT` 的漏网连接」，去重累计成待审清单，审查后一键归类写回 Clash Verge 的自定义规则集。
**域名与纯 IP 两类都收**：域名写 `my-*.yaml`，IP/CIDR 写 `my-*-ip.yaml`（本机的名字；规则集名、先后顺序与代理组都从 Clash 生成的配置里读，见第四节）（如 Telegram 按 MTProto 直连数据中心 IP、无域名，必须按 IP 段放行）。独立运行、仅用 Python 标准库。采集、审查、归类不依赖 AI，也不联网；联网的只有：watch 每 30 秒经代理请求一次 `generate_204` 做线路探测（几十字节，见第二节「内核警告与代理线路探测」）、`update-data`（每月下载 IP→ASN 数据集与第 3 层的拦截名单、v2fly 分类），以及按需使用的推荐功能（本机证据的 DoH 查询与直连实测、RDAP、证书、模型调用、搜索），见第五节「推荐与理由」。

---

## 一、快速使用

### 适用对象

只适用于把 Clash Verge 配成「没列出的一律拦下」的人：规则的最后一条是 `MATCH,REJECT`，前面有自己的拉黑 / 直连 / 代理规则集（域名与 IP 各一套）。这样配的话，新网站在归类之前打不开，本工具就是用来审查这些被拦下的连接、把它们归类的。不打算这样用的话不需要本工具，订阅别人维护的规则即可。

### 下载与运行

1. 在 [Releases](https://github.com/edsfod/clash-review/releases) 下载 `clash-review-<版本>-win64.zip`，解压到任意位置（不要放进 Clash Verge 的配置目录）。
2. 双击 `review-gui.bat` 打开网页界面。要常驻采集，在 PowerShell 里运行 `install_task.ps1` 注册计划任务（登录时启动 watch，每月更新一次数据），`uninstall_task.ps1` 取消。
3. 包里带 python.org 官方的免安装版 Python（`python\`），不用另装。命令行用 `python\python.exe clash_review.py <命令>`；下文的 `python` 都指它（用源码时指你自己的 Python 3.8+）。
4. 设置在 `%APPDATA%\clash-review\`（`settings.json`、`no_send.txt`，都可选，样例见同名的 `.example` 文件），运行数据在 `%LOCALAPPDATA%\clash-review\`。升级时把程序目录整个换成新版即可，个人的东西不受影响。想全部留在程序目录里，在程序目录放一个名为 `portable` 的空文件。

### 前置条件
- Python 3.8 以上（发布包自带）。**工具仅用标准库，无需安装任何包。** `review-gui.bat` 与 `install_task.ps1` 用 `web-kit\find-python.ps1` 找解释器（注册表、py 启动器、常见安装目录、PATH），不写死路径；要指定就设环境变量 `TOOL_PYTHON`。
- 本目录自成一体，可以整个拷走单独用（见「可迁移」）。`web-kit/`（网页外壳）与 `prompt.md`（模型的系统提示）是随工具带的副本，不要在这里改。
- 可选的 `settings.json`（在设置目录里；格式见 `settings.example.json`）：`config_dir`、`rulesets`、`proxy_group`、`fallback_hosts`、`deepseek_key_file`、`destination`，见第四节。
- 工具会自动定位 Clash Verge 配置目录；若定位失败用 `--config-dir` 指定。**`--config-dir` 必须写在子命令之后**（如 `scan --config-dir X`），写在前面会被子命令的默认值覆盖。

### 日常：常驻采集（计划任务自动运行，无需手动）
```powershell
python clash_review.py watch            # 默认每 200 条连接日志落盘一次
```
`watch` 经内核命名管道 `\\.\pipe\verge-mihomo-*` 订阅 `/logs?level=info` 实时流，逐条归类，每累计 `--every` 条（默认 200）把增量合并写入 `var/pending.yaml` 与 `var/routed.yaml`。Clash 重启、管道断开时先落盘再自动重连。同一时间只允许一个 watch（`var/watch.lock`），重复启动的会直接退出。

### 手动命令（在本目录打开 PowerShell）
```powershell
# 查看待审清单（域名表 + IP 表；IP 自动标注 ASN/组织/国家/已知服务）
# 同一次访问带出的漏网项归为一组；每项附 procs（发起进程）与 ctx（前后相邻连接的主机）
python clash_review.py list

# 核对：收件箱（六个 type: file 规则集）的改动是否已被内核加载（比对条目数与修改时间）；
# 其它规则集（type: http 等，只读）是否已加载、本地缓存与内核的条目数是否一致；find-process-mode、
# iptoasn.com 与 settings.json 的 fallback_hosts 按规则顺序是否先命中代理规则集（工具代理回退要用）、watch 是否在跑、待审数量、
# 规则集与代理组是否从 Clash 配置读到、兜底是否 MATCH,REJECT。有问题退出码 1
python clash_review.py status

# 体检：收件箱的冗余条目（含已并入 http 规则集的）、残留占位、保留域名（.invalid/.example）、
# 全部规则集之间的跨类重叠、父域合并候选
python clash_review.py tidy            # 只读
python clash_review.py tidy --apply    # 只删冗余条目与残留占位（删除后匹配行为不变）

# 查看「地域放行」清单：被地域规则(GeoSite(cn)/GeoIP(CN)/geolocation-!cn)直接路由、
# 进不了漏网审查的域名/IP。用于发现本该拉黑的广告/追踪目标。可按子串过滤：
python clash_review.py routed --filter beacon
python clash_review.py routed --filter ads --top 100

# 可疑排序：给地域放行项打分，把可能的广告/追踪排到前面并附理由（只排序，不自动拉黑）
python clash_review.py routed --suggest
python clash_review.py routed --ok a.com,b.com     # 看过、确认正常，之后不再列出
python clash_review.py routed --unok a.com         # 取消

# 拉黑命中统计：各拉黑条目（my-reject / my-reject-ip）被连了多少次、由哪些进程发起。watch 运行时累计
python clash_review.py rejects
python clash_review.py rejects --filter statsig
python clash_review.py rejects --zero      # 另列出统计以来没有命中的拉黑条目
python clash_review.py rejects --hours 24  # 每条下面列最近 24 小时的逐时次数

# 审查后归类（逗号分隔可多个；自动识别 IP/CIDR 与域名，分别写入 my-*.yaml / my-*-ip.yaml）
python clash_review.py promote --proxy  a.com,b.com
python clash_review.py promote --proxy  149.154.160.0/20
python clash_review.py promote --direct c.com,203.0.113.4
python clash_review.py promote --reject d.com
#   · 归类单个 IP 时，若它落在内置已知服务段（如 Telegram），会自动扩成整段并提示。

# 忽略：只从待审移除，不写规则、不记名单（以后再连到它会重新进待审）。用于一次性噪声
python clash_review.py ignore badssl.com,INDEX.md

# 读日志文件的增量扫描（只处理上次之后的新行）。2.5.4 起 service 模式的日志文件
# 当前用户读不到，日常不靠它；用于 %APPDATA%\...\logs\ 下的旧日志或 sidecar 模式。
python clash_review.py scan
python clash_review.py scan --baseline   # 只把已处理位置推进到现有日志末尾，不计数

# （联网）下载 IP→ASN 数据集到 var/ipdata/，供 list 离线标注 IP 归属
python clash_review.py update-ipdata     # 来源 iptoasn.com；先直连，失败回退本机代理（Clash 的 mixed-port）
# （联网）下载第 3 层用的拦截名单与 v2fly 域名分类到 var/lists/ 并重建索引；update-data = 两者都做（月度任务用）
python clash_review.py update-lists
python clash_review.py update-data

# 流量统计：各主机的连接数与上传 / 下载字节（watch 每秒取一次内核 /connections）
python clash_review.py traffic
python clash_review.py traffic --sort ratio   # 按上传/下载比从高到低

# 三层并排看一个主机：本机事实、外部资料，加 --model 问模型，--rdap / --cert / --search 按需联网查
python layers.py business-ad.cdn-go.cn --model --cert
```
> 归类（promote）后，需在 Clash Verge 里对相应配置 **右键 → 重新激活**（或点 🔥）才生效。内核读的是 `C:\ProgramData\clash-verge-service\users\<哈希>\runtime\ruleset\` 下的副本，重新激活时才会复制过去。激活后跑一次 `status` 确认：副本保留原文件的修改时间，内核 `/providers/rules` 报告的 `updatedAt` 就是它，条目数与时间都和配置目录一致才算生效。2026-09-23 实测有过「点了重新激活但没生效」的情况（`clash-verge.yaml` 未重新生成），只有 `status` 能看出来。
>
> 配了规则服务（`settings.json` 的 `destination`，见第四节「目的地」）时不写收件箱，也不用重新激活：决定直接提交到规则服务，上线后常驻的 watch（或打开的网页）让内核立即重新取对应的规则集，一般一两分钟。写入失败时这一项留在待审里。

### 网页界面（推荐日常审查）
双击 `review-gui.bat`（或 `pythonw clash_review_web.py`）：在 `http://127.0.0.1:8765/` 于后台启动本地服务（`pythonw`，不开控制台窗口）并打开浏览器。已在运行时再双击只会打开浏览器。停止：`pythonw clash_review_web.py --stop`；没人用时自己退出：打开的页面每分钟报一次到，连续 30 分钟没有请求、且没有后台任务（推荐、实测）在跑，服务退出并释放端口，下次双击重新启动。运行日志在 `var/web.log`；启动失败（端口被占、找不到配置目录）弹对话框告知。所有读写调用 `clash_review.py` 的同一套函数，与命令行行为一致。设计稿：<https://claude.ai/artifact/7cA7kA8fjVRUiV6N3LYPCv> 第二行「v2 收件箱」（第一行 v1 已否决，保留作对比）。

三页都是同一个结构：页头、一条一行的列表、底部固定的操作栏。每行的操作按钮固定在左侧，判断要用的信息（发起进程、前后连接、可疑理由）作为第二行直接显示，不用点开。先逐行选择，再在底部统一应用；应用结果显示在操作栏上方。

- **顶栏**：即 `status` 的内容。一切正常时只有「规则集已生效 · watch 运行中 · 上次采集 · 内核版本」一行灰字；规则集有未生效改动时变琥珀色「my-xxx 未生效 · 去 Clash Verge 重新激活」，其它问题（连不上内核、watch 未运行、回退域名未放行）为绛红。切回浏览器窗口时自动重新检查。鼠标停在「上次采集」上可看最近 3 条 scan.log 与显示参数。
- **待审**：同一次访问带出的归在「同一次访问」小标题下（小标题上有整组操作），其余归在「单独出现」下。每行第二行是发起进程与前 3 个前后连接；点中该行再点一次、或按空格，展开全部前后连接（本组其它主机标铜色）。操作有代理、直连、拉黑、忽略四种；忽略只从待审移除、不写规则，用于测试站、打错的网址、命令行误把文件名当网址这类一次性噪声（不记名单，再出现会回来）。默认不选中任何一类，未选的应用后仍留在待审。
- **地域放行**：一张表，页头切换「可疑 / 可改直连 / 全部 / 直连 / 代理」。「可疑」即 `routed --suggest`，第二行是理由，可标「拉黑」或「正常」；「可改直连」见第二节「代理改直连」，可标「直连」（写入 my-direct 并移出地域放行）或「保持代理」；其它视图按次数排序，最多列 300 条，用搜索缩小范围，只能拉黑。拉黑的同时从地域放行清单移除。
- **规则**：配了规则服务时，左栏是服务端能写的全部规则集（这台电脑的 Clash 用到的排在前面），可以搜索全部规则集、改类、换层、删除、新增，直接提交到规则服务（带版本号，期间别处改过会提示重试），上线后自动让 Clash 重新取；没有体检页（冗余、重叠由服务端在写入时提示）；页头给管理页的链接（`destination.admin_url`）。没配时：左栏六个规则集，右侧分「条目 / 体检」两个页签。条目可搜索（搜全部规则集，每条标出所在的规则集）、新增、移到另一类、删除（删除后底部出现「撤销」）。体检即 `tidy`：冗余可一键清理，保留域名可逐条删除，合并候选可一键「合并为 +.父域」（确认框提示合并后父域下所有子域都会归入该类；写入父域时被覆盖的子域自动移除）。
- **说明**：每页标题旁的「说明」按钮，讲这页是做什么的、各个词的意思与原理。
- **推荐与理由**（待审、地域放行「可疑」）：只作提示，从不替你选。每行第二行开头的小标签：「名单：…」（被拦截名单收录，离线查，列表一加载就有）、「推荐 X」或琥珀色「分歧」（查询过的）、「查询中…」。推荐只写在这行标签上，按钮不加描边、不选中。主机名旁的「理由」（或按 `?`）展开三层：本机事实、外部资料、模型（归属与功能、触发场景、理由、每个选项的把握与理由），并注明查询时间、是否把前后连接发给了模型；没查过的点开即在后台查询，约几十秒。页头「为本页生成」只查本页还没查过的项（上次模型出错或已过期的算没查过；不发前后连接），按钮上注明未查项数，全部查过时变灰；要重查某项在它的理由面板里点「重新查询」。结果缓存在 `var/advice.json`。模型出错（如 DeepSeek 余额不足）时在理由里显示错误，名单与本机事实照常显示。
- **键盘**（焦点不在输入框时）：`↑` `↓`（或 `j` `k`）选择行；待审 `1` 代理、`2` 直连、`3` 拉黑、`4` 忽略、`0` 撤销、空格展开上下文；地域放行 `3` 拉黑、`0` 正常；`?` 展开理由；再按一次同一个键即取消；`Ctrl+Enter` 应用。
- **字体**（以 Claude Desktop 为基准）：界面 Segoe UI / 微软雅黑 UI，域名、IP 与数字 Consolas；正文 13px、次要 12px；只有页标题加粗，其它强调靠颜色。
- **配色**：四套，由 web-kit 提供（取值只在 `web-kit/schemes.json`，页面样式只引用变量）：深青（出厂，冷调深蓝绿黑，青绿 + 铜）、青瓷（冷灰青白，墨青 + 赭铜）、暖炭（取自 aoe2_balance v5，暖近黑，珊瑚强调）、象牙（v5 浅色，暖米白，墨字，珊瑚强调）；v5 取值怎么映射到本页变量名见 web-kit 的 README 与 `schemes.json`。在显示设置里选；顶栏最右的按钮在同一对的深浅之间切换（深青↔青瓷，暖炭↔象牙）。以前只存过深浅（`cr-theme`）而没存过配色的浏览器，按它取深青或青瓷，样子不变。只换颜色，页面样式不变。
- **显示设置**（面板由 web-kit 提供）：顶栏的调节按钮（主题切换左边）打开，可调配色（见上）、英文字体（Segoe UI Variable / Variable Small / 静态版 / Bahnschrift / Tahoma / Verdana / Arial）、英文粗细（300–500，不超过 500 时中文仍是常规体）、灰字亮度（默认与三档，每套配色各有自己的四档：深色逐档提亮、浅色逐档加深）。分三层：当前值存在本浏览器的 localStorage（`cr-display`，配色是其中的 `scheme`）；「设为默认」写 `var/ui_prefs.json`，本浏览器没存过设置时与「恢复默认」都用它；「还原出厂」删掉该文件，回到出厂值（深青、ui-style 的字体与粗细）。后端白名单来自 web-kit 的 `schemes.json`（配色只接受那四个 id，字体只接受列出的七种）；旧的默认值文件没有配色一项时按旧的深浅补上（没有就是深青）。
- **尺寸**：
  - 布局按窗口可用宽度（CSS 像素）断点：基准 1440（本机 2880×1920@200% 全屏即此宽）；1024 以下（半屏）列表行改两行，720 以下规则集改到上方。
  - 系统分辨率与缩放由后端 `/api/display` 直接向 Windows 读（web-kit 的 `read_displays`，页面一侧也在 web-kit）。页面里的 `devicePixelRatio` 是系统缩放 × 浏览器缩放，页面自己分不开：浏览器缩到 25% 时，200% 的屏看起来像 50%。页面据此反推浏览器缩放，不是 100% 时顶栏提示「Ctrl+0 复原」。
  - 系统层面屏幕 CSS 宽度 > 2200（如 4K@100%）时整体放大，上限 1.35 倍。
  - 标签页在后台时浏览器报 0×0、缩放 1，不采用，等可见时重测；缩放变化、窗口改大小时也重测。

服务只监听 127.0.0.1，校验 Host 头；写操作要求自定义请求头并校验 Origin，别的网页无法借浏览器改规则集。

> 所有写入（新增/删除/改分类、pending、routed）均为**原子写**（先写临时文件再 `os.replace`），杜绝历史上因写入中断留下的截断损坏（见配置目录 `ruleset/*.corrupt-bak`）。pending / routed 的「读-改-写」另加数据锁 `var/data.lock`，watch 落盘与网页归类不会互相覆盖。

待审域名较多时，可把 `prompt.md` 发给 AI，让它逐条给出归属与归类建议（用法见该文件头部）。

### 计划任务（本地 Windows 计划任务）
```powershell
pwsh -ExecutionPolicy Bypass -File .\install_task.ps1
```
以**普通权限**运行即可，注册两个用户级任务：

| 任务 | 触发 | 作用 |
|---|---|---|
| `ClashVerge-LeakScan` | 当前用户登录时；安装时立即启动 | 常驻 `watch --every 200`。无运行时长上限，单实例；任务失败时 1 分钟后重试（最多 3 次） |
| `ClashVerge-IPData-Update` | 每月 1 日 03:00；错过补跑、允许电池、仅联网时 | `update-ipdata` |

python 绝对路径烧入任务，不依赖 PATH/profile。重复运行安装脚本是安全的：会先停掉旧 watch、等它退出，再注册并启动新的。卸载：
```powershell
pwsh -ExecutionPolicy Bypass -File .\uninstall_task.ps1
```
**移动本目录后必须重跑 `install_task.ps1`**，计划任务里的路径不会跟着变。

---

## 二、它解决什么问题

Clash Verge 的分流规则以 `MATCH,REJECT` 兜底：未被任何规则收录的域名/连接默认被拒。这是有意的"白名单式"策略，但需要一个把"被误杀的漏网域名"捞回来审查、再决定其归属的闭环。本工具就是这个闭环的离线实现：

```
mihomo 内核日志流（命名管道 /logs）→ watch 提取 MATCH→REJECT 并去重累计 → list / 网页审查 → promote 归类进规则集 → 重新激活
```

"漏网"的判定：连接出口为 `REJECT` 且匹配规则为最终 `MATCH`。自动排除 `my-reject` / 去广告等"故意拒绝"、以及 DIRECT 失败等噪声。**域名与纯 IP 两类都收**（IP 仅排除私有/保留/回环/组播/fake-ip 段等噪声）；这正是 Telegram 这类"按 IP 直连、无域名"的连接得以被发现的关键——旧版把纯 IP 当噪声丢弃，故对 Telegram 完全失明。

已被规则集覆盖的域名/IP 不会再进入待审或地域放行清单（收件箱与只读的 http 规则集都算，见第四节）；watch 每次落盘时会重读规则集，期间刚归类的条目也不会被并回。

### 审查上下文

审查时要回答「当时在访问什么网页、用什么软件」（`prompt.md`「你会收到的三种清单」之后的本机证据），为此每个漏网项另记两项：

- **ctx**：该连接前后各 8 条连接的目标主机，最多 12 个。同一次页面加载带出的连接在日志里相邻，页面本身的域名通常就在其中。按条数取，不按时间。互相出现在对方 ctx 里的漏网项在 `list` 与网页中归为一组。
- **procs**：发起连接的进程名。只有内核开启 `find-process-mode: always` 时日志才带进程名（形如 `127.0.0.1:5(curl.exe) -->`）。可在 Clash Verge 的 `profiles/Merge.yaml` 中开启（作者本机已开启）。

内核自身的连接（`mihomo --> ...`，如 DoH）不计入 ctx。

### 拉黑命中统计

被 `my-reject` / `my-reject-ip` 拒掉的连接不进待审也不进地域放行，原本不留痕。watch 另把它们按拉黑条目计数，写 `var/reject_hits.json`，用 `rejects` 查看。用途：看哪些拉黑条目一直有流量、哪些早已没人连（`--zero`），以及某个拉黑的主机以后还会不会被连（如 `statsig.anthropic.com`，见代理主题 README 第 4 节）。

次数是**新建连接**的次数，分不出定时连接、失败重试还是多个进程各自连接，所以另按小时分桶（保留 14 天）、按进程分别计数；判断是不是「反复重试」要看逐时分布与进程，不能只看总数。2026-09-23 的教训：半小时 470 次 Datadog 看似重试，实为模型评估时 216 个 `claude -p` 进程各连 2 次；`gamingservices.exe` 连 `settings-win` 是每 15 秒整 2 次的固定节奏。

内核日志只写 `match RuleSet(my-reject)`，不写命中的是哪一条，故按当前规则集反查覆盖该主机的最具体条目；规则集刚改、内核还在用旧副本时可能反查不到，这时按主机本身记。地域规则里的去广告（`GEOSITE,category-ads-all`）拒绝不计入。只在 watch 里统计，`scan` 不统计。

### 地域放行的可疑排序

地域放行清单是没有审核过的原始池（上千项），`routed --suggest` 给每项打分，分数 ≥ 3 的按分数排出并附理由。四类信号：

| 信号 | 分值 | 说明 |
|---|---|---|
| 名称关键词 | 3（弱关键词 1.5） | `analytics`、`telemetry`、`sentry`、`cnzz` 等子串，或 `ad`、`stats`、`rum` 等整词。`dsp`、`ssp` 等有歧义的缩写只算弱关键词（`dsp.mp.microsoft.com` 是 Windows 更新分发） |
| 与已拉黑条目相似 | 同站 3 / 1；学出来的词最多 3 | 同站只在该站已知主机里拉黑占比 ≥50% 时记 3 分（≥20% 记 1 分），避免拉黑一个 google 广告域就把整个 google.com 标成可疑；学出来的词须只出现在 `my-reject`、且在地域放行里不普遍 |
| 跨站出现 | 最多 1.5 | 该主机最初 40 次出现时，前后各 3 条连接里出现过多少个不同站点（`sites` 字段）。只作辅助证据，单靠它到不了 3 分 |
| 子域像随机串 | 1.5 | 如 `o1158394`、`507b28fb-2ef1-...` |

看过、确认正常的记在 `var/routed_reviewed.txt`，之后不再列出；要拉黑的照常 `promote --reject`，进了规则集的自然也不再出现。2026-09-23 首次运行，1684 项中排出 23 项。

### 代理改直连

`geolocation-!cn` 按域名归属分，不看在国内能不能直连。微软、苹果、Steam 的下载 CDN、Office 更新、证书吊销检查等在国内有节点，直连更快也省代理流量；反过来「国内判给直连、想改走代理」很少，一般是网页打不开才发现，到「规则」页手动加即可，所以只做这一个方向。

网页「地域放行 → 可改直连」的候选（`clash_review.direct_candidates`）：走代理的域名，去掉登录/账号类、v2fly 标为 `category-ai-!cn` 的（AI 服务限制中国地区）、同站已人工归到代理的、拦截名单收录的、标过「保持代理」的（`var/routed_keepproxy.txt`），按流量与次数排。「实测」过两道关：

1. **测速**（`evidence.speed`）：直连与走代理（Clash 的 mixed-port）交替各测 3 次首字节时间取中位数；直连用腾讯 DoH 解析并扣掉解析时间（Clash 的 `direct-nameserver` 也是 223.5.5.5 / 1.12.12.12，测到的就是改直连后实际会连的节点）。直连连不上、不比代理快（直连 > 代理 × 0.8）、国内解析不到的隐藏，不问模型。结果挂在 `var/evidence_cache.json` 该主机的 `speed` 字段。
2. **按策略问模型**：过了测速的，按提示词笔记的策略（清单「可改直连」，结论 direct / proxy / reject）判断该不该直连，结果存 `var/advice.json` 的 `todirect:主机`。涉及登录、支付、个人数据或有地区限制的保持代理；属于拉黑一节的（如出口 IP 探测）照样拉黑。模型建议保持代理的也隐藏。

列表只剩没测的、待问模型的、建议直连或拉黑的（含分歧），最多 60 个；隐藏的连同原因可在页头展开。每行：主机名与它是什么网站（模型给的归属与用途）；第二行测速结论与近期流量；「理由」展开三层证据与模型对每个选项的理由。操作：直连（写 my-direct）、保持代理（记入 `routed_keepproxy.txt`）、拉黑（写 my-reject）。

不另测下载吞吐：2026-09-24 在三个推荐直连的主机上直连与代理各下两次、每次 4–8 MB（`archive.ubuntu.com` 的 `ls-lR.gz`、npm 的 typescript 包、jsDelivr 的 `typescript.js`），直连 1.2–7.6 MB/s、代理 0.7–2.2 MB/s，直连快 1.5–8 倍，与首字节的结论一致；每项多下几 MB 换不来新信息。

为什么要两道关：只比速度时，走代理多绕一趟境外节点，能直连的几乎都更快（2026-09-24：60 项里 55 项「推荐直连」），混进了出口 IP 探测（`api.ip.sb`）、支付（`js.stripe.com`）、身份认证（`api-iam.intercom.io`）。速度只说明线路，不说明该不该直连。更早还试过按 ASN 登记国家、按 TCP 握手 ≤ 80 ms 判断节点远近，都不对：任播 CDN 登记在美国、实际由近处节点响应；单次握手抖动大；「节点近」也不等于「比代理快」。

### 人工裁定日志与评估

网页上每次「应用」（待审的代理 / 直连 / 拉黑 / 忽略，地域放行的拉黑 / 正常 / 直连 / 保持代理），把每一项当时的证据快照（待审：次数、发起进程、前后连接、端口；地域放行：原去向、次数、跨站、端口）、模型当时的推荐（`advice.json` 里的汇总结论、模型结论、名单结论、提示词指纹）与你的决定，追加一行到 `var/testcases/decisions.jsonl`。地域放行按标记时所在的视图记为「可疑」「可改直连」或其它视图。

真实测试题由日常审查顺带积累，不再手工冻结：待审处理后条目就从清单里移除，事后冻结赶不上；早先冻结的 `pending-20260923.json` 里 11/16 是测试时自己造成的连接。

触发：上次评估之后的新裁定满 20 条，或满 10 条且已过 7 天（`DECISIONS_DUE`、`DECISIONS_DUE_SLOW`），`status` 的「裁定」一行与网页顶栏提示「有 N 条新裁定可评估」。评估：`python eval_decisions.py`（`--all` 全部重评），按页面统计模型推荐与你的决定是否一致、列出不一致的项与分歧项，报告写到 `var/eval/decisions-<日期>.md`，并把已评估条数记到 `var/testcases/decisions_eval.json`。只统计应用时已有模型推荐的项；没点过「理由」或「为本页生成」的项只计数。

### 内核警告与代理线路探测

watch 另写 `var/kernel_warn.log`，用来对上「代理间歇卡住」的时间（2026-09-24 起，起因是 Claude 应用多次心跳超时、请求超时重试，事后测线路却正常）：

- **内核的 warning / error 日志**原样存下，带时间。能抓到本机到节点这一段的故障（连不上节点、握手超时、被重置）。
- **代理线路探测**：每 30 秒经 mixed-port 请求一次 `https://www.gstatic.com/generate_204`（几十字节）；失败或慢于 3 秒记一行（含当时「节点选择」组用的节点），恢复时再记一行（`PROBE_EVERY`、`PROBE_SLOW`）。代理组取代理规则集所指的那个（本机「节点选择」），见第四节。
- 文件超过 4 MB 转存为 `kernel_warn.log.1`，只留一份旧的。

两样都要，是因为走 VLESS 节点时，卡在「节点到目标网站」这一段内核不报任何警告（见第六节）。

### 写入规则集时的检查

`promote`、网页的归类/改分类/手动新增都经同一写入函数。配了规则服务时，下面这些检查由服务端做（写法、同类覆盖、跨类重叠），它的提示原样显示；没配时写入收件箱前：

- 目标已被本类收件箱的现有条目覆盖，或按规则顺序先命中的是本类的只读规则集（如 http 规则集里已有）→ 不写入，提示；
- 新条目覆盖了本类收件箱已有的更小范围条目 → 这些旧条目一并移除，提示；
- 目标与另外两类（收件箱与只读规则集都算）有重叠 → 只提示哪个规则集生效（按 `rules` 里的顺序），不改别的规则集；
- 只读规则集读不到（本地缓存不在等）→ 照常写入，提示哪些没算进去；
- 写入真实条目时去掉残留的占位条目。

父域合并不自动做：`tidy` 列出同一父域下 ≥3 个子主机的候选，由人确认。简单取「最后两段」会误判大站与公共后缀（如 `microsoft.com` 下的遥测域名、免费子域服务 `qzz.io`）。确认后 `promote --<类> <父域>`，被覆盖的子条目会自动移除。

---

## 三、文件与数据

**设置与数据放在哪**（web-kit 的 `tooldirs.py`）：设置（`settings.json`、`no_send.txt`）在 `%APPDATA%\clash-review\`，运行数据在 `%LOCALAPPDATA%\clash-review\`，程序目录里只有发布的内容，升级时整个换掉。工具目录里放一个名为 `portable` 的文件（内容不限）就是便携模式：设置在工具目录，数据在工具目录的 `var/`。本篇其它地方说的 `var/` 都指数据目录。

源码（本目录）：

| 文件 | 作用 |
|------|------|
| `clash_review.py` | 主工具（watch / scan / list / routed / promote / status / tidy / update-ipdata），纯标准库 |
| `clash_review_web.py` / `web/` / `review-gui.bat` | 网页界面：`clash_review_web.py` 只写业务接口（`/api/*` 的 GET / POST 表），服务外壳（后台运行日志、失败对话框、单实例、`--stop`、空闲退出、Host / 自定义头 / Origin 校验、`/api/display`、`/api/prefs`、`/kit/*`）来自 `web-kit/webkit.py`；`web/` 为单页面（HTML/CSS/JS，无构建步骤），配色与显示设置面板来自 web-kit 的 `/kit/kit.css`、`/kit/kit.js`；不在源码目录生成 `__pycache__` |
| `audit_candidates.py` | 复查规则集：用可疑打分给已放行（代理、直连）的条目做留一打分，挑出像广告、遥测的候选，并报告对拉黑条目的召回。只读，默认用 `var/testcases/` 的冻结基准 |
| `advisor.py` | 第 2 层：调模型给出归类建议与理由。系统提示取自 `prompt.md` 的「背景与策略」「工具输出格式」两节；模型为 DeepSeek（API）与 Claude Haiku / Sonnet（本机 `claude -p`，替换默认系统提示、关工具、不读 CLAUDE.md）。DeepSeek 密钥取环境变量 `DEEPSEEK_API_KEY`，没有则读 `settings.json` 的 `deepseek_key_file` 所指的文件（Gemini 免费档搜索额度为 0，暂未接入） |
| `eval_models.py` | 第 2 层模型评估：规则集人工归类抽样、地域放行「可疑」24 项、编造主机与 statsig 三套题，结果与报告写 `var/eval/<run>/` |
| `compare_eval.py` | 按 `var/testcases/acceptable-20260923.json` 的口径比较各版本在 A 套上的表现，错误分严重（误拉黑）、中等（放进该拉黑的）、轻微（直连代理互换） |
| `verify_eval.py` | 核验评估结果：本机证据（国内 / 境外 DNS 视角与 ASN、直连实测、模型给的网址是否存在）能判的自动判，判不了的写成匿名人工清单 `var/eval/<run>/manual.md`；A 套按主机名分 dev / test 两半，改提示词只看 dev |
| `evidence.py` | 本机证据（第 1 层的一部分）：国内视角解析与运营商、直连实测（HTTPS 与 HTTP 都测）、同站归类；缓存 `var/evidence_cache.json`，7 天内不重查 |
| `external.py` | 第 3 层外部资料：离线查拦截名单（EasyPrivacy、EasyList 整域名规则、HaGeZi Pro、anti-AD）与 v2fly 域名分类（沿 include 追溯归属，遵守 `include:x @ads` 这类属性过滤）；按需查 RDAP、TLS 证书、搜索（`claude -p` 带网页搜索，结果逐条列出处）|
| `layers.py` | 三层并排与汇总：各层独立给结果（模型只看本机事实、不看名单），推荐按写明的规则汇总、只作提示，冲突标「有分歧」 |
| `no_send.txt` | 不外发名单（个人，不进仓库）：调模型时不发送的主机，按后缀匹配；没有这个文件就不过滤。格式与建议收录哪几类见 `no_send.example.txt` |
| `install_task.ps1` / `uninstall_task.ps1` | 注册 / 删除两个计划任务（纯 ASCII）；解释器由 `web-kit\find-python.ps1` 找 |
| `prompt.md` | 模型的系统提示（对话里也可直接用，见其头部）。改策略直接改它 |
| `web-kit/` | 网页外壳，[web-kit](https://github.com/edsfod/web-kit) 某个版本的完整副本，不在这里改 |
| `vendor.json` | 副本的来历：来源网址、标签、提交、tree 哈希（SWHID 格式）。核对与更新见「可迁移」 |
| `settings.example.json` | 设置的格式样例。本机的设置在 `settings.json`（不随工具给别人） |

运行产物（`var/`，除 `var/testcases/` 外任何时候可整体删除，删后审查历史清零）：

| 文件 | 作用 |
|------|------|
| `var/pending.yaml` | 待审清单（`domains:` 与 `ips:` 两段，自动去重累计；每项可带 `procs`、`ctx`） |
| `var/routed.yaml` | 地域放行清单（`direct:` / `proxy:` 两段；每项可带 `sites`） |
| `var/lists/` | 第 3 层名单原件与索引 `index.json.gz`（`update-lists` 下载，每月更新） |
| `var/advice.json` | 网页「理由」的查询结果（按 类型:主机），再打开页面直接显示；带 `prompt_hash`，过期规则见第五节「模型结果的缓存」 |
| `var/testcases/decisions.jsonl` / `decisions_eval.json` | 人工裁定日志（每次「应用」追加）/ 已评估到第几条 |
| `eval_decisions.py` | 模型推荐与人工裁定的一致性评估（见第二节「人工裁定日志与评估」） |
| `var/kernel_warn.log`（`.1`） | 内核警告与错误、代理线路探测的异常与恢复（watch 写；超过 4 MB 转存为 `.1`） |
| `var/web.log` | 网页服务在后台运行时的输出 |
| `var/identity.json` | 模型给的主机身份（归属与用途），按主机缓存、各页面共用，不按时间过期 |
| `var/traffic.json` | 流量统计：每个主机的连接数、上传 / 下载字节、单连接最大值、进程、命中规则 |
| `var/evidence_cache.json` / `var/external_cache.json` | 本机证据（7 天）与 RDAP、证书、搜索结果（30 天）的缓存 |
| `var/reject_hits.json` | 拉黑命中统计：按拉黑条目记次数、首末时间、命中的主机（最多 10 个）、各进程次数、逐时次数；`since` 为最早一次命中 |
| `var/routed_reviewed.txt` | 地域放行中看过、确认正常的主机，一行一个 |
| `var/routed_keepproxy.txt` | 「可改直连」里看过、决定保持代理的主机，一行一个 |
| `var/scan.log` | watch / scan 的运行摘要，只保留最近 500 行 |
| `var/scan_state.json` | scan 读日志文件时已处理到的位置（行首时间戳 + 同毫秒行摘要） |
| `var/watch.lock` | watch 单实例锁 |
| `var/ui_prefs.json` | 网页「显示设置」的默认值（「设为默认」写入；删掉即回到出厂值） |
| `var/data.lock` | pending / routed 读-改-写的互斥锁（watch 落盘、网页、promote 共用） |
| `var/destination.json`（`destination.lock`） | 配了规则服务时：服务端条目的缓存（10 分钟重取）、已提交的决定与上线状态（结束后保留一天） |
| `var/ipdata/ip2asn-v4.tsv.gz` | IP→ASN 数据集（`update-ipdata` 下载；可随时删，不影响审查） |
| `var/backup/` | 改动前的源码与数据备份，`<文件名>.<日期>` |
| `var/eval/` | 模型评估的逐题结果（JSON）、所用系统提示与 `report.md`，可中断续跑 |
| `var/testcases/` | 推荐功能的测试基准（另有 `acceptable-20260923.json`：用户裁定的评分口径）：冻结的规则集标注、地域放行快照、「可疑」24 项、标注来源记录。**不可删、不可改**，说明见该目录 `README.md` |

工具操作的 Clash Verge 端对象（**非本目录**）：
- 读：内核命名管道 `\\.\pipe\verge-mihomo-*` 的 `/logs` 流（watch）；`%APPDATA%\...\logs\service\*.log` 与 `logs\sidecar\*.log`（scan）
- 读：配置目录的 `clash-verge.yaml`（Clash Verge 激活配置时生成的完整配置）：规则集名与路径、先后顺序、代理组、兜底、`external-controller-pipe`、`mixed-port`（见第四节）
- 写（域名）：本机 `ruleset/my-proxy.yaml` / `my-direct.yaml` / `my-reject.yaml`（behavior=domain）
- 写（IP）：本机 `ruleset/my-proxy-ip.yaml` / `my-direct-ip.yaml` / `my-reject-ip.yaml`（behavior=ipcidr）

---

## 四、配置目录定位规则

需要找到 Clash Verge 配置目录（含 `profiles.yaml`），优先级：

1. 命令行 `--config-dir PATH`（写在子命令之后）
2. 环境变量 `CLASH_VERGE_DIR`
3. `settings.json` 的 `config_dir`
4. 脚本父目录（当工具置于 `<配置目录>/review/` 内时自动命中）
5. `%APPDATA%\io.github.clash-verge-rev.clash-verge-rev`（Windows 默认安装位置）

本工具不放在 Clash Verge 的配置目录里（重装或重置 Clash Verge 时那里会被清空），运行时通过第 5 条或显式 `--config-dir` 定位。`install_task.ps1` 注册的计划任务显式传入 `--config-dir`。

### 规则集、代理组与内核管道

不写死，从配置目录的 `clash-verge.yaml`（Clash Verge 每次激活配置时写出的完整配置）里读（`detect_layout`）：

| 读什么 | 怎么认 | 读不到时 |
|---|---|---|
| 收件箱（写入的六个规则集）的名字与文件 | `rules` 里的 `RULE-SET,<名字>,<去向>`，去向 `REJECT` / `REJECT-DROP` 为拉黑、`DIRECT` 为直连、其它（代理组名）为代理；`rule-providers` 里该名字的 `behavior`（`domain` / `ipcidr`）与 `path`，只认 `type: file`。每类（域名 / IP × 三类）取规则里第一个 | 按默认名 `my-<类>[-ip]` 猜，`status` 报「按默认名猜的」 |
| 只读规则集（「已有规则」一并算进去，从不写入） | 其余 `behavior` 为 `domain` / `ipcidr`、`type` 为 `file` 或 `http` 的 `RULE-SET`。`http` 的读 `path` 处的本地缓存（相对配置目录），`format` 支持 `yaml` 与 `text`；`classical` 与 `mrs` 不读 | 缓存不在、没写 `path`、格式读不了：跳过，`status` 报出来，写入时提示没算进去 |
| 先后顺序（同一目标落在多个规则集时谁生效） | 上面那些 `RULE-SET` 行的顺序 | 收件箱按 拉黑 → 直连 → 代理，排在只读规则集之前 |
| 代理组（线路探测记录当前节点） | 代理规则集的去向 | 不记节点（写 `?`） |
| 兜底 | `MATCH,<去向>` | `status` 报：不是 `MATCH,REJECT` 就没有「漏网」 |
| 内核管道 | `external-controller-pipe`；它不存在时再找 `\\.\pipe\verge-mihomo-*`（本机 yaml 里写的是 `sidecar-release`，实际在跑的是 `production`） | 报「找不到内核管道」，写明找了什么、可能是 Clash Verge 没运行或不是 2.5.x |
| mixed-port | `mixed-port` | 7897（Clash Verge 的默认值） |

只读规则集的本地缓存不一定是内核在用的那份：Clash Verge 2.5.x 的服务模式下，内核的工作目录在 `C:\ProgramData\clash-verge-service\users\<哈希>\runtime\`（普通用户读不到），按网址取来的文件写在那里，配置目录 `path` 处的文件内核不再更新（2026-09-25 实测：内核重新取到 167 条，配置目录的缓存仍是 166 条）。`status` 按条目数比对，不一致就报出来，这时「已有规则」按旧缓存判断。要让它跟上，由分发规则的一方在更新线上文件时把同一份文件写到 `path` 处。

### 目的地：本机文件或规则服务

归类决定写到哪里（设计与协议：[`docs/destinations.md`](docs/destinations.md)）：

- **本机文件**（默认）：上表的收件箱。
- **规则服务**：`settings.json` 里有 `destination`（格式见 `settings.example.json`）时，经写入接口直接写进自己维护的在线规则服务，不再写收件箱，也不要求 Clash 配置里有收件箱。`endpoint` 为写入接口，`key_file` 为写入密钥文件（只在本工具的 Python 进程里读，不进网页、不进网址），`rulesets` 指定每类写进服务端哪个规则集，`admin_url` 是服务端的管理页（规则页给链接，供别的设备用）。
  - 一次归类是一个提交；写入前的检查由服务端做。连不上、密钥不对、服务端拒绝时报原因，待审不变，不会自动改写到收件箱。
  - 服务端的条目经 `GET /rulesets?entries=1` 取来缓存 10 分钟，作为 Clash 里对应 `http` 规则集（网址以服务端给的 `path` 结尾）的「已有规则」，代替 `path` 处的本地缓存。刚提交的条目立即重取，watch 不会把它们放回待审。
  - 已提交的决定由 watch 与网页的后台线程每 15 秒查一次是否上线；上线后调用内核的 `PUT /providers/rules/<名字>` 让它立即重新取，并核对条目数。半小时仍未上线的不再等，`status` 报出来。
  - 访问服务端的线路：Clash 里对应这个服务的 `http` 规则集写了 `proxy`（内核自己也经代理组取它）时先经本机代理（`mixed-port`），否则先直连；直连最多等 8 秒，不通再换另一条。
  - `status` 多一节「写入目的地」（命令行当场问服务端；网页顶栏用缓存，不每次联网）：连不连得上、密钥对不对、每类写进哪个规则集、Clash 里对不对得上、GitHub 令牌何时到期（服务端给出时）、最近几次提交的状态。
  - 订阅、浏览、覆盖别人的规则集仍由 Clash Verge 与内核负责，本工具不做。

检测出的不对时，在 `settings.json` 里覆盖：`rulesets`（`{"domain": {"reject": 名字, …}, "ip": {…}}`，文件按 `<配置目录>/ruleset/<名字>.yaml`）、`proxy_group`。另有 `fallback_hosts`（别的工具经本机代理回退时要访问、`status` 要检查的域名）与 `deepseek_key_file`。

---

## 五、注意事项

- 工具放在本仓库而非 Clash Verge 的 app data 目录：app data 在重装/重置时会被清空（本配置即经历过一次重置）。
- 采集只在 watch 运行时发生。开机到登录之间、或 watch 被直接结束时尚未落盘的（不足 200 条）连接不会进入清单。
- 管道名 `verge-mihomo-*` 属 Clash Verge 内部实现，2.5.4 之前叫 `verge-mihomo-sidecar-release-*`，现为 `verge-mihomo-production-*`。若升级后 `var/scan.log` 持续出现 `watch waiting: no core pipe`，先查管道名是否又变了。
- 分类目前按动作（proxy/direct/reject）。未来若要按主题细分（ai/dev/media…），在配置的 `ruleset/` 下增分类文件并在 profile 规则里加对应 `RULE-SET` 行，`promote` 可相应扩展。
- 归类后务必重新激活配置，否则新规则不生效。
- **推荐与理由（进行中，只推荐、不自动选择）**：待审页给出推荐归类；待审与地域放行「可疑」的每一行，可按按钮查看详细理由（这个主机是谁的、做什么用、为什么这样推荐）。一个办法是调用模型，输入主机、发起进程、前后连接与现有规则集。2026-09-23 提出，先悬置。已认同分两层：第 1 层用本机数据做离线推荐（规则集同站条目、已知 IP 段、ASN、前后连接与发起进程的归类比例），理由即证据；第 2 层按按钮调模型，读提示词笔记的「背景与策略」一节（现为本目录的副本 `prompt.md`）。测试基准已冻结在 `var/testcases/`（规则集标注与地域放行「可疑」24 项，冻结时比最初的 23 项多了 `ingest.s.telemetry.intel.com`）；这 24 项在此之前不审核、不标「正常」也不拉黑。之后对规则集的复查由算法挑候选、由人决定，每条改动在 `var/testcases/provenance.json` 记来源，参考过模型的标注不用于评估第 2 层。第 2 层要能联网搜索：不认识的小众主机只有靠搜索才可能查到；但网上资料可能过时（2026-09-23 例：搜索结果称 Claude Code 用 `statsig.anthropic.com` 取功能开关，实测 2.1.280 不连它、功能开关来自 GrowthBook，见代理主题 README 第 4 节），所以来自网上的说法要标来源，与本机证据冲突时以本机为准。调用哪家模型不预先定：后端只留一个调用接口，Gemini API（Google 搜索辅助）与 Claude（`claude -p`，用 `--allowed-tools` 放开网页搜索、`--json-schema` 固定输出格式）各接一个，都开搜索，在 `var/testcases/` 的基准上比较与标注的一致率、有无编造、不认识时是否如实说明，再决定用哪个或两个都留。
  - 2026-09-23 改为三层并排（`layers.py`）：第 1 层本机事实（国内视角解析、直连实测、同站归类、流量）；第 2 层模型（DeepSeek-V4.1-Flash，只看本机事实，先问一次、结论是拉黑才复问两次投票）；第 3 层外部资料（五份名单离线，RDAP、证书、搜索按需）。推荐由写明的规则汇总：模型与名单都说拉黑才标「拉黑，一致」；只有模型说拉黑的标「有分歧」由人定。依据是 A 套三次运行回放：两者都说拉黑 58 次全对，误拉黑全部出在「只有模型说拉黑、名单没收录」那一格。推荐从不自动选中，界面只显示推荐与分歧。
  - 2026-09-23 定下的外发规则：发起进程总是发送；前后连接只在按单行「理由」时发送，且只发站点名（最多 6 个）；「为本页全部生成」不发前后连接；`no_send.txt` 里的主机一律不发。触发方式两种都做：单行「理由」按钮、「为本页全部生成」。
  - 评估改为不依赖人工先给答案（人工判断本身要参考模型）：A 用规则集里模型参与之前的人工归类检验方向；B 地域放行「可疑」24 项做盲评，冲突按证据裁定；C 用编造主机检验会不会编，用 statsig 检验是否以本机证据为准。首轮比较 DeepSeek（flash、v4-pro）与 Claude（Haiku、Sonnet），均不带搜索（DeepSeek API 无搜索；Gemini 免费档搜索额度为 0，以后再说）。
  - 模型结果的缓存（2026-09-24，`advisor.py`「缓存规则」）：按回答依赖什么分两类。**身份**（归属与用途）只取决于主机名，与在哪个页面看无关，按主机缓存在 `var/identity.json`、各页面共用，任一页面的查询成功时写入。**推荐与理由**（`var/advice.json`）取决于提示词与本机证据；同样的输入再问一遍只是重新抽样（见投票一节），所以不自动重查，只在提示词改过（按提示词指纹比对）时标「已过期」，「为本页生成」时重查。两类都不按时间过期，一直留到被新结果覆盖（用户定）。

---

## 可迁移

目标：以后给别人用，做成独立软件（exe）、Clash 的插件或增强扩展，形式未定。约束：目录能单独拿走，不读目录以外的文件，不写死本机路径与个人常量。

2026-09-23 讨论时的结论：exe 可用 PyInstaller 把后端与网页打成一个文件，但自用意义不大（每次改代码都要重打包，还可能被杀毒软件误报）；给别人用时难点不在打包，而在工具深度依赖本机这套配置，要先做「首次运行时自动检测与配置」。当时据此把网页做成后端只提供 API、页面只调用 API。

缺口与处理（2026-09-24 查，同日处理）：

| 缺口 | 处理 | 状态 |
|---|---|---|
| 引用工具目录以外的 web-kit | 本目录带一份副本 `web-kit/`，只导入自己那份；来历记在 `vendor.json` | 已处理 |
| 提示词读自工具目录以外的笔记 | 改为本目录的 `prompt.md`，它就是正本 | 已处理 |
| DeepSeek 密钥读自固定位置 | 环境变量 `DEEPSEEK_API_KEY`，或 `settings.json` 的 `deepseek_key_file`（密钥文件放哪由使用者定，工具只拿到路径） | 已处理 |
| 本人配置的命名写死 | 规则集名、顺序、代理组、兜底、管道、mixed-port 从 `clash-verge.yaml` 读，`settings.json` 可覆盖（第四节）；别的工具的回退域名移到 `settings.json` 的 `fallback_hosts`；网页上的规则集名与匹配顺序也取检测结果 | 已处理 |
| Python 路径写死 | `review-gui.bat`、`install_task.ps1` 改用 `web-kit\find-python.ps1` 查找；打包成 exe 后不再需要 | 已处理 |
| 只有中文界面 | 视发布对象再定 | 未做 |
| 只适配 Clash Verge 2.5.x 的 service 布局与管道名 | 管道优先按配置里的 `external-controller-pipe` 找；找不到时的提示写明找了什么、可能原因 | 已处理（仍只支持命名管道这一种接法） |

仍有的限制：「地域放行」按 `GeoSite(cn)`、`GeoIP(CN)`、`GeoSite(geolocation-!cn)` 这几个规则名认，用别的地域规则的配置认不出；评估脚本（`eval_models.py`、`audit_candidates.py`）读 `var/testcases/` 里冻结的 `my-*.yaml`，只对本机数据有意义。

整目录拷到别处单独运行已试过（2026-09-24，去掉 `var/` 与 `settings.json`）：`status` 读到本机 Clash 配置的规则集与代理组、提示词从 `prompt.md` 读、没有密钥时报清楚怎么设。

副本 `web-kit/` 只和线上的 web-kit 比，不引用任何本地工作目录：

- 核对副本没被改过：`git rev-parse HEAD:web-kit` 应等于 `vendor.json` 里 `tree` 的哈希部分，`git status web-kit` 应无改动。
- 查新版：`git ls-remote --tags https://github.com/edsfod/web-kit.git`。
- 更新：`git clone --depth 1 --branch <标签> https://github.com/edsfod/web-kit.git` 到临时目录，删掉其中的 `.git/`，整个替换 `web-kit/`，改 `vendor.json`，重启服务。
- 个人文件不进仓库（`.gitignore`）：`settings.json`、`no_send.txt`、`var/`、`portable`。平常它们也不在程序目录里（见第三节「设置与数据放在哪」）。
- 发布：打 `v*` 标签时 GitHub Actions（`.github/workflows/release.yml`）用 `web-kit/pack.py` 打成带免安装版 Python 的 zip 挂到 Releases；只在公开项目里运行。

---

## 六、否定结论

**采集**
- 读核心日志文件不行：Clash Verge 2.5.4 起 service 模式的日志移到只有 SYSTEM 可读的 ProgramData，改为订阅内核命名管道的 `/logs` 流。
- 把纯 IP 当噪声丢弃不行：Telegram 这类按 IP 直连、没有域名的连接因此完全看不到。
- 光存内核的警告与错误抓不到线路卡住：走 VLESS 节点时卡在「节点到目标」这一段，内核只记一条正常的 info 连接（2026-09-24 经 MyVPS 连 `github.com:81` 实测），所以另加主动探测。
- 拉黑命中的「次数」不能当作「重试」：半小时 470 次 Datadog 实为 216 个 `claude -p` 进程各连 2 次；要看逐时分布与进程。

**写规则**
- 单个 IP 裸写进 ipcidr 规则集不生效：mihomo 报 `invalid Ipcidr` 并跳过该条，要写成 `/32`。
- 父域合并不能自动做：取「最后两段」会误判大站（`microsoft.com` 下功能与遥测混在一起）与公共后缀（`qzz.io`、`workers.dev`）。

**可疑排序与复查**
- 用排序算法挑规则集里该改的条目不行：134 条只挑出 2 条，且都是小站点同站比例的假象；改为模型逐条建议、人工决定。
- `dsp`、`ssp` 这类缩写不能当强关键词：`dsp.mp.microsoft.com` 是 Windows 更新分发。

**模型推荐**
- 只有模型说拉黑、名单没收录的，不能直接推荐：误拉黑全部出在这一格，所以标「分歧」由人定。
- 每题只问一次不够：单次提问偶有高把握地误拉黑，但同一题三次里不重复出现；改为结论是拉黑才再问两次投票。
- 用 logprobs 取各选项的概率不行：DeepSeek-V4.1-Flash 先推理后作答，结论处概率恒为 1.0。
- 搜索结果的摘要不能直接用：会把相邻主机的资料套过来（`*-live-comet-*` 套到 `*-live-tracker-*`），只列出处。RDAP 对 .ru、.cn 等后缀查不到。
- v2fly 的 `include:microsoft @ads` 不能当成整份 microsoft 都是广告，要按属性过滤。
- `claude -p --bare` 只认 API 密钥、不认订阅登录，不能用。
- 直连实测只测 HTTPS 不行：只走 HTTP 的主机（如 Windows 更新）会被误报为连不上。

**代理改直连**
- 按 ASN 登记国家判断节点在不在国内不行：任播 CDN（微软、Fastly、Cloudflare）登记在美国，实际由近处节点响应。
- 按 TCP 握手 ≤ 80 ms 判断不行：单次抖动大（同一家的两个主机 264 与 56 ms），「节点近」也不等于比代理快。
- 只比直连与代理的速度不行：走代理多绕一趟境外节点，能直连的几乎都更快（60 项里 55 项推荐直连），混进出口 IP 探测、支付、身份认证；速度只说明线路，该不该直连按策略问模型。
- 不另测下载吞吐：与首字节的结论一致（见第二节），多下几 MB 换不来新信息。

**测试题**
- 手工冻结待审测试集不行：待审处理后条目就被移除，事后冻结赶不上，冻结的那批 11/16 还是测试时自己造成的连接；改为人工裁定日志。

**可迁移**
- 规则集名、代理组名写死不行（以后给别人用）：别人的配置不叫 `my-*`、不叫「节点选择」；Clash Verge 生成的 `clash-verge.yaml` 里本来就有，改为读它。
- 只按 `\\.\pipe\verge-mihomo-*` 找管道不够：配置里写明了管道名，优先用它；但本机配置写的 `sidecar-release` 与实际在跑的 `production` 不一致，所以仍保留按前缀找。

**网页**
- 照搬大屏的面板化样式不行（v1）：判断信息要逐条点开、域名与按钮隔得远；改为一条一行、操作在左。
- 在按钮上加推荐描边不行：与选中态混在一起；推荐只写在行内标签上。浅灰底的选中态在深色下看不出，改为实心填充。
- 用 `python.exe` 带控制台窗口运行不行：窗口里无事可做且会被误关；改 pythonw 后台运行，子进程一律 `CREATE_NO_WINDOW`，否则每个 curl 弹一个 cmd 窗口。

---

## 修订记录

- 2026-09-26（v1.3.0）：规则服务目的地下，规则页恢复为编辑器：列出服务端能写的全部规则集，改类、换层、删除、新增直接提交（带版本号，`POST /changes` 的 `base`），撤销删除按原样写回；v1.2.0 只给管理页链接，电脑上改规则要去管理页、每次输密钥。搜索改为搜全部规则集（两种目的地都是）。协议不变，用到服务端可选的 `layer`、`category` 字段。
- 2026-09-26（v1.2.2）：规则服务模式下提交更快（约 5 秒 → 2～3 秒）：写入后不再重读服务端的全部规则，直接把写成功的条目加进缓存；网页顶栏用缓存的服务端条目判断（1.5 秒 → 0.07 秒），命令行 `status` 仍当场问服务端；网页写入后先刷新列表，顶栏在后台更新。
- 2026-09-26（v1.2.1）：修 v1.2.0 的三处问题。网页在查询进行中每 1.5 秒重画一次，按下与松开鼠标落在新旧两个按钮上，「应用」点了没反应：改为按住鼠标期间不重画，松开后补画；提交中按钮显示「提交中…」，防重复提交；写进规则服务后不再提示「重新激活」。访问规则服务原先记住「上次成功的线路」，直连 pages.dev 偶尔成功一次就一直先走直连，每次等 20～40 秒（`status` 一次 43 秒）：改为看 Clash 里对应的 `http` 规则集写没写 `proxy`，写了就先经本机代理（约 0.6 秒），直连最多等 8 秒。`status` 对规则服务的规则集改用服务端的条目与内核比条数，不再读没人更新的本地缓存。
- 2026-09-26（v1.2.0）：归类决定可以写到「规则服务」（`settings.json` 的 `destination`，见第四节「目的地」）：一次归类一个提交，写入前的检查由服务端做，失败时待审不变；服务端的条目代替 `http` 规则集的本地缓存作为「已有规则」；已提交的决定上线后让内核立即重新取（watch 与网页的后台线程）；`status` 多一节「写入目的地」；规则页改为给服务端管理页的链接。没配时行为不变。加 `tests/test_destination.py`（假的规则服务与内核管道）。
- 2026-09-26（未发版）：新增设计稿 `docs/rule-sources.md`：规则集分订阅与支配两种模式，支配模式的写入协议草案；第四节加指向它的一段。
- 2026-09-26（未发版）：设计稿改写为 `docs/destinations.md`：去掉「订阅模式」（自己按网址取、列出、覆盖别人的规则集是 Clash Verge 与内核的事），改为归类决定写到「目的地」（本机文件或规则服务的写入接口）；已有规则的编辑归规则所在的服务。第四节的指向相应改写。
- 2026-09-25（v1.1.0）：「已有规则」改为看 Clash 配置里全部 `domain` / `ipcidr` 规则集（`type: file` 与 `type: http`，按 `rules` 顺序），`http` 的读 `path` 处的本地缓存，读不到的跳过并报出；写入仍只写收件箱（每类第一个 `type: file`）。涉及：漏网是否已覆盖、写入前的冗余与重叠提示、`tidy`（收件箱条目已并入 http 规则集时列为可清理；跨类重叠写出规则集名）、`rejects`（http 拉黑规则集的命中也计入）、回退域名检查（按规则顺序先命中的须是代理类）、网页的同站条目。`status` 分列收件箱与其它规则集（内核的 `vehicleType`、`ruleCount`，本地缓存条数）。只有收件箱时行为不变：旧版与新版在同一份配置上跑 `tidy`、`promote`、`tidy --apply`、`list`、`rejects`，输出与写出的文件逐字相同。另修：`--config-dir` 写在子命令前面时被忽略、退回自动定位的配置目录；读规则集与清单后未及时关闭文件。加 `tests/`（`python -m unittest discover -s tests`）。
- 2026-09-24（v1.0.0）：首次公开发布。此前在作者的私有工作区里开发，历史不随公开仓库发布。
