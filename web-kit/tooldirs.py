"""tooldirs —— 工具把使用者的设置与运行数据放在哪（仅标准库，不依赖 webkit.py，命令行工具也能用）。

    import tooldirs
    CONF_DIR, DATA_DIR = tooldirs.dirs(HERE, "clash-review")

- 平常：设置在 %APPDATA%\\<名字>\\（settings.json 与其它个人名单），运行数据在 %LOCALAPPDATA%\\<名字>\\
  （清单、缓存、日志、下载的数据）。程序目录里只有发布的内容，升级时整个换掉，不会丢个人的东西。
- 便携模式：工具目录里有名为 portable 的文件（内容不限）时，设置就在工具目录，数据在工具目录的 var/。
  给想整个拷走、不在本机留东西的人；开发时想和已安装的那份分开数据，也用它。

只返回路径，不创建目录；写文件的一方自己 os.makedirs(..., exist_ok=True)。
"""
import os


def dirs(tool_dir, name):
    """返回 (设置目录, 数据目录)。tool_dir 是工具根目录，name 是工具名（用作 AppData 下的文件夹名）。"""
    if os.path.exists(os.path.join(tool_dir, "portable")):
        return tool_dir, os.path.join(tool_dir, "var")
    home = os.path.expanduser("~")
    roaming = os.environ.get("APPDATA") or os.path.join(home, "AppData", "Roaming")
    local = os.environ.get("LOCALAPPDATA") or os.path.join(home, "AppData", "Local")
    return os.path.join(roaming, name), os.path.join(local, name)


def portable(tool_dir):
    return os.path.exists(os.path.join(tool_dir, "portable"))
