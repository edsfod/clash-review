"""模型选择（advisor「各家接口」）：settings.json 的 model、Codex 命令行的调用方式、推荐过期、网页的设置接口。不联网、不真调模型。

    python -m unittest discover -s tests
"""
import json, os, subprocess, unittest

import test_rulesets                          # 先导入：它把 APPDATA / LOCALAPPDATA 指到临时目录
from test_rulesets import cr
import advisor, clash_review_web as web


class Settings(unittest.TestCase):
    def setUp(self):
        if os.path.exists(cr.SETTINGS): os.remove(cr.SETTINGS)

    tearDown = setUp

    def write(self, d):
        os.makedirs(os.path.dirname(cr.SETTINGS), exist_ok=True)
        with open(cr.SETTINGS, "w", encoding="utf-8") as f: json.dump(d, f)

    def test_default_is_codex_sol(self):
        self.assertEqual(advisor.model_conf(), {"provider": "codex", "model": "gpt-6-sol", "effort": "low"})
        self.assertEqual(advisor.model_name(), "codex:gpt-6-sol")
        self.assertEqual(advisor.resolve()[1:], ("codex", "codex:gpt-6-sol"))

    def test_old_settings_keep_deepseek(self):
        self.write({"deepseek_key_file": "C:/k.txt"})
        self.assertEqual(advisor.model_name(), "openai:deepseek-flash")
        self.assertEqual(advisor.resolve()[1], "api")

    def test_explicit_model_wins(self):
        self.write({"deepseek_key_file": "C:/k.txt", "model": {"provider": "claude", "model": "sonnet"}})
        self.assertEqual(advisor.resolve()[1:], ("claude", "claude:sonnet"))

    def test_save_setting_keeps_other_keys(self):
        self.write({"proxy_group": "节点选择"})
        cr.save_setting("model", {"provider": "claude", "model": "haiku"})
        self.assertEqual(cr.settings(), {"proxy_group": "节点选择", "model": {"provider": "claude", "model": "haiku"}})

    def test_api_model_set(self):
        self.assertEqual(web.api_model_set(None, {"provider": "codex", "model": "gpt-6-luna", "effort": "bogus"}),
                         {"name": "codex:gpt-6-luna"})
        self.assertEqual(cr.settings()["model"], {"provider": "codex", "model": "gpt-6-luna", "effort": "low"})
        with self.assertRaises(web.ApiError): web.api_model_set(None, {"provider": "claude", "model": "opus"})
        with self.assertRaises(web.ApiError):
            web.api_model_set(None, {"provider": "openai", "base_url": "https://x", "model": "m", "key_file": "C:/nope/key.txt"})

    def test_no_model(self):
        self.assertEqual(web.api_model_set(None, {"provider": "none"}), {"name": "none"})
        self.assertFalse(advisor.model_enabled())
        with self.assertRaises(RuntimeError): advisor.resolve()
        self.assertEqual(web._stale({"prompt_hash": "p1", "model_name": "codex:gpt-6-sol"}, ("p1", "none")), "")   # 以前的推荐照常参考
        self.assertEqual(web._stale({"prompt_hash": "p0", "model_name": "none"}, ("p1", "none")), "提示词改过")
        self.assertEqual(web._stale({"prompt_hash": "p1", "model_name": "none"}, ("p1", "codex:gpt-6-sol")), "换了模型")
        web.api_model_set(None, {"provider": "codex"})
        self.assertTrue(advisor.model_enabled())

    def test_stale(self):
        ph = ("p1", "codex:gpt-6-sol")
        self.assertEqual(web._stale({"prompt_hash": "p0", "model_name": "codex:gpt-6-sol"}, ph), "提示词改过")
        self.assertEqual(web._stale({"prompt_hash": "p1"}, ph), "换了模型")                 # 1.4.0 之前没记模型名：DeepSeek 给的
        self.assertEqual(web._stale({"prompt_hash": "p1", "model_name": "codex:gpt-6-sol"}, ph), "")


class Codex(unittest.TestCase):
    def setUp(self):
        # 下面要在 CODEX_HOME 里建、删 auth.json：先确认它在临时目录里，碰不到本机真实的登录
        self.assertTrue(os.path.normcase(advisor.CODEX_HOME).startswith(os.path.normcase(test_rulesets._TMP.name)), advisor.CODEX_HOME)
        self.saved = (advisor.codex_exe, advisor._codex_features, advisor._codex_catalog, subprocess.run)
        advisor.codex_exe = lambda: "C:/codex.exe"
        advisor._codex_features = lambda exe: {"plugins", "shell_tool", "apps"}
        advisor._codex_catalog = lambda exe: "C:/catalog.json"
        self.calls = []
        os.makedirs(advisor.CODEX_HOME, exist_ok=True)
        open(os.path.join(advisor.CODEX_HOME, "auth.json"), "w").close()

    def tearDown(self):
        advisor.codex_exe, advisor._codex_features, advisor._codex_catalog, subprocess.run = self.saved
        os.remove(os.path.join(advisor.CODEX_HOME, "auth.json"))

    def fake_run(self, answer, stderr="tokens used\n8,423\n"):
        def run(cmd, **kw):
            self.calls.append((cmd, kw))
            out = cmd[cmd.index("-o") + 1]
            if answer is not None:
                with open(out, "w", encoding="utf-8") as f: f.write(answer)
            with open(cmd[cmd.index("--output-schema") + 1], encoding="utf-8") as f: self.schema = json.load(f)
            sysfile = [a for a in cmd if a.startswith("model_instructions_file=")][0].split("=", 1)[1]
            with open(json.loads(sysfile), encoding="utf-8") as f: self.sysmsg = f.read()
            return subprocess.CompletedProcess(cmd, 0, "", stderr)
        subprocess.run = run

    def test_command_is_bare(self):
        self.fake_run('{"a": 1}')
        text, meta = advisor._codex("gpt-6-sol", "low", "系统提示", "题目", 60)
        cmd, kw = self.calls[0]
        self.assertEqual(text, '{"a": 1}'); self.assertEqual(meta["tokens"], 8423)
        self.assertEqual(kw["env"]["CODEX_HOME"], advisor.CODEX_HOME)            # 单独的数据目录，不读 ~/.codex 的 AGENTS.md
        self.assertEqual(kw["input"], "题目"); self.assertEqual(self.sysmsg, "系统提示")
        self.assertEqual(self.schema, advisor.SCHEMA)
        for flag in ("--ignore-user-config", "--ephemeral", "--ignore-rules"): self.assertIn(flag, cmd)
        self.assertEqual(cmd[cmd.index("-m") + 1], "gpt-6-sol")
        self.assertEqual(cmd[cmd.index("--sandbox") + 1], "read-only")
        off = [cmd[i + 1] for i, a in enumerate(cmd) if a == "--disable"]
        self.assertEqual(sorted(off), ["apps", "plugins", "shell_tool"])             # 只关这个版本认得的
        conf = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-c"]
        for c in ("skills.bundled.enabled=false", "include_permissions_instructions=false",
                  "include_environment_context=false", "include_collaboration_mode_instructions=false",
                  'model_catalog_json="C:/catalog.json"'):
            self.assertIn(c, conf)

    def test_no_answer_raises(self):
        self.fake_run(None, stderr="ERROR: unexpected status 401 Unauthorized\n")
        with self.assertRaisesRegex(RuntimeError, "401"): advisor._codex("gpt-6-sol", "low", "s", "u", 60)

    def test_not_logged_in_fails_fast(self):
        os.remove(os.path.join(advisor.CODEX_HOME, "auth.json"))
        try:
            r = advisor.ask("codex-sol", {"kind": "todirect", "host": "example.com"}, sysmsg="s", retries=4)
            self.assertFalse(r["ok"]); self.assertIn("codex-login", r["error"]); self.assertLess(r["seconds"], 1)   # 不退避重试
        finally:
            open(os.path.join(advisor.CODEX_HOME, "auth.json"), "w").close()


class CodexCatalog(unittest.TestCase):
    """交给 Codex 的模型清单去掉让它另发工具的字段；清单太旧先刷新；旧位置的登录复制到新位置。"""
    def setUp(self):
        self.assertTrue(os.path.normcase(advisor.CODEX_HOME).startswith(os.path.normcase(test_rulesets._TMP.name)), advisor.CODEX_HOME)
        os.makedirs(advisor.CODEX_HOME, exist_ok=True)
        self.saved, self.calls = subprocess.run, []
        subprocess.run = lambda cmd, **kw: self.calls.append(cmd) or subprocess.CompletedProcess(cmd, 0, "", "")
        advisor._CODEX.pop("refreshed", None)
        self.cache = os.path.join(advisor.CODEX_HOME, "models_cache.json")
        with open(self.cache, "w", encoding="utf-8") as f:
            json.dump({"fetched_at": "x", "models": [{"slug": "m1", "tool_mode": "code_mode_only", "multi_agent_version": "v2",
                       "apply_patch_tool_type": "freeform", "experimental_supported_tools": ["clock"], "priority": 1}]}, f)

    def tearDown(self):
        subprocess.run = self.saved
        for p in (self.cache, advisor.CODEX_CATALOG):
            if os.path.exists(p): os.remove(p)

    def test_fields_dropped(self):
        path = advisor._codex_catalog("C:/codex.exe")
        with open(path, encoding="utf-8") as f: d = json.load(f)
        self.assertEqual(d, {"models": [{"slug": "m1", "experimental_supported_tools": [], "priority": 1}]})
        self.assertEqual(self.calls, [])                                          # 清单是新的，不刷新

    def test_stale_list_refreshed_once(self):
        os.utime(self.cache, (0, 0))
        advisor._codex_catalog("C:/codex.exe"); advisor._codex_catalog("C:/codex.exe")
        self.assertEqual(self.calls, [["C:/codex.exe", "debug", "models"]])

    def test_no_list_runs_without_catalog(self):
        os.remove(self.cache)
        self.assertIsNone(advisor._codex_catalog("C:/codex.exe"))

    def test_old_login_copied(self):
        old = advisor.OLD_CODEX_HOME
        self.assertNotEqual(old, advisor.CODEX_HOME)
        os.makedirs(old, exist_ok=True)
        with open(os.path.join(old, "auth.json"), "w") as f: f.write("{}")
        try:
            if os.path.exists(os.path.join(advisor.CODEX_HOME, "auth.json")): os.remove(os.path.join(advisor.CODEX_HOME, "auth.json"))
            self.assertTrue(advisor.codex_logged_in())
            self.assertTrue(os.path.exists(os.path.join(old, "auth.json")))         # 复制，不动旧的
        finally:
            os.remove(os.path.join(old, "auth.json")); os.remove(os.path.join(advisor.CODEX_HOME, "auth.json"))


if __name__ == "__main__":
    unittest.main()
