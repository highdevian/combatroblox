"""
Testes para shellbag_scanner.py, firewall_scanner.py e os novos scanners
adicionados em persistence.py (WMI) e system_hardening.py (ETW tamper).
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import patch, MagicMock


# ============================================================
# shellbag_scanner — scan_shellbag
# ============================================================

class TestScanShellbag:

    def test_no_winreg_returns_error(self):
        import shellbag_scanner
        with patch.object(shellbag_scanner, "HAS_WINREG", False):
            r = shellbag_scanner.scan_shellbag()
        assert r["status"] == "error"

    def test_no_registry_keys_returns_clean(self):
        import shellbag_scanner
        with patch.object(shellbag_scanner, "HAS_WINREG", True), \
             patch.object(shellbag_scanner, "_walk_bagmru", return_value=[]):
            r = shellbag_scanner.scan_shellbag()
        assert r["status"] == "clean"
        assert r["items"] == []

    def test_executor_folder_flagged(self):
        import shellbag_scanner
        with patch.object(shellbag_scanner, "HAS_WINREG", True), \
             patch.object(shellbag_scanner, "_walk_bagmru",
                          return_value=["solara", "Documents", "Downloads"]):
            r = shellbag_scanner.scan_shellbag()
        assert r["status"] == "suspicious"
        labels = [i["label"] for i in r["items"]]
        assert any("solara" in l.lower() for l in labels)

    def test_benign_folders_not_flagged(self):
        import shellbag_scanner
        with patch.object(shellbag_scanner, "HAS_WINREG", True), \
             patch.object(shellbag_scanner, "_walk_bagmru",
                          return_value=["Documents", "Pictures", "Downloads", "Music"]):
            r = shellbag_scanner.scan_shellbag()
        assert r["items"] == []

    def test_extract_strings_from_pidl_utf16(self):
        from shellbag_scanner import _extract_strings_from_pidl
        # Codifica "solara" em UTF-16 LE
        blob = "solara".encode("utf-16-le")
        found = _extract_strings_from_pidl(blob)
        assert any("solara" in s.lower() for s in found)

    def test_extract_strings_ignores_short(self):
        from shellbag_scanner import _extract_strings_from_pidl
        blob = "ab".encode("utf-16-le")
        found = _extract_strings_from_pidl(blob)
        assert not any(len(s) >= 4 for s in found)

    def test_deduplication(self):
        import shellbag_scanner
        # Mesma pasta duplicada na saída do walk — deve virar 1 item
        with patch.object(shellbag_scanner, "HAS_WINREG", True), \
             patch.object(shellbag_scanner, "_walk_bagmru",
                          return_value=["solara", "solara", "solara"]):
            r = shellbag_scanner.scan_shellbag()
        assert len(r["items"]) == 1


# ============================================================
# shellbag_scanner — scan_appcompat_flags
# ============================================================

class TestScanAppCompatFlags:

    def test_no_winreg_returns_error(self):
        import shellbag_scanner
        with patch.object(shellbag_scanner, "HAS_WINREG", False):
            r = shellbag_scanner.scan_appcompat_flags()
        assert r["status"] == "error"

    def test_no_key_returns_clean(self):
        import shellbag_scanner
        with patch.object(shellbag_scanner, "HAS_WINREG", True), \
             patch("winreg.OpenKey", side_effect=OSError("key not found")):
            r = shellbag_scanner.scan_appcompat_flags()
        assert r["status"] == "clean"
        assert r["items"] == []

    def test_executor_in_compat_key_flagged(self):
        import shellbag_scanner
        import winreg

        mock_key = MagicMock()
        enum_side = [
            (r"C:\Users\user\Downloads\solara.exe", "RUNASADMIN", winreg.REG_SZ),
            OSError("no more"),
        ]
        def enum_value(key, i):
            v = enum_side[i]
            if isinstance(v, Exception):
                raise v
            return v

        with patch.object(shellbag_scanner, "HAS_WINREG", True), \
             patch("winreg.OpenKey", return_value=mock_key), \
             patch("winreg.EnumValue", side_effect=enum_value), \
             patch("winreg.CloseKey"):
            r = shellbag_scanner.scan_appcompat_flags()

        assert r["status"] == "suspicious"
        assert any("solara" in i["label"].lower() for i in r["items"])

    def test_system_exe_not_flagged(self):
        import shellbag_scanner
        import winreg

        mock_key = MagicMock()
        enum_side = [
            (r"C:\Windows\System32\notepad.exe", "WIN95", winreg.REG_SZ),
            OSError("no more"),
        ]
        def enum_value(key, i):
            v = enum_side[i]
            if isinstance(v, Exception):
                raise v
            return v

        with patch.object(shellbag_scanner, "HAS_WINREG", True), \
             patch("winreg.OpenKey", return_value=mock_key), \
             patch("winreg.EnumValue", side_effect=enum_value), \
             patch("winreg.CloseKey"):
            r = shellbag_scanner.scan_appcompat_flags()

        assert r["items"] == []


# ============================================================
# firewall_scanner — scan_firewall_rules
# ============================================================

class TestScanFirewallRules:

    def test_no_winreg_returns_error(self):
        import firewall_scanner
        with patch.object(firewall_scanner, "HAS_WINREG", False):
            r = firewall_scanner.scan_firewall_rules()
        assert r["status"] == "error"

    def test_empty_keys_returns_clean(self):
        import firewall_scanner
        with patch.object(firewall_scanner, "HAS_WINREG", True), \
             patch("winreg.OpenKey", side_effect=OSError("no key")), \
             patch("winreg.CloseKey"):
            r = firewall_scanner.scan_firewall_rules()
        assert r["items"] == []

    def test_executor_in_rule_name_flagged(self):
        import firewall_scanner
        import winreg

        rule_str = ("v2.30|Action=Allow|Active=TRUE|Dir=Out|"
                    "App=C:\\Users\\user\\Downloads\\solara.exe|Name=solara rule|")
        mock_key = MagicMock()
        enum_side = [
            ("solara rule", rule_str, winreg.REG_SZ),
            OSError("done"),
        ]
        def ev(key, i):
            v = enum_side[i]
            if isinstance(v, Exception):
                raise v
            return v

        with patch.object(firewall_scanner, "HAS_WINREG", True), \
             patch("winreg.OpenKey", return_value=mock_key), \
             patch("winreg.EnumValue", side_effect=ev), \
             patch("winreg.CloseKey"):
            r = firewall_scanner.scan_firewall_rules()

        assert r["status"] == "suspicious"
        assert any("solara" in i["matched"] or "solara" in i["label"].lower()
                   for i in r["items"])

    def test_user_path_allow_outbound_medium(self):
        import firewall_scanner
        import winreg

        rule_str = ("v2.30|Action=Allow|Active=TRUE|Dir=Out|"
                    "App=C:\\Users\\user\\AppData\\Local\\loader.exe|Name=loader|")
        mock_key = MagicMock()
        enum_side = [("loader", rule_str, winreg.REG_SZ), OSError("done")]
        def ev(key, i):
            v = enum_side[i]
            if isinstance(v, Exception): raise v
            return v

        with patch.object(firewall_scanner, "HAS_WINREG", True), \
             patch("winreg.OpenKey", return_value=mock_key), \
             patch("winreg.EnumValue", side_effect=ev), \
             patch("winreg.CloseKey"):
            r = firewall_scanner.scan_firewall_rules()

        # loader.exe não é keyword de executor conhecido, mas é user-path
        items = [i for i in r["items"] if "firewall-user-allow" in i.get("matched", "")]
        assert len(items) >= 1
        assert items[0]["severity"] == "medium"

    def test_block_roblox_flagged_high(self):
        import firewall_scanner
        import winreg

        rule_str = ("v2.30|Action=Block|Active=TRUE|Dir=Out|"
                    "App=Any|Name=block-roblox|RM=roblox.com|")
        mock_key = MagicMock()
        enum_side = [("block-roblox", rule_str, winreg.REG_SZ), OSError("done")]
        def ev(key, i):
            v = enum_side[i]
            if isinstance(v, Exception): raise v
            return v

        with patch.object(firewall_scanner, "HAS_WINREG", True), \
             patch("winreg.OpenKey", return_value=mock_key), \
             patch("winreg.EnumValue", side_effect=ev), \
             patch("winreg.CloseKey"):
            r = firewall_scanner.scan_firewall_rules()

        items = [i for i in r["items"]
                 if "firewall-block-roblox" in i.get("matched", "")]
        assert len(items) >= 1
        assert items[0]["severity"] == "high"

    def test_legitimate_windows_app_not_flagged(self):
        import firewall_scanner
        import winreg

        rule_str = ("v2.30|Action=Allow|Active=TRUE|Dir=Out|"
                    "App=C:\\Program Files\\SomeApp\\app.exe|Name=someapp|")
        mock_key = MagicMock()
        enum_side = [("someapp", rule_str, winreg.REG_SZ), OSError("done")]
        def ev(key, i):
            v = enum_side[i]
            if isinstance(v, Exception): raise v
            return v

        with patch.object(firewall_scanner, "HAS_WINREG", True), \
             patch("winreg.OpenKey", return_value=mock_key), \
             patch("winreg.EnumValue", side_effect=ev), \
             patch("winreg.CloseKey"):
            r = firewall_scanner.scan_firewall_rules()

        assert r["items"] == []


# ============================================================
# persistence — scan_wmi_persistence
# ============================================================

class TestScanWmiPersistence:

    def _run_with_stdout(self, stdout_text, returncode=0):
        import persistence

        mock_result = MagicMock()
        mock_result.returncode = returncode
        mock_result.stdout = stdout_text
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            return persistence.scan_wmi_persistence()

    def test_no_subscriptions_clean(self):
        r = self._run_with_stdout("")
        assert r["items"] == []

    def test_filter_detected(self):
        stdout = "FILTER::MalLoader::SELECT * FROM __InstanceCreationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_Process'\n"
        r = self._run_with_stdout(stdout)
        assert r["status"] == "suspicious"
        assert any("wmi-event-filter" in i["matched"] for i in r["items"])

    def test_commandline_consumer_critical(self):
        stdout = "CONSUMER::CommandLineEventConsumer::CheatLoader::C:\\Users\\user\\cheat.exe\n"
        r = self._run_with_stdout(stdout)
        assert r["status"] == "suspicious"
        items = [i for i in r["items"] if "wmi-event-consumer" in i.get("matched", "")]
        assert items[0]["severity"] == "critical"

    def test_non_commandline_consumer_high(self):
        stdout = "CONSUMER::ActiveScriptEventConsumer::MyScript::\n"
        r = self._run_with_stdout(stdout)
        items = [i for i in r["items"] if "wmi-event-consumer" in i.get("matched", "")]
        assert items[0]["severity"] == "high"

    def test_scm_event_consumer_ignored(self):
        """SCM Event Log Consumer = baseline do Windows, não é persistência."""
        stdout = (
            "FILTER::SCM Event Log Filter::SELECT * FROM __InstanceModificationEvent\n"
            "CONSUMER::NTEventLogEventConsumer::SCM Event Log Consumer::\n"
        )
        r = self._run_with_stdout(stdout)
        assert r["items"] == []

    def test_subprocess_error_returns_error(self):
        import persistence
        with patch("subprocess.run", side_effect=OSError("no powershell")):
            r = persistence.scan_wmi_persistence()
        assert r["status"] == "error"


# ============================================================
# system_hardening — scan_etw_autologger_tamper
# ============================================================

class TestScanEtwAutologgerTamper:

    def test_no_winreg_returns_error(self):
        import system_hardening
        with patch.object(system_hardening, "_HAS_WINREG_SH", False):
            r = system_hardening.scan_etw_autologger_tamper()
        assert r["status"] == "error"

    def test_no_key_returns_error(self):
        import system_hardening
        with patch.object(system_hardening, "_HAS_WINREG_SH", True), \
             patch("winreg.OpenKey", side_effect=OSError("no key")):
            r = system_hardening.scan_etw_autologger_tamper()
        assert r["status"] == "error"

    def test_enabled_logger_no_flag(self):
        import system_hardening
        import winreg

        root_mock = MagicMock()
        sub_mock = MagicMock()
        enum_key_side = ["EventLog-Security", OSError("done")]
        def ek(key, i):
            v = enum_key_side[i]
            if isinstance(v, Exception): raise v
            return v

        with patch.object(system_hardening, "_HAS_WINREG_SH", True), \
             patch("winreg.OpenKey", side_effect=[root_mock, sub_mock]), \
             patch("winreg.EnumKey", side_effect=ek), \
             patch("winreg.QueryValueEx", return_value=(1, winreg.REG_DWORD)), \
             patch("winreg.CloseKey"):
            r = system_hardening.scan_etw_autologger_tamper()

        assert r["items"] == []

    def test_disabled_logger_flagged(self):
        import system_hardening
        import winreg

        root_mock = MagicMock()
        sub_mock = MagicMock()
        enum_key_side = ["EventLog-Security", OSError("done")]
        def ek(key, i):
            v = enum_key_side[i]
            if isinstance(v, Exception): raise v
            return v

        with patch.object(system_hardening, "_HAS_WINREG_SH", True), \
             patch("winreg.OpenKey", side_effect=[root_mock, sub_mock]), \
             patch("winreg.EnumKey", side_effect=ek), \
             patch("winreg.QueryValueEx", return_value=(0, winreg.REG_DWORD)), \
             patch("winreg.CloseKey"):
            r = system_hardening.scan_etw_autologger_tamper()

        assert r["status"] == "suspicious"
        assert any("EventLog-Security" in i["label"] for i in r["items"])
        assert r["items"][0]["severity"] == "high"

    def test_unknown_logger_not_flagged(self):
        import system_hardening
        import winreg

        root_mock = MagicMock()
        sub_mock = MagicMock()
        enum_key_side = ["SomeRandomLogger", OSError("done")]
        def ek(key, i):
            v = enum_key_side[i]
            if isinstance(v, Exception): raise v
            return v

        with patch.object(system_hardening, "_HAS_WINREG_SH", True), \
             patch("winreg.OpenKey", side_effect=[root_mock, sub_mock]), \
             patch("winreg.EnumKey", side_effect=ek), \
             patch("winreg.QueryValueEx", return_value=(0, winreg.REG_DWORD)), \
             patch("winreg.CloseKey"):
            r = system_hardening.scan_etw_autologger_tamper()

        assert r["items"] == []
