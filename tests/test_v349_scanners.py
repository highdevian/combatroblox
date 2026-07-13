"""
Testes para os 6 scanners novos da v3.49.0:
  - bits_scanner.scan_bits_jobs
  - hijack_scanner.scan_ifeo_hijack
  - hijack_scanner.scan_com_user_hijack
  - pca_scanner.scan_pca_appcompat_events
  - defender_mplog_scanner.scan_defender_mplog
  - streamproof_scanner.scan_streamproof_windows
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import patch, MagicMock


# ============================================================
# bits_scanner
# ============================================================

class TestBitsScanner:

    def _run(self, ps_stdout: str, returncode=0):
        import bits_scanner
        result = MagicMock()
        result.returncode = returncode
        result.stdout = ps_stdout
        result.stderr = ""
        with patch("subprocess.run", return_value=result):
            return bits_scanner.scan_bits_jobs()

    def test_no_jobs_clean(self):
        r = self._run("")
        assert r["items"] == []

    def test_windows_update_ignored(self):
        stdout = (
            "DisplayName  : Windows Update\n"
            "JobId        : {abc}\n"
            "JobState     : Transferred\n"
            "OwnerAccount : NT AUTHORITY\\SYSTEM\n"
            "TransferType : Download\n"
            "RemoteUrl    : http://update.microsoft.com/x.cab\n"
            "LocalFile    : C:\\Windows\\Temp\\x.cab\n"
            "\n"
        )
        r = self._run(stdout)
        assert r["items"] == []

    def test_executor_keyword_flagged(self):
        stdout = (
            "DisplayName  : dl\n"
            "JobId        : {xyz}\n"
            "JobState     : Transferred\n"
            "OwnerAccount : DESKTOP\\user\n"
            "TransferType : Download\n"
            "RemoteUrl    : http://random.tk/solara.exe\n"
            "LocalFile    : C:\\Users\\user\\Downloads\\solara.exe\n"
            "\n"
        )
        r = self._run(stdout)
        assert r["status"] == "suspicious"
        assert any("solara" in i["matched"] for i in r["items"])

    def test_user_path_no_publisher_medium(self):
        stdout = (
            "DisplayName  : sometag\n"
            "JobId        : {xyz}\n"
            "JobState     : Transferred\n"
            "OwnerAccount : DESKTOP\\user\n"
            "TransferType : Download\n"
            "RemoteUrl    : http://cdn.example.com/file.dat\n"
            "LocalFile    : C:\\Users\\user\\AppData\\Local\\Temp\\file.dat\n"
            "\n"
        )
        r = self._run(stdout)
        items = [i for i in r["items"] if "bits-user-path" in i.get("matched", "")]
        assert len(items) >= 1
        assert items[0]["severity"] == "medium"

    def test_random_guid_name_high(self):
        stdout = (
            "DisplayName  : abcdef1234567890abcdef01\n"
            "JobId        : {xyz}\n"
            "JobState     : Transferred\n"
            "OwnerAccount : DESKTOP\\user\n"
            "TransferType : Download\n"
            "RemoteUrl    : http://cdn.example.com/p.bin\n"
            "LocalFile    : C:\\Users\\user\\AppData\\Local\\Temp\\p.bin\n"
            "\n"
        )
        r = self._run(stdout)
        items = [i for i in r["items"]
                 if "bits-random-name-user-path" in i.get("matched", "")]
        assert len(items) >= 1
        assert items[0]["severity"] == "high"


# ============================================================
# hijack_scanner.scan_ifeo_hijack
# ============================================================

class TestIfeoHijack:

    def test_no_winreg_returns_error(self):
        import hijack_scanner
        with patch.object(hijack_scanner, "HAS_WINREG", False):
            r = hijack_scanner.scan_ifeo_hijack()
        assert r["status"] == "error"

    def test_no_key_error(self):
        import hijack_scanner
        with patch.object(hijack_scanner, "HAS_WINREG", True), \
             patch("winreg.OpenKey", side_effect=OSError("no key")):
            r = hijack_scanner.scan_ifeo_hijack()
        assert r["status"] == "error"

    def test_legit_vsjit_debugger_ignored(self):
        import hijack_scanner
        root_mock = MagicMock()
        sub_mock = MagicMock()
        # 1 entry: chrome.exe → vsjitdebugger.exe (legit)
        enum_key_side = ["chrome.exe", OSError("done")]
        def ek(key, i):
            v = enum_key_side[i]
            if isinstance(v, Exception): raise v
            return v

        def qv(sub, name):
            if name == "Debugger":
                return (r"C:\Windows\System32\vsjitdebugger.exe", 1)
            raise OSError("no val")

        with patch.object(hijack_scanner, "HAS_WINREG", True), \
             patch("winreg.OpenKey", side_effect=[root_mock, sub_mock]), \
             patch("winreg.EnumKey", side_effect=ek), \
             patch("winreg.QueryValueEx", side_effect=qv), \
             patch("winreg.CloseKey"):
            r = hijack_scanner.scan_ifeo_hijack()

        assert r["items"] == []

    def test_roblox_hijack_critical(self):
        import hijack_scanner
        root_mock = MagicMock()
        sub_mock = MagicMock()
        enum_key_side = ["RobloxPlayerBeta.exe", OSError("done")]
        def ek(key, i):
            v = enum_key_side[i]
            if isinstance(v, Exception): raise v
            return v

        def qv(sub, name):
            if name == "Debugger":
                return (r"C:\Users\user\Downloads\payload.exe", 1)
            raise OSError("no val")

        with patch.object(hijack_scanner, "HAS_WINREG", True), \
             patch("winreg.OpenKey", side_effect=[root_mock, sub_mock]), \
             patch("winreg.EnumKey", side_effect=ek), \
             patch("winreg.QueryValueEx", side_effect=qv), \
             patch("winreg.CloseKey"):
            r = hijack_scanner.scan_ifeo_hijack()

        assert r["status"] == "suspicious"
        assert any(i["severity"] == "critical" for i in r["items"])
        assert any("RobloxPlayerBeta" in i["label"] for i in r["items"])

    def test_generic_hijack_high(self):
        import hijack_scanner
        root_mock = MagicMock()
        sub_mock = MagicMock()
        enum_key_side = ["someapp.exe", OSError("done")]
        def ek(key, i):
            v = enum_key_side[i]
            if isinstance(v, Exception): raise v
            return v

        def qv(sub, name):
            if name == "Debugger":
                return (r"C:\Users\user\payload.exe", 1)
            raise OSError("no val")

        with patch.object(hijack_scanner, "HAS_WINREG", True), \
             patch("winreg.OpenKey", side_effect=[root_mock, sub_mock]), \
             patch("winreg.EnumKey", side_effect=ek), \
             patch("winreg.QueryValueEx", side_effect=qv), \
             patch("winreg.CloseKey"):
            r = hijack_scanner.scan_ifeo_hijack()

        assert r["status"] == "suspicious"
        assert r["items"][0]["severity"] == "high"


# ============================================================
# hijack_scanner.scan_com_user_hijack
# ============================================================

class TestComUserHijack:

    def test_no_winreg_returns_error(self):
        import hijack_scanner
        with patch.object(hijack_scanner, "HAS_WINREG", False):
            r = hijack_scanner.scan_com_user_hijack()
        assert r["status"] == "error"

    def test_no_key_returns_clean(self):
        import hijack_scanner
        with patch.object(hijack_scanner, "HAS_WINREG", True), \
             patch("winreg.OpenKey", side_effect=OSError("no key")):
            r = hijack_scanner.scan_com_user_hijack()
        assert r["status"] == "clean"

    def test_windows_path_ignored(self):
        import hijack_scanner
        root_mock = MagicMock()
        inproc_mock = MagicMock()
        clsid = "{00000000-0000-0000-0000-000000000001}"
        enum_key_side = [clsid, OSError("done")]
        def ek(key, i):
            v = enum_key_side[i]
            if isinstance(v, Exception): raise v
            return v

        def open_key(hive, path):
            if path.endswith("InprocServer32"):
                return inproc_mock
            return root_mock

        def qv(k, name):
            if name == "":
                return (r"C:\Windows\System32\somelegit.dll", 1)
            raise OSError()

        with patch.object(hijack_scanner, "HAS_WINREG", True), \
             patch("winreg.OpenKey", side_effect=open_key), \
             patch("winreg.EnumKey", side_effect=ek), \
             patch("winreg.QueryValueEx", side_effect=qv), \
             patch("winreg.CloseKey"):
            r = hijack_scanner.scan_com_user_hijack()

        assert r["items"] == []

    def test_user_path_dll_flagged(self):
        import hijack_scanner
        root_mock = MagicMock()
        inproc_mock = MagicMock()
        clsid = "{11111111-1111-1111-1111-111111111111}"
        enum_key_side = [clsid, OSError("done")]
        def ek(key, i):
            v = enum_key_side[i]
            if isinstance(v, Exception): raise v
            return v

        # OpenKey chamada: root, InprocServer32 (só a primeira variant funciona)
        def open_key(hive, path):
            if path.endswith("InprocServer32") and "InProc" not in path:
                return inproc_mock
            if path.endswith(("InProcServer32", "LocalServer32")):
                raise OSError("no")
            return root_mock

        def qv(k, name):
            if name == "":
                return (r"C:\Users\user\AppData\Roaming\evil.dll", 1)
            raise OSError()

        with patch.object(hijack_scanner, "HAS_WINREG", True), \
             patch("winreg.OpenKey", side_effect=open_key), \
             patch("winreg.EnumKey", side_effect=ek), \
             patch("winreg.QueryValueEx", side_effect=qv), \
             patch("os.path.isfile", return_value=False), \
             patch("winreg.CloseKey"):
            r = hijack_scanner.scan_com_user_hijack()

        assert r["status"] == "suspicious"
        # DLL não existe = high (hijack órfão)
        assert r["items"][0]["severity"] == "high"

    def test_trusted_appdata_ignored(self):
        import hijack_scanner
        root_mock = MagicMock()
        inproc_mock = MagicMock()
        clsid = "{22222222-2222-2222-2222-222222222222}"
        enum_key_side = [clsid, OSError("done")]
        def ek(key, i):
            v = enum_key_side[i]
            if isinstance(v, Exception): raise v
            return v

        def open_key(hive, path):
            if path.endswith("InprocServer32") and "InProc" not in path:
                return inproc_mock
            if path.endswith(("InProcServer32", "LocalServer32")):
                raise OSError("no")
            return root_mock

        def qv(k, name):
            if name == "":
                return (r"C:\Users\user\AppData\Local\Microsoft\Teams\current\Teams.dll", 1)
            raise OSError()

        with patch.object(hijack_scanner, "HAS_WINREG", True), \
             patch("winreg.OpenKey", side_effect=open_key), \
             patch("winreg.EnumKey", side_effect=ek), \
             patch("winreg.QueryValueEx", side_effect=qv), \
             patch("os.path.isfile", return_value=True), \
             patch("winreg.CloseKey"):
            r = hijack_scanner.scan_com_user_hijack()

        assert r["items"] == []


# ============================================================
# pca_scanner
# ============================================================

class TestPcaAppcompat:

    def _run(self, ps_stdout: str, returncode=0):
        import pca_scanner
        result = MagicMock()
        result.returncode = returncode
        result.stdout = ps_stdout
        result.stderr = ""
        with patch("subprocess.run", return_value=result):
            return pca_scanner.scan_pca_appcompat_events()

    def test_no_events_clean(self):
        # returncode 0 + stdout vazio = sem eventos → clean sem items
        r = self._run("")
        assert r["items"] == []

    def test_executor_in_path_flagged(self):
        stdout = "EVT::2026-07-13 10:00:00::FN=C:\\Users\\user\\Downloads\\solara.exe::CN=::PN=Solara\n"
        r = self._run(stdout)
        assert r["status"] == "suspicious"
        assert any("solara" in i["matched"].lower() for i in r["items"])

    def test_userpath_no_publisher_medium(self):
        stdout = "EVT::2026-07-13 10:00:00::FN=C:\\Users\\user\\Downloads\\unknown.exe::CN=::PN=unknown\n"
        r = self._run(stdout)
        items = [i for i in r["items"]
                 if "pca-userpath-nopublisher" in i.get("matched", "")]
        assert len(items) >= 1
        assert items[0]["severity"] == "medium"

    def test_signed_publisher_ignored(self):
        stdout = "EVT::2026-07-13 10:00:00::FN=C:\\Program Files\\App\\app.exe::CN=Microsoft::PN=App\n"
        r = self._run(stdout)
        assert r["items"] == []


# ============================================================
# defender_mplog_scanner
# ============================================================

class TestDefenderMplog:

    def test_no_dir_returns_error(self):
        import defender_mplog_scanner
        with patch("os.path.isdir", return_value=False):
            r = defender_mplog_scanner.scan_defender_mplog()
        assert r["status"] == "error"

    def test_empty_dir_clean(self):
        import defender_mplog_scanner
        with patch("os.path.isdir", return_value=True), \
             patch("os.listdir", return_value=[]):
            r = defender_mplog_scanner.scan_defender_mplog()
        assert r["items"] == []

    def test_hacktool_detection_flagged_critical(self):
        import defender_mplog_scanner
        from unittest.mock import mock_open
        # Data recente pra passar o cutoff de 90 dias
        content = (
            "2026-07-13T10:00:00 DETECTION_ADD "
            "ThreatName:HackTool:Win64/Executor "
            "path: C:\\Users\\user\\Downloads\\solara.exe\n"
        )
        m = mock_open(read_data=content)
        with patch("os.path.isdir", return_value=True), \
             patch("os.listdir", return_value=["MPLog-20260713-100000.log"]), \
             patch("builtins.open", m):
            r = defender_mplog_scanner.scan_defender_mplog()

        assert r["status"] == "suspicious"
        items = [i for i in r["items"] if i["severity"] == "critical"]
        assert len(items) >= 1

    def test_benign_pua_ignored(self):
        import defender_mplog_scanner
        from unittest.mock import mock_open
        content = (
            "2026-07-13T10:00:00 DETECTION_ADD "
            "ThreatName:PUA:Win32/uTorrent "
            "path: C:\\Program Files\\uTorrent\\utorrent.exe\n"
        )
        m = mock_open(read_data=content)
        with patch("os.path.isdir", return_value=True), \
             patch("os.listdir", return_value=["MPLog-20260713-100000.log"]), \
             patch("builtins.open", m):
            r = defender_mplog_scanner.scan_defender_mplog()

        assert r["items"] == []


# ============================================================
# streamproof_scanner
# ============================================================

class TestStreamproofScanner:

    def test_no_user32_returns_error(self):
        import streamproof_scanner
        with patch.object(streamproof_scanner, "_HAS_USER32", False):
            r = streamproof_scanner.scan_streamproof_windows()
        assert r["status"] == "error"

    def test_returns_clean_when_no_hits(self):
        import streamproof_scanner
        # Mocka EnumWindows pra não visitar nada
        with patch.object(streamproof_scanner, "_HAS_USER32", True), \
             patch.object(streamproof_scanner, "_EnumWindows", return_value=True):
            r = streamproof_scanner.scan_streamproof_windows()
        assert r["items"] == []


# ============================================================
# masquerade — RobloxCrashHandler foi adicionado?
# ============================================================

class TestRobloxCrashHandlerMasquerade:

    def test_robloxcrashhandler_in_masquerade_names(self):
        import live_analysis
        assert "robloxcrashhandler.exe" in live_analysis._ROBLOX_MASQUERADE_NAMES


# ============================================================
# Chain
# ============================================================

class TestScannerChain:

    def test_all_new_scanners_registered(self):
        import scanner_registry
        reg = scanner_registry.build_registry()
        names = {m.fn_name for m in reg}
        assert "scan_bits_jobs" in names
        assert "scan_ifeo_hijack" in names
        assert "scan_com_user_hijack" in names
        assert "scan_pca_appcompat_events" in names
        assert "scan_defender_mplog" in names
        assert "scan_streamproof_windows" in names

    def test_scanner_count_bumped(self):
        import version
        assert version.SCANNER_COUNT == 108
        assert version.VERSION == "3.49.0"
