"""
Testes v3.50.0:
  - os_integrity_scanner.scan_session_manager_abuse
  - os_integrity_scanner.scan_lsa_packages
  - task_execlog_scanner.scan_task_scheduler_execlog
  - cert_store_scanner.scan_certificate_store
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import patch, MagicMock


# ============================================================
# os_integrity — Session Manager
# ============================================================

class TestSessionManager:

    def test_no_winreg_returns_error(self):
        from telador import os_integrity_scanner
        with patch.object(os_integrity_scanner, "HAS_WINREG", False):
            r = os_integrity_scanner.scan_session_manager_abuse()
        assert r["status"] == "error"

    def test_no_key_returns_error(self):
        from telador import os_integrity_scanner
        with patch.object(os_integrity_scanner, "HAS_WINREG", True), \
             patch("winreg.OpenKey", side_effect=OSError("no key")):
            r = os_integrity_scanner.scan_session_manager_abuse()
        assert r["status"] == "error"

    def _run_with_values(self, boot_execute=None, setup_execute=None,
                         knowndlls_values=None, pending_rename=None):
        """Helper: mocka winreg calls e retorna resultado."""
        from telador import os_integrity_scanner
        root_mock = MagicMock()
        kdll_mock = MagicMock()

        def open_key(hive, path):
            if path.endswith("KnownDLLs"):
                return kdll_mock
            return root_mock

        def query_value(sub, name):
            if sub is root_mock:
                if name == "BootExecute":
                    return (boot_execute or [], 7)
                if name == "SetupExecute":
                    return (setup_execute or [], 7)
                if name == "PendingFileRenameOperations":
                    return (pending_rename or [], 7)
            raise OSError("no val")

        # KnownDLLs enumeration
        kdll_values = knowndlls_values or []
        def enum_value(key, i):
            if key is kdll_mock and i < len(kdll_values):
                return kdll_values[i]
            raise OSError("no more")

        with patch.object(os_integrity_scanner, "HAS_WINREG", True), \
             patch("winreg.OpenKey", side_effect=open_key), \
             patch("winreg.QueryValueEx", side_effect=query_value), \
             patch("winreg.EnumValue", side_effect=enum_value), \
             patch("winreg.CloseKey"):
            return os_integrity_scanner.scan_session_manager_abuse()

    def test_baseline_boot_execute_clean(self):
        r = self._run_with_values(boot_execute=["autocheck autochk *"])
        assert r["items"] == []

    def test_extra_boot_execute_critical(self):
        r = self._run_with_values(boot_execute=[
            "autocheck autochk *",
            "some_malicious.exe /run",
        ])
        assert r["status"] == "suspicious"
        items = [i for i in r["items"] if "bootexecute" in i["matched"]]
        assert len(items) >= 1
        assert items[0]["severity"] == "critical"

    def test_extra_knowndlls_critical(self):
        # Adiciona DLL não-padrão em KnownDLLs
        r = self._run_with_values(knowndlls_values=[
            ("kernel32", "kernel32.dll", 1),  # esperado
            ("evil_hook", "C:\\Users\\hack\\evil.dll", 1),  # NÃO esperado
        ])
        items = [i for i in r["items"] if "knowndlls-extra" in i["matched"]]
        assert len(items) >= 1
        assert items[0]["severity"] == "critical"

    def test_win11_baseline_knowndlls_clean(self):
        """*kernel32, wow64*, xtajit64* = baseline Win11, não CRITICAL."""
        r = self._run_with_values(knowndlls_values=[
            ("*kernel32", "kernel32.dll", 1),
            ("wow64", "wow64.dll", 1),
            ("wow64base", "wow64base.dll", 1),
            ("wow64con", "wow64con.dll", 1),
            ("wow64win", "wow64win.dll", 1),
            ("xtajit64", "xtajit64.dll", 1),
            ("xtajit64se", "xtajit64se.dll", 1),
            ("_xtajitf", "xtajitf.dll", 1),
        ])
        extras = [i for i in r["items"] if "knowndlls-extra" in i["matched"]]
        assert extras == []

    def test_pending_rename_with_executor_flagged(self):
        r = self._run_with_values(pending_rename=[
            "\\??\\C:\\Users\\user\\Downloads\\solara.exe",
            "",
        ])
        items = [i for i in r["items"] if "pending-rename" in i["matched"]]
        assert len(items) >= 1


# ============================================================
# os_integrity — LSA Packages
# ============================================================

class TestLsaPackages:

    def _run_with_values(self, auth=None, security=None, notification=None):
        from telador import os_integrity_scanner
        root_mock = MagicMock()
        def qv(sub, name):
            if name == "Authentication Packages":
                return (auth or [], 7)
            if name == "Security Packages":
                return (security or [], 7)
            if name == "Notification Packages":
                return (notification or [], 7)
            raise OSError()

        with patch.object(os_integrity_scanner, "HAS_WINREG", True), \
             patch("winreg.OpenKey", return_value=root_mock), \
             patch("winreg.QueryValueEx", side_effect=qv), \
             patch("winreg.CloseKey"):
            return os_integrity_scanner.scan_lsa_packages()

    def test_baseline_clean(self):
        r = self._run_with_values(
            auth=["msv1_0"],
            security=["kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u"],
            notification=["scecli"],
        )
        assert r["items"] == []

    def test_extra_auth_package_critical(self):
        r = self._run_with_values(auth=["msv1_0", "evil_pkg"])
        assert r["status"] == "suspicious"
        items = [i for i in r["items"] if "auth-package" in i["matched"]]
        assert len(items) >= 1
        assert items[0]["severity"] == "critical"

    def test_extra_notification_package_critical(self):
        r = self._run_with_values(notification=["scecli", "evil_notify"])
        items = [i for i in r["items"] if "notification-package" in i["matched"]]
        assert len(items) >= 1

    def test_empty_entries_ignored(self):
        r = self._run_with_values(security=["", '""', "kerberos"])
        assert r["items"] == []


# ============================================================
# task_execlog_scanner
# ============================================================

class TestTaskExeclog:

    def _run(self, ps_stdout: str, returncode=0):
        from telador import task_execlog_scanner
        result = MagicMock()
        result.returncode = returncode
        result.stdout = ps_stdout
        result.stderr = ""
        with patch("subprocess.run", return_value=result):
            return task_execlog_scanner.scan_task_scheduler_execlog()

    def test_no_events_clean(self):
        r = self._run("")
        assert r["items"] == []

    def test_windows_path_ignored(self):
        stdout = (
            "EVT::2026-07-13 10:00:00::TN=\\Microsoft\\Windows\\Foo\\Bar::"
            "AN=C:\\Windows\\System32\\wuauclt.exe\n"
        )
        r = self._run(stdout)
        assert r["items"] == []

    def test_executor_in_action_flagged(self):
        stdout = (
            "EVT::2026-07-13 10:00:00::TN=\\CheatTask::"
            "AN=C:\\Users\\user\\Downloads\\solara.exe\n"
        )
        r = self._run(stdout)
        assert r["status"] == "suspicious"
        assert any("solara" in i["matched"].lower() for i in r["items"])

    def test_userpath_no_keyword_medium(self):
        stdout = (
            "EVT::2026-07-13 10:00:00::TN=\\SomeTask::"
            "AN=C:\\Users\\user\\AppData\\unknown.exe\n"
        )
        r = self._run(stdout)
        items = [i for i in r["items"] if "tasksched-userpath" in i.get("matched", "")]
        assert len(items) >= 1
        assert items[0]["severity"] == "medium"


# ============================================================
# cert_store_scanner
# ============================================================

class TestCertStore:

    def _run(self, ps_stdout: str, returncode=0):
        from telador import cert_store_scanner
        result = MagicMock()
        result.returncode = returncode
        result.stdout = ps_stdout
        result.stderr = ""
        with patch("subprocess.run", return_value=result):
            return cert_store_scanner.scan_certificate_store()

    def test_no_certs_error(self):
        r = self._run("", returncode=1)
        assert r["status"] == "error"

    def test_trusted_ca_ignored(self):
        stdout = (
            "CERT::Cert:\\LocalMachine\\Root::"
            "SUBJ=CN=Microsoft Root Authority::"
            "ISSUER=CN=Microsoft Root Authority::"
            "NBEF=1997-01-10::NAFT=2020-12-31::"
            "THUMB=A43489159A520F0D93D032CCAF37E7FE20A8B419\n"
        )
        r = self._run(stdout)
        assert r["items"] == []

    def test_self_signed_unknown_flagged(self):
        stdout = (
            "CERT::Cert:\\LocalMachine\\Root::"
            "SUBJ=CN=RandomEvilCA, O=Unknown::"
            "ISSUER=CN=RandomEvilCA, O=Unknown::"
            "NBEF=2026-06-01::NAFT=2036-06-01::"
            "THUMB=DEADBEEF1234567890\n"
        )
        r = self._run(stdout)
        assert r["status"] == "suspicious"
        items = [i for i in r["items"] if "selfsigned" in i["matched"]]
        assert len(items) >= 1
        # NBEF 2026-06-01 é recente vs data atual 2026-07-13 → high
        assert items[0]["severity"] == "high"

    def test_suspicious_token_critical(self):
        stdout = (
            "CERT::Cert:\\LocalMachine\\Root::"
            "SUBJ=CN=Solara Loader::"
            "ISSUER=CN=Solara Loader::"
            "NBEF=2026-06-01::NAFT=2036-06-01::"
            "THUMB=DEAD1234\n"
        )
        r = self._run(stdout)
        items = [i for i in r["items"]
                 if "cert-suspicious-token" in i["matched"]]
        assert len(items) >= 1
        assert items[0]["severity"] == "critical"


# ============================================================
# Chain / registry
# ============================================================

class TestChain:

    def test_all_new_scanners_registered(self):
        from telador import scanner_registry
        reg = scanner_registry.build_registry()
        names = {m.fn_name for m in reg}
        assert "scan_session_manager_abuse" in names
        assert "scan_lsa_packages" in names
        assert "scan_task_scheduler_execlog" in names
        assert "scan_certificate_store" in names

    def test_scanner_count_bumped(self):
        from telador import version
        assert version.SCANNER_COUNT >= 112
        # Aceita 3.50.x (feat) e patches/minors posteriores.
        assert version.VERSION.startswith("3.5")
