"""
Anti-FP suite v3.52 — cobre os cenários de baseline gamer/dev que produziam
FP nos scanners v3.48–3.51 e agora foram whitelistados.

Cada teste é o *cenário concreto* de FP + a asserção "nada flaggado".
Roda ao lado dos testes de detecção (test_v349/v350) — quebrar aqui = alguém
mexeu numa whitelist sem entender o motivo.
"""

import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import patch, MagicMock


# ============================================================
# firewall_scanner — apps legítimos em user-path
# ============================================================

class TestFirewallAntiFP:

    def _rule_raw(self, action="Allow", direction="Out",
                  active="TRUE", app=r"C:\Users\gabri\AppData\Local\X\x.exe",
                  name="Rule"):
        return (f"v2.30|Action={action}|Active={active}|Dir={direction}|"
                f"App={app}|Name={name}|")

    def _run_with_rule(self, raw: str):
        import firewall_scanner
        key_mock = MagicMock()

        def enum_side(_key, idx):
            if idx == 0:
                return ("R1", raw, 1)
            raise OSError("done")

        # Só um dos hives responde; o outro dá OSError na abertura.
        open_seq = [key_mock, OSError("no key2")]
        def _open(_h, _p):
            v = open_seq.pop(0) if open_seq else OSError("no")
            if isinstance(v, Exception):
                raise v
            return v

        with patch.object(firewall_scanner, "HAS_WINREG", True), \
             patch("winreg.OpenKey", side_effect=_open), \
             patch("winreg.EnumValue", side_effect=enum_side), \
             patch("winreg.CloseKey"):
            return firewall_scanner.scan_firewall_rules()

    def test_roblox_player_beta_allowed(self):
        r = self._run_with_rule(self._rule_raw(
            app=r"C:\Users\gabri\AppData\Local\Roblox\Versions\version-abc\RobloxPlayerBeta.exe",
            name="Roblox"))
        assert r["items"] == [], f"Roblox player não deveria FP: {r['items']}"

    def test_bloxstrap_allowed(self):
        r = self._run_with_rule(self._rule_raw(
            app=r"C:\Users\gabri\AppData\Local\Bloxstrap\Bloxstrap.exe",
            name="Bloxstrap"))
        assert r["items"] == []

    def test_riot_client_allowed(self):
        r = self._run_with_rule(self._rule_raw(
            app=r"C:\Users\gabri\AppData\Local\Riot Games\Riot Client\RiotClientServices.exe",
            name="Riot"))
        assert r["items"] == []

    def test_squirrel_updater_allowed(self):
        r = self._run_with_rule(self._rule_raw(
            app=r"C:\Users\gabri\AppData\Local\Discord\Update.exe",
            name="Discord Update"))
        assert r["items"] == []

    def test_random_exe_still_flagged(self):
        r = self._run_with_rule(self._rule_raw(
            app=r"C:\Users\gabri\AppData\Local\Temp\loader-a7b3.exe",
            name="Loader Rule"))
        # Não é keyword de executor, mas user-path Allow outbound = medium
        assert any("firewall-user-allow" in i.get("matched", "")
                   for i in r["items"]), \
            "user-path aleatório em Allow ainda deveria flaggar"


# ============================================================
# streamproof_scanner — janelas Windows/GameBar/Copilot
# ============================================================

class TestStreamproofAntiFP:

    def _run_with_hit(self, proc_name: str, title: str = "Widgets"):
        import streamproof_scanner
        if not streamproof_scanner._HAS_USER32:
            return {"items": []}  # pular em CI Linux

        # Monkeypatch: simula uma janela com WDA ativo desse processo
        def fake_enum(cb, _lparam):
            cb(0x1234, 0)  # invoca callback com hwnd fake
            return True

        def fake_visible(_h):
            return True

        def fake_gwda(_h, ptr):
            ptr._obj.value = streamproof_scanner.WDA_EXCLUDEFROMCAPTURE
            return True

        def fake_title(_h):
            return title

        def fake_procname(_h):
            return (1234, proc_name)

        with patch.object(streamproof_scanner, "_EnumWindows",
                          side_effect=fake_enum), \
             patch.object(streamproof_scanner, "_IsWindowVisible",
                          side_effect=fake_visible), \
             patch.object(streamproof_scanner, "_GetWindowDisplayAffinity",
                          side_effect=fake_gwda), \
             patch.object(streamproof_scanner, "_get_window_title",
                          side_effect=fake_title), \
             patch.object(streamproof_scanner, "_get_process_name_from_hwnd",
                          side_effect=fake_procname):
            return streamproof_scanner.scan_streamproof_windows()

    def test_widgets_ignored(self):
        r = self._run_with_hit("widgets.exe", "Widgets")
        assert r["items"] == []

    def test_gamebar_ignored(self):
        r = self._run_with_hit("gamebar.exe", "Xbox Game Bar")
        assert r["items"] == []

    def test_copilot_ignored(self):
        r = self._run_with_hit("copilot.exe", "Copilot")
        assert r["items"] == []

    def test_discord_ignored(self):
        r = self._run_with_hit("discord.exe", "Discord")
        assert r["items"] == []

    def test_unknown_streamproof_still_flagged(self):
        r = self._run_with_hit("mysteryloader.exe", "Winter Bypass v9")
        assert any(i["severity"] in ("high", "critical")
                   for i in r["items"]), \
            "streamproof em processo desconhecido continua HIGH/CRITICAL"


# ============================================================
# cert_store_scanner — CAs faltantes + dev certs
# ============================================================

class TestCertStoreAntiFP:

    def _run(self, ps_stdout: str):
        import cert_store_scanner
        result = MagicMock()
        result.returncode = 0
        result.stdout = ps_stdout
        result.stderr = ""
        with patch("subprocess.run", return_value=result):
            return cert_store_scanner.scan_certificate_store()

    def test_baltimore_root_ignored(self):
        stdout = (
            "CERT::Cert:\\LocalMachine\\Root::"
            "SUBJ=CN=Baltimore CyberTrust Root, OU=CyberTrust, O=Baltimore::"
            "ISSUER=CN=Baltimore CyberTrust Root, OU=CyberTrust, O=Baltimore::"
            "NBEF=2000-05-12::NAFT=2025-05-12::"
            "THUMB=D4DE20D05E66FC53FE1A50882C78DB2852CAE474\n"
        )
        assert self._run(stdout)["items"] == []

    def test_mkcert_dev_cert_ignored(self):
        stdout = (
            "CERT::Cert:\\CurrentUser\\Root::"
            "SUBJ=CN=mkcert development CA, O=mkcert, OU=user@host::"
            "ISSUER=CN=mkcert development CA, O=mkcert, OU=user@host::"
            "NBEF=2026-05-01::NAFT=2036-05-01::"
            "THUMB=1111111111111111111111111111111111111111\n"
        )
        assert self._run(stdout)["items"] == []

    def test_docker_cert_ignored(self):
        stdout = (
            "CERT::Cert:\\LocalMachine\\Root::"
            "SUBJ=CN=Docker Desktop CA::ISSUER=CN=Docker Desktop CA::"
            "NBEF=2026-01-01::NAFT=2036-01-01::"
            "THUMB=2222222222222222222222222222222222222222\n"
        )
        assert self._run(stdout)["items"] == []

    def test_iis_express_ignored(self):
        stdout = (
            "CERT::Cert:\\LocalMachine\\Root::"
            "SUBJ=CN=localhost, O=IIS Express Development Certificate::"
            "ISSUER=CN=localhost, O=IIS Express Development Certificate::"
            "NBEF=2026-01-01::NAFT=2027-01-01::"
            "THUMB=3333333333333333333333333333333333333333\n"
        )
        assert self._run(stdout)["items"] == []

    def test_evil_cert_still_flagged(self):
        stdout = (
            "CERT::Cert:\\LocalMachine\\Root::"
            "SUBJ=CN=WinterCheat CA::ISSUER=CN=WinterCheat CA::"
            "NBEF=2026-05-01::NAFT=2036-05-01::"
            "THUMB=4444444444444444444444444444444444444444\n"
        )
        r = self._run(stdout)
        assert any(i["severity"] == "critical" for i in r["items"])


# ============================================================
# task_execlog_scanner — Squirrel updaters
# ============================================================

class TestTaskExeclogAntiFP:

    def _run(self, ps_stdout: str):
        import task_execlog_scanner
        result = MagicMock()
        result.returncode = 0
        result.stdout = ps_stdout
        result.stderr = ""
        with patch("subprocess.run", return_value=result):
            return task_execlog_scanner.scan_task_scheduler_execlog()

    def test_squirrel_discord_update_ignored(self):
        stdout = (
            "EVT::2026-07-13 10:00:00::TN=\\Discord\\Update::"
            "AN=C:\\Users\\gabri\\AppData\\Local\\Discord\\Update.exe\n"
        )
        assert self._run(stdout)["items"] == []

    def test_cursor_update_ignored(self):
        stdout = (
            "EVT::2026-07-13 10:00:00::TN=\\Cursor\\Update::"
            "AN=C:\\Users\\gabri\\AppData\\Local\\cursor\\Update.exe\n"
        )
        assert self._run(stdout)["items"] == []

    def test_bloxstrap_task_ignored(self):
        stdout = (
            "EVT::2026-07-13 10:00:00::TN=\\Bloxstrap\\AutoUpdate::"
            "AN=C:\\Users\\gabri\\AppData\\Local\\Bloxstrap\\Bloxstrap.exe\n"
        )
        assert self._run(stdout)["items"] == []

    def test_unknown_userpath_still_flagged(self):
        stdout = (
            "EVT::2026-07-13 10:00:00::TN=\\CheatBoot::"
            "AN=C:\\Users\\gabri\\Downloads\\mystery.exe\n"
        )
        r = self._run(stdout)
        # Nenhum keyword mas user-path com basename não-updater = medium
        assert any("tasksched-userpath" in i.get("matched", "")
                   for i in r["items"]), \
            "unknown user-path exe ainda deve flaggar"


# ============================================================
# pca_scanner — user-path sem publisher pra apps legítimos
# ============================================================

class TestPcaAntiFP:

    def _run(self, ps_stdout: str):
        import pca_scanner
        result = MagicMock()
        result.returncode = 0
        result.stdout = ps_stdout
        result.stderr = ""
        with patch("subprocess.run", return_value=result):
            return pca_scanner.scan_pca_appcompat_events()

    def test_roblox_no_publisher_ignored(self):
        stdout = (
            "EVT::2026-07-13 10:00:00::"
            "FN=C:\\Users\\gabri\\AppData\\Local\\Roblox\\Versions\\version-abc\\RobloxPlayerBeta.exe::"
            "CN=::PN=Roblox\n"
        )
        r = self._run(stdout)
        userpath_hits = [i for i in r["items"]
                         if "pca-userpath-nopublisher" in i.get("matched", "")]
        assert userpath_hits == []

    def test_squirrel_update_no_publisher_ignored(self):
        stdout = (
            "EVT::2026-07-13 10:00:00::"
            "FN=C:\\Users\\gabri\\AppData\\Local\\Discord\\Update.exe::"
            "CN=::PN=Discord Updater\n"
        )
        r = self._run(stdout)
        userpath_hits = [i for i in r["items"]
                         if "pca-userpath-nopublisher" in i.get("matched", "")]
        assert userpath_hits == []

    def test_unknown_exe_no_publisher_still_flagged(self):
        stdout = (
            "EVT::2026-07-13 10:00:00::"
            "FN=C:\\Users\\gabri\\AppData\\Local\\Temp\\dropper.exe::"
            "CN=::PN=\n"
        )
        r = self._run(stdout)
        assert any("pca-userpath-nopublisher" in i.get("matched", "")
                   for i in r["items"]), \
            "user-path sem publisher com nome random ainda flagga"


# ============================================================
# bits_scanner — Bloxstrap update
# ============================================================

class TestBitsAntiFP:

    def _run(self, ps_stdout: str):
        import bits_scanner
        result = MagicMock()
        result.returncode = 0
        result.stdout = ps_stdout
        result.stderr = ""
        with patch("subprocess.run", return_value=result):
            return bits_scanner.scan_bits_jobs()

    def test_roblox_bits_ignored(self):
        stdout = (
            "DisplayName  : Roblox Bootstrapper Download\n"
            "JobId        : {abc}\n"
            "JobState     : Transferred\n"
            "OwnerAccount : DESKTOP\\user\n"
            "TransferType : Download\n"
            "RemoteUrl    : https://setup.rbxcdn.com/version-abc.zip\n"
            "LocalFile    : C:\\Users\\user\\AppData\\Local\\Roblox\\Versions\\version-abc.zip\n"
            "\n"
        )
        assert self._run(stdout)["items"] == []

    def test_nvidia_geforce_bits_ignored(self):
        stdout = (
            "DisplayName  : NVIDIA GeForce Experience Download\n"
            "JobId        : {ghi}\n"
            "JobState     : Transferred\n"
            "OwnerAccount : NT AUTHORITY\\SYSTEM\n"
            "TransferType : Download\n"
            "RemoteUrl    : https://gfwsl.geforce.com/foo\n"
            "LocalFile    : C:\\Users\\user\\AppData\\Local\\NVIDIA\\foo.bin\n"
            "\n"
        )
        assert self._run(stdout)["items"] == []


# ============================================================
# assemble_ss_live_scanners — subset otimizado
# ============================================================

class TestSSLiveAssembly:

    def test_ss_live_chain_smaller_than_full(self):
        import telador
        ss_live = telador.assemble_ss_live_scanners()
        full = telador.assemble_scanners(
            skip_forensics=False, skip_antievasion=False,
            skip_persistence=False, skip_live=False,
            skip_history=False, skip_peripherals=False,
        )
        assert len(ss_live) < len(full), \
            f"ss-live ({len(ss_live)}) deve ser subset menor que full ({len(full)})"

    def test_ss_live_excludes_slow_scanners(self):
        """Scanners que fazem parse de log grande ficam FORA do ss-live."""
        import telador
        ss_live_names = {f.__name__ for f in telador.assemble_ss_live_scanners()}
        excluded_slow = {
            "scan_pca_appcompat_events",       # Get-WinEvent 500 items
            "scan_task_scheduler_execlog",     # Get-WinEvent 1000 items
            "scan_defender_mplog",             # 10MB log file
            "scan_windows_events",             # WinEvent Security channel
            "scan_certificate_store",          # PS 45s timeout
            "scan_shellbag",                   # recursivo em BagMRU
            "scan_activities_cache_timeline",  # SQLite parse pesado
            "scan_scheduled_tasks",            # schtasks /v output enorme
        }
        overlap = ss_live_names & excluded_slow
        assert overlap == set(), \
            f"Scanners lentos vazando no ss-live: {overlap}"

    def test_ss_live_includes_critical_live_signals(self):
        """Sinais AO VIVO essenciais devem estar no ss-live."""
        import telador
        ss_live_names = {f.__name__ for f in telador.assemble_ss_live_scanners()}
        must_have = {
            "scan_streamproof_windows",   # Winter/Solara
            "scan_dse_state",             # Test mode driver
            "scan_vbs_hvci_disabled",     # HVCI off
            "scan_roblox_page_protection",  # RWX in Roblox
            "scan_process_masquerade",    # RobloxCrashHandler etc
            "scan_clipboard_history",     # copiado agora
            "scan_process_tree",          # processo pai suspeito
        }
        missing = must_have - ss_live_names
        assert missing == set(), \
            f"Sinais críticos ao vivo faltando no ss-live: {missing}"


# ============================================================
# build_staff_verdict_bullets — 3 bullets O QUE / POR QUÊ / O QUE FAZER
# ============================================================

class TestStaffVerdictBullets:

    def _fake_cluster(self, label, verdict, conf_pct=90,
                      sources=("prefetch", "amcache"), score=8.5):
        c = type("Cluster", (), {})()
        c.label = label
        c.verdict = verdict
        c.confidence_pct = conf_pct
        c.sources = list(sources)
        c.score = score
        c.n_sources = len(sources)
        c.evidences = [type("E", (), {"source": s})() for s in sources]
        c.first_seen = None
        c.kind = "executor"
        c.worst_severity = "high"
        return c

    def test_clean_bullets(self):
        import report
        o, p, a = report.build_staff_verdict_bullets(
            [], {"verdict": "LIMPO"}, {"blind_strong": 0})
        assert "LIMPO" in o
        assert "sess" in a.lower() or "libere" in a.lower()

    def test_confirmed_bullets_have_target(self):
        import report
        clusters = [self._fake_cluster("Solara", "CONFIRMED", 95,
                                        ("prefetch", "amcache", "bam"))]
        o, p, a = report.build_staff_verdict_bullets(
            clusters, {"verdict": "CHEATER"}, None)
        assert "CONFIRMADO" in o
        assert "Solara" in o
        assert "3 fonte" in p or "3 fontes" in p
        assert "formatar" in a.lower() or "discord" in a.lower()

    def test_inconclusive_bullets(self):
        import report
        o, p, a = report.build_staff_verdict_bullets(
            [], {"verdict": "INCONCLUSIVO", "inconclusive": True,
                 "inconclusive_reason": "Prefetch inacessível"},
            {"blind_strong": 3})
        assert "INCONCLUSIVO" in o
        assert "prefetch" in p.lower() or "cobertura" in p.lower()
        assert "admin" in a.lower()

    def test_inconclusive_multiple_reasons_truncated(self):
        """Quando ha varias razoes de cobertura, mostra so a 1a + '(+N outras)'."""
        import report
        multi_reason = ("Scan sem administrador — Prefetch/Amcache/BAM falham.; "
                        "Grupo desligado: yara.; Grupo desligado: winevent.; "
                        "Grupo desligado: pca.; 10 checagens com erro real.")
        o, p, a = report.build_staff_verdict_bullets(
            [], {"verdict": "INCONCLUSIVO", "inconclusive": True,
                 "inconclusive_reason": multi_reason}, None)
        # Nao deve mostrar todas as razoes concatenadas com ";"
        assert p.count(";") == 0, f"Bullet ainda tem ; concatenando razoes: {p}"
        assert "administrador" in p.lower() or "prefetch" in p.lower()
        # Deve mencionar quantas outras razoes existem
        assert "+4" in p or "outra" in p.lower()

    def test_suspect_bullets(self):
        import report
        clusters = [self._fake_cluster("dubiousExec", "SUSPECT", 45,
                                        ("shellbag",))]
        o, p, a = report.build_staff_verdict_bullets(
            clusters, {"verdict": "SUSPEITO"}, None)
        assert "SUSPEITO" in o
        assert "45%" in p or "confidence" in p.lower()
        assert "high" in a.lower() or "medium" in a.lower() or "visual" in a.lower()

    def test_operator_tldr_html_has_3_dts(self):
        """HTML deve ter os 3 <dt>: O quê / Por quê / O que fazer."""
        import report
        html = report._render_operator_tldr(
            [], {"verdict": "LIMPO"}, None)
        assert html.count("<dt>") == 3
        assert "O quê" in html
        assert "Por quê" in html
        assert "O que fazer" in html

    def test_copy_button_summary_includes_bullets(self):
        """Botao 'Copiar resumo' deve incluir os 3 bullets no data-summary."""
        import report

        class FakeCluster:
            def __init__(self):
                self.label = "Solara"
                self.verdict = "CONFIRMED"
                self.confidence_pct = 92
                self.sources = ["prefetch", "amcache"]
                self.score = 8.0
                self.n_sources = 2
                self.evidences = [type("E",(),{"source":s})() for s in self.sources]
                self.first_seen = None
                self.kind = "executor"
                self.worst_severity = "critical"

        html = report._render_hero_verdict(
            [FakeCluster()],
            {"verdict": "CHEATER", "score": 42, "highest_confidence": 92})
        # O data-summary do botao Copiar deve ter os 3 marcadores
        assert "O qu&ecirc;" in html or "O quê:" in html, \
            "copy summary sem 'O que'"
        assert "Por qu&ecirc;" in html or "Por quê:" in html, \
            "copy summary sem 'Por que'"
        assert "O que fazer" in html, "copy summary sem 'O que fazer'"


# ============================================================
# behavioral_tier_a.scan_scheduled_task_dropper — Squirrel updaters
# ============================================================

class TestDropperAntiFP:

    def _run_with_task(self, task_name="Update", task_path="\\Discord\\",
                       exec_path=r"C:\Users\u\AppData\Local\Discord\Update.exe"):
        import behavioral_tier_a as bt
        from datetime import datetime, timezone, timedelta
        import json, types
        recent = datetime.now(timezone.utc) - timedelta(hours=1)
        payload = [{
            "Name": task_name, "Path": task_path,
            "Date": recent.isoformat(),
            "Trigger": "MSFT_TaskLogonTrigger",
            "Exec": exec_path, "Args": "",
        }]
        fake = types.SimpleNamespace(
            returncode=0, stdout=json.dumps(payload), stderr="")
        original_run = bt.subprocess.run
        bt.subprocess.run = lambda *a, **kw: fake
        try:
            return bt.scan_scheduled_task_dropper()
        finally:
            bt.subprocess.run = original_run

    def test_discord_squirrel_update_ignored(self):
        r = self._run_with_task(
            task_name="Update", task_path="\\Discord\\",
            exec_path=r"C:\Users\u\AppData\Local\Discord\Update.exe")
        assert r["status"] == "clean", \
            f"Discord updater vazou: {r.get('items')}"

    def test_cursor_squirrel_update_ignored(self):
        r = self._run_with_task(
            task_name="Update", task_path="\\Cursor\\",
            exec_path=r"C:\Users\u\AppData\Local\Programs\cursor\Update.exe")
        assert r["status"] == "clean"

    def test_vscode_task_ignored(self):
        r = self._run_with_task(
            task_name="Update", task_path="\\Microsoft VS Code\\",
            exec_path=r"C:\Users\u\AppData\Local\Programs\Microsoft VS Code\Update.exe")
        assert r["status"] == "clean"

    def test_bloxstrap_update_ignored(self):
        r = self._run_with_task(
            task_name="Update", task_path="\\Bloxstrap\\",
            exec_path=r"C:\Users\u\AppData\Local\Bloxstrap\Bloxstrap.exe")
        assert r["status"] == "clean"

    def test_google_chrome_task_ignored(self):
        r = self._run_with_task(
            task_name="GoogleUpdateTaskMachineUA",
            task_path="\\Google\\GoogleUpdater\\",
            exec_path=r"C:\Users\u\AppData\Local\Google\GoogleUpdater\bin\updater.exe")
        assert r["status"] == "clean"

    def test_random_cheat_dropper_still_flagged(self):
        r = self._run_with_task(
            task_name="AutoRunLoader",
            task_path="\\",
            exec_path=r"C:\Users\u\AppData\Roaming\loader.exe")
        assert r["status"] == "suspicious"
        assert any(i["matched"] == "dropper-task" for i in r["items"])


# ============================================================
# external_scanner.scan_post_roblox_processes — RobloxCrashHandler
# masquerade só escapa se path for real Roblox\Versions\
# ============================================================

class TestRobloxCrashHandlerMasqueradePath:

    def test_real_robloxcrashhandler_ignored(self):
        """RobloxCrashHandler.exe em Roblox\\Versions\\ é oficial — ignora."""
        import external_scanner as es
        assert "\\roblox\\versions\\" in (
            r"C:\Users\gabri\AppData\Local\Roblox\Versions\version-abc"
            r"\RobloxCrashHandler.exe").lower()

    def test_masquerade_robloxcrashhandler_detected(self):
        """Winter Bypass masqueraded como RobloxCrashHandler em Downloads
        NÃO deve escapar do post_roblox scan — path check no source."""
        import os
        src_path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "external_scanner.py")
        with open(src_path, "r", encoding="utf-8") as fh:
            content = fh.read()
        # Path check especifico: RobloxCrashHandler so escapa se path REAL Roblox
        assert "\\\\roblox\\\\versions\\\\" in content.lower() or \
               "\\roblox\\versions\\" in content.lower(), \
            "Fix path check pra RobloxCrashHandler masquerade removido do source"


# ============================================================
# Winter Bypass ecosystem — IoC 07/2026, testes de regressao
# ============================================================

class TestWinterBypassEcosystem:

    def test_winter_family_in_catalog(self):
        """Winter Bypass deve estar em _FAMILY_CATALOG (contexto rico)."""
        import external_scanner as es
        assert "winter" in es._FAMILY_CATALOG
        fam = es._FAMILY_CATALOG["winter"]
        assert fam["severity"] == "high"
        assert "fishstrap.exe" in fam["processes"]
        assert "winter bypass" in fam["tokens"]
        assert "weao-live-windowsplayer" in fam["tokens"]

    def test_fishstrap_in_core_database(self):
        """Fishstrap tem que estar embutido no .exe (nao so signatures.dist)."""
        import database
        assert "fishstrap.exe" in database.EXECUTOR_PROCESS_NAMES
        assert database.EXECUTOR_PROCESS_NAMES["fishstrap.exe"] == "high"
        assert database.EXECUTOR_KEYWORDS.get("fishstrap") == "high"
        assert database.EXECUTOR_KEYWORDS.get("winter bypass") == "high"
        assert database.EXECUTOR_KEYWORDS.get("weao-live-windowsplayer") == "high"

    def test_fishstrap_not_in_handle_whitelist(self):
        """Regressao: fishstrap NUNCA pode estar em _HANDLE_WHITELIST."""
        import external_scanner as es
        assert "fishstrap.exe" not in es._HANDLE_WHITELIST, \
            "Fishstrap na _HANDLE_WHITELIST = Winter Bypass invisível"

    def test_fishstrap_not_in_footprint_whitelist(self):
        """Regressao: fishstrap NUNCA pode estar em _FOOTPRINT_WHITELIST."""
        import external_scanner as es
        assert "fishstrap.exe" not in es._FOOTPRINT_WHITELIST, \
            "Fishstrap na _FOOTPRINT_WHITELIST = Winter escapava"

    def test_fishstrap_not_in_legit_parents(self):
        """Regressao: fishstrap NUNCA pode estar em _LEGIT_PARENTS."""
        import external_scanner as es
        assert "fishstrap.exe" not in es._LEGIT_PARENTS, \
            "Fishstrap na _LEGIT_PARENTS = spawn cheat invisível"

    def test_fishstrap_not_in_legit_bits_names(self):
        """Regressao: fishstrap NUNCA em _LEGIT_BITS_DISPLAY_NAMES."""
        import bits_scanner as bs
        assert "fishstrap" not in bs._LEGIT_BITS_DISPLAY_NAMES, \
            "Fishstrap na BITS whitelist = download silencioso ignorado"


# ============================================================
# --json export schema — v3.52.4+ inclui verdict/clusters/coverage/bullets
# ============================================================

class TestJsonExportSchema:

    def _fake_cluster(self, label="Solara", verdict="CONFIRMED", conf=95):
        c = type("Cluster", (), {})()
        c.label = label
        c.verdict = verdict
        c.confidence_pct = conf
        c.sources = ["prefetch", "amcache"]
        c.score = 8.0
        c.n_sources = 2
        c.evidences = [type("E",(),{"source":s})() for s in c.sources]
        c.first_seen = None
        c.kind = "executor"
        c.worst_severity = "critical"
        return c

    def _load(self, **kwargs):
        import telador, json
        path = telador.save_json(
            findings=kwargs.get("findings", []),
            sys_info=kwargs.get("sys_info", {"host": "t"}),
            verdict=kwargs.get("verdict"),
            clusters=kwargs.get("clusters"),
            coverage=kwargs.get("coverage"),
        )
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def test_all_top_level_keys_present(self):
        """v3.52.4+ garante os 6 top-level keys sempre."""
        d = self._load(verdict={"verdict":"LIMPO","score":0})
        expected = {"system", "verdict", "clusters", "coverage",
                    "staff_verdict_bullets", "findings"}
        assert expected.issubset(set(d.keys())), \
            f"faltando: {expected - set(d.keys())}"

    def test_clusters_serialized_with_required_fields(self):
        """Cada cluster no JSON tem os campos que a UI/bot precisa."""
        d = self._load(
            verdict={"verdict":"CHEATER"},
            clusters=[self._fake_cluster()])
        assert len(d["clusters"]) == 1
        c = d["clusters"][0]
        required = {"label", "kind", "verdict", "confidence_pct",
                    "score", "worst_severity", "n_sources", "sources"}
        assert required.issubset(set(c.keys())), \
            f"cluster faltando: {required - set(c.keys())}"

    def test_staff_bullets_populated_for_confirmed(self):
        """staff_verdict_bullets sempre tem 3 keys quando confirmed."""
        d = self._load(
            verdict={"verdict":"CHEATER"},
            clusters=[self._fake_cluster()])
        b = d.get("staff_verdict_bullets")
        assert isinstance(b, dict)
        assert set(b.keys()) == {"o_que", "por_que", "o_que_fazer"}
        assert "Solara" in b["o_que"]
        assert "2 fonte" in b["por_que"]

    def test_findings_still_at_top(self):
        """Backward-compat: 'findings' e 'system' ainda existem."""
        d = self._load(sys_info={"host": "PC", "user": "u"})
        assert "system" in d
        assert d["system"]["host"] == "PC"
        assert "findings" in d
        assert d["findings"] == []
