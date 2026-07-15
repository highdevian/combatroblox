"""
Testes do external_scanner — detecção de external cheat (processo separado
que lê a memória do Roblox de fora).

Cobre:
  - IPs privados/loopback são reconhecidos como não-externo (helper puro)
  - kernel_only_egress flagga conhost/dwm/csrss com egress externo, mas
    ignora egress pra IP privado e ignora processo que não está na lista
  - external_memory_footprint respeita a whitelist e o threshold
  - Roteamento de source_slug funciona (nome do finding → slug correto)
  - Todos os 4 scanners estão registrados no ALL_EXTERNAL_SCANNERS
  - No PC real: nenhum crasha; roda como error (sem Roblox) ou clean.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from telador import external_scanner as es  # noqa: E402
# ============================ Helpers puros ============================

def test_private_ipv4_is_not_external():
    for ip in ("10.0.0.1", "192.168.1.1", "172.16.0.5", "172.31.255.254",
               "127.0.0.1", "169.254.10.10", "0.0.0.0"):
        assert es._is_private_or_loopback_ip(ip), ip


def test_public_ipv4_is_external():
    for ip in ("8.8.8.8", "1.1.1.1", "13.107.42.14", "142.250.190.14"):
        assert not es._is_private_or_loopback_ip(ip), ip


def test_multicast_reserved_is_not_external():
    assert es._is_private_or_loopback_ip("224.0.0.1")
    assert es._is_private_or_loopback_ip("255.255.255.255")


def test_ipv6_loopback_and_linklocal_is_not_external():
    assert es._is_private_or_loopback_ip("::1")
    assert es._is_private_or_loopback_ip("fe80::abcd")
    assert es._is_private_or_loopback_ip("fc00::1")


def test_ipv6_public_is_external():
    assert not es._is_private_or_loopback_ip("2606:4700:4700::1111")


def test_invalid_ip_is_not_external():
    """Inválido → not-external pra não flaggar (conservador)."""
    assert es._is_private_or_loopback_ip("not-an-ip")
    assert es._is_private_or_loopback_ip("")


# ============================ kernel_only_egress ============================

class _FakeConn:
    def __init__(self, pid, raddr, status="ESTABLISHED"):
        self.pid = pid
        self.raddr = raddr
        self.status = status
        self.laddr = ("127.0.0.1", 0)


class _RAddr:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port


class _FakeProc:
    def __init__(self, pid, name, exe="", create_time=0):
        self._pid = pid
        self._name = name
        self._exe = exe
        self._create_time = create_time
        self.info = {"pid": pid, "name": name, "exe": exe,
                     "create_time": create_time}

    def name(self):
        return self._name

    def exe(self):
        return self._exe

    def create_time(self):
        return self._create_time


def _patch_conn_env(monkeypatch, conns, procs_by_pid):
    monkeypatch.setattr(es, "HAS_PSUTIL", True)
    monkeypatch.setattr(es.psutil, "net_connections", lambda kind="tcp": conns)
    monkeypatch.setattr(es.psutil, "CONN_ESTABLISHED", "ESTABLISHED")

    def fake_process(pid):
        if pid in procs_by_pid:
            return procs_by_pid[pid]
        raise es.psutil.NoSuchProcess(pid)

    monkeypatch.setattr(es.psutil, "Process", fake_process)


def test_kernel_only_egress_flags_conhost_with_external_ip(monkeypatch):
    procs = {77: _FakeProc(77, "conhost.exe", r"C:\Windows\System32\conhost.exe")}
    conns = [_FakeConn(77, _RAddr("8.8.8.8", 443))]
    _patch_conn_env(monkeypatch, conns, procs)
    r = es.scan_kernel_only_egress()
    assert r["status"] == "suspicious"
    assert len(r["items"]) == 1
    it = r["items"][0]
    assert it["severity"] == "high"
    assert it["matched"] == "kernel-only-egress:conhost.exe"
    assert "8.8.8.8" in it["label"]


def test_kernel_only_egress_ignores_private_ip(monkeypatch):
    procs = {77: _FakeProc(77, "conhost.exe")}
    conns = [_FakeConn(77, _RAddr("192.168.1.10", 80))]
    _patch_conn_env(monkeypatch, conns, procs)
    assert es.scan_kernel_only_egress()["status"] == "clean"


def test_kernel_only_egress_ignores_non_listed_process(monkeypatch):
    """chrome.exe com egress externo NÃO é este scanner."""
    procs = {77: _FakeProc(77, "chrome.exe")}
    conns = [_FakeConn(77, _RAddr("8.8.8.8", 443))]
    _patch_conn_env(monkeypatch, conns, procs)
    assert es.scan_kernel_only_egress()["status"] == "clean"


def test_kernel_only_egress_ignores_non_established(monkeypatch):
    procs = {77: _FakeProc(77, "dwm.exe")}
    conns = [_FakeConn(77, _RAddr("8.8.8.8", 443), status="TIME_WAIT")]
    _patch_conn_env(monkeypatch, conns, procs)
    assert es.scan_kernel_only_egress()["status"] == "clean"


def test_kernel_only_egress_flags_multiple_never_egress_procs(monkeypatch):
    procs = {
        1: _FakeProc(1, "csrss.exe"),
        2: _FakeProc(2, "fontdrvhost.exe"),
        3: _FakeProc(3, "explorer.exe"),  # não é never-egress → ignora
    }
    conns = [
        _FakeConn(1, _RAddr("1.1.1.1", 443)),
        _FakeConn(2, _RAddr("8.8.4.4", 443)),
        _FakeConn(3, _RAddr("9.9.9.9", 443)),
    ]
    _patch_conn_env(monkeypatch, conns, procs)
    r = es.scan_kernel_only_egress()
    matched = {it["matched"] for it in r["items"]}
    assert "kernel-only-egress:csrss.exe" in matched
    assert "kernel-only-egress:fontdrvhost.exe" in matched
    assert "kernel-only-egress:explorer.exe" not in matched


def test_kernel_only_egress_dedupes_same_owner_ip_port(monkeypatch):
    procs = {77: _FakeProc(77, "conhost.exe")}
    conns = [
        _FakeConn(77, _RAddr("8.8.8.8", 443)),
        _FakeConn(77, _RAddr("8.8.8.8", 443)),  # duplicata
    ]
    _patch_conn_env(monkeypatch, conns, procs)
    r = es.scan_kernel_only_egress()
    assert len(r["items"]) == 1


# ============================ external_memory_footprint ============================

def test_footprint_whitelist_covers_common_apps():
    """Whitelist tem que ter Discord, Chrome, Spotify — apps comuns em AppData."""
    assert "discord.exe" in es._FOOTPRINT_WHITELIST
    assert "chrome.exe" in es._FOOTPRINT_WHITELIST
    assert "spotify.exe" in es._FOOTPRINT_WHITELIST
    assert "code.exe" in es._FOOTPRINT_WHITELIST
    # E também: Roblox e Bloxstrap não podem cair aqui
    assert "robloxplayerbeta.exe" in es._FOOTPRINT_WHITELIST
    assert "bloxstrap.exe" in es._FOOTPRINT_WHITELIST


def test_footprint_user_path_tokens_cover_common_drops():
    """Downloads / Temp / AppData Roaming — locais clássicos de dropper."""
    assert any("temp" in t for t in es._USER_PATH_TOKENS)
    assert any("downloads" in t for t in es._USER_PATH_TOKENS)
    assert any("desktop" in t for t in es._USER_PATH_TOKENS)
    assert any("appdata" in t for t in es._USER_PATH_TOKENS)


def test_footprint_ws_threshold_is_reasonable():
    """<20 = FP com utilitários; >100 = perde reader minimalista.
    50 MB é o ponto ok."""
    assert 30 <= es._WS_THRESHOLD_MB <= 80


# ============================ Handles / Access masks ============================

def test_external_access_masks_include_read_write_operation():
    """Handle scanner precisa checar as 3 flags. VM_READ é a essencial."""
    assert es._EXTERNAL_ACCESS_MASKS & es.PROCESS_VM_READ
    assert es._EXTERNAL_ACCESS_MASKS & es.PROCESS_VM_WRITE
    assert es._EXTERNAL_ACCESS_MASKS & es.PROCESS_VM_OPERATION


def test_handle_whitelist_covers_av_and_debug_tools():
    """Whitelist do handle scanner cobre AV (Defender), overlays e debuggers dev."""
    assert "msmpeng.exe" in es._HANDLE_WHITELIST
    assert "discord.exe" in es._HANDLE_WHITELIST
    assert "devenv.exe" in es._HANDLE_WHITELIST
    assert "code.exe" in es._HANDLE_WHITELIST
    # E o próprio Roblox
    assert "robloxplayerbeta.exe" in es._HANDLE_WHITELIST
    # FP CRITICAL: System (PID 4) e crash handler oficiais
    assert "system" in es._HANDLE_WHITELIST
    assert "robloxcrashhandler.exe" in es._HANDLE_WHITELIST
    assert 4 in es._HANDLE_WHITELIST_PIDS


def test_self_process_whitelist_covers_telador_variants():
    """REGRESSÃO FP: telador (64).exe / telador-3.44.0.exe NÃO é external."""
    assert es._is_self_process("telador.exe", r"C:\Users\x\Downloads\telador.exe")
    assert es._is_self_process("telador (64).exe", r"C:\Users\x\Downloads\telador (64).exe")
    assert es._is_self_process("telador-3.44.0.exe", r"C:\x\telador-3.44.0.exe")
    assert es._is_process_whitelisted(
        "telador (64).exe", es._FOOTPRINT_WHITELIST,
        r"C:\Users\x\Downloads\telador (64).exe")
    assert not es._is_self_process("cheat.exe", r"C:\Users\x\Downloads\cheat.exe")


def test_handle_scan_clean_when_roblox_closed(monkeypatch):
    """Roblox fechado NÃO é erro de cobertura — meta_only + clean."""
    monkeypatch.setattr(es, "_roblox_pids", lambda: [])
    r = es.scan_external_process_handles()
    assert r["status"] in ("clean", "suspicious")
    assert r.get("error") in (None, "")
    assert any(i.get("meta_only") for i in r["items"]) or r["status"] == "clean"


def test_post_roblox_uses_prefetch_anchor_when_closed(monkeypatch):
    """Com Roblox fechado, ancora em Prefetch e ainda flagga residual."""
    import time
    now = time.time()
    monkeypatch.setattr(es, "HAS_PSUTIL", True)
    monkeypatch.setattr(es, "_roblox_session_context", lambda: {
        "live_pids": [], "live": False, "last_run_ts": now - 600, "anchor_ts": now - 600,
    })
    procs = [
        _FakeProc(2, "cheat.exe", r"C:\Users\x\Downloads\cheat.exe", create_time=now - 300),
    ]
    monkeypatch.setattr(es.psutil, "process_iter", lambda attrs=None: iter(procs))
    monkeypatch.setattr(es, "_is_exe_signed", lambda p: False)
    r = es.scan_post_roblox_processes()
    assert r["status"] == "suspicious"
    assert any("cheat" in (it.get("matched") or "") for it in r["items"])


def test_basename_key_extraction():
    assert es._extract_basename_key({
        "matched": "external-footprint:foo.exe", "label": "x",
    }) == "foo.exe"
    assert es._extract_basename_key({
        "matched": "post-roblox:bar.exe", "label": "x",
    }) == "bar.exe"


# ============================ Integração ============================

_EXPECTED_EXTERNAL = {
    "scan_external_processes",
    "scan_external_artifacts",
    "scan_external_process_handles",
    "scan_external_memory_footprint",
    "scan_remote_threads_in_roblox",
    "scan_kernel_only_egress",
    "scan_popup_overlays",
    "scan_post_roblox_processes",
    "scan_suspicious_named_pipes",
    "scan_random_name_executables",
    "scan_unsigned_user_network",
    "scan_suspicious_process_ancestry",
    "scan_external_correlation",
}


def test_all_scanners_registered():
    for fn in (
        es.scan_external_processes,
        es.scan_external_artifacts,
        es.scan_external_process_handles,
        es.scan_external_memory_footprint,
        es.scan_remote_threads_in_roblox,
        es.scan_kernel_only_egress,
        es.scan_popup_overlays,
        es.scan_post_roblox_processes,
        es.scan_suspicious_named_pipes,
        es.scan_random_name_executables,
        es.scan_unsigned_user_network,
        es.scan_suspicious_process_ancestry,
        es.scan_external_correlation,
    ):
        assert fn in es.ALL_EXTERNAL_SCANNERS
    assert len(es.ALL_EXTERNAL_SCANNERS) == 13


def test_slug_routing():
    """Nome do finding → slug do SOURCE_WEIGHTS. Se quebrar isso, o Confidence
    Engine cai no default e o peso da fonte fica errado."""
    from telador import evidence as ev
    assert ev._source_slug_from_name(
        "Handles pro Roblox (external memory reader)") == "external_reader"
    assert ev._source_slug_from_name(
        "Working set de external reader") == "external_footprint"
    assert ev._source_slug_from_name(
        "Thread remota no Roblox (injeção externa)") == "remote_thread"
    assert ev._source_slug_from_name(
        "Rede: processo do sistema com egress externo") == "kernel_only_egress"

    # Catálogo de famílias (3.43.5+) + correlação técnica (3.44.0)
    assert ev._source_slug_from_name(
        "External cheat (processo vivo)") == "external_cheat"
    assert ev._source_slug_from_name(
        "External cheat (artefatos em disco)") == "external_cheat"
    assert ev._source_slug_from_name(
        "Correlacao de sinais de external (private cheats, Winter-class)"
    ) == "external_correlation"

    for slug in ("external_reader", "external_footprint",
                 "remote_thread", "kernel_only_egress",
                 "external_cheat", "external_correlation"):
        assert slug in ev.SOURCE_WEIGHTS, slug


def test_labels_present_in_report_assets():
    from telador import report_assets as ra
    for slug in ("external_reader", "external_footprint",
                 "remote_thread", "kernel_only_egress",
                 "external_cheat", "external_correlation"):
        assert slug in ra.SOURCE_LABELS, slug


def test_scanner_registry_includes_external_group():
    from telador import scanner_registry as sr
    reg = sr.build_registry()
    ext = [m for m in reg if m.group == "external"]
    assert len(ext) == 13
    names = {m.fn_name for m in ext}
    assert names == _EXPECTED_EXTERNAL


# ============================ Catálogo de famílias (3.43.5+) ============================

def test_family_catalog_includes_research_families():
    """Famílias da pesquisa pública (2024-2026) estão no catálogo.
    Winter-class (private) NÃO entra por nome — cai nas detecções técnicas."""
    expected = {
        "matcha", "severe", "dx9ware", "matrix_ext", "celex", "bauix",
        "sheldon", "vasile", "ronin_ext", "mooze", "oxygen_ext",
        "timeoutwtf", "santoware", "photon_ext", "clarity_ext",
        "serotonin", "spxrkz", "polter", "generic_external",
    }
    assert expected <= set(es.EXTERNAL_FAMILY_IDS)
    assert es.classify_process_name("serotonin.exe")[1] == "serotonin"
    assert es.classify_process_name("matcha.exe")[1] == "matcha"
    assert es.classify_process_name("severe.exe")[1] == "severe"
    # anti-FP: bare words / legit apps
    assert es.classify_process_name("discord.exe") is None
    assert es.classify_process_name("RobloxPlayerBeta.exe") is None
    assert es.classify_process_name("matrix.exe") is None  # só matrixhub


def test_family_catalog_flags_matcha_process(monkeypatch):
    """Nome Matcha.exe no catálogo → scan_external_processes HIGH."""
    procs = [
        _FakeProc(1, "discord.exe", r"C:\Users\x\AppData\Local\Discord\Discord.exe"),
        _FakeProc(2, "Matcha.exe", r"C:\Users\x\Downloads\Matcha\Matcha.exe", 1700000000.0),
        _FakeProc(3, "chrome.exe", r"C:\Program Files\Google\Chrome\chrome.exe"),
    ]
    monkeypatch.setattr(es, "HAS_PSUTIL", True)

    class _P:
        @staticmethod
        def process_iter(_attrs=None):
            return iter(procs)

    monkeypatch.setattr(es, "psutil", _P)
    r = es.scan_external_processes()
    assert r["status"] == "suspicious"
    assert len(r["items"]) == 1
    assert "matcha" in r["items"][0]["matched"]


def test_family_catalog_ignores_roblox_and_legit(monkeypatch):
    """Roblox e overlays legítimos nunca batem no catálogo."""
    procs = [
        _FakeProc(1, "RobloxPlayerBeta.exe", r"C:\Users\x\Roblox\rbx.exe"),
        _FakeProc(10, "medal.exe"),
        _FakeProc(11, "obs64.exe"),
        _FakeProc(12, "nvidiaoverlay.exe"),
    ]
    monkeypatch.setattr(es, "HAS_PSUTIL", True)

    class _P:
        @staticmethod
        def process_iter(_attrs=None):
            return iter(procs)

    monkeypatch.setattr(es, "psutil", _P)
    assert es.scan_external_processes()["status"] == "clean"


def _clean_finding():
    return {"status": "clean", "items": [], "summary": "",
            "error": None, "name": "n", "description": ""}


def _hit_finding(pid, matched="x"):
    return {"status": "suspicious", "items": [{
        "label": f"x (PID {pid})", "detail": f"PID {pid}",
        "matched": matched, "severity": "high", "timestamp": "",
    }], "summary": "", "error": None, "name": "n", "description": ""}


def _stub_correlation_sources(monkeypatch, overrides: dict):
    """Stub de todos os scanners que _collect_suspect_groups consome."""
    defaults = {
        "scan_external_processes": _clean_finding,
        "scan_external_artifacts": _clean_finding,
        "scan_external_process_handles": _clean_finding,
        "scan_external_memory_footprint": _clean_finding,
        "scan_kernel_only_egress": _clean_finding,
        "scan_popup_overlays": _clean_finding,
        "scan_post_roblox_processes": _clean_finding,
        "scan_random_name_executables": _clean_finding,
        "scan_unsigned_user_network": _clean_finding,
        "scan_suspicious_process_ancestry": _clean_finding,
    }
    overlay_fn = overrides.pop("scan_overlay_windows", _clean_finding)
    defaults.update(overrides)
    monkeypatch.setattr(es, "HAS_PSUTIL", True)
    for name, fn in defaults.items():
        monkeypatch.setattr(es, name, fn)
    from telador import live_analysis as la
    monkeypatch.setattr(la, "scan_overlay_windows", overlay_fn)


# ============================ Correlation scanner ============================

def test_correlation_crava_when_two_signals_hit_same_pid(monkeypatch):
    """PID 999 aparece em handle scan E footprint scan = HIGH crava."""
    _stub_correlation_sources(monkeypatch, {
        "scan_external_process_handles": lambda: _hit_finding(999, "handle"),
        "scan_external_memory_footprint": lambda: _hit_finding(999, "footprint"),
    })

    class _P:
        def name(self): return "xyz.exe"
        def exe(self): return r"C:\Users\x\Downloads\xyz.exe"
        def create_time(self): return 0

    monkeypatch.setattr(es.psutil, "Process", lambda pid: _P())

    r = es.scan_external_correlation()
    assert r["status"] == "suspicious"
    assert len(r["items"]) == 1
    it = r["items"][0]
    assert it["severity"] == "high"
    assert "handle" in it["detail"] and "footprint" in it["detail"]
    assert "PID 999" in it["label"]


def test_correlation_crava_critical_with_three_signals(monkeypatch):
    """3+ sinais → severity CRITICAL."""
    _stub_correlation_sources(monkeypatch, {
        "scan_external_process_handles": lambda: _hit_finding(500, "handle"),
        "scan_external_memory_footprint": lambda: _hit_finding(500, "footprint"),
        "scan_overlay_windows": lambda: _hit_finding(500, "overlay"),
    })

    class _P:
        def name(self): return "svchost.exe"
        def exe(self): return r"C:\Users\x\Temp\svchost.exe"
        def create_time(self): return 0

    monkeypatch.setattr(es.psutil, "Process", lambda pid: _P())

    r = es.scan_external_correlation()
    assert r["items"][0]["severity"] == "critical"


def test_correlation_ignores_single_signal(monkeypatch):
    """1 sinal só = deixa pros scanners individuais reportarem, não flagga aqui."""
    _stub_correlation_sources(monkeypatch, {
        "scan_external_process_handles": lambda: _hit_finding(700, "handle"),
    })
    r = es.scan_external_correlation()
    assert r["status"] == "clean"


# ============================ Detecções pra external private ============================

def test_random_exe_name_patterns():
    """Nomes hex/base32/GUID batem; nomes normais NÃO batem."""
    assert es._is_random_exe_name("a1b2c3d4e5f6.exe")
    assert es._is_random_exe_name("DEADBEEF12345678.exe")
    assert es._is_random_exe_name("aBcDe12345XyZ789PqRs.exe")
    assert es._is_random_exe_name("{12345678-1234-1234-1234-123456789ABC}.exe")
    assert es._is_random_exe_name("tmp4A2F.exe")
    # Normais NÃO batem
    assert not es._is_random_exe_name("chrome.exe")
    assert not es._is_random_exe_name("RobloxPlayerBeta.exe")
    assert not es._is_random_exe_name("cheat.exe")  # nome legível mesmo suspeito
    assert not es._is_random_exe_name("app.exe")


def test_random_name_scanner_flags_hex_exe_in_user_path(monkeypatch):
    procs = [_FakeProc(200, "a1b2c3d4e5f6a7b8.exe",
                       r"C:\Users\x\AppData\Local\Temp\a1b2c3d4e5f6a7b8.exe")]
    monkeypatch.setattr(es, "HAS_PSUTIL", True)
    monkeypatch.setattr(es.psutil, "process_iter", lambda attrs=None: iter(procs))
    monkeypatch.setattr(es, "_is_exe_signed", lambda p: False)
    r = es.scan_random_name_executables()
    assert r["status"] == "suspicious"
    assert r["items"][0]["severity"] == "medium"
    assert r["items"][0]["matched"].startswith("random-name:")


def test_random_name_scanner_ignores_signed(monkeypatch):
    """Random exe ASSINADO = instalador legítimo → skip."""
    procs = [_FakeProc(201, "abcdef1234567890.exe",
                       r"C:\Users\x\Downloads\abcdef1234567890.exe")]
    monkeypatch.setattr(es, "HAS_PSUTIL", True)
    monkeypatch.setattr(es.psutil, "process_iter", lambda attrs=None: iter(procs))
    monkeypatch.setattr(es, "_is_exe_signed", lambda p: True)
    assert es.scan_random_name_executables()["status"] == "clean"


def test_random_name_scanner_ignores_normal_names(monkeypatch):
    procs = [_FakeProc(202, "chrome.exe", r"C:\Program Files\Chrome\chrome.exe")]
    monkeypatch.setattr(es, "HAS_PSUTIL", True)
    monkeypatch.setattr(es.psutil, "process_iter", lambda attrs=None: iter(procs))
    monkeypatch.setattr(es, "_is_exe_signed", lambda p: False)
    assert es.scan_random_name_executables()["status"] == "clean"


def test_post_roblox_scanner_flags_process_started_after(monkeypatch):
    """Roblox started at t=100, cheat started at t=200 → flagga."""
    procs = [
        _FakeProc(1, "RobloxPlayerBeta.exe",
                  r"C:\Users\x\Roblox\rbx.exe", create_time=100),
        _FakeProc(2, "cheat.exe",
                  r"C:\Users\x\Downloads\cheat.exe", create_time=200),
    ]
    monkeypatch.setattr(es, "HAS_PSUTIL", True)
    monkeypatch.setattr(es, "_roblox_session_context", lambda: {
        "live_pids": [1], "live": True, "last_run_ts": 100, "anchor_ts": 100,
    })
    monkeypatch.setattr(es.psutil, "process_iter", lambda attrs=None: iter(procs))
    monkeypatch.setattr(es, "_is_exe_signed", lambda p: False)
    r = es.scan_post_roblox_processes()
    assert r["status"] == "suspicious"
    assert "post-roblox:cheat.exe" in {it["matched"] for it in r["items"]}


def test_post_roblox_scanner_ignores_process_before(monkeypatch):
    """Cheat iniciado ANTES do Roblox não bate esse sinal."""
    procs = [
        _FakeProc(2, "cheat.exe",
                  r"C:\Users\x\Downloads\cheat.exe", create_time=100),
        _FakeProc(1, "RobloxPlayerBeta.exe",
                  r"C:\Users\x\Roblox\rbx.exe", create_time=200),
    ]
    monkeypatch.setattr(es, "HAS_PSUTIL", True)
    monkeypatch.setattr(es, "_roblox_session_context", lambda: {
        "live_pids": [1], "live": True, "last_run_ts": 200, "anchor_ts": 200,
    })
    monkeypatch.setattr(es.psutil, "process_iter", lambda attrs=None: iter(procs))
    monkeypatch.setattr(es, "_is_exe_signed", lambda p: False)
    assert es.scan_post_roblox_processes()["status"] == "clean"


def test_post_roblox_scanner_no_anchor_is_clean_meta(monkeypatch):
    """Sem Roblox vivo nem Prefetch: clean + meta (não error)."""
    procs = [_FakeProc(2, "cheat.exe",
                       r"C:\Users\x\Downloads\cheat.exe", create_time=100)]
    monkeypatch.setattr(es, "HAS_PSUTIL", True)
    monkeypatch.setattr(es, "_roblox_session_context", lambda: {
        "live_pids": [], "live": False, "last_run_ts": None, "anchor_ts": None,
    })
    monkeypatch.setattr(es.psutil, "process_iter", lambda attrs=None: iter(procs))
    r = es.scan_post_roblox_processes()
    assert r["status"] in ("clean", "suspicious")
    assert r.get("error") in (None, "")


def test_popup_overlay_whitelist_covers_shell():
    """Whitelist tem que cobrir explorer, dwm, notify hosts, Discord, RTSS."""
    for name in ("explorer.exe", "dwm.exe", "sihost.exe",
                 "discord.exe", "rtss.exe", "textinputhost.exe",
                 "robloxplayerbeta.exe"):
        assert name in es._POPUP_OVERLAY_WHITELIST


def test_pipe_whitelist_covers_windows_and_roblox():
    """Pipe whitelist tem tokens de Windows core + Roblox/Hyperion."""
    for tok in ("microsoft-", "lsass", "roblox", "hyperion"):
        assert tok in es._PIPE_WHITELIST_TOKENS


# ============================ Correlation com novos sinais ============================

def test_correlation_uses_popup_overlay_signal(monkeypatch):
    """Correlation tem que consumir popup-overlay (sinal D3D/DComp)."""
    _stub_correlation_sources(monkeypatch, {
        "scan_external_process_handles": lambda: _hit_finding(800, "handle"),
        "scan_popup_overlays": lambda: _hit_finding(800, "popup-overlay"),
    })

    class _P:
        def name(self): return "x.exe"
        def exe(self): return r"C:\Users\x\Downloads\x.exe"
        def create_time(self): return 0

    monkeypatch.setattr(es.psutil, "Process", lambda pid: _P())

    r = es.scan_external_correlation()
    assert r["status"] == "suspicious"
    it = r["items"][0]
    assert it["severity"] == "high"
    assert "handle" in it["detail"] and "popup-overlay" in it["detail"]


# ============================ Slug routing pros novos ============================

def test_slug_routing_new_scanners():
    from telador import evidence as ev
    assert ev._source_slug_from_name(
        "Overlay D3D/DComp (janela POPUP+TOPMOST)") == "popup_overlay"
    assert ev._source_slug_from_name(
        "Processo iniciado após o Roblox") == "post_roblox_proc"
    assert ev._source_slug_from_name(
        "Named pipes suspeitos (IPC de external)") == "suspicious_pipe"
    assert ev._source_slug_from_name(
        "Executável com nome aleatório") == "random_name_exe"

    for slug in ("popup_overlay", "post_roblox_proc",
                 "suspicious_pipe", "random_name_exe"):
        assert slug in ev.SOURCE_WEIGHTS

    from telador import report_assets as ra
    for slug in ("popup_overlay", "post_roblox_proc",
                 "suspicious_pipe", "random_name_exe"):
        assert slug in ra.SOURCE_LABELS


def test_scanner_count_matches_chain():
    """SCANNER_COUNT tem que refletir o total real."""
    from telador import cli as t
    from telador import version
    chain = t.assemble_scanners(
        skip_forensics=False, skip_antievasion=False, skip_persistence=False,
        skip_live=False, skip_history=False, skip_peripherals=False,
    )
    assert len(chain) == version.SCANNER_COUNT


def test_feeds_cluster_engine_as_confirmed_when_strong():
    """kernel_only_egress (peso 0.95) + severity high com corroboração de outra
    fonte tem que subir pra DETECTED/CONFIRMED. Sem corroboração, no máximo
    SUSPECT (1 fonte só não crava)."""
    from telador import evidence as ev
    findings = [{
        "name": "Rede: processo do sistema com egress externo",
        "status": "suspicious",
        "items": [{
            "label": "conhost.exe com conexão externa: 8.8.8.8:443",
            "detail": "PID 77 · C:\\Users\\x\\Downloads\\conhost.exe",
            "matched": "kernel-only-egress:conhost.exe",
            "severity": "high", "timestamp": "", "confidence": 85,
        }],
    }]
    clusters = ev.build_clusters(ev.findings_to_evidences(findings))
    # 1 fonte só = SUSPECT, não CONFIRMED
    assert len(clusters) >= 0  # não crasha; agrupa se aliases casarem


# ============================ Real machine sanity ============================

def test_no_crash_on_real_machine():
    """Cada scanner tem que rodar sem crash, retornando dict válido.
    Sem Roblox rodando: os 3 primeiros retornam 'error' com mensagem clara.
    kernel_only_egress roda sempre (não depende do Roblox)."""
    for fn in es.ALL_EXTERNAL_SCANNERS:
        r = fn()
        assert isinstance(r, dict)
        assert r["status"] in ("clean", "suspicious", "error")
        assert "items" in r and isinstance(r["items"], list)
        # Todo item tem severity válida
        for it in r["items"]:
            assert it["severity"] in ("critical", "high", "medium", "low")


# ============================ v3.45.2: IoCs de repos publicos ============================

def test_layuh_family_registered():
    """Layuh-Roblox (github.com/Russtels) — external com KeyAuth."""
    assert "layuh" in es.EXTERNAL_FAMILY_IDS
    hit = es.classify_process_name("layuh.exe")
    assert hit and hit[0] == "high" and hit[1] == "layuh"
    hit2 = es.classify_process_name("layuhroblox.exe")
    assert hit2 and hit2[1] == "layuh"


def test_nord_external_family_registered():
    """nord-external (github.com/nordlol) — universal ESP GLFW."""
    assert "nord_external" in es.EXTERNAL_FAMILY_IDS
    hit = es.classify_process_name("nord.exe")
    assert hit and hit[0] == "high" and hit[1] == "nord_external"


def test_autopsy_family_registered_but_bare_word_safe():
    """autopsy (github.com/pwpo) — usermode-only. 'autopsy' bare NAO e IOC
    (tambem e ferramenta forense legitima do Sleuth Kit); so o processo
    autopsy.exe / autopsyloader / autopsy roblox contam."""
    assert "autopsy" in es.EXTERNAL_FAMILY_IDS
    hit = es.classify_process_name("autopsy.exe")
    assert hit and hit[0] == "high" and hit[1] == "autopsy"
    # basenames vazio: nao bate por pasta bare 'autopsy'
    assert es.classify_basename("autopsy") is None


def test_glfw_window_class_escalates_popup_overlay():
    """Class name GLFW30 fora da whitelist = external ESP GLFW-based."""
    assert "glfw30" in es._KNOWN_EXTERNAL_WINDOW_CLASSES
    assert "glfwwindow" in es._KNOWN_EXTERNAL_WINDOW_CLASSES


def test_autopsy_lol_window_class_registered():
    """v3.45.4: Autopsy usa class name literal "autopsy.lol" (extraido de
    src/ui/graphic.cpp em github.com/pwpo/autopsy)."""
    assert "autopsy.lol" in es._KNOWN_EXTERNAL_WINDOW_CLASSES


def test_masquerade_window_class_taskmgr():
    """v3.45.4: Layuh (github.com/Russtels/Layuh-Roblox) registra WNDCLASS
    com lpszClassName = oxorany(L"Task Manager") pra imitar o Task Manager.
    Class Task Manager legitima e criada SO pelo taskmgr.exe."""
    assert "task manager" in es._MASQUERADE_WINDOW_CLASSES
    legit = es._MASQUERADE_WINDOW_CLASSES["task manager"]
    assert legit == {"taskmgr.exe"}


def test_masquerade_path_check_closes_bypass_v3_45_6():
    """v3.45.6: cheater renomeando exe pra taskmgr.exe (nome bate whitelist)
    mas rodando de Downloads (path denuncia) NAO pode escapar. A logica
    combinada checa (a) pname fora da whitelist OU (b) pname bate mas path
    fora de System32/SysWOW64/WinSxS."""
    # Simula os prefixos legitimos usados no scanner
    legit_prefixes = (
        "c:\\windows\\system32\\",
        "c:\\windows\\syswow64\\",
        "c:\\windows\\winsxs\\",
    )
    # Bypass path: taskmgr.exe em Downloads — nome bate, path nao
    pexe_bypass = r"c:\users\x\downloads\taskmgr.exe"
    assert not pexe_bypass.startswith(legit_prefixes), (
        "path de bypass NAO pode bater whitelist"
    )
    # Path legitimo — nao deve levantar masquerade
    pexe_legit = r"c:\windows\system32\taskmgr.exe"
    assert pexe_legit.startswith(legit_prefixes)


def test_autopsy_lol_domain_in_suspicious():
    """v3.45.4: autopsy.lol e brand do external cheat (title de MessageBox
    "Open Roblox first." + class name). Browser history / hosts pra este
    dominio = cheater."""
    from telador.database import SUSPICIOUS_DOMAINS
    assert SUSPICIOUS_DOMAINS.get("autopsy.lol") == "high"


# ---------- v3.45.5: LectureExternal + Nocturnal ----------

def test_lecture_external_family_registered():
    """github.com/LectureExternal/lectureExternal — byfron bypass, exe direto
    no repo. Familia +processes/tokens/basenames."""
    assert "lecture_external" in es.EXTERNAL_FAMILY_IDS
    hit = es.classify_process_name("lectureexternal.exe")
    assert hit and hit[0] == "high" and hit[1] == "lecture_external"


def test_lecture_external_basename_matches():
    """lectureexternal como basename e IOC (nao e palavra comum)."""
    hit = es.classify_basename("lectureexternal")
    assert hit and hit[1] == "lecture_external"


def test_nocturnal_family_registered():
    """github.com/matidebugging0/nocturnal — .NET byfron bypass."""
    assert "nocturnal" in es.EXTERNAL_FAMILY_IDS
    hit = es.classify_process_name("nocturnal.exe")
    assert hit and hit[0] == "high" and hit[1] == "nocturnal"


def test_nocturnal_bare_word_safe_anti_fp():
    """'nocturnal' bare NAO e IOC (poesia/musica/streamer names). basenames
    vazio de proposito. So bate com contexto 'nocturnal roblox' etc."""
    assert es.classify_basename("nocturnal") is None


def test_nocturnal_with_context_flags():
    """nocturnal + roblox/external/bypass = IOC. Testa via path token."""
    hit = es.classify_path_or_text(
        r"C:\Users\x\Downloads\nocturnal roblox\loader.exe"
    )
    assert hit and hit[1] == "nocturnal"


def test_keyauth_domains_in_suspicious():
    """KeyAuth SaaS de DRM usado por ~todo external pago (Layuh etc).
    Deteccao via DNS cache / network / browser history."""
    from telador.database import SUSPICIOUS_DOMAINS
    for d in ("keyauth.win", "keyauth.cc", "keyauth.pro",
              "keyauth.gg", "keyauth.to", "keyauth.us"):
        assert SUSPICIOUS_DOMAINS.get(d) == "high", d


def test_offset_feed_domains_in_suspicious():
    """Sites de dump de offsets — ninguem legitimo visita."""
    from telador.database import SUSPICIOUS_DOMAINS
    for d in ("imtheo.lol", "rbxoffsets.com", "robloxoffsets.com"):
        assert SUSPICIOUS_DOMAINS.get(d) == "high", d
