"""Tier S (v3.46.0) — system_hardening scanners.

Foco em unit tests que exercitam a lógica de detecção sem depender de admin,
Roblox rodando ou hive vivo. Onde precisamos, monkeypatch em subprocess/sqlite.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import types
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import system_hardening as sh  # noqa: E402


# ------------------------------ DSE / Test Mode ------------------------------

def _fake_run_ok(stdout: str, returncode: int = 0):
    def _fn(*args, **kwargs):
        return types.SimpleNamespace(
            returncode=returncode, stdout=stdout, stderr="",
        )
    return _fn


def _fake_run_fail(stderr: str = "Acesso negado", returncode: int = 1):
    def _fn(*args, **kwargs):
        return types.SimpleNamespace(
            returncode=returncode, stdout="", stderr=stderr,
        )
    return _fn


def test_dse_testsigning_yes_high(monkeypatch):
    """bcdedit reporta testsigning Yes → HIGH item."""
    stdout = (
        "Windows Boot Loader\r\n-------------------\r\n"
        "identifier              {current}\r\n"
        "testsigning             Yes\r\n"
        "nointegritychecks       No\r\n"
    )
    monkeypatch.setattr(sh.subprocess, "run", _fake_run_ok(stdout))
    r = sh.scan_dse_state()
    assert r["status"] == "suspicious"
    matches = [i for i in r["items"] if i.get("matched") == "dse-bcd-testsigning"]
    assert matches, "esperava hit de dse-bcd-testsigning"
    assert matches[0]["severity"] == "high"


def test_dse_nointegritychecks_yes_high(monkeypatch):
    stdout = "nointegritychecks       Yes\r\ntestsigning             No\r\n"
    monkeypatch.setattr(sh.subprocess, "run", _fake_run_ok(stdout))
    r = sh.scan_dse_state()
    slugs = [i["matched"] for i in r["items"]]
    assert "dse-bcd-nointegritychecks" in slugs


def test_dse_normal_windows_clean(monkeypatch):
    """Windows normal: nada ligado → clean."""
    stdout = "identifier {current}\r\ntestsigning No\r\nnointegritychecks No\r\n"
    monkeypatch.setattr(sh.subprocess, "run", _fake_run_ok(stdout))
    r = sh.scan_dse_state()
    # Sem hit; pode ter cadastrado LOW pra CI\State anômalo se registry deu.
    high = [i for i in r["items"] if i.get("severity") == "high"]
    assert not high


def test_dse_bcdedit_denied_returns_error(monkeypatch):
    monkeypatch.setattr(sh.subprocess, "run", _fake_run_fail("Acesso negado."))
    r = sh.scan_dse_state()
    assert r["status"] == "error"
    assert "bcdedit" in (r.get("error") or "").lower()


# ------------------------------ VBS / HVCI ------------------------------

def test_vbs_disabled_critical(monkeypatch):
    payload = {
        "VirtualizationBasedSecurityStatus": 0,
        "SecurityServicesConfigured": [],
        "SecurityServicesRunning": [],
    }
    monkeypatch.setattr(sh.subprocess, "run", _fake_run_ok(json.dumps(payload)))
    r = sh.scan_vbs_hvci_disabled()
    slugs = [i["matched"] for i in r["items"]]
    assert "vbs-disabled" in slugs
    assert r["items"][0]["severity"] == "critical"


def test_vbs_configured_not_running_high(monkeypatch):
    payload = {"VirtualizationBasedSecurityStatus": 1,
               "SecurityServicesConfigured": [], "SecurityServicesRunning": []}
    monkeypatch.setattr(sh.subprocess, "run", _fake_run_ok(json.dumps(payload)))
    r = sh.scan_vbs_hvci_disabled()
    slugs = [i["matched"] for i in r["items"]]
    assert "vbs-not-running" in slugs


def test_hvci_tampered_critical(monkeypatch):
    """VBS on + HVCI configurado + HVCI NÃO running → tampering."""
    payload = {
        "VirtualizationBasedSecurityStatus": 2,
        "SecurityServicesConfigured": [1, 2],
        "SecurityServicesRunning": [1],  # HVCI (2) faltando
    }
    monkeypatch.setattr(sh.subprocess, "run", _fake_run_ok(json.dumps(payload)))
    r = sh.scan_vbs_hvci_disabled()
    slugs = [i["matched"] for i in r["items"]]
    assert "hvci-tampered" in slugs


def test_vbs_healthy_clean(monkeypatch):
    payload = {
        "VirtualizationBasedSecurityStatus": 2,
        "SecurityServicesConfigured": [1, 2],
        "SecurityServicesRunning": [1, 2],
    }
    monkeypatch.setattr(sh.subprocess, "run", _fake_run_ok(json.dumps(payload)))
    r = sh.scan_vbs_hvci_disabled()
    assert r["status"] == "clean"


def test_vbs_powershell_fail_returns_error(monkeypatch):
    monkeypatch.setattr(sh.subprocess, "run", _fake_run_fail("erro CIM"))
    r = sh.scan_vbs_hvci_disabled()
    assert r["status"] == "error"


# ------------------------------ Roblox RWX ------------------------------

def test_roblox_rwx_no_psutil(monkeypatch):
    monkeypatch.setattr(sh, "HAS_PSUTIL", False)
    r = sh.scan_roblox_page_protection()
    assert r["status"] == "error"
    assert "psutil" in (r.get("error") or "").lower()


def test_roblox_rwx_not_running(monkeypatch):
    monkeypatch.setattr(sh, "HAS_PSUTIL", True)
    monkeypatch.setattr(sh, "_find_roblox_pid", lambda: None)
    r = sh.scan_roblox_page_protection()
    assert r["status"] == "error"
    assert "roblox" in (r.get("error") or "").lower()


# ------------------------------ ActivitiesCache ------------------------------

def _make_activities_db(path: str, rows: list[tuple[str, int, int, str | None]]):
    """Cria SQLite fake com o schema mínimo da tabela Activity."""
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "CREATE TABLE Activity ("
            "AppId TEXT, StartTime INTEGER, LastModifiedOnClient INTEGER, "
            "Payload TEXT)"
        )
        conn.executemany(
            "INSERT INTO Activity VALUES (?, ?, ?, ?)", rows,
        )
        conn.commit()
    finally:
        conn.close()


def test_activities_matches_executor_keyword(tmp_path, monkeypatch):
    """AppId contendo keyword de executor gera hit MEDIUM."""
    # Setup fake structure em tmp_path
    cdp = tmp_path / "ConnectedDevicesPlatform" / "L.gabri"
    cdp.mkdir(parents=True)
    db = cdp / "ActivitiesCache.db"
    _make_activities_db(str(db), [
        ("solara-executor.exe", 1720000000, 1720000000, None),
        ("chrome.exe", 1720000000, 1720000000, None),
    ])
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr(sh, "EXECUTOR_KEYWORDS", ("solara", "xeno", "krnl"))
    r = sh.scan_activities_cache_timeline()
    matches = [i for i in r["items"] if "activities-cache" in i.get("matched", "")]
    assert matches, f"esperava hit; items={r['items']} err={r.get('error')}"
    assert any("solara" in m["matched"] for m in matches)


def test_activities_no_cdp_dir_returns_error(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    r = sh.scan_activities_cache_timeline()
    assert r["status"] == "error"
    assert "connecteddevicesplatform" in (r.get("error") or "").lower()


def test_activities_empty_keyword_list_returns_error(tmp_path, monkeypatch):
    cdp = tmp_path / "ConnectedDevicesPlatform" / "L.x"
    cdp.mkdir(parents=True)
    db = cdp / "ActivitiesCache.db"
    _make_activities_db(str(db), [("nothing", 0, 0, None)])
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr(sh, "EXECUTOR_KEYWORDS", ())
    r = sh.scan_activities_cache_timeline()
    assert r["status"] == "error"
    assert "executor_keywords" in (r.get("error") or "").lower()


def test_activities_severity_from_dict(tmp_path, monkeypatch):
    """EXECUTOR_KEYWORDS é dict {kw: sev} — severity deve vir do dict."""
    cdp = tmp_path / "ConnectedDevicesPlatform" / "L.x"
    cdp.mkdir(parents=True)
    db = cdp / "ActivitiesCache.db"
    _make_activities_db(str(db), [
        ("solara-executor.exe", 1720000000, 1720000000, None),
        ("process hacker binary", 1720000000, 1720000000, None),
    ])
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr(sh, "EXECUTOR_KEYWORDS", {
        "solara": "high", "process hacker": "low",
    })
    r = sh.scan_activities_cache_timeline()
    by_kw = {i["matched"]: i["severity"] for i in r["items"]}
    assert by_kw.get("activities-cache:solara") == "high"
    assert by_kw.get("activities-cache:process hacker") == "low"


def test_activities_clean_no_match(tmp_path, monkeypatch):
    cdp = tmp_path / "ConnectedDevicesPlatform" / "L.x"
    cdp.mkdir(parents=True)
    db = cdp / "ActivitiesCache.db"
    _make_activities_db(str(db), [
        ("chrome.exe", 1720000000, 1720000000, None),
        ("notepad.exe", 1720000000, 1720000000, None),
    ])
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr(sh, "EXECUTOR_KEYWORDS", ("solara",))
    r = sh.scan_activities_cache_timeline()
    assert r["status"] == "clean"


# ------------------------------ Chain / registry ------------------------------

def test_all_scanners_exist():
    assert len(sh.ALL_SYSTEM_HARDENING_SCANNERS) == 4
    names = [f.__name__ for f in sh.ALL_SYSTEM_HARDENING_SCANNERS]
    assert set(names) == {
        "scan_dse_state",
        "scan_vbs_hvci_disabled",
        "scan_roblox_page_protection",
        "scan_activities_cache_timeline",
    }


def test_registry_has_system_hardening_group():
    import scanner_registry
    reg = scanner_registry.build_registry()
    groups = {m.group for m in reg}
    assert "system_hardening" in groups
    sh_scanners = [m for m in reg if m.group == "system_hardening"]
    assert len(sh_scanners) == 4
