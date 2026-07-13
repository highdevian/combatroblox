"""Tier A behavioral scanners — dropper task, AMSI bypass, APC injection."""
from __future__ import annotations

import json
import os
import sys
import types
from datetime import datetime, timedelta, timezone


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import behavioral_tier_a as bt  # noqa: E402


def _fake_run(stdout: str, returncode: int = 0):
    def _fn(*args, **kwargs):
        return types.SimpleNamespace(
            returncode=returncode, stdout=stdout, stderr="",
        )
    return _fn


def _fake_run_fail(stderr: str = "erro", returncode: int = 1):
    def _fn(*args, **kwargs):
        return types.SimpleNamespace(
            returncode=returncode, stdout="", stderr=stderr,
        )
    return _fn


# ------------------------------ Scheduled Task Dropper ------------------------------

def test_dropper_detects_recent_logon_userpath(monkeypatch):
    """Task criada agora + AtLogon + exe em C:\\Users\\ → hit."""
    recent = datetime.now(timezone.utc) - timedelta(hours=2)
    payload = [{
        "Name": "MalwareLoader",
        "Path": "\\",
        "Date": recent.isoformat(),
        "Trigger": "MSFT_TaskLogonTrigger",
        "Exec": "C:\\Users\\gabri\\AppData\\Roaming\\loader.exe",
        "Args": "",
    }]
    monkeypatch.setattr(bt.subprocess, "run", _fake_run(json.dumps(payload)))
    r = bt.scan_scheduled_task_dropper()
    assert r["status"] == "suspicious"
    assert any(i["matched"] == "dropper-task" for i in r["items"])


def test_dropper_ignores_old_task(monkeypatch):
    """Task de 30 dias atrás → não hit (só últimas 24h)."""
    old = datetime.now(timezone.utc) - timedelta(days=30)
    payload = [{
        "Name": "OldTask", "Path": "\\", "Date": old.isoformat(),
        "Trigger": "MSFT_TaskLogonTrigger",
        "Exec": "C:\\Users\\gabri\\loader.exe", "Args": "",
    }]
    monkeypatch.setattr(bt.subprocess, "run", _fake_run(json.dumps(payload)))
    r = bt.scan_scheduled_task_dropper()
    assert r["status"] == "clean"


def test_dropper_ignores_system_path(monkeypatch):
    """Task recente + AtLogon mas exe em Program Files → não hit."""
    recent = datetime.now(timezone.utc) - timedelta(hours=1)
    payload = [{
        "Name": "SteamUpdate", "Path": "\\", "Date": recent.isoformat(),
        "Trigger": "MSFT_TaskLogonTrigger",
        "Exec": "C:\\Program Files (x86)\\Steam\\bin\\updater.exe",
        "Args": "",
    }]
    monkeypatch.setattr(bt.subprocess, "run", _fake_run(json.dumps(payload)))
    r = bt.scan_scheduled_task_dropper()
    assert r["status"] == "clean"


def test_dropper_ignores_non_logon_trigger(monkeypatch):
    """Task recente + userpath mas trigger é Daily → não hit."""
    recent = datetime.now(timezone.utc) - timedelta(hours=1)
    payload = [{
        "Name": "DailyBackup", "Path": "\\", "Date": recent.isoformat(),
        "Trigger": "MSFT_TaskDailyTrigger",
        "Exec": "C:\\Users\\gabri\\backup.exe", "Args": "",
    }]
    monkeypatch.setattr(bt.subprocess, "run", _fake_run(json.dumps(payload)))
    r = bt.scan_scheduled_task_dropper()
    assert r["status"] == "clean"


def test_dropper_ps_fail_returns_error(monkeypatch):
    monkeypatch.setattr(bt.subprocess, "run", _fake_run_fail("Get-ScheduledTask erro"))
    r = bt.scan_scheduled_task_dropper()
    assert r["status"] == "error"


def test_dropper_pssafe_boot_trigger(monkeypatch):
    """BootTrigger também vale como persistência."""
    recent = datetime.now(timezone.utc) - timedelta(hours=1)
    payload = [{
        "Name": "BootLoader", "Path": "\\", "Date": recent.isoformat(),
        "Trigger": "MSFT_TaskBootTrigger",
        "Exec": "C:\\Users\\gabri\\loader.exe", "Args": "",
    }]
    monkeypatch.setattr(bt.subprocess, "run", _fake_run(json.dumps(payload)))
    r = bt.scan_scheduled_task_dropper()
    assert r["status"] == "suspicious"


# ------------------------------ AMSI Bypass ------------------------------

def test_amsi_no_psutil(monkeypatch):
    monkeypatch.setattr(bt, "HAS_PSUTIL", False)
    r = bt.scan_amsi_bypass()
    assert r["status"] == "error"


def test_amsi_no_powershell_running(monkeypatch):
    monkeypatch.setattr(bt, "HAS_PSUTIL", True)
    monkeypatch.setattr(bt, "_find_powershell_pids", lambda: [])
    r = bt.scan_amsi_bypass()
    assert r["status"] == "error"
    assert "powershell" in (r.get("error") or "").lower()


# ------------------------------ APC Injection ------------------------------

def test_apc_no_psutil(monkeypatch):
    monkeypatch.setattr(bt, "HAS_PSUTIL", False)
    r = bt.scan_apc_injection()
    assert r["status"] == "error"


def test_apc_no_roblox_running(monkeypatch):
    class _FakePsutil:
        NoSuchProcess = Exception
        AccessDenied = Exception
        @staticmethod
        def process_iter(attrs):
            return iter([])
        class Process:
            def __init__(self, pid): pass
    monkeypatch.setattr(bt, "HAS_PSUTIL", True)
    monkeypatch.setattr(bt, "psutil", _FakePsutil)
    r = bt.scan_apc_injection()
    assert r["status"] == "error"
    assert "roblox" in (r.get("error") or "").lower()


def test_apc_ignores_gpu_overlay_dlls(monkeypatch):
    """DLLs de overlay (NVIDIA/Discord/RTSS) em programdata NÃO viram FP."""
    class _FakeProc:
        def __init__(self):
            self.info = {"name": "RobloxPlayerBeta.exe", "pid": 100}
        def memory_maps(self, grouped=False):
            return [
                types.SimpleNamespace(path="C:\\ProgramData\\NVIDIA Corporation\\Drs\\nvinject.dll"),
                types.SimpleNamespace(path="C:\\Users\\gabri\\AppData\\Local\\Discord\\app\\overlay.dll"),
            ]
    class _FakeProcess:
        def __init__(self, pid): self._m = _FakeProc()
        def memory_maps(self, grouped=False):
            return self._m.memory_maps(grouped)
    class _FakePsutil:
        NoSuchProcess = Exception
        AccessDenied = Exception
        @staticmethod
        def process_iter(attrs):
            return iter([_FakeProc()])
        Process = _FakeProcess
    monkeypatch.setattr(bt, "HAS_PSUTIL", True)
    monkeypatch.setattr(bt, "psutil", _FakePsutil)
    r = bt.scan_apc_injection()
    assert r["status"] == "clean"


def test_apc_ignores_windows_path_dlls(monkeypatch):
    """DLL em C:\\Windows\\ ou Program Files → não hit (legit)."""
    class _FakeProc:
        def __init__(self):
            self.info = {"name": "RobloxPlayerBeta.exe", "pid": 100}
        def memory_maps(self, grouped=False):
            return [
                types.SimpleNamespace(path="C:\\Windows\\System32\\kernel32.dll"),
                types.SimpleNamespace(path="C:\\Program Files\\Roblox\\Versions\\v.dll"),
            ]
    class _FakeProcess:
        def __init__(self, pid): self._m = _FakeProc()
        def memory_maps(self, grouped=False):
            return self._m.memory_maps(grouped)
    class _FakePsutil:
        NoSuchProcess = Exception
        AccessDenied = Exception
        @staticmethod
        def process_iter(attrs):
            return iter([_FakeProc()])
        Process = _FakeProcess
    monkeypatch.setattr(bt, "HAS_PSUTIL", True)
    monkeypatch.setattr(bt, "psutil", _FakePsutil)
    r = bt.scan_apc_injection()
    assert r["status"] == "clean"


def test_apc_detects_userpath_dll(monkeypatch):
    """DLL em C:\\Users\\ → hit."""
    class _FakeProc:
        def __init__(self):
            self.info = {"name": "RobloxPlayerBeta.exe", "pid": 100}
        def memory_maps(self, grouped=False):
            return [
                types.SimpleNamespace(path="C:\\Windows\\System32\\kernel32.dll"),
                types.SimpleNamespace(path="C:\\Users\\gabri\\Downloads\\injected.dll"),
            ]
    class _FakeProcess:
        def __init__(self, pid): self._m = _FakeProc()
        def memory_maps(self, grouped=False):
            return self._m.memory_maps(grouped)
    class _FakePsutil:
        NoSuchProcess = Exception
        AccessDenied = Exception
        @staticmethod
        def process_iter(attrs):
            return iter([_FakeProc()])
        Process = _FakeProcess
    monkeypatch.setattr(bt, "HAS_PSUTIL", True)
    monkeypatch.setattr(bt, "psutil", _FakePsutil)
    r = bt.scan_apc_injection()
    assert r["status"] == "suspicious"
    assert any("apc-injection" in i["matched"] for i in r["items"])


# ------------------------------ Chain / registry ------------------------------

def test_all_scanners_exist():
    assert len(bt.ALL_BEHAVIORAL_TIER_A_SCANNERS) == 3
    names = [f.__name__ for f in bt.ALL_BEHAVIORAL_TIER_A_SCANNERS]
    assert set(names) == {
        "scan_scheduled_task_dropper",
        "scan_amsi_bypass",
        "scan_apc_injection",
    }


def test_registry_has_behavioral_tier_a_group():
    import scanner_registry
    reg = scanner_registry.build_registry()
    groups = {m.group for m in reg}
    assert "behavioral_tier_a" in groups
    bta_scanners = [m for m in reg if m.group == "behavioral_tier_a"]
    assert len(bta_scanners) == 3
