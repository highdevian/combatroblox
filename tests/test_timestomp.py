"""
Testes da detecção de anomalias de timestamp (timestomp_scanner.py).

Foco no núcleo `_classify_times` (FP-safety do gate de backdate) e numa
integração criando um arquivo com mtime no futuro.
"""

import os
import sys
import time
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import timestomp_scanner as ts  # noqa: E402


_NOW = datetime(2026, 6, 20, 12, 0, 0)


# ----------------------------- núcleo: _classify_times -----------------------------

def test_future_created_flagged():
    fut = _NOW + timedelta(days=10)
    sev, m, _motivo = ts._classify_times(fut, _NOW, _NOW, is_executor=False)
    assert sev == "medium"
    assert m == "timestamp-futuro"


def test_future_modified_flagged():
    fut = _NOW + timedelta(days=10)
    sev, m, _ = ts._classify_times(_NOW, fut, _NOW, is_executor=False)
    assert m == "timestamp-futuro"


def test_small_future_skew_not_flagged():
    """Tolerância de 1 dia — relógio levemente adiantado não dispara."""
    skew = _NOW + timedelta(hours=2)
    assert ts._classify_times(skew, skew, _NOW, is_executor=False) is None


def test_backdated_executor_flagged():
    """Executor com criação antes de 2006 = backdated."""
    old = datetime(2004, 1, 1)
    sev, m, _ = ts._classify_times(old, _NOW, _NOW, is_executor=True)
    assert sev == "medium"
    assert m == "timestamp-backdated"


def test_backdated_non_executor_not_flagged():
    """FP-SAFE: arquivo NÃO-executor com data antiga NÃO flagga (gate). Arquivo
    legítimo antigo (doc de 2004 copiado) não é nosso problema."""
    old = datetime(2004, 1, 1)
    assert ts._classify_times(old, _NOW, _NOW, is_executor=False) is None


def test_normal_recent_times_not_flagged():
    recent = _NOW - timedelta(days=3)
    assert ts._classify_times(recent, recent, _NOW, is_executor=True) is None


def test_none_times_safe():
    assert ts._classify_times(None, None, _NOW, is_executor=True) is None


# ----------------------------- integração (fs real) -----------------------------

def test_scan_flags_future_file(tmp_path, monkeypatch):
    normal = tmp_path / "normal.exe"
    normal.write_bytes(b"MZ")
    fut = tmp_path / "thing.exe"
    fut.write_bytes(b"MZ")
    future = time.time() + 30 * 86400
    os.utime(fut, (future, future))

    monkeypatch.setattr(ts, "_SCAN_DIRS", [str(tmp_path)])
    r = ts.scan_timestomp()
    assert r["status"] == "suspicious"
    assert len(r["items"]) == 1
    assert r["items"][0]["matched"] == "timestamp-futuro"
    assert "thing.exe" in r["items"][0]["label"]


def test_scan_clean_on_normal_files(tmp_path, monkeypatch):
    (tmp_path / "app.exe").write_bytes(b"MZ")
    (tmp_path / "lib.dll").write_bytes(b"MZ")
    monkeypatch.setattr(ts, "_SCAN_DIRS", [str(tmp_path)])
    assert ts.scan_timestomp()["status"] == "clean"


def test_file_times_returns_datetimes(tmp_path):
    p = tmp_path / "x.exe"
    p.write_bytes(b"MZ")
    created, modified = ts._file_times(str(p))
    assert isinstance(modified, datetime)


# ----------------------------- engine -----------------------------

def test_slug_maps_to_anti_forense():
    import evidence as ev
    assert ev._source_slug_from_name("Anomalia de timestamp (time-stomping)") == "anti_forense"


def test_feeds_cluster_engine():
    import evidence as ev
    findings = [{
        "name": "Anomalia de timestamp (time-stomping)", "status": "suspicious",
        "items": [{
            "label": "Timestamp adulterado: cheat.exe", "detail": "x",
            "matched": "timestamp-futuro", "severity": "medium",
            "timestamp": "", "confidence": 50,
        }],
    }]
    clusters = ev.build_clusters(ev.findings_to_evidences(findings))
    assert len(clusters) == 1
    assert clusters[0].verdict != "CONFIRMED"


def test_registered_in_scanner_list():
    assert ts.scan_timestomp in ts.ALL_TIMESTOMP_SCANNERS
