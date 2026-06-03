"""
Testes do dashboard local --watch (watch_server.py).

Garante que:
  - o servidor sobe em loopback e serve o dashboard + /state
  - scanners streamados aparecem no estado
  - clusters se formam ao vivo (prévia)
  - finalize() trava o estado final
  - NADA é exposto fora de 127.0.0.1
"""

import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import watch_server  # noqa: E402

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _close_server_after_test():
    """Fecha o servidor após cada teste — sem isso o socket de escuta
    fica aberto (ResourceWarning) já que cada start() sobe um novo."""
    yield
    watch_server.stop()


def _finding(name, items):
    return {"name": name, "status": "suspicious" if items else "clean", "items": items}


def _hit(label, matched, severity="high"):
    return {"label": label, "detail": "", "matched": matched,
            "severity": severity, "timestamp": "", "confidence": 85}


def _get_state(url):
    with urllib.request.urlopen(url + "state", timeout=5) as r:
        return json.load(r)


def test_server_binds_loopback_only():
    url = watch_server.start(2, open_browser=False)
    assert url is not None
    assert url.startswith("http://127.0.0.1:")
    # porta != 0
    port = int(url.rsplit(":", 1)[1].rstrip("/"))
    assert port > 0


def test_dashboard_html_served():
    url = watch_server.start(1, open_browser=False)
    with urllib.request.urlopen(url, timeout=5) as r:
        html = r.read().decode("utf-8")
    assert "TELADOR" in html
    assert "127.0.0.1" in html  # badge de local
    assert "/state" in html     # faz polling


def test_push_scanner_appears_in_state():
    url = watch_server.start(3, open_browser=False)
    watch_server.push_scanner(_finding("Prefetch", [_hit(r"C:\x\solara.exe", "solara")]), 1, 3)
    st = _get_state(url)
    assert st["done"] == 1
    assert st["total"] == 3
    assert len(st["scanners"]) == 1
    assert st["scanners"][0]["name"] == "Prefetch"
    assert st["scanners"][0]["n_hits"] == 1


def test_clusters_form_live_preview():
    url = watch_server.start(3, open_browser=False)
    # 3 fontes batendo em Solara → deve formar cluster ao vivo
    watch_server.push_scanner(_finding("Prefetch", [_hit(r"C:\Windows\Prefetch\SOLARA.EXE-A.pf", "solara")]), 1, 3)
    watch_server.push_scanner(_finding("Amcache", [_hit(r"C:\Users\b\Solara\Solara.exe", "solara executor")]), 2, 3)
    watch_server.push_scanner(_finding("BAM", [_hit("[BAM] solara.exe", "solara.exe")]), 3, 3)
    st = _get_state(url)
    assert st["status"] == "scanning"
    assert st["live_preview"] is True
    labels = [c["label"] for c in st["clusters"]]
    assert "Solara" in labels
    solara = next(c for c in st["clusters"] if c["label"] == "Solara")
    assert solara["n_sources"] == 3


def test_finalize_locks_state():
    import evidence as ev
    url = watch_server.start(1, open_browser=False)
    findings = [_finding("Kernel Drivers", [
        _hit(r"C:\Windows\System32\drivers\winring0.sys", "driver-byovd:winring0", "critical")])]
    watch_server.push_scanner(findings[0], 1, 1)
    clusters = ev.build_clusters(ev.findings_to_evidences(findings))
    verdict = {"verdict": "ALTAMENTE SUSPEITO", "color": "#ff4d4f", "score": 25,
               "critical": 1, "high": 0, "medium": 0, "low": 0}
    watch_server.finalize(clusters, verdict)
    st = _get_state(url)
    assert st["status"] == "done"
    assert st["live_preview"] is False
    assert st["verdict"]["verdict"] == "ALTAMENTE SUSPEITO"


def test_clean_pc_no_clusters():
    url = watch_server.start(2, open_browser=False)
    watch_server.push_scanner(_finding("Prefetch", []), 1, 2)
    watch_server.push_scanner(_finding("Amcache", []), 2, 2)
    watch_server.finalize([], {"verdict": "LIMPO", "color": "#3fbf7f", "score": 0,
                               "critical": 0, "high": 0, "medium": 0, "low": 0})
    st = _get_state(url)
    assert st["status"] == "done"
    assert st["clusters"] == []
