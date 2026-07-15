"""
Testes do scanner de serviços forenses críticos (service_state_scanner.py).

Foco:
  - _classify decide HIGH/MEDIUM/clean a partir do dict de stopped
  - eventlog parado é sempre HIGH (cega TODO Event Log)
  - 3+ outros parados juntos = HIGH com matched 'multi'
  - 2 outros = MEDIUM "pair" (debloater pode parar Diagtrack+DPS sem ser cheat)
  - 1 isolado = MEDIUM
  - integração com Confidence Engine + plumbing (label/slug)
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from telador import service_state_scanner as ss  # noqa: E402
# ----------------------------- _classify (núcleo puro) -----------------------------

def test_classify_empty_is_no_items():
    assert ss._classify({}) == []


def test_classify_eventlog_alone_high():
    items = ss._classify({"eventlog": "stopped"})
    assert len(items) == 1
    assert items[0]["severity"] == "high"
    assert items[0]["matched"] == "service-stopped:eventlog"


def test_classify_one_other_isolated_medium():
    items = ss._classify({"diagtrack": "stopped"})
    assert len(items) == 1
    assert items[0]["severity"] == "medium"
    assert items[0]["matched"] == "service-stopped:diagtrack"


def test_classify_two_others_pair_medium():
    """ANTI-FP: 2 críticos parados (sem eventlog) = MEDIUM "pair", NÃO HIGH.
    Debloater scripts comumente param Diagtrack+DPS — bumpar pra HIGH com 2 era
    FP em PC de gamer paranoico."""
    items = ss._classify({"dps": "stopped", "diagtrack": "stopped"})
    assert len(items) == 1
    assert items[0]["severity"] == "medium"
    assert items[0]["matched"] == "service-stopped:pair"
    assert "dps" in items[0]["detail"].lower()
    assert "diagtrack" in items[0]["detail"].lower()


def test_classify_three_others_multi_high():
    """3+ críticos parados = HIGH multi (raro em PC normal mesmo com debloater)."""
    items = ss._classify({
        "dps": "stopped", "diagtrack": "stopped", "pcasvc": "stopped"})
    assert len(items) == 1
    assert items[0]["severity"] == "high"
    assert items[0]["matched"] == "service-stopped:multi"


def test_classify_eventlog_plus_three_others_two_items():
    """eventlog + 3 outros = 2 items: HIGH do eventlog + HIGH 'multi'."""
    items = ss._classify({
        "eventlog": "stopped", "dps": "stopped", "diagtrack": "stopped",
        "pcasvc": "stopped"})
    matched = {it["matched"] for it in items}
    assert "service-stopped:eventlog" in matched
    assert "service-stopped:multi" in matched
    assert all(it["severity"] == "high" for it in items)


def test_classify_eventlog_plus_one_other():
    """eventlog HIGH + 1 outro isolado MEDIUM. Não inflar pra multi com 1."""
    items = ss._classify({"eventlog": "stopped", "diagtrack": "stopped"})
    severities = {it["matched"]: it["severity"] for it in items}
    assert severities.get("service-stopped:eventlog") == "high"
    assert severities.get("service-stopped:diagtrack") == "medium"


def test_classify_eventlog_plus_pair_three_items():
    """eventlog + 2 outros = eventlog HIGH + pair MEDIUM (não multi com 2)."""
    items = ss._classify({
        "eventlog": "stopped", "dps": "stopped", "diagtrack": "stopped"})
    by_match = {it["matched"]: it["severity"] for it in items}
    assert by_match["service-stopped:eventlog"] == "high"
    assert by_match["service-stopped:pair"] == "medium"


def test_classify_cdpusersvc_isolated_medium():
    """cdpusersvc casado por prefixo, label humano correto."""
    items = ss._classify({ss.CDPUSER_PREFIX: "stopped"})
    assert len(items) == 1
    assert items[0]["severity"] == "medium"
    assert ss.CDPUSER_LABEL.lower() in items[0]["detail"].lower()


# ----------------------------- _label_for -----------------------------

def test_label_for_known():
    assert ss._label_for("eventlog") == "Windows Event Log"
    assert ss._label_for("dps") == "Diagnostic Policy Service"
    assert ss._label_for(ss.CDPUSER_PREFIX) == ss.CDPUSER_LABEL


def test_label_for_unknown_passthrough():
    assert ss._label_for("nada") == "nada"


# ----------------------------- scan_critical_services (com mock) -----------------------------

def test_scan_clean_when_nothing_stopped(monkeypatch):
    monkeypatch.setattr(ss, "_list_stopped_services", lambda: {})
    r = ss.scan_critical_services()
    assert r["status"] == "clean"


def test_scan_error_when_no_access(monkeypatch):
    monkeypatch.setattr(ss, "_list_stopped_services", lambda: None)
    r = ss.scan_critical_services()
    assert r["status"] == "error"


def test_scan_suspicious_when_eventlog_down(monkeypatch):
    monkeypatch.setattr(ss, "_list_stopped_services",
                         lambda: {"eventlog": "stopped"})
    r = ss.scan_critical_services()
    assert r["status"] == "suspicious"
    assert r["items"][0]["severity"] == "high"


def test_scan_real_machine_no_crash():
    """Roda na máquina real (sem mock). Não pode crashar — só clean/susp/error."""
    r = ss.scan_critical_services()
    assert r["status"] in ("clean", "suspicious", "error")
    for it in r["items"]:
        assert it["severity"] in ("low", "medium", "high")


# ----------------------------- Plumbing -----------------------------

def test_registered_in_chain():
    """Tá no ALL_SERVICE_STATE_SCANNERS pra ser pego pelo assemble_scanners."""
    assert ss.scan_critical_services in ss.ALL_SERVICE_STATE_SCANNERS


def test_slug_label_and_weight():
    """Slug 'service_state' tem peso em evidence.SOURCE_WEIGHTS e label em
    report_assets.SOURCE_LABELS, e o mapper de nome→slug acerta."""
    from telador import evidence as ev
    from telador import report_assets
    assert "service_state" in ev.SOURCE_WEIGHTS
    assert ev.SOURCE_WEIGHTS["service_state"] >= 0.80
    assert "service_state" in report_assets.SOURCE_LABELS
    assert ev._source_slug_from_name(
        "Serviços forenses críticos parados") == "service_state"


# ----------------------------- ANTI-FP: sgrmbroker e SysMain fora da lista -----------------------------

def test_sgrmbroker_not_in_critical_list():
    """REGRESSÃO: sgrmbroker é trigger-start em Win11, costuma estar Stopped
    em PC saudável. Não pode estar na lista — geraria FP estrutural."""
    names = {k for k, _ in ss.CRITICAL_FORENSIC_SERVICES}
    assert "sgrmbroker" not in names


def test_sysmain_not_in_critical_list():
    """REGRESSÃO: SysMain já é coberto por extra_forensics.scan_prefetch_sysmain
    via Start Type=Disabled. Incluir aqui duplicaria score."""
    names = {k for k, _ in ss.CRITICAL_FORENSIC_SERVICES}
    assert "sysmain" not in names


# ----------------------------- BUG #4: cdpusersvc dedup ordem-independente -----------------------------

class _FakeSvc:
    """Mock minimalista de psutil._common.WindowsService."""
    def __init__(self, name, status):
        self._name = name
        self._status = status
    def name(self):
        return self._name
    def status(self):
        return self._status


def _patch_psutil_services(monkeypatch, fake_list):
    monkeypatch.setattr(ss, "HAS_PSUTIL", True)
    monkeypatch.setattr("psutil.win_service_iter", lambda: iter(fake_list))


def test_cdpusersvc_running_first_then_stopped_not_flagged(monkeypatch):
    """REGRESSÃO BUG #4: se a iteração vê uma instância RUNNING antes de uma
    STOPPED, a stopped NÃO pode virar flag (havia bug ordem-dependente)."""
    fake = [
        _FakeSvc("cdpusersvc_1abc", "running"),
        _FakeSvc("cdpusersvc_2def", "stopped"),
    ]
    _patch_psutil_services(monkeypatch, fake)
    stopped = ss._list_stopped_services()
    assert ss.CDPUSER_PREFIX not in stopped, (
        "cdpusersvc com 1 running + 1 stopped NÃO deve flaggar — "
        "Win10/11 normalmente tem múltiplas instâncias")


def test_cdpusersvc_all_stopped_flags(monkeypatch):
    """Inverso: TODAS instâncias paradas = flagga (é o sinal real)."""
    fake = [
        _FakeSvc("cdpusersvc_1abc", "stopped"),
        _FakeSvc("cdpusersvc_2def", "stopped"),
    ]
    _patch_psutil_services(monkeypatch, fake)
    stopped = ss._list_stopped_services()
    assert ss.CDPUSER_PREFIX in stopped


def test_cdpusersvc_no_instances_observed_not_flagged(monkeypatch):
    """PC que não tem cdpusersvc instalado = ausência ≠ parado. Não flagga."""
    _patch_psutil_services(monkeypatch, [_FakeSvc("foobar", "running")])
    stopped = ss._list_stopped_services()
    assert ss.CDPUSER_PREFIX not in stopped


def test_cdpusersvc_stopped_first_then_running_not_flagged(monkeypatch):
    """Mesma garantia, mas ordem inversa: stopped primeiro, depois running.
    Ainda assim NÃO flagga (passe duplo é ordem-independente)."""
    fake = [
        _FakeSvc("cdpusersvc_1abc", "stopped"),
        _FakeSvc("cdpusersvc_2def", "running"),
    ]
    _patch_psutil_services(monkeypatch, fake)
    stopped = ss._list_stopped_services()
    assert ss.CDPUSER_PREFIX not in stopped
