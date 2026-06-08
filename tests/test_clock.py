"""
Testes da detecção de manipulação do relógio (clock_tampering.py).

Foco: parsing de hora, a decisão de salto-pra-trás (núcleo), o parse do XML do
wevtutil, os mocks de scan, e a integração com o Confidence Engine.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import clock_tampering as ct  # noqa: E402


def test_parse_iso_variants():
    assert ct._parse_iso("2026-06-08T17:00:00Z") is not None
    assert ct._parse_iso("2026-06-08T17:00:00.000000000Z") is not None
    assert ct._parse_iso("lixo") is None
    assert ct._parse_iso("") is None


def test_clock_item_backward_big_high():
    it = ct._clock_item("2026-06-08T20:00:00Z", "2026-06-08T17:00:00Z", "gabri", "x")
    assert it is not None
    assert it["severity"] == "high"          # 3h pra trás
    assert it["matched"] == "clock-rollback"


def test_clock_item_backward_medium():
    it = ct._clock_item("2026-06-08T20:00:00Z", "2026-06-08T19:30:00Z", "gabri")
    assert it is not None
    assert it["severity"] == "medium"        # 30 min pra trás


def test_clock_item_forward_ignored():
    # salto pra frente (NTP/bateria) = não é o ataque
    assert ct._clock_item("2026-06-08T17:00:00Z", "2026-06-08T20:00:00Z") is None


def test_clock_item_small_jump_ignored():
    # < 10 min = drift normal
    assert ct._clock_item("2026-06-08T20:00:00Z", "2026-06-08T19:55:00Z") is None


def test_clock_item_unparseable_none():
    assert ct._clock_item("lixo", "tambem lixo") is None


def test_parse_4616_xml():
    ns = "http://schemas.microsoft.com/win/2004/08/events/event"
    one = (
        f"<Event xmlns='{ns}'><System><EventID>4616</EventID></System>"
        "<EventData>"
        "<Data Name='SubjectUserName'>gabri</Data>"
        "<Data Name='SubjectUserSid'>S-1-5-21-111-222-333-1001</Data>"
        "<Data Name='PreviousTime'>2026-06-08T20:00:00.000000000Z</Data>"
        "<Data Name='NewTime'>2026-06-08T17:00:00.000000000Z</Data>"
        "<Data Name='ProcessName'>C:\\Windows\\System32\\svchost.exe</Data>"
        "</EventData></Event>"
    )
    evs = ct._parse_4616_xml(one + one)
    assert len(evs) == 2
    assert evs[0]["subject"] == "gabri"
    assert evs[0]["sid"] == "S-1-5-21-111-222-333-1001"
    assert evs[0]["prev"].startswith("2026-06-08T20:00")
    assert evs[0]["new"].startswith("2026-06-08T17:00")


# ============== FP: correção de relógio por serviço (NTP/dual-boot) ==============

def test_service_sid_backward_jump_is_low_context():
    """REGRESSÃO FP: salto pra trás por LOCAL SERVICE (S-1-5-19 = W32Time/NTP)
    ou SYSTEM (S-1-5-18 = correção de boot/dual-boot) é o SO, não o usuário.
    Deve virar LOW contexto, não MEDIUM/HIGH."""
    for sid in ("S-1-5-19", "S-1-5-18", "S-1-5-20"):
        it = ct._clock_item("2026-06-08T20:00:00Z", "2026-06-08T17:00:00Z",
                            "SERVIÇO LOCAL", "C:\\Windows\\System32\\svchost.exe", sid)
        assert it is not None
        assert it["severity"] == "low", f"sid {sid} deveria ser low"
        assert it["matched"] == "clock-rollback-servico"


def test_service_classification_is_locale_independent():
    """O subject vem localizado ('SERVIÇO LOCAL' em PT-BR). A classificação
    NÃO pode depender do nome — só do SID. Subject em qualquer idioma + SID de
    serviço = low."""
    it = ct._clock_item("2026-06-08T20:00:00Z", "2026-06-08T18:00:00Z",
                        "qualquer-nome-localizado", "svchost.exe", "S-1-5-19")
    assert it["severity"] == "low"


def test_svchost_fallback_when_sid_missing():
    """Sem SID no evento, svchost.exe como processo = pista de serviço → low."""
    it = ct._clock_item("2026-06-08T20:00:00Z", "2026-06-08T17:00:00Z",
                        "", "C:\\Windows\\System32\\svchost.exe", "")
    assert it["severity"] == "low"
    assert it["matched"] == "clock-rollback-servico"


def test_interactive_user_backward_jump_stays_high():
    """Não pode regredir: usuário interativo (SID S-1-5-21-…) voltando o relógio
    é o anti-bypass real — continua HIGH/MEDIUM."""
    it = ct._clock_item("2026-06-08T20:00:00Z", "2026-06-08T17:00:00Z",
                        "gabri", "C:\\Windows\\System32\\SystemSettingsAdminFlows.exe",
                        "S-1-5-21-111-222-333-1001")
    assert it["severity"] == "high"
    assert it["matched"] == "clock-rollback"


def test_is_service_actor_helper():
    assert ct._is_service_actor("S-1-5-19", "") is True
    assert ct._is_service_actor("s-1-5-18", "qualquer.exe") is True
    assert ct._is_service_actor("S-1-5-21-1-2-3-1001", "svchost.exe") is False  # user SID manda
    assert ct._is_service_actor("", "C:\\Windows\\System32\\svchost.exe") is True
    assert ct._is_service_actor("", "cmd.exe") is False


def test_scan_flags_rollback(monkeypatch):
    monkeypatch.setattr(ct, "_query_4616", lambda: [
        {"prev": "2026-06-08T20:00:00Z", "new": "2026-06-08T17:00:00Z",
         "subject": "gabri", "process": "x"}])
    r = ct.scan_clock_tampering()
    assert r["status"] == "suspicious"
    assert r["items"][0]["severity"] == "high"


def test_scan_clean_on_forward_only(monkeypatch):
    monkeypatch.setattr(ct, "_query_4616", lambda: [
        {"prev": "2026-06-08T17:00:00Z", "new": "2026-06-08T20:00:00Z",
         "subject": "SYSTEM", "process": "svchost.exe"}])
    r = ct.scan_clock_tampering()
    assert r["status"] == "clean"


def test_scan_clean_when_no_events(monkeypatch):
    monkeypatch.setattr(ct, "_query_4616", lambda: [])
    assert ct.scan_clock_tampering()["status"] == "clean"


def test_scan_error_when_no_access(monkeypatch):
    monkeypatch.setattr(ct, "_query_4616", lambda: None)
    assert ct.scan_clock_tampering()["status"] == "error"


def test_real_machine_no_crash():
    r = ct.scan_clock_tampering()
    assert r["status"] in ("clean", "suspicious", "error")
    for it in r["items"]:
        assert it["severity"] in ("low", "medium", "high")


def test_slug_and_cluster():
    import evidence as ev
    assert ev._source_slug_from_name("Manipulação do relógio do sistema") == "clock_tampering"
    findings = [{
        "name": "Manipulação do relógio do sistema", "status": "suspicious",
        "items": [{"label": "Relógio voltado 3h pra trás", "detail": "x",
                   "matched": "clock-rollback", "severity": "high",
                   "timestamp": "", "confidence": 60}],
    }]
    cl = ev.build_clusters(ev.findings_to_evidences(findings))
    assert len(cl) == 1
    assert cl[0].verdict != "CONFIRMED"
