"""
Testes do diff_tool.py — comparação entre 2 SS via .tsr assinado.

Caso de uso: "esse cara já foi telado antes? veio com hits NOVOS desde a
última vez?". O .tsr é JSON + HMAC, então também testamos a integridade
(um .tsr adulterado tem que ser rejeitado).

Sem teste antes destes.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import diff_tool  # noqa: E402


def _finding(name, items):
    return {"name": name, "status": "suspicious" if items else "clean", "items": items}


def _it(label, matched, severity="high", detail="d"):
    return {"label": label, "detail": detail, "matched": matched, "severity": severity}


SYS = {"host": "PC-DO-FULANO", "user": "fulano"}


# ============================ Round-trip + integridade ============================

def test_save_and_load_roundtrip(tmp_path):
    findings = [_finding("Prefetch", [_it("solara.exe", "solara")])]
    p = str(tmp_path / "ss1.tsr")
    diff_tool.save_tsr(findings, SYS, p)
    assert os.path.isfile(p)

    payload, err = diff_tool.load_tsr(p)
    assert err is None, err
    assert payload["version"] == diff_tool.APP_VERSION
    assert payload["system"]["host"] == "PC-DO-FULANO"
    assert payload["findings"][0]["items"][0]["matched"] == "solara"


def test_load_detects_tampering(tmp_path):
    """Cheater edita o .tsr pra apagar um hit -> HMAC tem que rejeitar."""
    findings = [_finding("Prefetch", [_it("solara.exe", "solara")])]
    p = str(tmp_path / "ss.tsr")
    diff_tool.save_tsr(findings, SYS, p)

    # adultera o payload no arquivo, sem recalcular a assinatura
    with open(p, encoding="utf-8") as fh:
        wrapper = json.load(fh)
    wrapper["payload"]["findings"] = []  # apaga os hits
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(wrapper, fh)

    payload, err = diff_tool.load_tsr(p)
    assert payload is None
    assert err is not None and "HMAC" in err


def test_load_missing_file():
    payload, err = diff_tool.load_tsr("nao_existe_12345.tsr")
    assert payload is None
    assert err is not None


def test_load_bad_json(tmp_path):
    p = str(tmp_path / "lixo.tsr")
    with open(p, "w", encoding="utf-8") as fh:
        fh.write("isso não é json {{{")
    payload, err = diff_tool.load_tsr(p)
    assert payload is None
    assert err is not None


# ============================ Lógica de diff ============================

def _payload(findings, ts="2026-06-01T10:00:00", host="PC"):
    return {"timestamp": ts, "system": {"host": host}, "findings": findings}


def test_diff_detects_new_hits():
    old = _payload([_finding("Prefetch", [_it("krnl.exe", "krnl")])])
    new = _payload([_finding("Prefetch", [
        _it("krnl.exe", "krnl"),           # persistente
        _it("solara.exe", "solara"),       # NOVO
    ])])
    d = diff_tool.diff_reports(old, new)
    added_matched = [item.get("matched") for _src, item in d["added"]]
    persistent_matched = [item.get("matched") for _src, item in d["persistent"]]
    assert "solara" in added_matched
    assert "krnl" in persistent_matched
    assert len(d["added"]) == 1
    assert len(d["persistent"]) == 1


def test_diff_detects_removed_hits():
    old = _payload([_finding("Prefetch", [_it("krnl.exe", "krnl")])])
    new = _payload([_finding("Prefetch", [])])
    d = diff_tool.diff_reports(old, new)
    removed_matched = [item.get("matched") for _src, item in d["removed"]]
    assert "krnl" in removed_matched
    assert len(d["added"]) == 0


def test_diff_identical_no_changes():
    f = [_finding("Prefetch", [_it("krnl.exe", "krnl")])]
    d = diff_tool.diff_reports(_payload(f), _payload(f))
    assert len(d["added"]) == 0
    assert len(d["removed"]) == 0
    assert len(d["persistent"]) == 1


def test_diff_carries_metadata():
    old = _payload([], ts="2026-01-01T00:00:00", host="OLD-PC")
    new = _payload([], ts="2026-06-01T00:00:00", host="NEW-PC")
    d = diff_tool.diff_reports(old, new)
    assert d["old_host"] == "OLD-PC"
    assert d["new_host"] == "NEW-PC"
    assert d["old_ts"] == "2026-01-01T00:00:00"


def test_format_diff_console_runs():
    """format_diff_console não pode crashar e deve mencionar as contagens."""
    old = _payload([_finding("Prefetch", [_it("a.exe", "krnl")])])
    new = _payload([_finding("Prefetch", [_it("b.exe", "solara")])])
    d = diff_tool.diff_reports(old, new)
    out = diff_tool.format_diff_console(d)
    assert isinstance(out, str)
    assert "NOVOS" in out
    assert "solara" in out
