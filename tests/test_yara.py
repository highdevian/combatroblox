"""
Testes do scanner de assinatura binária estilo YARA (scan_yara_binaries).

Prova:
  - A engine pura (_count_matches / _match_rules): conta padrões ASCII e UTF-16,
    e a condição N-de-N decide.
  - As regras built-in: binário com a API de exploit Luau -> HIGH; combo de
    injeção -> MEDIUM; binário comum -> nada.
  - O scanner: PEGA o PE casado, mas DESCARTA quando é o próprio telador, quando
    o arquivo é assinado, e quando não é PE (sem header MZ).
  - Integração: registrado, roteia p/ yara_signature, alimenta o cluster engine.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from telador import yara_scan as ys  # noqa: E402
def _exploit_blob(n=8):
    """PE falso com N símbolos da regra de exploit Luau."""
    syms = ys.BUILTIN_RULES[0]["strings"][:n]
    return b"MZ" + b"\x00" * 64 + b"".join(s + b"\x00" for s in syms)


def _injector_blob(n=6):
    syms = ys.BUILTIN_RULES[1]["strings"][:n]
    return b"MZ" + b"\x00" * 64 + b"".join(s + b"\x00" for s in syms)


# ----------------------------- engine pura -----------------------------

def test_count_matches_ascii():
    data = b"foo getrawmetatable bar hookmetamethod baz"
    assert ys._count_matches(data, [b"getrawmetatable", b"hookmetamethod",
                                    b"ausente"]) == 2


def test_count_matches_utf16():
    """Wide string (UTF-16LE) também conta."""
    data = "hookfunction".encode("utf-16le")
    assert ys._count_matches(data, [b"hookfunction"]) == 1


def test_match_rules_exploit_rule_fires():
    rules = ys._match_rules(_exploit_blob(8), ys.BUILTIN_RULES)
    names = {r["matched"] for r in rules}
    assert "yara:executor-luau-api" in names


def test_match_rules_below_threshold_silent():
    """Poucos símbolos (< min_matches) não disparam — anti-FP."""
    blob = b"MZ" + b"getgenv getrenv"  # só 2 da regra que pede 6
    assert ys._match_rules(blob, ys.BUILTIN_RULES) == []


def test_injector_rule_is_medium():
    rules = ys._match_rules(_injector_blob(6), ys.BUILTIN_RULES)
    inj = [r for r in rules if r["matched"] == "yara:injector-toolmarks"]
    assert inj and inj[0]["severity"] == "medium"


# ----------------------------- scanner (mockado) -----------------------------

def _patch(monkeypatch, files: dict, signed=None, self_paths=()):
    """files: path -> bytes. signed: path -> True/False/None."""
    monkeypatch.setattr(ys, "_iter_candidate_files", lambda: iter(files.keys()))
    monkeypatch.setattr(ys, "_read_bytes", lambda p, cap: files.get(p, b""))
    monkeypatch.setattr(ys, "_is_signed",
                        lambda p: (signed or {}).get(p))
    monkeypatch.setattr(ys, "_is_self", lambda p: p in self_paths)


def test_scanner_flags_unsigned_executor(monkeypatch):
    path = r"C:\Users\x\Downloads\trabalho.exe"
    _patch(monkeypatch, {path: _exploit_blob(8)}, signed={path: False})
    r = ys.scan_yara_binaries()
    assert r["status"] == "suspicious"
    assert len(r["items"]) == 1
    it = r["items"][0]
    assert it["severity"] == "high"
    assert it["matched"] == "yara:executor-luau-api"
    assert "trabalho.exe" in it["label"]


def test_scanner_skips_signed_app(monkeypatch):
    """App VALIDAMENTE assinado que casou = legítimo -> descarta."""
    path = r"C:\Users\x\Downloads\legit.exe"
    _patch(monkeypatch, {path: _exploit_blob(8)}, signed={path: True})
    assert ys.scan_yara_binaries()["status"] == "clean"


def test_scanner_skips_self(monkeypatch):
    """O próprio telador.exe embute os símbolos — nunca se auto-flagga."""
    path = r"C:\Users\x\Downloads\telador.exe"
    _patch(monkeypatch, {path: _exploit_blob(8)}, signed={path: False},
           self_paths=(path,))
    assert ys.scan_yara_binaries()["status"] == "clean"


def test_scanner_skips_non_pe(monkeypatch):
    """Sem header MZ não é PE -> nem roda regra (perf + anti-FP)."""
    path = r"C:\Users\x\Downloads\notes.exe"
    blob = b"PK" + b"getrawmetatable hookmetamethod newcclosure checkcaller " \
           b"iscclosure islclosure getnamecallmethod"
    _patch(monkeypatch, {path: blob}, signed={path: False})
    assert ys.scan_yara_binaries()["status"] == "clean"


def test_scanner_clean_on_benign_pe(monkeypatch):
    path = r"C:\Users\x\Downloads\app.exe"
    _patch(monkeypatch, {path: b"MZ" + b"\x00" * 200 + b"hello world"},
           signed={path: None})
    assert ys.scan_yara_binaries()["status"] == "clean"


def test_unknown_signature_still_flags(monkeypatch):
    """Assinatura indeterminada (None) NÃO descarta — só True descarta."""
    path = r"C:\Users\x\Downloads\x.dll"
    _patch(monkeypatch, {path: _exploit_blob(8)}, signed={path: None})
    assert ys.scan_yara_binaries()["status"] == "suspicious"


# ----------------------------- integração -----------------------------

def test_registered_in_scanner_list():
    assert ys.scan_yara_binaries in ys.ALL_YARA_SCANNERS


def test_slug_maps_to_yara_signature():
    from telador import evidence as ev
    from telador import report_assets
    assert ev._source_slug_from_name("Assinatura binária (YARA)") == "yara_signature"
    assert "yara_signature" in ev.SOURCE_WEIGHTS
    # label próprio no relatório (senão cai no fallback feio "Yara Signature")
    assert "yara_signature" in report_assets.SOURCE_LABELS


def test_feeds_cluster_engine():
    from telador import evidence as ev
    findings = [{
        "name": "Assinatura binária (YARA)",
        "status": "suspicious",
        "items": [{
            "label": "YARA: solara.exe — Executor Roblox (API de exploit Luau embutida)",
            "detail": r"C:\Users\x\Downloads\solara.exe",
            "matched": "yara:executor-luau-api", "severity": "high",
            "timestamp": "", "confidence": 85,
        }],
    }]
    clusters = ev.build_clusters(ev.findings_to_evidences(findings))
    assert len(clusters) == 1


def test_real_machine_no_crash():
    """No PC real: varre de verdade, não pode crashar; resultado válido."""
    r = ys.scan_yara_binaries()
    assert r["status"] in ("clean", "suspicious", "error")
    for it in r["items"]:
        assert it["severity"] in ("high", "medium")


# ----------------------------- regras externas (yara_rules.json) -----------------------------

def test_validate_external_rule_ok():
    rule = ys._validate_external_rule({
        "name": "Regra X", "severity": "high", "min_matches": 2,
        "strings": ["aaa", "bbb"]})
    assert rule is not None
    assert rule["strings"] == [b"aaa", b"bbb"]  # convertido pra bytes
    assert rule["severity"] == "high" and rule["min_matches"] == 2
    assert rule["matched"].startswith("yara-custom:")  # default derivado


def test_validate_external_rule_rejects_bad():
    bad = [
        {"severity": "high", "strings": ["a"]},          # sem name
        {"name": "x", "severity": "ULTRA", "strings": ["a"]},  # severity invalida
        {"name": "x", "severity": "high", "strings": []},      # strings vazio
        {"name": "x", "severity": "high", "strings": ["a"], "min_matches": 0},  # mm<1
        "nao e dict",
    ]
    for b in bad:
        assert ys._validate_external_rule(b) is None


def test_load_external_rules_from_env(tmp_path, monkeypatch):
    import json
    p = tmp_path / "yara_rules.json"
    p.write_text(json.dumps([
        {"name": "Custom", "severity": "high", "matched": "yara:custom",
         "min_matches": 1, "strings": ["MARCADORUNICO"]},
        {"name": "lixo invalido"},  # ignorada, não derruba as outras
    ]), encoding="utf-8")
    monkeypatch.setenv("TELADOR_YARA_RULES", str(p))
    rules = ys._load_external_rules()
    assert len(rules) == 1
    assert rules[0]["matched"] == "yara:custom"


def test_load_external_rules_missing_file_is_empty(monkeypatch):
    monkeypatch.setenv("TELADOR_YARA_RULES", r"Z:\nao\existe\yara_rules.json")
    assert ys._load_external_rules() == []


def test_scanner_uses_external_rules(monkeypatch):
    """Regra externa entra no scan junto das built-in."""
    custom = {"name": "Custom", "severity": "high", "matched": "yara:custom",
              "why": "marcador.", "min_matches": 1, "strings": [b"MARCADORUNICO"]}
    monkeypatch.setattr(ys, "_load_external_rules", lambda: [custom])
    path = r"C:\Users\x\Downloads\z.exe"
    _patch(monkeypatch, {path: b"MZ" + b"\x00" * 64 + b"MARCADORUNICO"},
           signed={path: False})
    r = ys.scan_yara_binaries()
    assert any(it["matched"] == "yara:custom" for it in r["items"])
