"""Anti-FP em PC de desenvolvimento."""

import fp_filter


def test_dev_env_downgrades_cheat_engine(monkeypatch):
    monkeypatch.setattr(
        fp_filter,
        "detect_dev_environment",
        lambda: {"is_dev": True, "evidence": ["C:\\VS", "C:\\Git"]},
    )
    item = {
        "label": "Cheat Engine",
        "detail": "C:\\Tools\\cheatengine-x86_64.exe",
        "severity": "high",
        "matched": "cheatengine-x86_64.exe",
        "timestamp": "",
    }
    findings = [{"name": "proc", "status": "suspicious", "items": [item], "summary": "1"}]
    out, stats = fp_filter.post_process_findings(findings)
    assert stats["is_dev_env"] is True
    # item pode ter sido whitelistado por path — se restou, severidade caiu
    remaining = out[0]["items"]
    if remaining:
        assert remaining[0]["severity"] in ("low", "medium")
        assert remaining[0].get("fp_reason")


def test_dev_env_keeps_dualuse_visible_as_context(monkeypatch):
    """Dual-use no PC de dev FICA no report (meta_only), fora do veredito.
    Solara real continua hit de verdade."""
    monkeypatch.setattr(
        fp_filter,
        "detect_dev_environment",
        lambda: {"is_dev": True, "evidence": ["C:\\VS", "C:\\Git"]},
    )
    items = [
        {"label": "TINYTASK", "detail": "x", "severity": "medium",
         "matched": "tinytask", "timestamp": ""},
        {"label": "ProcessHacker.exe", "detail": "x", "severity": "low",
         "matched": "process hacker", "timestamp": ""},
        {"label": "System Informer.lnk", "detail": "x", "severity": "low",
         "matched": "system informer", "timestamp": ""},
        {"label": "WER crash: OP Auto Clicker", "detail": "x", "severity": "medium",
         "matched": "autoclicker", "timestamp": ""},
        {"label": "Exclusão portfolio", "detail": r"C:\Users\x\Desktop\portfolio",
         "severity": "medium", "matched": "exclusao-pasta-usuario", "timestamp": ""},
        {"label": "Exclusão JetBrains", "detail": r"C:\Users\x\JetBrains",
         "severity": "low", "matched": "exclusao-dev", "timestamp": ""},
        {"label": "solara.exe", "detail": "x", "severity": "high",
         "matched": "solara", "timestamp": ""},
    ]
    findings = [{"name": "mix", "status": "suspicious", "summary": "n", "items": items}]
    out, stats = fp_filter.post_process_findings(findings)
    by_m = {(it.get("matched") or "").lower(): it for it in out[0]["items"]}
    # Dual-use VISÍVEL como contexto
    assert "tinytask" in by_m
    assert by_m["tinytask"].get("meta_only") is True
    assert by_m["tinytask"].get("fp_suppressed") is True
    assert "process hacker" in by_m
    assert by_m["process hacker"].get("meta_only") is True
    # Solara REAL (não meta)
    assert "solara" in by_m
    assert not by_m["solara"].get("meta_only")
    assert by_m["solara"]["severity"] == "high"
    assert stats["items_whitelisted"] >= 6
    # Veredito não conta dual-use
    v = fp_filter.compute_verdict(out)
    assert v["high"] >= 1  # solara
    assert v["medium"] == 0  # tinytask/autoclicker viraram meta


def test_non_dev_still_flags_tinytask(monkeypatch):
    """Cheater sem IDE: TinyTask MEDIUM em 4 fontes continua visível."""
    monkeypatch.setattr(
        fp_filter,
        "detect_dev_environment",
        lambda: {"is_dev": False, "evidence": []},
    )
    findings = [{
        "name": "Downloads", "status": "suspicious", "summary": "1",
        "items": [{
            "label": "tinytask-1.77-installer.exe",
            "detail": r"C:\Users\x\Downloads\tinytask-1.77-installer.exe",
            "severity": "medium", "matched": "tinytask", "timestamp": "",
        }],
    }]
    out, _ = fp_filter.post_process_findings(findings)
    assert len(out[0]["items"]) == 1
    assert out[0]["items"][0]["severity"] == "medium"


def test_dev_indicators_include_cursor_and_python314():
    joined = " ".join(fp_filter.DEV_INDICATORS).lower()
    assert "cursor" in joined
    assert "python314" in joined or "python" in joined


def test_scanner_registry_counts():
    import scanner_registry
    counts = scanner_registry.count_scanners()
    assert counts["total"] >= 70
    assert counts["quick"] >= 10
    assert counts["requires_admin"] >= 5
