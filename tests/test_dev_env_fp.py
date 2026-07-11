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


def test_dev_env_suppresses_dualuse_fps(monkeypatch):
    """REGRESSÃO FP: dual-use do supervisor some no PC de dev.
    TinyTask, Process Hacker, AutoClicker, exclusão portfolio/JetBrains."""
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
        # executor real NÃO some
        {"label": "solara.exe", "detail": "x", "severity": "high",
         "matched": "solara", "timestamp": ""},
    ]
    findings = [{"name": "mix", "status": "suspicious", "summary": "n", "items": items}]
    out, stats = fp_filter.post_process_findings(findings)
    remaining = {(it.get("matched") or "").lower() for it in out[0]["items"]}
    assert "tinytask" not in remaining
    assert "process hacker" not in remaining
    assert "system informer" not in remaining
    assert "autoclicker" not in remaining
    assert "exclusao-pasta-usuario" not in remaining
    assert "exclusao-dev" not in remaining
    assert "solara" in remaining
    assert stats["items_whitelisted"] >= 6


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
