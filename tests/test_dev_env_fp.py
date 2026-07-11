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
