"""Sidebar HTML ignora meta_only nos badges."""
import report


def test_sidebar_badge_ignores_meta_only():
    findings = [
        {
            "name": "DLL Injection (Roblox)",
            "status": "clean",
            "items": [
                {"label": "roblox", "severity": "low", "matched": "roblox-running",
                 "meta_only": True, "detail": "", "timestamp": ""},
                {"label": "roblox2", "severity": "low", "matched": "roblox-running",
                 "meta_only": True, "detail": "", "timestamp": ""},
            ],
        },
        {
            "name": "Prefetch",
            "status": "suspicious",
            "items": [
                {"label": "solara", "severity": "high", "matched": "solara",
                 "meta_only": False, "detail": "", "timestamp": ""},
            ],
        },
    ]
    html = report._render_sidebar(findings, {"score": 1, "color": "#f00"})
    # DLL Injection NÃO tem badge numérico
    assert "DLL Injection" in html
    assert 'nav-badge">2</span>' not in html
    # Prefetch TEM badge 1
    assert "Prefetch" in html
    assert 'nav-badge">1</span>' in html


def test_section_opens_only_for_real_hits():
    finding = {
        "name": "Allowlist de domínios confiáveis",
        "description": "x",
        "status": "clean",
        "summary": "1 item(s) de contexto (informativo, sem hit real)",
        "items": [
            {"label": "15 dominios", "severity": "low", "matched": "trusted-domains-active",
             "meta_only": True, "detail": "x", "timestamp": ""},
        ],
        "error": None,
    }
    html = report._render_section(finding)
    # details sem open (só meta)
    assert "<details open" not in html
    assert "status-clean" in html
