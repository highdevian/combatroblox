"""Sidebar HTML ignora meta_only nos badges."""
from telador import report
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


def test_sidebar_signals_dual_use_context():
    """Dual-use dev (fp_suppressed) DEVE aparecer no sidebar como nav-context
    com badge cinza — supervisor precisa ver que há items pra clicar."""
    findings = [{
        "name": "Adulteração do Windows Defender",
        "status": "clean",
        "items": [
            {"label": "Exclusão portfolio", "severity": "low",
             "matched": "exclusao-pasta-usuario", "meta_only": True,
             "fp_suppressed": True, "detail": "", "timestamp": ""},
            {"label": "Exclusão JetBrains", "severity": "low",
             "matched": "exclusao-dev", "meta_only": True,
             "fp_suppressed": True, "detail": "", "timestamp": ""},
        ],
    }]
    html = report._render_sidebar(findings, {"score": 0, "color": "#0f0"})
    assert "Adulteração do Windows Defender" in html
    assert "nav-context" in html
    assert 'nav-badge">2</span>' in html


def test_section_shows_context_items_with_contexto_badge():
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
    # contexto aparece na tabela
    assert "15 dominios" in html
    assert "CONTEXTO" in html or "status-clean" in html
    assert "info" in html
