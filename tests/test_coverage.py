"""Cobertura + promoção LIMPO → INCONCLUSIVO."""

import scan_coverage as coverage_mod
import fp_filter


def _finding(name, status="clean", items=None, error=None):
    return {
        "name": name,
        "status": status,
        "items": items or [],
        "error": error,
        "summary": error or "",
    }


def test_build_coverage_flags_no_admin():
    findings = [_finding("prefetch", "error", error="Access denied")]
    cov = coverage_mod.build_coverage(findings, is_admin=False)
    assert cov["incomplete"] is True
    assert cov["blind_strong"] is True
    assert any("administrador" in r.lower() or "admin" in r.lower() for r in cov["reasons"])


def test_build_coverage_quick_mode():
    cov = coverage_mod.build_coverage([], is_admin=True, quick=True)
    assert cov["incomplete"] is True
    assert any("quick" in r.lower() for r in cov["reasons"])


def test_apply_coverage_promotes_limpo_to_inconclusive():
    verdict = {"verdict": "LIMPO", "score": 0, "color": "green"}
    cov = coverage_mod.build_coverage([], is_admin=False)
    out = coverage_mod.apply_coverage_to_verdict(verdict, cov)
    assert out["verdict"] == "INCONCLUSIVO"
    assert out["inconclusive"] is True


def test_apply_coverage_keeps_cheater():
    verdict = {"verdict": "CHEATER CONFIRMADO", "score": 99}
    cov = coverage_mod.build_coverage([], is_admin=False)
    out = coverage_mod.apply_coverage_to_verdict(verdict, cov)
    assert out["verdict"] == "CHEATER CONFIRMADO"
    assert not out.get("inconclusive")


def test_error_status_survives_fp_filter():
    findings = [
        _finding("amcache", "error", items=[], error="Access denied"),
        _finding(
            "browser",
            "suspicious",
            items=[{
                "label": "hit",
                "detail": "x",
                "severity": "low",
                "matched": "solara",
                "timestamp": "",
            }],
        ),
    ]
    out, stats = fp_filter.post_process_findings(findings)
    err = next(f for f in out if f["name"] == "amcache")
    assert err["status"] == "error"
    assert stats.get("n_error_scanners", 0) >= 1


def test_compute_verdict_tracks_error_scanners():
    findings = [
        _finding("prefetch", "error", error="nope"),
        _finding("x", "clean", items=[]),
    ]
    v = fp_filter.compute_verdict(findings)
    assert v["n_error_scanners"] >= 1
    assert "prefetch" in v["sources_with_errors"]
