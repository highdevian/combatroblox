"""
Testes de deteccao v3.53 — novos IoCs 2026 (HWID spoofers modernos, KMS
activators, mais Winter Bypass paths) + anti-FP em peripherals.
"""

import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ============================================================
# HWID spoofers 2026 (BE-Kit / Naza / Zerotwo / etc)
# ============================================================

class TestHwidSpoofers2026:

    def _match(self, text):
        from matching import invalidate, match_keyword
        invalidate()
        return match_keyword(text)

    def test_bekit_matches(self):
        kw, sev = self._match(r"C:\Users\u\Downloads\BE-Kit v2.exe")
        assert kw and sev == "high", f"BE-Kit deveria matchar HIGH: {kw!r} ({sev})"

    def test_naza_hwid_matches(self):
        kw, sev = self._match("naza hwid v3")
        assert kw and sev == "high"

    def test_insane_bypass_matches(self):
        kw, sev = self._match("Insane Bypass 2026 by user")
        assert kw and sev == "high"

    def test_zerotwo_hwid_matches(self):
        kw, sev = self._match("ZeroTwo HWID")
        assert kw and sev == "high"

    def test_koshun_matches(self):
        kw, sev = self._match("Koshun HWID Spoofer")
        assert kw and sev == "high"

    def test_hwspoof_matches(self):
        kw, sev = self._match(r"C:\hwspoof.exe")
        assert kw and sev == "high"

    def test_hwid_bypass_generic_matches(self):
        kw, sev = self._match("HWID Bypass Tool for Roblox")
        assert kw and sev == "high"

    def test_temp_spoofer_matches(self):
        kw, sev = self._match("Temp Spoofer Bypass Hyperion")
        assert kw and sev == "high"

    def test_perm_spoofer_matches(self):
        kw, sev = self._match("Perm Spoofer 2026")
        assert kw and sev == "high"

    def test_zerotwo_anime_no_fp(self):
        """Regressao: 'zerotwo' sozinho (personagem anime) nao deve casar."""
        kw, sev = self._match("zerotwo anime wallpaper by darling")
        assert kw is None, f"FP: {kw}"

    def test_insane_skills_no_fp(self):
        """Regressao: 'insane' generico nao deve casar."""
        kw, sev = self._match("insane skills montage 2026")
        assert kw is None


# ============================================================
# KMS activators (Windows pirata) — LOW severity, contexto
# ============================================================

class TestKmsActivators:

    def _match(self, text):
        from matching import invalidate, match_keyword
        invalidate()
        return match_keyword(text)

    def test_kmsauto_low(self):
        kw, sev = self._match("KMSAuto Net 2.0")
        assert kw == "kmsauto"
        assert sev == "low", "KMS deve ser LOW (dual-use, muita gente pirata Win)"

    def test_kmspico_low(self):
        kw, sev = self._match("kmspico.exe")
        assert kw == "kmspico"
        assert sev == "low"

    def test_hwidgen_low(self):
        kw, sev = self._match("HWIDgen 3.0")
        assert kw == "hwidgen"
        assert sev == "low"

    def test_windows_loader_low(self):
        kw, sev = self._match("Windows Loader by DAZ")
        assert kw and sev == "low"

    def test_process_names_have_kms(self):
        """Regressao: processos KMS estao em EXECUTOR_PROCESS_NAMES."""
        import database
        assert database.EXECUTOR_PROCESS_NAMES.get("kmsauto.exe") == "low"
        assert database.EXECUTOR_PROCESS_NAMES.get("kmspico.exe") == "low"
        assert database.EXECUTOR_PROCESS_NAMES.get("hwidgen.exe") == "low"


# ============================================================
# Peripherals anti-FP — G HUB instalado sozinho e contexto, nao veredict
# ============================================================

class TestPeripheralsAntiFP:
    """Ensure G HUB (and other legit gaming SW) is 'contexto', nao veredict."""

    def _run_isolated(self, mouse_dict):
        """Roda scan_mouse_software_installed com MOUSE_SOFTWARE substituido."""
        import peripherals
        from unittest.mock import patch
        # peripherals faz `from database import MOUSE_SOFTWARE` — precisa
        # patchar no namespace do peripherals, nao no database.
        with patch.object(peripherals, "MOUSE_SOFTWARE", mouse_dict), \
             patch("os.path.isdir", return_value=True), \
             patch("os.path.getmtime", return_value=0.0):
            return peripherals.scan_mouse_software_installed()

    def test_ghub_installed_is_meta_only(self):
        """G HUB instalado (sem macro com red flag) deve ser meta_only=True.
        Todo dono de Logitech G-series tem G HUB — FP em milhoes."""
        r = self._run_isolated({
            "logitech_ghub": {
                "name": "Logitech G HUB",
                "paths": [r"C:\fake\ghub"],
            }})
        assert len(r["items"]) == 1
        item = r["items"][0]
        assert item.get("meta_only") is True, \
            f"G HUB deveria ser meta_only=True (contexto), foi {item}"
        assert item["severity"] == "low"

    def test_bloody_is_not_meta_only(self):
        """Bloody (historicamente cheat-friendly) fica visivel no veredict."""
        r = self._run_isolated({
            "bloody": {
                "name": "Bloody Software",
                "paths": [r"C:\fake\bloody"],
            }})
        assert len(r["items"]) == 1
        item = r["items"][0]
        # Bloody ainda flagga (LOW), nao vira meta_only
        assert item.get("meta_only") is False
        assert item["severity"] == "low"

    def test_razer_is_meta_only(self):
        """Razer Synapse (todo dono de mouse Razer tem) e' meta_only."""
        r = self._run_isolated({
            "razer_synapse": {
                "name": "Razer Synapse",
                "paths": [r"C:\fake\razer"],
            }})
        assert len(r["items"]) == 1
        assert r["items"][0].get("meta_only") is True
