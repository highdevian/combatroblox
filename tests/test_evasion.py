"""
Testes de evasão de ban e contas alt:
  - Gerenciadores de alt / multi-instância (RAM, MultiBloxy, Multi Roblox…)
  - HWID spoofers (burlar ban de hardware do Hyperion/Byfron)

Garante detecção E ausência de FP em ferramentas legítimas (FPS Unlocker,
Bloxstrap, Fishstrap) e palavras comuns ("alt", "multi", "smbios").
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import matching   # noqa: E402
import database   # noqa: E402


def setup_module(_):
    matching.invalidate()


# ============================ Alt managers / multi-instância ============================

def test_alt_managers_detected_medium():
    cases = ["Roblox Account Manager.exe", "rbx account manager", "alt manager",
             "MultiBloxy", "multi roblox", "multirblx", "roblox multi instance",
             "rbxmulti.exe", "multi account manager"]
    for c in cases:
        kw, sev = matching.match_keyword(c)
        assert kw is not None, f"NÃO detectou: {c!r}"
        assert sev in ("medium", "high")


def test_account_manager_upgraded_from_low():
    """RAM estava como 'low' (sub-avaliado). Agora deve ser medium."""
    assert database.EXECUTOR_KEYWORDS.get("roblox account manager") == "medium"


# ============================ HWID spoofers ============================

def test_hwid_spoofers_detected_high():
    # keywords (com espaço) — process names colados (robloxspoofer.exe) são
    # cobertos por test_spoofer_process_names_present, não por match_keyword.
    cases = ["hwid changer", "serial spoofer", "smbios spoofer", "mac spoofer",
             "byfron spoofer", "hyperion spoofer", "roblox spoofer",
             "exodus spoofer", "HWID Changer.exe"]
    for c in cases:
        kw, sev = matching.match_keyword(c)
        assert kw is not None, f"NÃO detectou spoofer: {c!r}"
        assert sev == "high", f"{c!r} devia ser high (ban evasion)"


def test_spoofer_process_names_present():
    for name in ["hwidchanger.exe", "byfronspoofer.exe", "robloxspoofer.exe",
                 "multibloxy.exe", "roblox account manager.exe"]:
        assert name in database.EXECUTOR_PROCESS_NAMES, f"{name} faltando"


# ============================ FP: legítimos NÃO podem casar ============================

LEGIT_AND_COMMON = [
    "roblox fps unlocker",       # tool legítimo de FPS
    "rbxfpsunlocker.exe",
    "bloxstrap.exe",             # bootstrapper legítimo (open-source)
    # "fishstrap" REMOVIDO — descoberto em 07/2026 como wrapper do Winter
    # Bypass. Agora está em EXECUTOR_KEYWORDS + EXECUTOR_PROCESS_NAMES e
    # DEVE casar (test_fishstrap_matches abaixo).
    "my alt account on discord", # "alt" comum, não é "alt manager"
    "steam multi instance",      # multi-instance de OUTRO jogo, não Roblox
    "altair.exe",                # nome que contém "alt"
    "multimedia player",         # contém "multi"
    "smbios info tool",          # "smbios" sem "spoofer"
    "default account settings",  # "account" comum
]


def test_legit_and_common_terms_no_false_positive():
    for t in LEGIT_AND_COMMON:
        kw, sev = matching.match_keyword(t)
        assert kw is None, f"FALSO POSITIVO: {t!r} casou com {kw!r}"


def test_fishstrap_matches_after_winter_bypass_ioc():
    """Fishstrap é o wrapper do Winter Bypass — DEVE casar (IoC 07/2026)."""
    for t in ("fishstrap", "fishstrap.exe", "winter bypass",
              "C:\\Users\\u\\AppData\\Local\\Fishstrap\\Fishstrap.exe"):
        kw, sev = matching.match_keyword(t)
        assert kw is not None, f"Winter/Fishstrap deveria casar: {t!r}"
        assert sev == "high", f"Winter/Fishstrap deveria ser HIGH: {t!r} -> {sev}"
