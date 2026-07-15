"""
Testes da detecção de autoclickers / macros standalone.

O usuário pediu: "encontrar todos tipos de macros... se o cara usou
autoclicker no jogo". Estes garantem que as ferramentas de autoclique/macro
são detectadas (em qualquer fonte forense via keyword/process match) E que
palavras inocentes não disparam FP.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from telador import matching   # noqa: E402
from telador import database   # noqa: E402
def setup_module(_):
    # garante que as keywords novas estão compiladas
    matching.invalidate()


# ============================ Autoclickers PEGAM ============================

AUTOCLICKER_SAMPLES = [
    "op autoclicker",
    "OPAutoClicker.exe",
    "Speed AutoClicker.exe",
    "speedautoclicker",
    r"C:\Users\x\Downloads\GSAutoClicker.exe",
    "TinyTask.exe",
    "Mouse Recorder Pro",
    "macro recorder",
    "Pulover's Macro Creator",
    "MurGee auto clicker",
    "mini mouse macro",
    "perfect automation",
]


def test_autoclicker_tools_are_detected():
    for sample in AUTOCLICKER_SAMPLES:
        kw, sev = matching.match_keyword(sample)
        assert kw is not None, f"NÃO detectou autoclicker/macro: {sample!r}"
        assert sev in ("medium", "high")


def test_roblox_specific_macro_is_high():
    for sample in ["roblox auto clicker", "Roblox Autoclicker", "auto farm macro"]:
        kw, sev = matching.match_keyword(sample)
        assert kw is not None
        assert sev == "high", f"{sample!r} devia ser high (Roblox-específico)"


def test_autoclicker_in_process_names():
    for name in ["opautoclicker.exe", "speedautoclicker.exe", "tinytask.exe",
                 "macrorecorder.exe", "autoclicker.exe"]:
        assert name in database.EXECUTOR_PROCESS_NAMES, f"{name} faltando em process names"
        assert database.EXECUTOR_PROCESS_NAMES[name] in ("medium", "high")


# ============================ FP: palavras inocentes NÃO pegam ============================

INNOCENT_SAMPLES = [
    "microsoft autoupdate",
    "fast and furious.mp4",
    "my macros folder",
    "autocad.exe",
    "clickteam fusion",
    "macromedia flash",
    "clicker heroes",          # jogo legítimo
    r"C:\Program Files\AutoCAD 2024\acad.exe",
]


def test_innocent_terms_do_not_false_positive():
    for sample in INNOCENT_SAMPLES:
        kw, sev = matching.match_keyword(sample)
        assert kw is None, f"FALSO POSITIVO: {sample!r} casou com {kw!r}"


# ============================ Conteúdo de macro (red flags) ============================

def test_macro_content_red_flags_present():
    """As red flags de CONTEÚDO de macro (no recoil, auto click, etc) seguem
    cobertas — complementam a detecção por nome de ferramenta."""
    for flag in ["no recoil", "auto click", "rapid fire", "auto headshot"]:
        assert flag in database.MACRO_RED_FLAGS
