"""
Matching central de keywords de executor.

Usa WORD-BOUNDARY em vez de substring puro. Diferença prática:

    substring:      "argon" casa "argonauts" (jogo), "trigon" casa "trigonometria"
    word-boundary:  "argon" casa "argon.exe", "/argon/", "argon-x" — mas NÃO
                    casa "argonauts", "darkargon", "scriptwarehouse"...

Reduz falsos positivos de tokens que são substring de palavras maiores,
sem perder detecção de nome real de executor (que sempre vem delimitado
por separador: ponto, barra, espaço, hífen, fim de string).

Mantém a mesma interface/ordem do antigo `_match_keyword`: retorna o
PRIMEIRO match na ordem de inserção de EXECUTOR_KEYWORDS.
"""

import re

from database import EXECUTOR_KEYWORDS

_PATTERNS = None


def _compile():
    """Compila um pattern word-boundary por keyword (uma vez, cacheado)."""
    global _PATTERNS
    pats = []
    for kw, sev in EXECUTOR_KEYWORDS.items():
        if not kw:
            continue
        esc = re.escape(kw)
        # \b só faz sentido quando a borda do keyword é alfanumérica. Se o
        # keyword começa/termina com símbolo (ex.: ".exe" hipotético), a borda
        # vira substring naquele lado — comportamento correto.
        pre = r"\b" if kw[0].isalnum() else ""
        suf = r"\b" if kw[-1].isalnum() else ""
        pats.append((re.compile(pre + esc + suf, re.IGNORECASE), kw, sev))
    _PATTERNS = pats
    return pats


def invalidate():
    """Descarta o cache de patterns. Chamar após mexer em EXECUTOR_KEYWORDS
    (ex.: depois de mesclar signatures.json) pra forçar recompilação."""
    global _PATTERNS
    _PATTERNS = None


def match_keyword(text):
    """Retorna (keyword, severity) do primeiro match, ou (None, None)."""
    if not text:
        return None, None
    pats = _PATTERNS if _PATTERNS is not None else _compile()
    for pat, kw, sev in pats:
        if pat.search(text):
            return kw, sev
    return None, None


def domain_in_text(domain: str, text: str) -> bool:
    """
    True se `domain` aparece em `text` como domínio DE VERDADE — não como
    pedaço de um domínio maior.

    Casa:   "wave.gg", "wave.gg/x", "https://wave.gg", "sub.wave.gg"
    NÃO casa: "soundwave.gg", "wave.ggames.com"

    Regra: a ocorrência precisa ter fronteira nos dois lados. À esquerda,
    o char anterior não pode ser alfanumérico nem hífen (senão é parte de
    um label maior tipo "sound-wave"); um ponto à esquerda é OK (subdomínio).
    À direita, o char seguinte não pode ser alfanumérico (senão é outro TLD,
    tipo ".ggames").
    """
    if not domain or not text:
        return False
    dlow = domain.lower()
    tlow = text.lower()
    start = 0
    n = len(dlow)
    while True:
        i = tlow.find(dlow, start)
        if i == -1:
            return False
        left_ok = (i == 0) or not (tlow[i - 1].isalnum() or tlow[i - 1] == "-")
        j = i + n
        right_ok = (j >= len(tlow)) or not tlow[j].isalnum()
        if left_ok and right_ok:
            return True
        start = i + 1
