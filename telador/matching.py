"""
Matching central de keywords de executor.

Usa WORD-BOUNDARY em vez de substring puro. Diferença prática:

    substring:      "argon" casa "argonauts" (jogo), "trigon" casa "trigonometria"
    word-boundary:  "argon" casa "argon.exe", "/argon/", "argon-x" — mas NÃO
                    casa "argonauts", "darkargon", "scriptwarehouse"...

Reduz falsos positivos de tokens que são substring de palavras maiores,
sem perder detecção de nome real de executor (que sempre vem delimitado
por separador: ponto, barra, espaço, hífen, fim de string).

Implementação: mega-regex agrupada por (borda_esquerda, borda_direita,
severidade) — uma alternância `(kw1|kw2|…)` por grupo, ordenada por
comprimento desc (pra "synapse x" casar antes de "synapse"). Ordem de
RETORNO segue a ordem dos grupos, não mais a ordem de inserção crua de
EXECUTOR_KEYWORDS; mas é equivalente no que importa — validado contra a
implementação antiga por-keyword: 0 divergência em SE-casa e 0 em
SEVERIDADE (só muda QUAL string de keyword é reportada, p.ex. 'krnl.exe'
em vez de 'krnl', que resolve pro mesmo alias canônico).
"""

import re
import functools

from .database import EXECUTOR_KEYWORDS

_PATTERNS = None


def _compile():
    """Compila um pattern word-boundary agrupado por tipo de borda e severidade.
    Mega-regex: (kw1|kw2|kw3) roda milhares de vezes mais rápido que um loop de regexes."""
    global _PATTERNS
    groups = {}
    for kw, sev in EXECUTOR_KEYWORDS.items():
        if not kw:
            continue
        esc = re.escape(kw)
        pre = r"\b" if kw[0].isalnum() else ""
        suf = r"\b" if kw[-1].isalnum() else ""
        
        key = (pre, suf, sev)
        if key not in groups:
            groups[key] = []
        groups[key].append(esc)
        
    pats = []
    for (pre, suf, sev), kws in groups.items():
        # Sort by length descending so longer keywords match first ("synapse x" before "synapse")
        kws.sort(key=len, reverse=True)
        pattern_str = pre + r"(" + r"|".join(kws) + r")" + suf
        pats.append((re.compile(pattern_str, re.IGNORECASE), sev))
        
    _PATTERNS = pats
    return pats


def invalidate():
    """Descarta o cache de patterns. Chamar após mexer em EXECUTOR_KEYWORDS
    (ex.: depois de mesclar signatures.json) pra forçar recompilação."""
    global _PATTERNS
    _PATTERNS = None


def match_keyword(text):
    """Retorna (keyword_original, severity) do primeiro match, ou (None, None)."""
    if not text:
        return None, None
    pats = _PATTERNS if _PATTERNS is not None else _compile()
    for pat, sev in pats:
        m = pat.search(text)
        if m:
            return m.group(1).lower(), sev
    return None, None


def count_distinct_keywords(text) -> int:
    """Conta quantos keywords DISTINTOS de executor aparecem em `text`
    (word-boundary, mesmo matching de match_keyword).

    Usado pra detectar LISTA DE ASSINATURA: uma linha que enumera vários
    executores numa alternância (`solara|xeno|wave|...`) está DEFININDO a
    wordlist (script anti-cheat, o próprio Telador, signatures.json embutido),
    não rodando cheat. Comando real referencia UM executor."""
    if not text:
        return 0
    pats = _PATTERNS if _PATTERNS is not None else _compile()
    found = set()
    for pat, _sev in pats:
        for m in pat.finditer(text):
            found.add(m.group(1).lower())
    return len(found)


@functools.lru_cache(maxsize=1024)
def _compile_word(word: str) -> re.Pattern:
    esc = re.escape(word.lower())
    pre = r"\b" if word[0].isalnum() else ""
    suf = r"\b" if word[-1].isalnum() else ""
    return re.compile(pre + esc + suf)


def word_in_text(word: str, text: str) -> bool:
    """Substring com fronteira de palavra — 'wipe' casa 'wipe.exe' mas NÃO
    'swipe'. Pra listas matchadas por substring que têm termos curtos/comuns
    (ex.: CLEANER_NAMES com 'wipe'/'shred'). Cacheia o pattern por palavra."""
    if not word or not text:
        return False
    pat = _compile_word(word)
    return bool(pat.search(text.lower()))


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
