"""
Detecção de ferramentas de limpeza / secure-delete — pré-limpeza de rastro.

Antes da SS, o suspeito roda um "limpador" pra apagar o rastro do cheat de forma
irreversível. Ferramenta de secure-delete (SDelete, Eraser, BCWipe…) num PC de
jogador não tem motivo legítimo — é destruição de evidência. Cleaner geral
(CCleaner, Wise) é rotineiro, então fica como contexto (baixo).

Lê o Prefetch (lista os .pf — barato, sem parse binário) e casa contra a lista
de limpadores. O .pf prova que a ferramenta RODOU; o mtime ≈ última execução.
Precisa de admin (Prefetch); sem admin = erro gracioso.

Mapeia pro source 'anti_forense' (é o que é).
"""

from models import _result, _item, _fmt_ts
import os
import re


_PREFETCH = r"C:\Windows\Prefetch"

# (substring no nome do .pf/exe, severidade, rótulo).
#   high   = secure-delete / shredder: sem motivo legítimo num PC de jogo.
#   medium = limpador com secure-delete embutido (comum, mas relevante).
#   low    = limpador geral (rotineiro) — contexto, não infla veredito.
_CLEANER_TOOLS = [
    # secure-delete / shredders (intent forte)
    ("sdelete",        "high",   "SDelete (secure delete)"),
    ("eraser",         "high",   "Eraser"),
    ("bcwipe",         "high",   "BCWipe"),
    ("hardwipe",       "high",   "Hardwipe"),
    ("wipefile",       "high",   "WipeFile"),
    ("freeraser",      "high",   "Freeraser"),
    ("fileshredder",   "high",   "File Shredder"),
    ("secureeraser",   "high",   "Secure Eraser"),
    ("blankandsecure", "high",   "Blank And Secure"),
    ("sdelete64",      "high",   "SDelete (secure delete)"),
    # cleaners com secure-delete (médio)
    ("bleachbit",      "medium", "BleachBit"),
    ("privazer",       "medium", "PrivaZer"),
    # cleaners gerais (rotineiro — contexto)
    ("ccleaner",       "low",    "CCleaner"),
    ("wisedisk",       "low",    "Wise Disk Cleaner"),
    ("wisecare",       "low",    "Wise Care"),
]


_token_cache = {}


def _token_at_word_start(token: str, text: str) -> bool:
    """True se `token` aparece em `text` no INÍCIO de uma palavra — precedido
    por começo-de-string ou char não-alfanumérico. Permite sufixo (versão):

        'eraser'  casa 'ERASER.EXE-A1B2.pf'  e  'MY-ERASER.pf'
        'eraser'  NÃO casa 'PHOTOERASER.pf'  (preced. por 'o') nem 'freeraser'
        'sdelete' casa 'SDELETE64.EXE-...'    (sufixo numérico OK)

    Resolve o FP de substring puro: 'eraser' pegava editores de foto
    ('Photo Eraser', 'Background Eraser') e 'freeraser' tem token próprio."""
    pat = _token_cache.get(token)
    if pat is None:
        pat = re.compile(r"(?<![a-z0-9])" + re.escape(token))
        _token_cache[token] = pat
    return bool(pat.search(text))


def _match_cleaner(filename: str):
    """Retorna (severity, label) se o .pf for de um limpador conhecido; senão None.
    Núcleo testável."""
    low = (filename or "").lower()
    if not low.endswith(".pf"):
        return None
    for sub, sev, label in _CLEANER_TOOLS:
        if _token_at_word_start(sub, low):
            return sev, label
    return None


def scan_cleaner_tools() -> dict:
    """Limpadores / secure-delete que rodaram (Prefetch). Pré-limpeza pré-SS."""
    try:
        files = os.listdir(_PREFETCH)
    except OSError as e:
        return _result("Ferramentas de limpeza / anti-forense",
                       "Limpadores/secure-delete que rodaram antes da SS",
                       [], error=f"sem acesso ao Prefetch (rode como admin): {e}")

    items = []
    seen = set()
    for f in files:
        hit = _match_cleaner(f)
        if not hit:
            continue
        sev, label = hit
        if label in seen:
            continue
        seen.add(label)
        try:
            mtime = _fmt_ts(os.path.getmtime(os.path.join(_PREFETCH, f)))
        except OSError:
            mtime = ""
        kind = "Apagador seguro / shredder" if sev == "high" else "Limpador"
        items.append(_item(
            label=f"Ferramenta de limpeza executada: {label}",
            detail=f"Prefetch: {f}\n{label} rodou nesta máquina"
                   + (f" (última execução {mtime})" if mtime else "") + ". "
                   f"{kind} — rodar limpeza pouco antes da SS é pré-limpeza de rastro. "
                   f"Cruze o horário com a janela de jogo. "
                   + ("Secure-delete num PC de jogador não tem uso legítimo."
                      if sev == "high" else "Cleaner comum; vale o contexto."),
            severity=sev, matched=f"cleaner:{label.lower().split(' ')[0][:24]}",
            timestamp=mtime,
        ))

    return _result("Ferramentas de limpeza / anti-forense",
                   "Limpadores/secure-delete que rodaram antes da SS", items)


ALL_CLEANER_SCANNERS = [
    scan_cleaner_tools,
]
