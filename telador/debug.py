"""
Canal de debug opt-in (--verbose).

Por padrão é no-op: não polui a saída, não custa nada. Quando ligado, loga no
stderr as exceções que normalmente seriam ENGOLIDAS por `except ...: pass` nos
leitores de artefato. Isso importa num tool forense: um scanner que falha calado
(ex.: não conseguiu ler um hive do registro) devolve "nada encontrado" pra
aquela fonte — e um "LIMPO" sem aquela fonte é cobertura reduzida, não inocência.
Com --verbose o telador mostra o que falhou de verdade.
"""

import sys

_ENABLED = False


def enable() -> None:
    global _ENABLED
    _ENABLED = True


def is_enabled() -> bool:
    return _ENABLED


def dbg(context: str, exc: BaseException | None = None) -> None:
    """Loga um evento de debug (no-op se --verbose não estiver ligado)."""
    if not _ENABLED:
        return
    msg = f"[debug] {context}"
    if exc is not None:
        msg += f": {type(exc).__name__}: {exc}"
    print(msg, file=sys.stderr)
