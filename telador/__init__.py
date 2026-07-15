"""Telador — SS forense pra Roblox.

Import publico:
    from telador import VERSION
    from telador import cli as telador   # API do scanner (assemble_*, main, ...)
    import telador; telador.assemble_scanners(...)  # via __getattr__
"""
from .version import (
    VERSION,
    VERSION_DISPLAY,
    SCANNER_COUNT,
    PRODUCT_NAME,
    PRODUCT_TAGLINE,
)

__all__ = [
    "VERSION",
    "VERSION_DISPLAY",
    "SCANNER_COUNT",
    "PRODUCT_NAME",
    "PRODUCT_TAGLINE",
    "cli",
    "gui",
]


def __getattr__(name: str):
    """Compat: `import telador; telador.assemble_scanners` resolve no cli."""
    if name in {"cli", "gui"}:
        import importlib
        return importlib.import_module(f".{name}", __name__)
    # Reexporta API do CLI (assemble_scanners, main, cross_correlate, ...)
    from . import cli as _cli
    if hasattr(_cli, name):
        return getattr(_cli, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
