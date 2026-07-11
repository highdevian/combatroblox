"""
Registry de scanners: nome, grupo, custo, requires_admin, tags.

Usado pra inventário, --quick documentation e futura UI.
Não substitui assemble_scanners — complementa com metadados.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict


@dataclass(frozen=True)
class ScannerMeta:
    fn_name: str
    group: str
    label: str
    requires_admin: bool = False
    cost: str = "medium"  # low | medium | high
    tags: tuple[str, ...] = ()
    in_quick: bool = False


def _label(fn_name: str) -> str:
    return fn_name.replace("scan_", "").replace("_", " ")


def build_registry() -> list[ScannerMeta]:
    """Constrói metadados a partir das listas ALL_* existentes."""
    import scanners
    import live_analysis
    import command_history
    import peripherals
    import persistence
    import antievasion
    import forensics
    import extra_forensics
    import yara_scan
    import winevent_scanner
    import network_scanners
    import discord_cache
    import fresh_install
    import removable_media
    import user_accounts
    import defender_tampering
    import clock_tampering
    import cleaner_tools
    import ads_scanner
    import timestomp_scanner
    import dma_scanner
    import external_scanner
    import anti_forensic_deep
    import service_state_scanner

    groups: list[tuple[str, list, dict]] = [
        ("base", scanners.ALL_SCANNERS, {"in_quick": True, "cost": "low"}),
        ("live", live_analysis.ALL_LIVE_ANALYSIS_SCANNERS, {"cost": "high", "tags": ("live",)}),
        ("history", command_history.ALL_COMMAND_HISTORY_SCANNERS, {"cost": "medium"}),
        ("peripherals", peripherals.ALL_PERIPHERAL_SCANNERS, {"cost": "low"}),
        ("persistence", persistence.ALL_PERSISTENCE_SCANNERS, {"cost": "medium"}),
        ("antievasion", antievasion.ALL_ANTIEVASION_SCANNERS, {"cost": "low"}),
        ("forensic", forensics.ALL_FORENSIC_SCANNERS, {"requires_admin": True, "cost": "high", "tags": ("forensic", "admin")}),
        ("extra_forensic", extra_forensics.ALL_EXTRA_FORENSIC_SCANNERS, {"requires_admin": True, "cost": "high", "tags": ("forensic",)}),
        ("yara", yara_scan.ALL_YARA_SCANNERS, {"cost": "high", "tags": ("binary",)}),
        ("winevent", winevent_scanner.ALL_WINEVENT_SCANNERS, {"requires_admin": True, "cost": "medium", "tags": ("admin",)}),
        ("network", network_scanners.ALL_NETWORK_SCANNERS, {"cost": "low"}),
        ("discord", discord_cache.ALL_DISCORD_SCANNERS, {"cost": "low"}),
        ("fresh_install", fresh_install.ALL_FRESH_INSTALL_SCANNERS, {"cost": "low"}),
        ("removable", removable_media.ALL_REMOVABLE_SCANNERS, {"cost": "low"}),
        ("accounts", user_accounts.ALL_USER_ACCOUNT_SCANNERS, {"cost": "low"}),
        ("defender", defender_tampering.ALL_DEFENDER_SCANNERS, {"requires_admin": True, "cost": "medium", "tags": ("admin",)}),
        ("clock", clock_tampering.ALL_CLOCK_SCANNERS, {"cost": "low"}),
        ("cleaner", cleaner_tools.ALL_CLEANER_SCANNERS, {"cost": "low"}),
        ("ads", ads_scanner.ALL_ADS_SCANNERS, {"cost": "medium"}),
        ("timestomp", timestomp_scanner.ALL_TIMESTOMP_SCANNERS, {"cost": "medium"}),
        ("dma", dma_scanner.ALL_DMA_SCANNERS, {"cost": "low", "tags": ("hardware",)}),
        ("external", external_scanner.ALL_EXTERNAL_SCANNERS, {
            "cost": "medium", "tags": ("live", "external"),
        }),
        ("service_state", service_state_scanner.ALL_SERVICE_STATE_SCANNERS, {"cost": "low"}),
        ("anti_forensic_deep", anti_forensic_deep.ALL_ANTI_FORENSIC_DEEP_SCANNERS, {
            "requires_admin": True, "cost": "high", "tags": ("forensic",),
        }),
    ]

    out: list[ScannerMeta] = []
    for group, chain, opts in groups:
        for fn in chain:
            name = getattr(fn, "__name__", str(fn))
            out.append(ScannerMeta(
                fn_name=name,
                group=group,
                label=_label(name),
                requires_admin=bool(opts.get("requires_admin")),
                cost=str(opts.get("cost", "medium")),
                tags=tuple(opts.get("tags") or ()),
                in_quick=bool(opts.get("in_quick")),
            ))
    return out


def registry_as_dicts() -> list[dict]:
    return [asdict(m) for m in build_registry()]


def count_scanners() -> dict[str, int]:
    reg = build_registry()
    by_group: dict[str, int] = {}
    for m in reg:
        by_group[m.group] = by_group.get(m.group, 0) + 1
    by_group["total"] = len(reg)
    by_group["quick"] = sum(1 for m in reg if m.in_quick)
    by_group["requires_admin"] = sum(1 for m in reg if m.requires_admin)
    return by_group
