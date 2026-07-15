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
    from . import scanners
    from . import live_analysis
    from . import command_history
    from . import peripherals
    from . import persistence
    from . import antievasion
    from . import forensics
    from . import extra_forensics
    from . import yara_scan
    from . import winevent_scanner
    from . import network_scanners
    from . import discord_cache
    from . import fresh_install
    from . import removable_media
    from . import user_accounts
    from . import defender_tampering
    from . import clock_tampering
    from . import cleaner_tools
    from . import ads_scanner
    from . import timestomp_scanner
    from . import dma_scanner
    from . import external_scanner
    from . import anti_forensic_deep
    from . import service_state_scanner
    from . import system_hardening
    from . import behavioral_tier_a
    from . import shellbag_scanner
    from . import firewall_scanner
    from . import bits_scanner
    from . import hijack_scanner
    from . import pca_scanner
    from . import defender_mplog_scanner
    from . import streamproof_scanner
    from . import os_integrity_scanner
    from . import task_execlog_scanner
    from . import cert_store_scanner
    from . import clipboard_history_scanner
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
        ("system_hardening", system_hardening.ALL_SYSTEM_HARDENING_SCANNERS, {
            "requires_admin": True, "cost": "medium", "tags": ("forensic", "state"),
        }),
        ("behavioral_tier_a", behavioral_tier_a.ALL_BEHAVIORAL_TIER_A_SCANNERS, {
            "requires_admin": True, "cost": "medium", "tags": ("behavioral", "live"),
        }),
        ("shellbag", shellbag_scanner.ALL_SHELLBAG_SCANNERS, {
            "cost": "medium", "tags": ("forensic",),
        }),
        ("firewall", firewall_scanner.ALL_FIREWALL_SCANNERS, {
            "requires_admin": True, "cost": "low", "tags": ("network",),
        }),
        ("bits", bits_scanner.ALL_BITS_SCANNERS, {
            "cost": "medium", "tags": ("network", "forensic"),
        }),
        ("hijack", hijack_scanner.ALL_HIJACK_SCANNERS, {
            "requires_admin": True, "cost": "medium", "tags": ("forensic", "hijack"),
        }),
        ("pca", pca_scanner.ALL_PCA_SCANNERS, {
            "requires_admin": True, "cost": "medium", "tags": ("forensic", "admin"),
        }),
        ("defender_mplog", defender_mplog_scanner.ALL_DEFENDER_MPLOG_SCANNERS, {
            "requires_admin": True, "cost": "medium", "tags": ("forensic",),
        }),
        ("streamproof", streamproof_scanner.ALL_STREAMPROOF_SCANNERS, {
            "cost": "low", "tags": ("live", "anti-ss"),
        }),
        ("os_integrity", os_integrity_scanner.ALL_OS_INTEGRITY_SCANNERS, {
            "requires_admin": True, "cost": "low", "tags": ("forensic", "boot"),
        }),
        ("task_execlog", task_execlog_scanner.ALL_TASK_EXECLOG_SCANNERS, {
            "requires_admin": True, "cost": "medium", "tags": ("forensic",),
        }),
        ("cert_store", cert_store_scanner.ALL_CERT_STORE_SCANNERS, {
            "cost": "medium", "tags": ("forensic", "network"),
        }),
        ("clipboard", clipboard_history_scanner.ALL_CLIPBOARD_SCANNERS, {
            "cost": "low", "tags": ("forensic", "live"),
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
