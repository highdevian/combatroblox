"""
Detecção (PARCIAL, heurística) de cheats EXTERNAL de Roblox.

External = processo/driver FORA do RobloxPlayerBeta que lê memória (RPM/WPM
ou via kernel) e desenha overlay (ESP/aimbot). Diferente de executor internal
(Xeno/Solara-class) que injeta e corre scripts Luau dentro do cliente.

O Hyperion (AC do cliente) é fraco contra external; o Windows forense (Prefetch,
Amcache, BAM, processo vivo, pastas de loader) é o canal certo. Este módulo:

  1) Processos vivos com nomes de famílias conhecidas (Matcha, Severe, DX9, …)
  2) Artefatos em disco em paths graváveis pelo user (pastas/loaders)
  3) Slot de signatures extensível (in-module + signatures.json)

Catálogo de famílias baseado em pesquisa pública (Reddit r/robloxhackers,
UnknownCheats, showcases YouTube 2024–2026): Matcha, Severe, DX9WARE, Matrix,
Celex, Bauix, Sheldon, Vasile, Ronin-external, Mooze, Oxygen-external,
timeoutwtf, Santoware, Photon, Clarity, Serotonin, Spxrkz, OMEGA, etc.

NÃO é bala de prata:
  - rebuilds diários mudam o .exe name → prefira família + multi-fonte
  - hashes públicos de YouTube/cracks são lixo forense
  - bare words comuns (severe, matrix, photon, clarity) NÃO entram sozinhas

Anti-FP: nunca flagga processos de overlay legítimo (Medal, Overwolf, …).
loader.exe / map.exe / app.exe sozinhos NÃO são IOC.
"""

from __future__ import annotations

import os
import re

from models import _result, _item, _fmt_ts

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


# ============================ Catálogo de famílias (pesquisa 2024-2026) ============================
# Cada família: label, severity default, process basenames (.exe), path tokens,
# basenames de pasta exactos, aliases extras pro cluster engine.
# Fontes: cena public (UC, Reddit, showcases) — nomes de produto, não hashes.

_FAMILY_CATALOG: dict[str, dict] = {
    # --- Paid / notórios (driver-based frequentemente) ---
    "matcha": {
        "label": "Matcha (external aimbot/ESP, frequentemente com driver/kernel)",
        "severity": "high",
        "processes": [
            "matcha.exe", "matchaexternal.exe", "matcha_external.exe",
            "matcha-external.exe", "matchaloader.exe", "matcha loader.exe",
            "matchabeta.exe", "matcha beta.exe",
        ],
        "tokens": [
            "matcha external", "matcha-external", "matcha_external",
            "matcha beta", "matchabeta", "matchaloader", "matcha.exe",
            "matcha latte",  # discord branding matchalattewin
        ],
        "basenames": [
            "matcha", "matcha external", "matcha-external", "matcha_external",
            "matcha beta", "matchabeta",
        ],
        "aliases": ["matchaexternal", "matcha loader"],
    },
    "severe": {
        # Reddit/YouTube: paid external de longa data (ESP/aimbot/script external)
        # NÃO usar bare "severe" (inglês comum) em path tokens soltos.
        "label": "Severe (external aimbot/ESP/executor externo)",
        "severity": "high",
        "processes": [
            "severe.exe", "severeexternal.exe", "severe_external.exe",
            "severe-external.exe", "severe2.exe", "severe 2.0.exe",
            "severeloader.exe",
        ],
        "tokens": [
            "severe external", "severe-external", "severe_external",
            "severe.exe", "severe 2.0", "severe2",
        ],
        "basenames": [
            "severe external", "severe-external", "severe_external",
            "severe2", "severe 2.0", "severe2.0",
        ],
        # basename "severe" sozinho: arriscado mas comum em pastas de loader;
        # severity high só como pasta exact (SS Roblox).
        "aliases": ["severeexternal"],
        "risky_basenames": ["severe"],  # pasta exact only
    },
    "dx9ware": {
        # DX9 / DX9WARE — external notório (driver-class, Discord "coi")
        "label": "DX9WARE / DX9 (external kernel-class)",
        "severity": "high",
        "processes": [
            "dx9ware.exe", "dx9wareloader.exe", "dx9 external.exe",
            "dx9external.exe", "dx9_external.exe",
        ],
        "tokens": [
            "dx9ware", "dx9 ware", "dx9-ware", "dx9external",
            "dx9 external", "dx9_external",
        ],
        "basenames": ["dx9ware", "dx9 ware", "dx9external", "dx9 external"],
        "aliases": ["dx9ware"],
        # NÃO: bare "dx9" (DirectX)
    },
    "matrix_ext": {
        # Matrix / MatrixHub external (≠ matrix hub de scripts — tokens compostos)
        "label": "Matrix / MatrixHub (external)",
        "severity": "high",
        "processes": [
            "matrixhub.exe", "matrix external.exe", "matrixexternal.exe",
            "mtxhub.exe", "matrixext.exe",
        ],
        "tokens": [
            "matrix external", "matrixhub", "mtxhub", "matrix-external",
            "matrix_external", "matrixexternal",
        ],
        "basenames": [
            "matrixhub", "matrix external", "matrix-external",
            "matrixexternal", "mtxhub",
        ],
        "aliases": ["matrixhub", "mtxhub", "matrixexternal"],
        # NÃO: bare "matrix"
    },
    "celex": {
        # Celex / Celex V3 — Da Hood external (histórico de malware em cracks)
        "label": "Celex (external; cracks frequentemente malware)",
        "severity": "high",
        "processes": [
            "celex.exe", "celexexternal.exe", "celex_external.exe",
            "celex-external.exe", "celexv3.exe", "celex v3.exe",
        ],
        "tokens": [
            "celex external", "celex-external", "celex v3", "celexv3",
            "celex.exe",
        ],
        "basenames": ["celex", "celex external", "celex v3", "celexv3"],
        "aliases": ["celexexternal"],
    },
    "bauix": {
        # Bauix — marketing moon.sex
        "label": "Bauix (external; moon.sex)",
        "severity": "high",
        "processes": ["bauix.exe", "bauixexternal.exe", "bauix_external.exe"],
        "tokens": ["bauix external", "bauix.exe", "bauixexternal"],
        "basenames": ["bauix", "bauix external"],
        "aliases": ["bauixexternal"],
    },
    "sheldon": {
        "label": "Sheldon External (free/showcase)",
        "severity": "high",
        "processes": [
            "sheldonexternal.exe", "sheldon_external.exe",
            "sheldon-external.exe", "sheldon external.exe",
        ],
        "tokens": [
            "sheldon external", "sheldonexternal", "sheldon-external",
        ],
        "basenames": ["sheldon external", "sheldonexternal"],
        "aliases": ["sheldonexternal"],
        # NÃO: sheldon.exe (nome próprio comum)
    },
    "vasile": {
        # UC source release — aimbot/ESP/silent aim
        "label": "Vasile (external aimbot/ESP, UC source)",
        "severity": "high",
        "processes": ["vasile.exe", "vasileexternal.exe"],
        "tokens": ["vasile external", "vasile.exe"],
        "basenames": ["vasile", "vasile external"],
        "aliases": ["vasileexternal"],
    },
    "ronin_ext": {
        # Ronin posicionado como external em showcases (≠ só "ronin executor")
        "label": "Ronin External",
        "severity": "high",
        "processes": [
            "roninexternal.exe", "ronin_external.exe", "ronin-external.exe",
            "ronin external.exe",
        ],
        "tokens": ["ronin external", "roninexternal", "ronin-external"],
        "basenames": ["ronin external", "roninexternal"],
        "aliases": ["roninexternal"],
    },
    "mooze": {
        "label": "Mooze (external)",
        "severity": "high",
        "processes": ["mooze.exe", "moozeexternal.exe"],
        "tokens": ["mooze external", "mooze.exe"],
        "basenames": ["mooze", "mooze external"],
        "aliases": ["moozeexternal"],
    },
    "oxygen_ext": {
        # Oxygen External showcase — NÃO confundir com "oxygen u" executor
        "label": "Oxygen External",
        "severity": "high",
        "processes": [
            "oxygenexternal.exe", "oxygen_external.exe", "oxygen-external.exe",
        ],
        "tokens": ["oxygen external", "oxygenexternal", "oxygen-external"],
        "basenames": ["oxygen external", "oxygenexternal"],
        "aliases": ["oxygenexternal"],
    },
    "timeoutwtf": {
        "label": "timeoutwtf / Timeout (external free/showcase)",
        "severity": "medium",
        "processes": ["timeoutwtf.exe", "timeoutexternal.exe", "timeout external.exe"],
        "tokens": ["timeoutwtf", "timeout external", "timeout exploit"],
        "basenames": ["timeoutwtf", "timeout external"],
        "aliases": ["timeoutwtf"],
    },
    "santoware": {
        "label": "Santoware (external)",
        "severity": "high",
        "processes": ["santoware.exe", "santo ware.exe"],
        "tokens": ["santoware", "santo ware"],
        "basenames": ["santoware", "santo ware"],
        "aliases": ["santoware"],
    },
    "photon_ext": {
        # Photon external — só compostos (photon sozinho = FP físico/graphics)
        "label": "Photon External",
        "severity": "high",
        "processes": ["photonexternal.exe", "photon_external.exe", "photon external.exe"],
        "tokens": ["photon external", "photonexternal"],
        "basenames": ["photon external", "photonexternal"],
        "aliases": ["photonexternal"],
    },
    "clarity_ext": {
        "label": "Clarity External",
        "severity": "high",
        "processes": ["clarityexternal.exe", "clarity external.exe"],
        "tokens": ["clarity external", "clarityexternal"],
        "basenames": ["clarity external", "clarityexternal"],
        "aliases": ["clarityexternal"],
    },
    "serotonin": {
        "label": "Serotonin (external)",
        "severity": "high",
        "processes": ["serotonin.exe", "serotoninexternal.exe"],
        "tokens": ["serotonin external", "serotonin.exe"],
        "basenames": ["serotonin", "serotonin external"],
        "aliases": ["serotoninexternal"],
    },
    "spxrkz": {
        # UC: Spxrkz Roblox External
        "label": "Spxrkz (external)",
        "severity": "high",
        "processes": ["spxrkz.exe", "spxrkzexternal.exe"],
        "tokens": ["spxrkz external", "spxrkz.exe"],
        "basenames": ["spxrkz", "spxrkz external"],
        "aliases": ["spxrkzexternal"],
    },
    "yerba": {
        # Tags de cena Da Hood / external
        "label": "Yerba (external)",
        "severity": "medium",
        "processes": ["yerba.exe", "yerbaexternal.exe"],
        "tokens": ["yerba external", "yerbaexternal"],
        "basenames": ["yerba external", "yerbaexternal"],
        # bare "yerba" = chá — só composto
        "aliases": ["yerbaexternal"],
    },
    "omega_esp": {
        "label": "OMEGA / stomega (ESP external educacional)",
        "severity": "medium",
        "processes": ["stomega.exe", "omegaesp.exe"],
        "tokens": ["omega-launcher", "omega launcher", "stomega"],
        "basenames": ["omega-launcher", "omega launcher", "stomega"],
        "aliases": ["stomega", "omega-launcher"],
    },
    "polter": {
        # UC threads: polter.sys mapped via kdmapper em external kernel
        "label": "Polter (driver/mapper associado a external kernel)",
        "severity": "high",
        "processes": ["polter.exe", "poltermapper.exe"],
        "tokens": ["polter.sys", "polter.exe", "polter mapper"],
        "basenames": ["polter", "polter.sys"],
        "aliases": ["polter.sys"],
    },
    "generic_external": {
        "label": "External cheat genérico (aimbot/ESP fora do cliente)",
        "severity": "medium",
        "processes": [
            "robloxexternal.exe", "rbxexternal.exe",
            "externalesp.exe", "externalaimbot.exe",
            "ucrobloxexternal.exe",
        ],
        "tokens": [
            "roblox external", "robloxexternal", "rbx external",
            "external aimbot", "external esp", "external cheat",
            "ucrobloxexternal",
        ],
        "basenames": ["robloxexternal", "rbxexternal", "ucrobloxexternal"],
        "aliases": [
            "robloxexternal", "rbxexternal", "external aimbot",
            "external esp", "external cheat", "roblox external",
        ],
    },
}

# Domínios públicos associados a products external (browser history / DNS)
EXTERNAL_DOMAINS: dict[str, str] = {
    "moon.sex": "high",           # Bauix marketing
    "celex.gg": "high",
    "celexofficial.com": "medium",
}


def _build_tables():
    """Expande o catálogo em tabelas de lookup mutáveis (signatures.json merge)."""
    processes: dict[str, tuple[str, str]] = {}
    tokens: dict[str, tuple[str, str]] = {}
    basenames: dict[str, tuple[str, str]] = {}
    labels: dict[str, str] = {}
    aliases: dict[str, str] = {}
    family_ids: set[str] = set()

    for fam, meta in _FAMILY_CATALOG.items():
        family_ids.add(fam)
        sev = meta.get("severity", "high")
        labels[fam] = meta.get("label", fam)
        aliases[fam] = fam

        for p in meta.get("processes", []):
            pl = p.lower().strip()
            processes[pl] = (sev, fam)
            aliases[pl] = fam
            stem = pl[:-4] if pl.endswith(".exe") else pl
            aliases[stem] = fam

        for t in meta.get("tokens", []):
            tl = t.lower().strip()
            tokens[tl] = (sev, fam)
            aliases[tl] = fam

        for b in meta.get("basenames", []):
            bl = b.lower().strip()
            basenames[bl] = (sev, fam)
            aliases[bl] = fam

        for b in meta.get("risky_basenames", []):
            bl = b.lower().strip()
            basenames[bl] = (sev, fam)
            aliases[bl] = fam

        for a in meta.get("aliases", []):
            aliases[a.lower().strip()] = fam

    return processes, tokens, basenames, labels, aliases, frozenset(family_ids)


(
    EXTERNAL_PROCESS_NAMES,
    EXTERNAL_PATH_TOKENS,
    EXTERNAL_BASENAME_EXACT,
    EXTERNAL_FAMILY_LABELS,
    EXTERNAL_ALIAS_MAP,
    EXTERNAL_FAMILY_IDS,
) = _build_tables()

# Compat: evidence.py e testes antigos
EXTERNAL_FAMILY_CANONICALS = EXTERNAL_FAMILY_IDS


# Processos legítimos que NUNCA devem ser flagados por este scanner
LEGIT_PROCESS_BLOCKLIST: set[str] = {
    "discord.exe", "discordcanary.exe", "discordptb.exe", "discorddevelopment.exe",
    "nvcontainer.exe", "nvidia share.exe", "nvidia web helper.exe",
    "nvidiaoverlay.exe", "nvidia app.exe", "amddvr.exe", "radeonsoftware.exe",
    "obs64.exe", "obs32.exe", "obs.exe", "streamlabs obs.exe",
    "xsplit.core.exe", "action.exe",
    "medal.exe", "medalencoder.exe", "medal-helper.exe",
    "overwolf.exe", "overwolfbrowser.exe", "overwolfhelper.exe",
    "steam.exe", "gameoverlayui.exe", "steamwebhelper.exe",
    "epicgameslauncher.exe", "galaxyclient.exe", "robloxplayerbeta.exe",
    "robloxstudiobeta.exe", "robloxplayerlauncher.exe", "roblox.exe",
    "rtss.exe", "msiafterburner.exe", "rivatunerstatisticsserver.exe",
    "nahimicsvc.exe", "nahimic3.exe", "lghub.exe", "lghub_agent.exe",
    "razer synapse.exe", "razersynapse.exe", "icue.exe",
    "wallpaper32.exe", "wallpaper64.exe",
    "steelseriesgg.exe", "steelseriesengine.exe", "ggwave.exe",
    "explorer.exe", "textinputhost.exe", "applicationframehost.exe",
    "shellexperiencehost.exe", "startmenuexperiencehost.exe",
    "searchhost.exe", "searchapp.exe", "gamebar.exe", "gamebarft.exe",
    "xboxgamebar.exe", "snippingtool.exe", "screenclippinghost.exe",
    "lockapp.exe", "peopleexperiencehost.exe", "systemsettings.exe",
    "magnify.exe", "narrator.exe", "powertoys.exe", "powertoys.awake.exe",
    "flow.launcher.exe", "translucenttb.exe", "f.lux.exe", "flux.exe",
    "1password.exe", "bitwarden.exe", "everything.exe",
    "code.exe", "cursor.exe", "devenv.exe", "windsurf.exe",
    "python.exe", "pythonw.exe", "py.exe",
}

_ARTIFACT_ROOTS = [
    r"%LOCALAPPDATA%",
    r"%APPDATA%",
    r"%USERPROFILE%\Downloads",
    r"%USERPROFILE%\Desktop",
    r"%USERPROFILE%\Documents",
    r"%TEMP%",
    r"%LOCALAPPDATA%\Temp",
]

_MAX_ARTIFACT_HITS = 40
_MAX_DIRS_WALKED = 800
_MAX_DEPTH = 3


# ============================ Classificadores puros ============================

def _wordish_contains(haystack: str, needle: str) -> bool:
    if not haystack or not needle:
        return False
    h = haystack.lower()
    n = needle.lower()
    if n.startswith(("\\", "/", "\\\\")) or n.endswith(("\\", "/")):
        return n in h
    pattern = r"(?<![a-z0-9])" + re.escape(n) + r"(?![a-z0-9])"
    return re.search(pattern, h) is not None


def classify_process_name(name: str) -> tuple[str, str, str] | None:
    """(severity, family_id, matched_key) se o nome de processo casa IOC; senão None."""
    if not name:
        return None
    n = name.lower().strip()
    if n in LEGIT_PROCESS_BLOCKLIST:
        return None
    hit = EXTERNAL_PROCESS_NAMES.get(n)
    if hit:
        sev, family = hit
        return sev, family, n
    base = os.path.basename(n)
    if base != n:
        if base in LEGIT_PROCESS_BLOCKLIST:
            return None
        hit = EXTERNAL_PROCESS_NAMES.get(base)
        if hit:
            sev, family = hit
            return sev, family, base
    return None


def classify_basename(name: str) -> tuple[str, str, str] | None:
    """(severity, family_id, matched) se o basename (pasta/arquivo) é IOC exato."""
    if not name:
        return None
    n = name.lower().strip()
    stem = n
    for ext in (".exe", ".rar", ".zip", ".7z", ".dll", ".sys"):
        if stem.endswith(ext):
            stem = stem[: -len(ext)]
            break
    hit = EXTERNAL_BASENAME_EXACT.get(n) or EXTERNAL_BASENAME_EXACT.get(stem)
    if hit:
        sev, family = hit
        return sev, family, n
    if n in EXTERNAL_PROCESS_NAMES:
        sev, family = EXTERNAL_PROCESS_NAMES[n]
        return sev, family, n
    return None


def classify_path_or_text(text: str) -> tuple[str, str, str] | None:
    """(severity, family_id, matched_token) se path/texto casa token de external."""
    if not text:
        return None
    base = os.path.basename(text.replace("/", "\\").rstrip("\\"))
    best: tuple[str, str, str] | None = classify_basename(base) if base else None
    best_len = len(best[2]) if best else 0
    sev_rank = {"high": 3, "medium": 2, "low": 1}

    if len(text) < 4:
        return best

    for token, (sev, family) in EXTERNAL_PATH_TOKENS.items():
        if not _wordish_contains(text, token):
            continue
        tlen = len(token)
        if best is None:
            best = (sev, family, token)
            best_len = tlen
            continue
        bsev = best[0]
        if sev_rank.get(sev, 0) > sev_rank.get(bsev, 0) or (
            sev_rank.get(sev, 0) == sev_rank.get(bsev, 0) and tlen > best_len
        ):
            best = (sev, family, token)
            best_len = tlen
    return best


def family_label(family_id: str) -> str:
    return EXTERNAL_FAMILY_LABELS.get(family_id, f"{family_id} (external)")


def keywords_for_database() -> dict[str, str]:
    """Gera keywords severity para mesclar em EXECUTOR_KEYWORDS / Prefetch."""
    out: dict[str, str] = {}
    for token, (sev, _fam) in EXTERNAL_PATH_TOKENS.items():
        out[token] = sev
    for proc, (sev, _fam) in EXTERNAL_PROCESS_NAMES.items():
        out[proc] = sev
        if proc.endswith(".exe"):
            out.setdefault(proc[:-4], sev)
    return out


def process_names_for_database() -> dict[str, str]:
    return {k: v[0] for k, v in EXTERNAL_PROCESS_NAMES.items()}


def folder_names_for_database() -> dict[str, str]:
    return {k: v[0] for k, v in EXTERNAL_BASENAME_EXACT.items()}


# ============================ Scanners ============================

def scan_external_processes() -> dict:
    """Processos vivos cujo nome casa famílias de external cheat Roblox."""
    name = "External cheat (processo vivo)"
    desc = (
        "Processo separado do Roblox com nome de external aimbot/ESP conhecido "
        "(Matcha, Severe, DX9, Matrix, Celex, …) — não é executor Luau (Xeno/Solara)"
    )
    if not HAS_PSUTIL:
        return _result(name, desc, [], error="psutil não instalado")

    items = []
    seen: set[str] = set()

    try:
        for proc in psutil.process_iter(["pid", "name", "exe", "create_time"]):
            try:
                info = proc.info
                pname = (info.get("name") or "").strip()
                if not pname:
                    continue
                hit = classify_process_name(pname)
                if not hit:
                    exe = info.get("exe") or ""
                    path_hit = classify_path_or_text(exe) if exe else None
                    if not path_hit:
                        continue
                    sev, family, matched = path_hit
                    key = f"path:{matched}:{info.get('pid')}"
                else:
                    sev, family, matched = hit
                    key = f"proc:{matched}:{info.get('pid')}"

                if key in seen:
                    continue
                seen.add(key)

                exe = (info.get("exe") or "").lower()
                base_exe = os.path.basename(exe) if exe else pname.lower()
                if base_exe in LEGIT_PROCESS_BLOCKLIST:
                    continue

                pid = info.get("pid")
                ts = ""
                try:
                    ct = info.get("create_time")
                    if ct:
                        ts = _fmt_ts(ct)
                except (OSError, TypeError, ValueError):
                    pass

                flabel = family_label(family)
                detail_parts = [
                    f"PID {pid}",
                    f"família: {flabel}",
                    f"matched={matched}",
                ]
                if exe:
                    detail_parts.append(exe)
                detail_parts.append(
                    "External = processo fora do Roblox (RPM/overlay/driver). "
                    "Corrobore com Prefetch/Amcache/BAM e overlay click-through. "
                    "Sozinho é pista forte de produto, não prova de uso in-game."
                )

                items.append(_item(
                    label=f"External vivo: {pname} [{family}]",
                    detail="\n".join(detail_parts),
                    severity=sev,
                    matched=f"external-proc:{family}:{matched}",
                    timestamp=ts,
                ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except Exception as e:
        return _result(name, desc, [], error=str(e))

    return _result(name, desc, items)


def _iter_artifact_candidates(roots: list[str] | None = None):
    """Yield (path, basename_lower) sob roots, depth-limitado. Mockável nos testes."""
    roots = roots if roots is not None else _ARTIFACT_ROOTS
    walked = 0
    for raw in roots:
        root = os.path.expandvars(raw)
        if not os.path.isdir(root):
            continue
        root_depth = root.rstrip("\\/").count(os.sep)
        try:
            for dirpath, dirnames, filenames in os.walk(root):
                walked += 1
                if walked > _MAX_DIRS_WALKED:
                    return
                depth = dirpath.rstrip("\\/").count(os.sep) - root_depth
                if depth >= _MAX_DEPTH:
                    dirnames[:] = []
                dirnames[:] = [
                    d for d in dirnames
                    if d.lower() not in {
                        "node_modules", ".git", "__pycache__", "windows",
                        "microsoft", "packages", "nvidia", "intel", "amd",
                        "steam", "steamapps", "epic games",
                    }
                ]
                base_dir = os.path.basename(dirpath)
                yield dirpath, base_dir.lower()
                for fn in filenames:
                    yield os.path.join(dirpath, fn), fn.lower()
        except OSError:
            continue


def scan_external_artifacts() -> dict:
    """Pastas/arquivos em paths de user com tokens de external cheat."""
    name = "External cheat (artefatos em disco)"
    desc = (
        "Pastas/loaders de external aimbot/ESP em Downloads/AppData/Desktop/Temp "
        "(Matcha/Severe/DX9/Matrix/Celex/… — slot de signatures extensível)"
    )
    items = []
    seen: set[str] = set()

    try:
        for path, token_base in _iter_artifact_candidates():
            if len(items) >= _MAX_ARTIFACT_HITS:
                break
            hit = classify_basename(token_base) or classify_path_or_text(path)
            if not hit:
                continue
            sev, family, matched = hit
            norm = path.lower()
            dedupe_key = f"{family}:{os.path.dirname(norm)}"
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)

            flabel = family_label(family)
            is_dir = os.path.isdir(path)
            kind = "pasta" if is_dir else "arquivo"
            items.append(_item(
                label=f"Artefato external ({kind}): {os.path.basename(path)} [{family}]",
                detail=(
                    f"{path}\n"
                    f"família: {flabel}\n"
                    f"matched={matched}\n"
                    "Loader/pasta de external cheat Roblox (fora do cliente). "
                    "Prefetch/BAM com o mesmo nome reforça o cluster. "
                    "Nomes rebranded não entram até atualizar signatures."
                ),
                severity=sev,
                matched=f"external-path:{family}:{matched}",
            ))
    except Exception as e:
        return _result(name, desc, [], error=str(e))

    return _result(name, desc, items)



import ctypes
from ctypes import wintypes

import debug

try:
    from database import ROBLOX_PROCESS_NAMES as _RBX_NAMES
except ImportError:
    _RBX_NAMES = ["RobloxPlayerBeta.exe", "RobloxPlayerLauncher.exe"]

# Alias — as detecções técnicas foram escritas usando ROBLOX_PROCESS_NAMES
ROBLOX_PROCESS_NAMES = _RBX_NAMES

# ============================ Win32 / NT setup ============================

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010
PROCESS_DUP_HANDLE = 0x0040
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_WRITE = 0x0020

THREAD_QUERY_INFORMATION = 0x0040
THREAD_QUERY_LIMITED_INFORMATION = 0x0800

DUPLICATE_SAME_ACCESS = 0x2
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004

# NtQuerySystemInformation classes
SystemExtendedHandleInformation = 64

# NtQueryInformationThread classes
ThreadQuerySetWin32StartAddress = 9

# NtQueryObject classes
ObjectTypeInformation = 2

try:
    kernel32 = ctypes.windll.kernel32

    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE

    kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenThread.restype = wintypes.HANDLE

    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    kernel32.GetCurrentProcess.restype = wintypes.HANDLE

    kernel32.DuplicateHandle.argtypes = [
        wintypes.HANDLE, wintypes.HANDLE, wintypes.HANDLE,
        ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD,
        wintypes.BOOL, wintypes.DWORD,
    ]
    kernel32.DuplicateHandle.restype = wintypes.BOOL

    # VirtualQueryEx setup no top (não muta em cada call de _module_ranges_via_virtualquery)
    # A struct MEMORY_BASIC_INFORMATION real fica declarada depois; usamos c_void_p
    # aqui e reintroduzimos POINTER na função — argtypes vem com aquele setup.

    HAS_KERNEL32 = True
except (AttributeError, OSError):
    HAS_KERNEL32 = False

try:
    ntdll = ctypes.windll.ntdll

    ntdll.NtQuerySystemInformation.argtypes = [
        ctypes.c_int, ctypes.c_void_p, wintypes.ULONG, ctypes.POINTER(wintypes.ULONG),
    ]
    ntdll.NtQuerySystemInformation.restype = ctypes.c_long  # NTSTATUS

    ntdll.NtQueryInformationThread.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
        wintypes.ULONG, ctypes.POINTER(wintypes.ULONG),
    ]
    ntdll.NtQueryInformationThread.restype = ctypes.c_long

    ntdll.NtQueryObject.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
        wintypes.ULONG, ctypes.POINTER(wintypes.ULONG),
    ]
    ntdll.NtQueryObject.restype = ctypes.c_long

    HAS_NTDLL = True
except (AttributeError, OSError):
    HAS_NTDLL = False



# ============================ (1) Handles pro Roblox ============================

# Layout de SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX (class 64). Pointer-sized fields
# (Object, UniqueProcessId, HandleValue) precisam ser c_size_t no x64 pra não
# quebrar alinhamento — DWORD/HANDLE misturados desalinham tudo.
class SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(ctypes.Structure):
    _fields_ = [
        ("Object", ctypes.c_size_t),
        ("UniqueProcessId", ctypes.c_size_t),
        ("HandleValue", ctypes.c_size_t),
        ("GrantedAccess", wintypes.ULONG),
        ("CreatorBackTraceIndex", wintypes.USHORT),
        ("ObjectTypeIndex", wintypes.USHORT),
        ("HandleAttributes", wintypes.ULONG),
        ("Reserved", wintypes.ULONG),
    ]


def _query_system_handles(max_mb: int = 512) -> list:
    """Enumera todos os handles do Windows via NtQuerySystemInformation.
    Cresce o buffer até caber (STATUS_INFO_LENGTH_MISMATCH = precisa mais).
    Retorna lista de SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX (não converte pra dict
    porque a lista tem centenas de milhares de entradas — velocidade importa)."""
    if not HAS_NTDLL:
        return []
    size = 1 << 20  # 1 MB inicial
    while size <= (max_mb << 20):
        buf = ctypes.create_string_buffer(size)
        ret_len = wintypes.ULONG(0)
        status = ntdll.NtQuerySystemInformation(
            SystemExtendedHandleInformation, buf, size, ctypes.byref(ret_len)
        )
        if status == 0:
            break
        if status == STATUS_INFO_LENGTH_MISMATCH or (status & 0xFFFFFFFF) == STATUS_INFO_LENGTH_MISMATCH:
            size *= 2
            continue
        # Outros erros: desiste
        debug.dbg(f"NtQuerySystemInformation falhou: 0x{status & 0xFFFFFFFF:X}")
        return []
    else:
        return []

    # Layout: ULONG_PTR NumberOfHandles; ULONG_PTR Reserved; SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[]
    num_handles = ctypes.c_size_t.from_buffer(buf).value
    # Handles começa depois de 2 ULONG_PTR
    entry_offset = ctypes.sizeof(ctypes.c_size_t) * 2
    entry_size = ctypes.sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)
    handles = []
    for i in range(num_handles):
        try:
            entry = SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX.from_buffer(
                buf, entry_offset + i * entry_size
            )
            handles.append(entry)
        except (ValueError, IndexError):
            break
    return handles


# Cache do índice — não muda enquanto o processo tá rodando (não muda no Windows
# até reboot). Evita re-scanear a system handle table 108k× a cada chamada.
_PROCESS_TYPE_INDEX_CACHE: int | None = None


def _find_process_type_index(all_handles: list = None) -> int:
    """Descobre o ObjectTypeIndex do tipo 'Process' consultando os handles do
    próprio processo. Cacheia o resultado — Windows não muda o índice em runtime.
    all_handles: se já foi enumerado antes, passa aqui pra evitar 2ª chamada cara."""
    global _PROCESS_TYPE_INDEX_CACHE
    if _PROCESS_TYPE_INDEX_CACHE is not None:
        return _PROCESS_TYPE_INDEX_CACHE
    if not (HAS_NTDLL and HAS_KERNEL32):
        return -1
    try:
        our_pid = os.getpid()
        handles = all_handles if all_handles is not None else _query_system_handles()
        for h_entry in handles:
            if h_entry.UniqueProcessId != our_pid:
                continue
            name = _query_object_type_name(h_entry.HandleValue)
            if name and name.lower() == "process":
                _PROCESS_TYPE_INDEX_CACHE = h_entry.ObjectTypeIndex
                return _PROCESS_TYPE_INDEX_CACHE
        return -1
    except Exception as e:
        debug.dbg("Falha em _find_process_type_index", e)
        return -1


class _UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", wintypes.LPWSTR),
    ]


class _OBJECT_TYPE_INFORMATION(ctypes.Structure):
    _fields_ = [("TypeName", _UNICODE_STRING)]
    # Segue mais campos que a gente não usa — só precisamos do TypeName


def _query_object_type_name(handle_value: int) -> str | None:
    """Retorna o nome do tipo ('Process', 'File', ...) do objeto atrás do handle,
    ou None se falhar. handle_value vem da tabela de handles do NOSSO processo."""
    if not HAS_NTDLL:
        return None
    buf = ctypes.create_string_buffer(1024)
    ret_len = wintypes.ULONG(0)
    try:
        status = ntdll.NtQueryObject(
            wintypes.HANDLE(handle_value),
            ObjectTypeInformation, buf, 1024, ctypes.byref(ret_len)
        )
        if status != 0:
            return None
        info = _OBJECT_TYPE_INFORMATION.from_buffer(buf)
        return info.TypeName.Buffer or None
    except (ValueError, OSError):
        return None


def _roblox_pids() -> list[int]:
    if not HAS_PSUTIL:
        return []
    names_lower = {n.lower() for n in ROBLOX_PROCESS_NAMES}
    pids = []
    for p in psutil.process_iter(["pid", "name"]):
        try:
            n = (p.info.get("name") or "").lower()
            if n in names_lower:
                pids.append(p.info["pid"])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return pids


def _roblox_object_addresses(roblox_pids: list[int], all_handles: list) -> set:
    """Retorna o conjunto de endereços de objeto kernel (Object) que correspondem
    aos processos do Roblox. Descobre olhando NOSSOS handles: quando o Telador
    abriu um handle pro PID do Roblox, o Object aparece na tabela — casamos por
    UniqueProcessId==nosso_pid + PID do handle == Roblox. Alternativa: qualquer
    handle na tabela cujo UniqueProcessId (dono) seja o Roblox e Object aponte
    pra si mesmo — mas o processo tem handle pra si próprio, então cada Roblox
    PID cria pelo menos um Object único.

    Estratégia final (a mais simples e correta): pra cada handle na tabela cujo
    UniqueProcessId (dono do handle) == PID do Roblox e cujo HandleValue é o
    pseudo-handle -1 do próprio processo, o Object aponta pro EPROCESS do Roblox.
    Como pseudo-handle é especial e nem sempre aparece, a gente extrai TODOS os
    Objects usados como target de qualquer handle e depois checa qual é Roblox
    por outro caminho — não trivial. Solução robusta: abrir um handle nosso pro
    Roblox e ler nosso próprio Object dele (via handle table)."""
    if not (HAS_PSUTIL and HAS_KERNEL32):
        return set()

    our_pid = os.getpid()
    # Mapa: HandleValue nosso -> Object
    our_handles_to_object = {
        h.HandleValue: h.Object
        for h in all_handles
        if h.UniqueProcessId == our_pid
    }

    roblox_objects = set()
    for rpid in roblox_pids:
        # Tenta abrir handle QUERY_LIMITED (não requer admin pra maioria dos
        # processos de usuário, e SEMPRE funciona pro Roblox rodando no mesmo
        # user context).
        h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, rpid)
        if not h:
            # Retry com QUERY_INFORMATION
            h = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, rpid)
        if not h:
            continue
        try:
            # Nosso handle novo → qual Object?
            obj = our_handles_to_object.get(int(h))
            if obj:
                roblox_objects.add(obj)
        finally:
            kernel32.CloseHandle(h)
    return roblox_objects


# Processos que legitimamente abrem handles pro Roblox (não flagga).
_HANDLE_WHITELIST = {
    # AV / EDR
    "msmpeng.exe", "mssense.exe", "windefend.exe", "sense.exe",
    "avastsvc.exe", "avguard.exe", "mcshield.exe", "mbam.exe",
    "kavfsscs.exe", "eset service.exe", "esets_daemon.exe",
    "bdservicehost.exe", "sophosanti-virusserver.exe",
    # Compat / telemetria Microsoft
    "compattelrunner.exe", "wmiprvse.exe", "svchost.exe",
    "runtimebroker.exe", "backgroundtaskhost.exe",
    # Shell / gerenciadores comuns que abrem handles limitados
    "explorer.exe", "taskmgr.exe", "sihost.exe", "dwm.exe",
    "searchindexer.exe", "csrss.exe",
    # O próprio Roblox / Bloxstrap
    "robloxplayerbeta.exe", "robloxplayerlauncher.exe",
    "bloxstrap.exe", "fishstrap.exe",
    # Overlays legítimos
    "discord.exe", "nvcontainer.exe", "steam.exe", "rtss.exe",
    "obs64.exe", "obs32.exe", "obs.exe",
    # Debuggers de dev (whitelist parcial; se dev abre debugger no Roblox é seu problema)
    "devenv.exe", "code.exe",
    # O Telador
    "python.exe", "pythonw.exe", "telador.exe",
}

# Bits de acesso que caracterizam "external memory reader" no processo alvo.
# PROCESS_VM_READ = ler memória. PROCESS_VM_OPERATION+WRITE = escrever/patchar.
# PROCESS_QUERY_INFORMATION sozinho é benigno demais (task manager também usa).
_EXTERNAL_ACCESS_MASKS = PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_VM_WRITE


def scan_external_process_handles() -> dict:
    """Enumera todos os handles do Windows e flagga quem tem handle pro
    RobloxPlayerBeta com PROCESS_VM_READ / VM_WRITE / VM_OPERATION.

    Pega EXATAMENTE o que um external precisa: um handle com direito de leitura
    de memória no processo do Roblox. Handle64.exe é usermode e cheat com driver
    pode ocultar; NtQuerySystemInformation opera no NT layer e pega mais.

    Sem admin, alguns donos de handle vêm como PID sem nome — o número de handles
    e a máscara de acesso ainda são visíveis (é a informação decisiva).
    """
    name = "Handles pro Roblox (external memory reader)"
    desc = "Processos com handle PROCESS_VM_READ/WRITE no RobloxPlayerBeta"

    if not (HAS_PSUTIL and HAS_KERNEL32 and HAS_NTDLL):
        return _result(name, desc, [], error="APIs Win32/NT indisponíveis")

    rpids = _roblox_pids()
    if not rpids:
        return _result(name, desc, [], error="Roblox não está rodando — abra o jogo antes")

    all_handles = _query_system_handles()
    if not all_handles:
        return _result(name, desc, [], error="NtQuerySystemInformation falhou (rode como admin)")

    process_type_idx = _find_process_type_index(all_handles)
    roblox_objects = _roblox_object_addresses(rpids, all_handles)
    if not roblox_objects:
        return _result(name, desc, [], error="Não consegui resolver o objeto kernel do Roblox — rode como admin")

    our_pid = os.getpid()
    items = []
    seen_owners = set()

    for h in all_handles:
        if h.UniqueProcessId == our_pid:
            continue  # ignora nossos próprios handles
        if h.UniqueProcessId in rpids:
            continue  # Roblox tem handle pra si próprio → ignora
        if process_type_idx >= 0 and h.ObjectTypeIndex != process_type_idx:
            continue  # só objetos de tipo Process
        if h.Object not in roblox_objects:
            continue
        # Filtra por máscara: precisa de pelo menos um bit "dangerous"
        if not (h.GrantedAccess & _EXTERNAL_ACCESS_MASKS):
            continue

        owner_pid = int(h.UniqueProcessId)
        # dedupe por dono
        if owner_pid in seen_owners:
            continue
        seen_owners.add(owner_pid)

        # Resolve nome/exe do dono
        pname = "?"
        pexe = ""
        try:
            p = psutil.Process(owner_pid)
            pname = (p.name() or "?").lower()
            try:
                pexe = p.exe() or ""
            except (psutil.AccessDenied, PermissionError):
                pexe = "(sem acesso)"
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        if pname in _HANDLE_WHITELIST:
            continue

        # Descreve o acesso
        access_desc = []
        if h.GrantedAccess & PROCESS_VM_READ:
            access_desc.append("VM_READ")
        if h.GrantedAccess & PROCESS_VM_WRITE:
            access_desc.append("VM_WRITE")
        if h.GrantedAccess & PROCESS_VM_OPERATION:
            access_desc.append("VM_OPERATION")
        access_str = "+".join(access_desc) or f"0x{h.GrantedAccess:X}"

        # Severity: VM_WRITE/VM_OPERATION = pode PATCHEAR memória do Roblox (crava
        # CRITICAL — nenhum uso legítimo escreve na memória do Roblox). VM_READ
        # sozinho = external memory reader (HIGH).
        sev = "critical" if (h.GrantedAccess & (PROCESS_VM_WRITE | PROCESS_VM_OPERATION)) else "high"

        items.append(_item(
            label=f"External reader: {pname} (PID {owner_pid})",
            detail=f"{pexe or '(exe desconhecido)'}\n"
                   f"Processo tem handle no RobloxPlayerBeta com direito de "
                   f"{access_str} (GrantedAccess=0x{h.GrantedAccess:X}). "
                   f"External cheat precisa exatamente disso pra ler/escrever memória "
                   f"do Roblox. Whitelist cobre AV/EDR/overlays legítimos — o que sobra "
                   f"aqui é o suspeito principal do external.",
            severity=sev,
            matched=f"external-handle:{pname}",
        ))

    return _result(name, desc, items)


# ============================ (2) Working set inflado ============================

# Apps que legitimamente vivem em pastas de usuário/AppData e podem ter working
# set alto (100+ MB). Não vira false positive.
_FOOTPRINT_WHITELIST = {
    # Comunicação
    "discord.exe", "discordcanary.exe", "discordptb.exe", "slack.exe",
    "teams.exe", "msteams.exe", "whatsapp.exe", "telegram.exe", "signal.exe",
    "zoom.exe", "skype.exe",
    # Navegadores
    "chrome.exe", "msedge.exe", "msedgewebview2.exe", "firefox.exe",
    "brave.exe", "opera.exe", "opera_gx.exe", "vivaldi.exe", "arc.exe",
    # Devtools
    "code.exe", "cursor.exe", "devenv.exe", "python.exe", "pythonw.exe",
    "node.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "wt.exe",
    "git.exe", "git-bash.exe", "mintty.exe", "conhost.exe",
    # Media / criatividade
    "spotify.exe", "obs64.exe", "obs32.exe", "obs.exe", "steam.exe",
    "steamwebhelper.exe", "epicgameslauncher.exe", "galaxyclient.exe",
    "riotclientservices.exe", "leagueoflegends.exe", "vanguard.exe",
    # Launchers / anti-cheat
    "bloxstrap.exe", "fishstrap.exe", "robloxplayerbeta.exe",
    "robloxplayerlauncher.exe", "robloxstudiobeta.exe",
    # Utilidades comuns em AppData
    "1password.exe", "bitwarden.exe", "everything.exe", "flow.launcher.exe",
    "powertoys.exe", "translucenttb.exe", "lghub.exe", "lghub_agent.exe",
    "icue.exe", "razer synapse.exe", "asus_framework.exe",
    "nvcontainer.exe", "nvidia share.exe", "nvidia web helper.exe",
    "rtss.exe", "msiafterburner.exe",
}

# Paths onde apps legítimos vivem — não é "user path"
_LEGIT_PATH_PREFIXES = (
    "c:\\windows\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
)

# Paths típicos de cheat / dropper
_USER_PATH_TOKENS = (
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\downloads\\",
    "\\desktop\\",
    "\\documents\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\$recycle.bin\\",
)

# Threshold de working set. External precisa buferizar leituras — <30 MB é
# raro pra memory reader útil. Mas subimos pra 50 MB pra evitar FP com
# utilities menores que rodam em AppData.
_WS_THRESHOLD_MB = 50


def _is_exe_signed(path: str):
    """Reutiliza a verificação de assinatura do live_analysis (WinVerifyTrust
    com cache). Import atrasado pra evitar ciclo se live_analysis mudar."""
    try:
        from live_analysis import _is_dll_signed
        return _is_dll_signed(path)
    except Exception:
        return None


def scan_external_memory_footprint() -> dict:
    """Processos com Working Set > 50 MB, exe NÃO-assinado, rodando de pasta
    gravável pelo usuário, com Roblox ativo. External precisa buferizar
    leituras da memória do Roblox — RAM inflada é tell involuntário. Só flagga
    quando os 3 sinais combinam (RAM + user path + não-assinado) e Roblox está
    ativo. Whitelist cobre apps comuns em AppData.
    """
    name = "Working set de external reader"
    desc = "Processo não-assinado com RAM inflada em pasta de usuário (external buferizando Roblox)"

    if not HAS_PSUTIL:
        return _result(name, desc, [], error="psutil não instalado")

    rpids = _roblox_pids()
    if not rpids:
        return _result(name, desc, [], error="Roblox não está rodando — abra o jogo antes")

    items = []
    for proc in psutil.process_iter(["pid", "name", "exe", "create_time"]):
        try:
            pname = (proc.info.get("name") or "").lower()
            exe = proc.info.get("exe") or ""
            if not exe:
                continue
            if pname in _FOOTPRINT_WHITELIST:
                continue

            low_exe = exe.lower().replace("/", "\\")
            # Skip: dentro de path legítimo
            if low_exe.startswith(_LEGIT_PATH_PREFIXES):
                continue
            # Skip: WindowsApps / Packages / SystemApps (UWP)
            if any(tok in low_exe for tok in (
                "\\windowsapps\\", "\\systemapps\\",
                "\\appdata\\local\\packages\\",
            )):
                continue
            # Só pega quem tá em user path clássico OU em ProgramData / raiz do C
            if not any(tok in low_exe for tok in _USER_PATH_TOKENS):
                continue

            # Working set
            try:
                mi = psutil.Process(proc.info["pid"]).memory_info()
                ws_mb = mi.rss / (1024 * 1024)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            if ws_mb < _WS_THRESHOLD_MB:
                continue

            # Verifica assinatura
            signed = _is_exe_signed(exe)
            if signed is not False:
                continue  # assinado ou desconhecido → benefício da dúvida

            ts = _fmt_ts(proc.info.get("create_time") or 0)
            items.append(_item(
                label=f"External reader (pegada de RAM): {pname}",
                detail=f"PID {proc.info['pid']} · RAM {ws_mb:.0f} MB · {exe}\n"
                       f"Processo NÃO-ASSINADO em pasta de usuário com working set "
                       f"acima de {_WS_THRESHOLD_MB} MB, com Roblox ativo. External "
                       f"precisa buferizar as leituras da memória do Roblox — RAM "
                       f"inflada é tell involuntário. Whitelist cobre Discord, "
                       f"Spotify, VS Code e utilitários comuns em AppData; se caiu "
                       f"aqui, é candidato principal a external.",
                severity="medium",
                matched=f"external-footprint:{pname}",
                timestamp=ts,
            ))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception as e:
            debug.dbg("external_memory_footprint iter falhou", e)
            continue

    return _result(name, desc, items)


# ============================ (3) Thread remota no Roblox ============================

class _MEMORY_BASIC_INFORMATION_LOCAL(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


def _module_ranges_via_psutil(pid: int) -> list[tuple[int, int]]:
    """Retorna [(base, end)] dos módulos carregados no processo — via psutil,
    que já enfrenta as APIs certas. End = base + size."""
    ranges = []
    try:
        proc = psutil.Process(pid)
        for m in proc.memory_maps(grouped=False):
            path = getattr(m, "path", "") or ""
            if not path.lower().endswith((".dll", ".exe", ".acm", ".ocx", ".drv")):
                continue
            # psutil.memory_map dá "addr" no formato "start-end" (Linux) ou
            # base como int em Windows. Robusto: campos variam.
            addr = getattr(m, "addr", None) or getattr(m, "address", None)
            size = getattr(m, "size", None) or getattr(m, "rss", None) or 0
            if addr is None:
                continue
            # Normaliza addr
            if isinstance(addr, str):
                if "-" in addr:
                    base_hex, end_hex = addr.split("-", 1)
                    base = int(base_hex, 16)
                    end = int(end_hex, 16)
                    ranges.append((base, end))
                    continue
                base = int(addr, 16)
            elif isinstance(addr, int):
                base = addr
            else:
                continue
            if size:
                ranges.append((base, base + size))
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return ranges


def _module_ranges_via_virtualquery(handle) -> list[tuple[int, int]]:
    """Fallback: percorre VirtualQueryEx pegando regiões AllocationBase de tipo
    MEM_IMAGE — cada AllocationBase é uma DLL/EXE mapeada. Retorna ranges únicos."""
    MEM_IMAGE = 0x1000000
    kernel32.VirtualQueryEx.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p,
        ctypes.POINTER(_MEMORY_BASIC_INFORMATION_LOCAL), ctypes.c_size_t,
    ]
    kernel32.VirtualQueryEx.restype = ctypes.c_size_t

    mbi = _MEMORY_BASIC_INFORMATION_LOCAL()
    size_mbi = ctypes.sizeof(mbi)
    ranges: dict[int, int] = {}  # alloc_base -> highest end
    address = 0
    seen = 0
    while seen < 200000:
        res = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address),
                                      ctypes.pointer(mbi), size_mbi)
        if res == 0:
            break
        base_addr = mbi.BaseAddress or 0
        region_size = mbi.RegionSize or 0
        if region_size == 0:
            break
        if mbi.Type == MEM_IMAGE and mbi.AllocationBase:
            alloc = int(mbi.AllocationBase)
            end = base_addr + region_size
            if alloc not in ranges or end > ranges[alloc]:
                ranges[alloc] = end
        address = base_addr + region_size
        seen += 1
    return [(base, end) for base, end in ranges.items()]


def _thread_start_address(tid: int) -> int | None:
    """NtQueryInformationThread(ThreadQuerySetWin32StartAddress). Precisa abrir
    a thread com THREAD_QUERY_INFORMATION."""
    if not (HAS_KERNEL32 and HAS_NTDLL):
        return None
    h = kernel32.OpenThread(THREAD_QUERY_LIMITED_INFORMATION, False, tid)
    if not h:
        h = kernel32.OpenThread(THREAD_QUERY_INFORMATION, False, tid)
    if not h:
        return None
    try:
        addr = ctypes.c_size_t(0)
        ret_len = wintypes.ULONG(0)
        status = ntdll.NtQueryInformationThread(
            h, ThreadQuerySetWin32StartAddress,
            ctypes.byref(addr), ctypes.sizeof(addr), ctypes.byref(ret_len)
        )
        if status != 0:
            return None
        return addr.value
    finally:
        kernel32.CloseHandle(h)


def _enum_threads_of_process(pid: int) -> list[int]:
    """Retorna TIDs do processo. Usa CreateToolhelp32Snapshot pra ser
    independente do psutil (que às vezes não expõe TIDs)."""
    TH32CS_SNAPTHREAD = 0x00000004

    class THREADENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ThreadID", wintypes.DWORD),
            ("th32OwnerProcessID", wintypes.DWORD),
            ("tpBasePri", wintypes.LONG),
            ("tpDeltaPri", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
        ]

    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
    kernel32.Thread32First.restype = wintypes.BOOL
    kernel32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
    kernel32.Thread32Next.restype = wintypes.BOOL

    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if not snap or snap == wintypes.HANDLE(-1).value:
        return []
    tids = []
    try:
        te = THREADENTRY32()
        te.dwSize = ctypes.sizeof(te)
        ok = kernel32.Thread32First(snap, ctypes.byref(te))
        while ok:
            if te.th32OwnerProcessID == pid:
                tids.append(te.th32ThreadID)
            ok = kernel32.Thread32Next(snap, ctypes.byref(te))
    finally:
        kernel32.CloseHandle(snap)
    return tids


def scan_remote_threads_in_roblox() -> dict:
    """Enumera threads do Roblox e flagga as com StartAddress FORA de qualquer
    módulo carregado — assinatura de thread criada por CreateRemoteThread
    (injetor externo). Complementa scan_roblox_manual_map: thread remota fina
    (shellcode que só chama LoadLibrary e sai) não deixa PE header pra achar,
    mas deixa StartAddress fora de todo módulo.
    """
    name = "Thread remota no Roblox (injeção externa)"
    desc = "Thread do Roblox com StartAddress fora de qualquer módulo carregado"

    if not (HAS_PSUTIL and HAS_KERNEL32 and HAS_NTDLL):
        return _result(name, desc, [], error="APIs indisponíveis")

    rpids = _roblox_pids()
    if not rpids:
        return _result(name, desc, [], error="Roblox não está rodando — abra o jogo antes")

    items = []
    for rpid in rpids:
        h_proc = kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, False, rpid,
        )
        if not h_proc:
            items.append(_item(
                label=f"PID {rpid} — sem acesso",
                detail="Não consegui abrir o processo do Roblox. Rode como admin.",
                severity="low", matched="access-denied", meta_only=True,
            ))
            continue
        try:
            # 1) Ranges dos módulos
            ranges = _module_ranges_via_psutil(rpid)
            if not ranges:
                ranges = _module_ranges_via_virtualquery(h_proc)
            if not ranges:
                items.append(_item(
                    label=f"PID {rpid} — módulos não enumerados",
                    detail="Não consegui listar módulos carregados. Rode como admin.",
                    severity="low", matched="modules-unavailable", meta_only=True,
                ))
                continue

            # Ordena pra busca binária mental (não vale a pena bisect aqui,
            # <200 módulos = varredura linear é rápida)
            ranges.sort()

            def _addr_in_any_module(a: int) -> bool:
                for base, end in ranges:
                    if base <= a < end:
                        return True
                return False

            # 2) Threads e start addresses
            tids = _enum_threads_of_process(rpid)
            if not tids:
                continue
            for tid in tids:
                addr = _thread_start_address(tid)
                if addr is None or addr == 0:
                    continue
                if _addr_in_any_module(addr):
                    continue
                # Fora de todo módulo → suspeito
                items.append(_item(
                    label=f"Thread remota no Roblox (TID {tid})",
                    detail=f"PID {rpid} · StartAddress 0x{addr:X}\n"
                           f"Thread do RobloxPlayerBeta com endereço de início FORA de "
                           f"qualquer módulo carregado (nenhuma DLL/EXE cobre esse endereço). "
                           f"Assinatura clássica de CreateRemoteThread — injetor externo criou "
                           f"a thread apontando pra shellcode alocado com VirtualAllocEx. "
                           f"Complementa scan_roblox_manual_map (que olha regiões PE).",
                    severity="high",
                    matched=f"remote-thread:{addr:x}",
                ))
        finally:
            kernel32.CloseHandle(h_proc)

    return _result(name, desc, items)


# ============================ (4) Rede de processos que nunca fazem rede ============================

# Processos do Windows que, em máquina de usuário comum, NUNCA fazem TCP externa.
# Se um destes tem conexão ESTABLISHED pra IP externo, é altíssima confiança que
# o binário foi trocado (masquerading) ou o processo foi hollowed pra um cheat
# que chama pra casa. Sem FP conhecido.
_NEVER_EGRESS_PROCS = {
    "conhost.exe",       # console host — não faz rede
    "dwm.exe",           # window manager — não faz rede
    "csrss.exe",         # subsystem — não faz rede
    "wininit.exe",       # init — não faz rede
    "smss.exe",          # session manager — não faz rede
    "fontdrvhost.exe",   # font driver — não faz rede
    "lsm.exe",           # local session manager — não faz rede
    "sihost.exe",        # shell infrastructure — não faz rede TCP externa
    "textinputhost.exe", # IME — não faz rede
    "spoolsv.exe",       # spooler — não faz rede (LPD é UDP raro)
    "audiodg.exe",       # audio device graph — não faz rede
    "ctfmon.exe",        # CTF loader — não faz rede
    "dashost.exe",       # device association — não faz rede
    "wudfhost.exe",      # user-mode driver framework — não faz rede
    "searchprotocolhost.exe",  # search protocol — não faz TCP externa
    "searchfilterhost.exe",    # search filter — não faz rede
}


def _is_private_or_loopback_ip(ip: str) -> bool:
    """True pra IPs privados (RFC1918), loopback, link-local — o que NÃO conta
    como egress externo."""
    if not ip:
        return True
    ip = ip.strip()
    # IPv6
    if ":" in ip:
        low = ip.lower()
        if low in ("::", "::1"):
            return True
        # link-local fe80::/10 e unique-local fc00::/7
        if low.startswith(("fe8", "fe9", "fea", "feb", "fc", "fd")):
            return True
        return False
    # IPv4
    parts = ip.split(".")
    if len(parts) != 4:
        return True  # inválido → considera não-externo (não flagga)
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return True
    if a == 10:
        return True
    if a == 127:
        return True
    if a == 169 and b == 254:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 0:
        return True
    if a >= 224:
        return True  # multicast / reservado
    return False


def scan_kernel_only_egress() -> dict:
    """Detecta processos do Windows que NUNCA fazem rede em máquina de usuário
    comum (conhost, dwm, csrss, wininit, fontdrvhost, sihost, spoolsv, audiodg…)
    com conexão TCP ESTABLISHED pra IP externo. Assinatura de nome camuflado:
    o cheat foi renomeado pra `conhost.exe` (que ninguém suspeita) e faz
    phone-home pra servidor de auth/config.

    FP zero conhecido: esses binários simplesmente não fazem TCP externa em
    máquina limpa. Sinal HIGH e CRAVA sozinho (peso alto no Confidence Engine).
    """
    name = "Rede: processo do sistema com egress externo"
    desc = "Processo do Windows que nunca faz rede com conexão TCP externa (cheat com nome camuflado)"

    if not HAS_PSUTIL:
        return _result(name, desc, [], error="psutil não instalado")

    try:
        conns = psutil.net_connections(kind="tcp")
    except (psutil.AccessDenied, PermissionError):
        return _result(name, desc, [], error="Acesso negado ao net_connections (rode como admin)")
    except Exception as e:
        return _result(name, desc, [], error=str(e))

    items = []
    seen_keys = set()

    for c in conns:
        if c.status != psutil.CONN_ESTABLISHED:
            continue
        if not c.raddr:
            continue
        rip = c.raddr.ip if hasattr(c.raddr, "ip") else c.raddr[0]
        rport = c.raddr.port if hasattr(c.raddr, "port") else c.raddr[1]
        if _is_private_or_loopback_ip(rip):
            continue

        pid = c.pid or 0
        if pid == 0:
            continue

        try:
            proc = psutil.Process(pid)
            pname = (proc.name() or "").lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

        if pname not in _NEVER_EGRESS_PROCS:
            continue

        try:
            pexe = proc.exe() or ""
        except (psutil.AccessDenied, PermissionError):
            pexe = "(sem acesso)"

        key = (pname, pid, rip, rport)
        if key in seen_keys:
            continue
        seen_keys.add(key)

        items.append(_item(
            label=f"{pname} com conexão externa: {rip}:{rport}",
            detail=f"PID {pid} · {pexe}\n"
                   f"Processo '{pname}' fez conexão TCP ESTABLISHED pra {rip}:{rport}. "
                   f"Em máquina de usuário comum esse processo não faz rede — a conexão "
                   f"só existe se o binário foi trocado (masquerading) ou hollowed pra um "
                   f"cheat que chama pra casa (servidor de auth/config do external). "
                   f"Confirme o path do exe: '{pexe}' deve estar em System32.",
            severity="high",
            matched=f"kernel-only-egress:{pname}",
        ))

    return _result(name, desc, items)


# ============================ Chain ============================


# ============================ (7) Overlay POPUP+TOPMOST (D3D/DComp) ============================

# Externals PRIVATE frequentemente evitam LAYERED+TRANSPARENT+TOPMOST porque isso é o
# padrão que scan_overlay_windows já pega. Alternativa comum: janela WS_POPUP topmost
# renderizada com D3D/DComp direto — sem transparency style. Pega isso complementar.
#
# Estilos: WS_POPUP (0x80000000) sem WS_CAPTION nem WS_THICKFRAME + WS_EX_TOPMOST.
# Anti-FP: whitelist tight de processos que legitimamente usam popup topmost
# (Rainmeter, Wallpaper Engine, tray tooltips, IME candidates, DesktopWindowXamlSource…).

WS_POPUP        = 0x80000000
WS_CAPTION      = 0x00C00000
WS_THICKFRAME   = 0x00040000
WS_VISIBLE      = 0x10000000
GWL_STYLE       = -16
GWL_EXSTYLE_LOC = -20
WS_EX_TOPMOST_LOC = 0x00000008
WS_EX_LAYERED_LOC = 0x00080000
WS_EX_TOOLWINDOW  = 0x00000080
WS_EX_NOACTIVATE  = 0x08000000

# Whitelist de processos que legitimamente têm janela POPUP+TOPMOST sem transparency.
# Foi montada com base em varredura de PC limpo (todos os hits foram estes).
_POPUP_OVERLAY_WHITELIST = {
    # Shell / Windows
    "explorer.exe", "textinputhost.exe", "shellexperiencehost.exe",
    "startmenuexperiencehost.exe", "searchhost.exe", "searchapp.exe",
    "sihost.exe", "runtimebroker.exe", "applicationframehost.exe",
    "systemsettings.exe", "lockapp.exe", "peopleexperiencehost.exe",
    "widgets.exe", "widgetservice.exe", "yourphone.exe",
    "phoneexperiencehost.exe", "gamebar.exe", "xboxgamebar.exe",
    "gamebarft.exe", "snippingtool.exe", "screenclippinghost.exe",
    "notificationhosterror.exe", "smartscreen.exe",
    # UI comuns
    "ctfmon.exe", "dwm.exe", "logonui.exe",
    # Gráficos / RGB / overlay legítimo
    "nvcontainer.exe", "nvidia share.exe", "nvidia web helper.exe",
    "radeonsoftware.exe", "amddvr.exe",
    "rtss.exe", "msiafterburner.exe", "rivatunerstatisticsserver.exe",
    "rainmeter.exe", "wallpaper32.exe", "wallpaper64.exe",
    "translucenttb.exe", "flow.launcher.exe", "powertoys.exe",
    "powertoys.awake.exe", "everything.exe",
    # Comunicação
    "discord.exe", "discordcanary.exe", "discordptb.exe",
    "slack.exe", "teams.exe", "msteams.exe", "whatsapp.exe",
    # Captura / streaming
    "obs64.exe", "obs32.exe", "obs.exe", "streamlabs obs.exe",
    "xsplit.core.exe",
    # Steam / launchers
    "steam.exe", "gameoverlayui.exe", "steamwebhelper.exe",
    "epicgameslauncher.exe", "galaxyclient.exe",
    # Password managers (autofill popups)
    "1password.exe", "bitwarden.exe",
    # IMEs
    "chsime.exe", "chtime.exe", "imjpuex.exe",
    # Editors
    "code.exe", "cursor.exe", "devenv.exe", "notepad.exe",
    "notepad++.exe", "sublime_text.exe",
    # Browsers (popup blockers, extensions)
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
    "opera.exe", "vivaldi.exe", "arc.exe",
    # Anti-Virus
    "msmpeng.exe", "avastui.exe", "avguard.exe",
    "windefend.exe", "securityhealthsystray.exe",
    # O Roblox
    "robloxplayerbeta.exe", "robloxplayerlauncher.exe",
    "bloxstrap.exe", "fishstrap.exe",
    "robloxstudiobeta.exe",
}


def _get_window_rect(hwnd) -> tuple[int, int, int, int]:
    try:
        user32 = ctypes.windll.user32
        r = wintypes.RECT()
        if user32.GetWindowRect(hwnd, ctypes.byref(r)):
            return (r.left, r.top, r.right, r.bottom)
    except Exception:
        pass
    return (0, 0, 0, 0)


def scan_popup_overlays() -> dict:
    """Detecta janelas POPUP+TOPMOST fora da whitelist. Complementa
    scan_overlay_windows (que pega LAYERED+TRANSPARENT+TOPMOST) pegando o
    padrão mais moderno de overlay: renderização D3D/DComp em janela popup
    sem transparency style. Externals PRIVATE frequentemente usam isso
    porque o padrão LAYERED já é bem conhecido/detectado.
    """
    name = "Overlay D3D/DComp (janela POPUP+TOPMOST)"
    desc = "Janela POPUP+TOPMOST fora de whitelist — ESP renderizado direto no D3D"

    if not (HAS_PSUTIL and HAS_KERNEL32):
        return _result(name, desc, [], error="APIs indisponíveis")

    try:
        user32 = ctypes.windll.user32
    except (AttributeError, OSError):
        return _result(name, desc, [], error="user32 indisponível")

    items = []
    seen_pids = set()

    EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, ctypes.c_void_p)

    def cb(hwnd, _):
        try:
            if not user32.IsWindowVisible(hwnd):
                return True
            style = user32.GetWindowLongW(hwnd, GWL_STYLE) & 0xFFFFFFFF
            ex = user32.GetWindowLongW(hwnd, GWL_EXSTYLE_LOC) & 0xFFFFFFFF

            # Precisa ser POPUP + TOPMOST. Se tem WS_CAPTION/THICKFRAME é janela
            # de app normal (não overlay).
            if not (style & WS_POPUP):
                return True
            if style & (WS_CAPTION | WS_THICKFRAME):
                return True
            if not (ex & WS_EX_TOPMOST_LOC):
                return True
            # LAYERED+TRANSPARENT já é pego por scan_overlay_windows — deixa
            # esse scanner focar no COMPLEMENTAR (POPUP+TOPMOST sem LAYERED).
            if ex & WS_EX_LAYERED_LOC:
                return True

            # Precisa ter tamanho não-trivial (>50x50 pra evitar controles minúsculos)
            l, t, r, b = _get_window_rect(hwnd)
            w, h = (r - l), (b - t)
            if w < 50 or h < 50:
                return True

            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            pid_val = pid.value
            if pid_val in seen_pids:
                return True
            seen_pids.add(pid_val)

            try:
                pname = psutil.Process(pid_val).name().lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pname = "?"

            if pname in _POPUP_OVERLAY_WHITELIST:
                return True

            # Título (contexto)
            length = user32.GetWindowTextLengthW(hwnd)
            title = ""
            if length > 0:
                buf = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, buf, length + 1)
                title = buf.value or ""

            # Class name (mais forte que title — externals costumam ter class name random)
            cls_buf = ctypes.create_unicode_buffer(256)
            user32.GetClassNameW(hwnd, cls_buf, 256)
            cls = cls_buf.value or ""

            items.append(_item(
                label=f"Overlay POPUP+TOPMOST: {pname}",
                detail=f"PID {pid_val} · janela {w}x{h} · class '{cls}'"
                       + (f" · título '{title}'" if title else " · sem título"),
                severity="medium",
                matched=f"popup-overlay:{pname}",
            ))
        except Exception as e:
            debug.dbg("popup overlay scan falhou", e)
        return True

    try:
        user32.EnumWindows(EnumWindowsProc(cb), 0)
    except Exception as e:
        return _result(name, desc, [], error=str(e))

    return _result(name, desc, items)


# ============================ (8) Processo iniciado APÓS o Roblox ============================

# Segundos de folga: process manager do Windows spawn múltiplos processos em cascata
# ao abrir o Roblox (crashhandler, bloxstrap helper, etc). 3s absorve isso.
_POST_ROBLOX_GRACE_SEC = 3


def scan_post_roblox_processes() -> dict:
    """Flagga processos NÃO-assinados, em user path, que começaram DEPOIS do
    Roblox. External só existe pra atacar o Roblox — típico rodar o external
    depois de abrir o jogo. Sinal comportamental sozinho não crava (MEDIUM),
    mas eleva no correlation quando combinado com handle/overlay/footprint.
    """
    name = "Processo iniciado após o Roblox"
    desc = "Processo não-assinado em user path que começou depois do RobloxPlayerBeta"

    if not HAS_PSUTIL:
        return _result(name, desc, [], error="psutil não instalado")

    # Menor create_time entre PIDs do Roblox
    roblox_min_ts = None
    for p in psutil.process_iter(["pid", "name", "create_time"]):
        try:
            n = (p.info.get("name") or "").lower()
            if n in {rn.lower() for rn in ROBLOX_PROCESS_NAMES}:
                ct = p.info.get("create_time")
                if ct is None:
                    continue
                if roblox_min_ts is None or ct < roblox_min_ts:
                    roblox_min_ts = ct
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if roblox_min_ts is None:
        return _result(name, desc, [], error="Roblox não está rodando")

    # Threshold: strictly after (com grace pra spawn em cascata do launcher)
    cutoff = roblox_min_ts + _POST_ROBLOX_GRACE_SEC

    items = []
    for proc in psutil.process_iter(["pid", "name", "exe", "create_time"]):
        try:
            pname = (proc.info.get("name") or "").lower()
            ct = proc.info.get("create_time") or 0
            if ct <= cutoff:
                continue
            exe = proc.info.get("exe") or ""
            if not exe:
                continue

            # Skip: whitelist ampla (o mesmo do footprint + roblox helpers comuns)
            if pname in _FOOTPRINT_WHITELIST:
                continue
            # Skip: crash handler e helpers do Roblox
            if pname in {"robloxcrashhandler.exe", "robloxlauncher.exe"}:
                continue

            low_exe = exe.lower().replace("/", "\\")
            if low_exe.startswith(_LEGIT_PATH_PREFIXES):
                continue
            if any(tok in low_exe for tok in (
                "\\windowsapps\\", "\\systemapps\\",
                "\\appdata\\local\\packages\\",
            )):
                continue
            # Só flagga se está em user path (Downloads/Temp/Desktop/...)
            if not any(tok in low_exe for tok in _USER_PATH_TOKENS):
                continue

            # Assinatura: só flagga se COMPROVADAMENTE não-assinado
            signed = _is_exe_signed(exe)
            if signed is not False:
                continue

            ts = _fmt_ts(ct)
            delta = ct - roblox_min_ts
            items.append(_item(
                label=f"Processo pós-Roblox: {pname}",
                detail=f"PID {proc.info['pid']} · iniciado {delta:.1f}s após o Roblox · {exe}\n"
                       f"Processo NÃO-assinado em pasta de usuário, iniciado DEPOIS do "
                       f"Roblox. Sinal comportamental: cheat externo tipicamente roda "
                       f"depois de abrir o jogo pra ter alvo. Sozinho é MEDIUM; combinado "
                       f"com handle/overlay/footprint no correlation vira HIGH/CRITICAL.",
                severity="medium",
                matched=f"post-roblox:{pname}",
                timestamp=ts,
            ))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception as e:
            debug.dbg("post-roblox iter falhou", e)
            continue

    return _result(name, desc, items)


# ============================ (9) Named pipes suspeitos ============================

# Named pipes conhecidos do Windows / apps comuns. Match por prefixo/substring.
_PIPE_WHITELIST_TOKENS = (
    # Windows core
    "microsoft-", "mojoshm.", "wkssvc", "trkwks", "eventlog", "epmapper",
    "lsass", "spoolss", "ntsvcs", "sync-", "winreg", "srvsvc",
    "netlogon", "keysvc", "protected_storage", "browser",
    "atsvc", "policyagent", "wmi", "psexesvc",
    "term", "cepinf", "chrome.", "discord-", "vscode-",
    "cliprdr", "rdpdr", "tsc-", "iisipm",
    # Apps comuns
    "roblox", "hyperion", "byfron",
    "onedrive", "office", "excel", "word", "outlook",
    "slack.", "electron", "steam", "epicgames",
    # Dev tools
    "dbg-", "python-", "node-ipc", "npm-", "cargo-",
    "sccm", "docker", "wsl-", "vpnkit", "cnc-",
)


def scan_suspicious_named_pipes() -> dict:
    """Enumera named pipes ativos e flagga os com nome não-Microsoft.

    Externals frequentemente usam named pipes pra IPC entre reader (memory) e
    renderer (overlay) — arquitetura de 2+ processos torna cada um mais leve
    (menor working set individual) e desacopla a detecção. Nome do pipe é
    tipicamente random/GUID e não bate whitelist de app conhecido.

    Sozinho é MEDIUM: existem apps custom que criam pipes com nome próprio.
    Combinado no correlation, eleva o veredito do PID dono.
    """
    name = "Named pipes suspeitos (IPC de external)"
    desc = "Pipes com nome não-Microsoft/não-app-conhecido — IPC típica de reader/renderer"

    if not HAS_KERNEL32:
        return _result(name, desc, [], error="kernel32 indisponível")

    try:
        pipes = os.listdir(r"\\.\pipe\\")
    except OSError as e:
        return _result(name, desc, [], error=f"não consegui listar pipes: {e}")

    items = []
    seen_pipes = set()

    # Estratégia: só reporta pipes com nome COMPROVADAMENTE random. Testes:
    # (a) hex puro >= 12 chars (a-f0-9)
    # (b) GUID no formato canônico
    # (c) base64/base32 puro >= 20 chars SEM vogais consecutivas ou padrão CamelCase
    # Pipes com palavras em inglês (WiFiNetworkManagerTask, WidgetsCommandPipe)
    # NÃO batem — apps do Windows criam pipes com nomes descritivos e a gente
    # não reporta esses. Externals privados costumam usar random-hex ou GUID.
    random_hex = re.compile(r"^[0-9a-f]{12,}$", re.IGNORECASE)
    guid_pipe = re.compile(
        r"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$"
    )
    # Contém padrão CamelCase (Xxx…Xxx) ou palavras — não é random
    camel_or_word = re.compile(r"[a-z][A-Z]|[A-Z]{2,}[a-z]")

    for pname in pipes:
        low = pname.lower()
        if low in seen_pipes:
            continue
        seen_pipes.add(low)

        if any(tok in low for tok in _PIPE_WHITELIST_TOKENS):
            continue
        if len(pname) <= 3 or pname.isdigit():
            continue

        base_name = pname.split("\\")[-1].split("/")[-1]

        # CamelCase / palavras em inglês → não é random
        if camel_or_word.search(base_name):
            continue

        is_random = bool(random_hex.match(base_name) or
                         guid_pipe.match(base_name))
        if not is_random:
            continue

        items.append(_item(
            label=f"Named pipe suspeito: {pname}",
            detail=f"\\\\.\\pipe\\{pname}\n"
                   f"Pipe com nome random (hex/base32/GUID) — externals com arquitetura "
                   f"reader+renderer usam pipes com nomes randomizados no build pra IPC. "
                   f"Sozinho é MEDIUM; correlação eleva o veredito do PID dono.",
            severity="medium",
            matched=f"pipe:{low[:32]}",
        ))

    return _result(name, desc, items)


# ============================ (10) Executável com nome aleatório ============================

import re as _re_module

# Padrões clássicos de exe gerado com nome random pra escapar de blacklist:
#  - [a-f0-9]{8,}\.exe   → hex random
#  - [A-Za-z0-9]{20,}\.exe → base64/base32
#  - {GUID}.exe          → guid
_RANDOM_NAME_PATTERNS = (
    _re_module.compile(r"^[a-f0-9]{8,64}\.exe$", _re_module.IGNORECASE),
    _re_module.compile(r"^[A-Za-z0-9+/=_-]{20,64}\.exe$"),
    _re_module.compile(r"^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                       r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}\.exe$"),
    # Prefixos de temp
    _re_module.compile(r"^tmp[0-9a-fA-F]{4,}\.exe$", _re_module.IGNORECASE),
)


def _is_random_exe_name(name: str) -> bool:
    for pat in _RANDOM_NAME_PATTERNS:
        if pat.match(name):
            return True
    return False


def scan_random_name_executables() -> dict:
    """Processos rodando com .exe de nome random (hex/base32/GUID) em user path.
    External private frequentemente é distribuído com nome random gerado no
    build pra escapar de blacklist e telemetria por nome.

    Sozinho é MEDIUM. No correlation, se esse mesmo PID também tem handle no
    Roblox ou overlay, crava.
    """
    name = "Executável com nome aleatório"
    desc = "Processo rodando .exe com nome hex/base32/GUID em user path"

    if not HAS_PSUTIL:
        return _result(name, desc, [], error="psutil não instalado")

    items = []
    for proc in psutil.process_iter(["pid", "name", "exe", "create_time"]):
        try:
            pname = (proc.info.get("name") or "").lower()
            exe = proc.info.get("exe") or ""
            if not exe:
                continue
            if not _is_random_exe_name(pname):
                continue

            low_exe = exe.lower().replace("/", "\\")
            if low_exe.startswith(_LEGIT_PATH_PREFIXES):
                continue
            if any(tok in low_exe for tok in (
                "\\windowsapps\\", "\\systemapps\\",
                "\\appdata\\local\\packages\\",
            )):
                continue

            signed = _is_exe_signed(exe)
            # Se ASSINADO, provavelmente instalador legítimo → skip.
            if signed is True:
                continue

            ts = _fmt_ts(proc.info.get("create_time") or 0)
            items.append(_item(
                label=f"Nome random: {pname}",
                detail=f"PID {proc.info['pid']} · {exe}\n"
                       f"Executável com nome hex/base32/GUID em user path. Externals "
                       f"private frequentemente são distribuídos com nome random pra "
                       f"escapar de blacklist e telemetria. Combinado com handle/overlay "
                       f"no correlation, crava external.",
                severity="medium",
                matched=f"random-name:{pname}",
                timestamp=ts,
            ))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception as e:
            debug.dbg("random-name iter falhou", e)
            continue

    return _result(name, desc, items)



# ============================ Correlacao de sinais (Winter/Matcha/etc) ============================

def _roblox_pids_correlation() -> list:
    if not HAS_PSUTIL:
        return []
    names_lower = {n.lower() for n in _RBX_NAMES}
    pids = []
    for p in psutil.process_iter(["pid", "name"]):
        try:
            n = (p.info.get("name") or "").lower()
            if n in names_lower:
                pids.append(p.info["pid"])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return pids


def _extract_pid_from_item(it: dict) -> int:
    for key in ("label", "detail"):
        text = it.get(key, "") or ""
        m = re.search(r"PID (\d+)", text)
        if m:
            return int(m.group(1))
    return 0


def _collect_suspect_pids() -> dict:
    """Roda os sinais de external (catalogo + tecnicos) e agrega por PID.
    Um PID em 2+ fontes = external quase certo."""
    suspects = {}

    def _add(pid, source):
        if pid <= 0:
            return
        suspects.setdefault(pid, []).append(source)

    for scanner_fn, tag in [
        (scan_external_processes, "family-catalog"),
        (scan_external_process_handles, "handle"),
        (scan_external_memory_footprint, "footprint"),
        (scan_kernel_only_egress, "egress"),
        (scan_popup_overlays, "popup-overlay"),
        (scan_post_roblox_processes, "post-roblox"),
        (scan_random_name_executables, "random-name"),
    ]:
        try:
            r = scanner_fn()
            for it in r.get("items", []):
                if it.get("meta_only"):
                    continue
                pid = _extract_pid_from_item(it)
                if pid:
                    _add(pid, tag)
        except Exception as e:
            debug.dbg("correlation " + tag + " scan falhou", e)

    try:
        import live_analysis as _la
        r = _la.scan_overlay_windows()
        for it in r.get("items", []):
            if it.get("meta_only"):
                continue
            pid = _extract_pid_from_item(it)
            if pid:
                _add(pid, "overlay-layered")
    except Exception as e:
        debug.dbg("correlation overlay-layered scan falhou", e)

    return suspects


def scan_external_correlation() -> dict:
    """Correlaciona sinais de external no MESMO PID. Nenhum app legitimo cai em 2+ sinais.

    Sinais:
      - family-catalog : bate _FAMILY_CATALOG (Matcha/Severe/DX9/Serotonin/...)
      - handle         : handle PROCESS_VM_READ no RobloxPlayerBeta
      - footprint      : RAM > 50 MB + user path + nao-assinado
      - egress         : conhost/dwm/csrss com TCP externa
      - popup-overlay  : janela POPUP+TOPMOST (D3D/DComp overlay)
      - overlay-layered: janela LAYERED+TRANSPARENT+TOPMOST (ESP classico)
      - post-roblox    : nao-assinado, user path, iniciado depois do Roblox
      - random-name    : .exe com nome hex/base32/GUID em user path

    Regras: 3+ sinais = CRITICAL (crava sozinho); 2 sinais = HIGH. Externals
    PRIVATE (Winter, etc, sem match de nome) caem aqui pela combinacao de
    handle + overlay + footprint.
    """
    name = "Correlacao de sinais de external (private cheats, Winter-class)"
    desc = "Multiplos sinais convergindo no mesmo PID"

    if not HAS_PSUTIL:
        return _result(name, desc, [], error="psutil nao instalado")

    suspects = _collect_suspect_pids()
    if not suspects:
        return _result(name, desc, [])

    items = []
    for pid, sources in suspects.items():
        uniq = sorted(set(sources))
        if len(uniq) < 2:
            continue
        pname = "?"
        pexe = ""
        pcreated = ""
        try:
            p = psutil.Process(pid)
            pname = (p.name() or "?").lower()
            try:
                pexe = p.exe() or ""
            except (psutil.AccessDenied, PermissionError):
                pexe = "(sem acesso)"
            try:
                pcreated = _fmt_ts(p.create_time())
            except Exception:
                pass
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        sev = "critical" if len(uniq) >= 3 else "high"
        sources_str = " + ".join(uniq)
        detail_txt = pexe + " (iniciado " + (pcreated or "?") + ")"
        detail_txt += "\nSinais convergentes: " + sources_str + " (" + str(len(uniq)) + " fontes)."
        detail_txt += "\nNenhum app legitimo cai em 2+ sinais de external. Este e o alvo."
        items.append(_item(
            label="EXTERNAL confirmado por correlacao: " + pname + " (PID " + str(pid) + ")",
            detail=detail_txt,
            severity=sev,
            matched="external-corr:" + pname + ":" + str(len(uniq)),
            timestamp=pcreated,
        ))

    items.sort(key=lambda i: -int(i["matched"].split(":")[-1]))
    return _result(name, desc, items)


ALL_EXTERNAL_SCANNERS = [
    # Catalogo + artefatos (3.43.5-3.43.7)
    scan_external_processes,
    scan_external_artifacts,
    # Deteccoes tecnicas (3.44.0)
    scan_external_process_handles,
    scan_external_memory_footprint,
    scan_remote_threads_in_roblox,
    scan_kernel_only_egress,
    scan_popup_overlays,
    scan_post_roblox_processes,
    scan_suspicious_named_pipes,
    scan_random_name_executables,
    scan_external_correlation,  # roda por ultimo - agrega dos outros
]
