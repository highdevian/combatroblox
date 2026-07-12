"""
Confidence Engine — modelo Evidence/Cluster.

A arquitetura velha era:
    scanners → findings (lista de items soltos) → verdict global

O problema: o mesmo executor aparecia em 5 scanners diferentes, com
`matched` ligeiramente diferente ("solara", "solara.exe", "solara executor"),
e o cross_correlate antigo (por keyword) tratava cada variante como
cluster separado.

A arquitetura nova é:
    scanners → findings → Evidence[] → Cluster[] (por target_id) → verdict

Cada Evidence é uma observação atômica. Várias Evidence sobre o MESMO
target_id viram 1 Cluster. O Cluster tem score próprio, lista de fontes
distintas, e verdict próprio.

Vantagem prática:
  - 1 executor com 5 evidências de 5 fontes vira 1 cluster CONFIRMED,
    não 5 hits que precisam ser interpretados.
  - Cap automático: cluster com 1 fonte só nunca chega a CONFIRMED
    (exceto critical), reduzindo FP.
  - Hash batendo num executor conhecido = critical instantâneo.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Optional


# ============================== Source weights ==============================
# Quão confiável é a fonte. Combina com severity pra calcular score do
# cluster. Calibrado pra refletir a realidade forense Windows:
#   - kernel/process running NOW = quase fato
#   - Prefetch/BAM/USN = log direto do kernel
#   - ShimCache/DNS cache = stale/volátil, peso menor
#   - Heurísticas (anti-forense, anti-VM) = sinal, não prova

SOURCE_WEIGHTS: dict[str, float] = {
    # Kernel-level / fatos observáveis
    "kernel_drivers":       0.95,
    "live_processes":       0.95,
    "live_dll_injection":   0.90,
    "dma_hardware":         0.80,   # ID de placa FPGA/USB de DMA no registro (heurístico — pode spoofar)
    "external_cheat":       0.85,   # processo/artefato de external aimbot/ESP (fora do cliente Roblox)
    "external_corroboration": 0.55, # bônus sintético external+forense (não inventa cluster)
    "yara_signature":       0.85,   # match de conteúdo binário (símbolos de exploit/injeção)
    "event_log_exec":       0.88,   # 7045/4104 — execução/instalação logada pelo kernel
    "defender_detection":   0.90,   # 1116/1117 — o próprio AV detectou o hacktool/executor
    "executor_structure":   0.80,   # comportamental — exe não-assinado + runtime web
    "launcher_integrity":   0.90,   # binário oficial do Roblox adulterado / launcher falso
    "usn_journal":          0.95,
    "bam":                  0.90,
    "prefetch":             0.90,

    # Registry / arquivos do Windows — sólidos
    "amcache":              0.85,
    "userassist":           0.70,
    "muicache":             0.65,
    "shimcache":            0.50,   # atualiza só no shutdown
    "jumplists":            0.70,
    "srum":                 0.80,

    # Roblox-specific — forte (são logs do próprio cliente)
    "roblox_logs":          0.85,
    "roblox_bytecode":      0.80,
    "bloxstrap":            0.75,

    # Histórico / cache — intent forte mas indireto
    "browser_history":      0.80,
    "downloads":            0.85,
    "dns_cache":            0.60,
    "discord_cache":        0.60,

    # Anti-forense / anti-evasão — heurísticas
    "anti_forense":         0.70,
    "anti_evasion":         0.65,
    "powershell_history":   0.70,
    "command_history":      0.70,
    "persistence":          0.75,
    "peripherals":          0.70,
    "network":              0.70,
    "fresh_install":        0.55,
    "scripts":              0.65,
    "recycle_bin":          0.75,
    "removable_media":      0.78,
    "user_accounts":        0.60,
    "defender_tampering":   0.80,
    "clock_tampering":      0.70,
    "service_state":        0.85,   # serviço crítico parado runtime (eventlog/DPS/Diagtrack)
    "operator_seam":        0.90,   # costura de operador: degrau de skill + troca de IP na mesma conta
    "hidden_files":         0.65,
    "filesystem":           0.70,

    # v3.44.0 — external cheat detection técnica
    "external_reader":      0.92,   # handle PROCESS_VM_READ apontando pro Roblox
    "external_footprint":   0.72,   # working set inflado + user path + não-assinado
    "remote_thread":        0.90,   # thread no Roblox com StartAddress fora de módulos
    "kernel_only_egress":   0.95,   # conhost/dwm/csrss com TCP externa — FP zero
    "external_correlation": 0.98,   # 2+ sinais no mesmo PID — nenhum app legítimo cai em 2
    "popup_overlay":        0.75,   # POPUP+TOPMOST (D3D/DComp) — external private moderno
    "post_roblox_proc":     0.70,   # não-assinado iniciado após Roblox
    "suspicious_pipe":      0.60,   # named pipe random — IPC reader/renderer
    "random_name_exe":      0.75,   # nome hex/base32/GUID em user path
    "user_path_network":    0.88,   # não-assinado user path + TCP pública (loader)
    "suspicious_ancestry":  0.72,   # spawn shell→unsigned perto da sessão Roblox

    # v3.44.0 — forense pós-mortem (sobrevive a cleaner)
    "defender_history":     0.92,   # Defender viu o exe — sobrevive a "Clear History"
    "dxshader_burst":       0.55,   # burst de shader D3D — comportamental
    "wer_crash":            0.88,   # exe crashou de user path — persistente
    "reliability_monitor":  0.60,   # RAC/SUM — ponteiro pra perfmon /rel

    # v3.46.0 — Tier S state-based (evadir custa desligar Windows security)
    "dse_state":            0.95,   # BCD testsigning/nointegritychecks ligados
    "vbs_disabled":         0.95,   # VBS/HVCI desativados — cheater precisa disso
    "roblox_rwx_page":      0.90,   # página RWX dentro de RobloxPlayerBeta.exe (patching)
    "activities_cache":     0.85,   # Timeline SQLite — cleaner popular não limpa

    # v3.47.0 — Tier A behavioral (forçar cheater a mudar arquitetura)
    "dropper_task":         0.80,   # task recente + AtLogon + exe user-path
    "amsi_bypass":          0.92,   # AmsiScanBuffer patcheada no PowerShell
    "apc_injection":        0.85,   # DLL fora de path legítimo no Roblox
}

DEFAULT_SOURCE_WEIGHT = 0.65


# ============================== Aliases ==============================
# Mapa de variantes → ID canônico de executor.
# Sem isso, "solara", "solara.exe", "solara executor", "solara hub"
# viram 4 clusters separados — exatamente o que mata o veredito unificado.
# Build automatico a partir de EXECUTOR_KEYWORDS no _build_aliases().

# Sufixos que removemos pra reduzir variantes ao nome canônico.
# Ordem importa — sufixos mais longos primeiro pra match guloso.
_CANONICAL_SUFFIXES = [
    "-bootstrapper",
    " bootstrapper",
    "bootstrapper",
    " executor",
    " exec",
    " launcher",
    "launcher",
    " hub",
    " external",
    "-external",
    "_external",
    " beta",
    "-beta",
    "_beta",
    " loader",
    "-loader",
    "_loader",
    ".exe",
    ".dll",
    ".cx",
    ".cc",
    ".dev",
    ".lat",
    ".lol",
    ".now",
    ".gg",
]

# Tokens que NÃO devem ser canonizados (são distintos por design).
# Ex: "arceus x" não pode virar "arceus" (palavra comum, pokémon).
_DO_NOT_CANONICALIZE = {
    "arceus x", "arceusx",
    "oxygen u",
    "trigon evo",
    "delta executor", "delta exploit",  # delta sozinho é comum demais
    # external genérico — não colapsar pra "external"/"roblox"
    "external aimbot", "external esp", "external cheat",
    "roblox external", "robloxexternal",
}

# Famílias de EXTERNAL cheat — catálogo canônico em external_scanner
# (pesquisa pública 2024-2026). Import por referência: signatures.json merge
# muta o mesmo dict.
try:
    from external_scanner import (
        EXTERNAL_ALIAS_MAP as EXTERNAL_ALIAS_OVERRIDES,
        EXTERNAL_FAMILY_LABELS as _EXTERNAL_FAMILY_LABELS,
        EXTERNAL_FAMILY_IDS as EXTERNAL_FAMILY_CANONICALS,
    )
except ImportError:  # pragma: no cover
    EXTERNAL_FAMILY_CANONICALS = frozenset()
    EXTERNAL_ALIAS_OVERRIDES = {}
    _EXTERNAL_FAMILY_LABELS = {}


def _canonicalize_executor_name(name: str) -> str:
    """
    Normaliza variantes ao nome canônico:
      "solara.exe" → "solara"
      "Solara Executor" → "solara"
      "wave.cx" → "wave"
      "solaraexec" → "solara"  (sufixo colado)
      "arceus x" → "arceus x"  (preservado)
    """
    if not name:
        return ""
    s = name.strip().lower()
    if s in _DO_NOT_CANONICALIZE:
        return s
    for suf in _CANONICAL_SUFFIXES:
        if s.endswith(suf):
            s = s[: -len(suf)].strip()
            break
    # Sufixo "exec" colado (sem hífen/espaço): "solaraexec" → "solara",
    # "waveexec" → "wave". Só aplica se a base remanescente tem ≥3 chars
    # pra evitar quebrar nomes muito curtos.
    if s.endswith("exec"):
        candidate = s[:-4].rstrip(" -_")
        if len(candidate) >= 3:
            s = candidate
    return s


def resolve_external_family(matched: str) -> Optional[str]:
    """Se o matched aponta pra família external conhecida, retorna o ID canônico."""
    if not matched:
        return None
    key = matched.strip().lower()
    # Prefixo dos scanners external_scanner
    for prefix in ("external-proc:", "external-path:"):
        if key.startswith(prefix):
            rest = key[len(prefix):]
            family = rest.split(":", 1)[0].strip()
            if family in EXTERNAL_FAMILY_CANONICALS:
                return family
            if family and family != "custom":
                return family
            if ":" in rest:
                token = rest.split(":", 1)[1]
                return resolve_external_family(token)
            return None
    if key in EXTERNAL_ALIAS_OVERRIDES:
        return EXTERNAL_ALIAS_OVERRIDES[key]
    base = os.path.basename(key.replace("/", "\\"))
    if base in EXTERNAL_ALIAS_OVERRIDES:
        return EXTERNAL_ALIAS_OVERRIDES[base]
    canon = _canonicalize_executor_name(key)
    if canon in EXTERNAL_ALIAS_OVERRIDES:
        return EXTERNAL_ALIAS_OVERRIDES[canon]
    if canon in EXTERNAL_FAMILY_CANONICALS:
        return canon
    return None


def external_family_label(family: str) -> str:
    return _EXTERNAL_FAMILY_LABELS.get(family, f"{family} (external)")


_aliases_cache: Optional[dict[str, str]] = None


def _build_aliases() -> dict[str, str]:
    """Constrói o mapa alias → canonical a partir de EXECUTOR_KEYWORDS + external."""
    global _aliases_cache
    if _aliases_cache is not None:
        return _aliases_cache
    try:
        from database import EXECUTOR_KEYWORDS
    except ImportError:
        _aliases_cache = {}
        return _aliases_cache

    mapping: dict[str, str] = {}
    for kw in EXECUTOR_KEYWORDS:
        if not kw:
            continue
        ext = resolve_external_family(kw)
        if ext:
            mapping[kw.lower()] = ext
            mapping.setdefault(ext, ext)
            continue
        canon = _canonicalize_executor_name(kw)
        if canon:
            mapping[kw.lower()] = canon
            mapping.setdefault(canon, canon)

    for alias, family in EXTERNAL_ALIAS_OVERRIDES.items():
        mapping[alias] = family
        mapping.setdefault(family, family)

    _aliases_cache = mapping
    return mapping


def invalidate_aliases() -> None:
    """Limpa cache de aliases (chamar após load_external_signatures)."""
    global _aliases_cache
    _aliases_cache = None


def resolve_alias(matched: str) -> Optional[str]:
    """Retorna o ID canônico do executor/external, ou None se não bater."""
    if not matched:
        return None
    ext = resolve_external_family(matched)
    if ext:
        return ext
    aliases = _build_aliases()
    key = matched.strip().lower()
    if key in aliases:
        return aliases[key]
    canon = _canonicalize_executor_name(key)
    if canon in aliases:
        return aliases[canon]
    return None


# ============================== Target ID ==============================

_PATH_RE = re.compile(r"[A-Za-z]:\\[^\s\"<>|]+|\\\\\?\\[A-Za-z]:\\[^\s\"<>|]+")


def _extract_path(text: str) -> Optional[str]:
    """Extrai o primeiro path Windows que apareça no texto."""
    if not text:
        return None
    m = _PATH_RE.search(text)
    return m.group(0) if m else None


def _normalize_path(path: str) -> str:
    """Lowercase + NT path → DOS + expandvars + strip de aspas."""
    if not path:
        return ""
    p = path.strip().strip('"').strip("'")
    # NT path \\?\C:\... → C:\...
    if p.startswith("\\\\?\\"):
        p = p[4:]
    # \??\C:\... → C:\...
    if p.startswith("\\??\\"):
        p = p[4:]
    p = os.path.expandvars(p)
    return p.lower().replace("/", "\\")


# Prefixos comuns de "matched" usados pelos scanners pra sinalizar
# o que casou. Ajuda a distinguir categoria sem alias.
_MATCHED_PREFIXES_BYOVD = ("driver-byovd:", "driver-userpath:", "driver-unsigned:")
_MATCHED_PREFIXES_USN   = ("usn:",)
_MATCHED_PREFIXES_ANTI  = ("anti-forense:", "vss:", "event-log-gap:", "ps-history:",
                           "ps-scriptblock:")


def _infer_kind(label: str, matched: str) -> str:
    """Categoriza o target: executor / byovd / anti_forense / tool."""
    lbl = (label or "").lower()
    m = (matched or "").lower()
    if m.startswith("seam-"):
        return "operator_swap"
    if m.startswith("external-") or m.startswith("external:"):
        return "external_cheat"
    if m.startswith(_MATCHED_PREFIXES_BYOVD):
        return "byovd"
    if m.startswith(_MATCHED_PREFIXES_ANTI):
        return "anti_forense"
    if m.startswith("exclusao-executor:"):
        return "executor"
    if m.startswith("exclusao-") or m.startswith("defender-") or "exclusão do defender" in lbl:
        return "anti_forense"
    if "cheat engine" in m or "process hacker" in m or "injector" in m:
        return "tool"
    return "executor"


@dataclass(frozen=True)
class TargetId:
    """Identificador estruturado de target. tipo + valor."""
    scheme: str   # "sha256" | "path" | "executor" | "raw"
    value: str

    def __str__(self) -> str:
        return f"{self.scheme}:{self.value}"

    def __hash__(self) -> int:
        return hash((self.scheme, self.value))


def compute_target_id(item: dict) -> tuple[TargetId, str, str]:
    """
    Retorna (target_id, label_amigavel, kind).

    Cascata (mais forte primeiro):
      0) seam / external-proc|path prefix
      1) sha256 do pe_info — agrupa cópias com nome diferente
      2) path normalizado — agrupa por arquivo no disco
         (se o path for família external conhecida, vira external:family)
      3) external/executor canônico via aliases — agrupa variantes textuais
      4) raw label — fallback, não agrupa nada com mais nada
    """
    # 0) costura de operador — evento próprio (não é executor/arquivo). Agrupa
    #    todos os seam-* num alvo só, com label e kind dedicados.
    matched0 = (item.get("matched") or "").lower()
    if matched0.startswith("seam-"):
        return TargetId("operator_swap", "costura"), "Troca de operador", "operator_swap"

    # 0b) external scanners — matched="external-proc:matcha:matcha.exe"
    ext_family = resolve_external_family(matched0)
    if ext_family and (
        matched0.startswith("external-proc:")
        or matched0.startswith("external-path:")
    ):
        return (
            TargetId("external", ext_family),
            external_family_label(ext_family),
            "external_cheat",
        )

    # 1) hash
    pe = item.get("pe_info") or {}
    sha = (pe.get("sha256") or "").lower()
    if sha and len(sha) == 64:
        name = os.path.basename(pe.get("path", "") or item.get("label", "")) or sha[:12]
        kind = _infer_kind(item.get("label", ""), item.get("matched", ""))
        return TargetId("sha256", sha), name, kind

    # 2) path
    candidate_text = (item.get("label") or "") + " " + (item.get("detail") or "")
    path = _extract_path(candidate_text)
    if path:
        norm = _normalize_path(path)
        if norm:
            # Path que já revela família external (…\Matcha\loader.exe)
            path_ext = _path_to_external_family(norm)
            if path_ext:
                return (
                    TargetId("external", path_ext),
                    external_family_label(path_ext),
                    "external_cheat",
                )
            name = os.path.basename(norm) or norm
            kind = _infer_kind(item.get("label", ""), item.get("matched", ""))
            return TargetId("path", norm), name, kind

    # 3) external canônico (keyword Prefetch "matcha.exe" etc.)
    if ext_family:
        return (
            TargetId("external", ext_family),
            external_family_label(ext_family),
            "external_cheat",
        )

    # 3b) executor canônico
    canon = resolve_alias(item.get("matched", ""))
    if canon:
        # resolve_alias pode devolver family external se override bateu
        if canon in EXTERNAL_FAMILY_CANONICALS or canon in _EXTERNAL_FAMILY_LABELS:
            return (
                TargetId("external", canon),
                external_family_label(canon),
                "external_cheat",
            )
        return TargetId("executor", canon), canon.title(), "executor"

    # 4) raw — fallback
    raw_key = (item.get("matched") or item.get("label") or "unknown").lower()
    kind = _infer_kind(item.get("label", ""), item.get("matched", ""))
    return TargetId("raw", raw_key), item.get("label", "?") or raw_key, kind


# ============================== Evidence ==============================

@dataclass
class Evidence:
    """Uma observação atômica produzida por um scanner."""
    source: str                          # slug do scanner — "prefetch", "amcache", ...
    source_weight: float                 # 0..1
    severity: str                        # low / medium / high / critical
    target_id: TargetId
    target_label: str                    # nome amigável: "Solara", "winring0.sys"
    target_kind: str                     # "executor" | "byovd" | "anti_forense" | "tool"
    confidence: int                      # 0..100 (do item, já calculado em fp_filter)
    timestamp: Optional[datetime]
    raw: dict = field(repr=False)        # o item original, preservado pra report/debug


# ============================== Cluster ==============================

# Tabela de pesos por severidade (alinhada com fp_filter.SEVERITY_WEIGHT)
_SEV_W = {"critical": 25, "high": 10, "medium": 4, "low": 1}


@dataclass
class Cluster:
    """Várias Evidence sobre o mesmo target_id."""
    target_id: TargetId
    label: str
    kind: str
    evidences: list[Evidence] = field(default_factory=list)

    @property
    def sources(self) -> set[str]:
        return {e.source for e in self.evidences}

    @property
    def n_sources(self) -> int:
        return len(self.sources)

    @property
    def has_critical(self) -> bool:
        return any(e.severity == "critical" for e in self.evidences)

    @property
    def has_high(self) -> bool:
        return any(e.severity == "high" for e in self.evidences)

    @property
    def worst_severity(self) -> str:
        order = ["low", "medium", "high", "critical"]
        worst_idx = -1
        for e in self.evidences:
            if e.severity in order:
                worst_idx = max(worst_idx, order.index(e.severity))
        return order[worst_idx] if worst_idx >= 0 else "low"

    @property
    def first_seen(self) -> Optional[datetime]:
        ts = [e.timestamp for e in self.evidences if e.timestamp]
        return min(ts) if ts else None

    @property
    def last_seen(self) -> Optional[datetime]:
        ts = [e.timestamp for e in self.evidences if e.timestamp]
        return max(ts) if ts else None

    @property
    def score(self) -> float:
        """
        Score com diminishing returns por fonte e bônus por diversidade.
        Premissa: 5 evidências de 5 fontes vale MUITO mais que 5 evidências
        da mesma fonte.
        """
        if not self.evidences:
            return 0.0

        # Soma ponderada (severity * source_weight)
        # Diminishing returns DENTRO da mesma fonte: 1ª evidência conta cheia,
        # 2ª conta 0.5, 3ª conta 0.33, etc. Evita farm de uma fonte só.
        by_source: dict[str, list[Evidence]] = {}
        for e in self.evidences:
            by_source.setdefault(e.source, []).append(e)

        raw = 0.0
        for evs in by_source.values():
            # ordena por severity desc pra contar as fortes primeiro
            evs_sorted = sorted(
                evs,
                key=lambda e: _SEV_W.get(e.severity, 0),
                reverse=True,
            )
            for i, e in enumerate(evs_sorted):
                w = _SEV_W.get(e.severity, 0) * e.source_weight
                raw += w / (i + 1)

        # Bônus de diversidade: cada fonte adicional vale 30% a mais
        diversity_bonus = 1.0 + 0.3 * max(0, self.n_sources - 1)
        return round(raw * diversity_bonus, 2)

    @property
    def confidence_pct(self) -> int:
        """0..100. Combina score + n_sources + has_critical."""
        s = self.score
        # mapeamento empírico: score 50+ ≈ 95%, score 20 ≈ 75%, score 5 ≈ 40%
        if self.has_critical and self.n_sources >= 2:
            return min(99, 88 + self.n_sources * 2)
        if self.has_critical:
            return 82
        if s >= 50: return min(96, 80 + int(s / 5))
        if s >= 25: return 70 + int((s - 25) * 0.4)
        if s >= 12: return 50 + int((s - 12) * 1.5)
        if s >= 4:  return 25 + int((s - 4) * 3)
        return min(20, int(s * 5))

    @property
    def verdict(self) -> str:
        """
        Verdict do cluster considerando FP protection.

        Regra anti-FP central: 1 fonte só nunca chega a CONFIRMED
        (exceto se for evidência critical, ex: hash conhecido).
        Isso elimina o caso "Amcache acidentalmente tem entrada parecida
        com 'solara'" virando confirmação.
        """
        if self.has_critical and self.n_sources >= 2:
            return "CONFIRMED"
        if self.has_critical:
            # critical isolado é forte mas não cravado
            return "DETECTED"

        s = self.score
        n = self.n_sources

        # FP protection — 1 fonte só nunca confirma sem critical
        if n == 1:
            if s >= 8: return "SUSPECT"
            return "WEAK"

        # 2+ fontes
        if s >= 40 and n >= 3: return "CONFIRMED"
        if s >= 20 and n >= 2: return "DETECTED"
        if s >= 8:             return "SUSPECT"
        return "WEAK"


VERDICT_RANK = {"WEAK": 0, "SUSPECT": 1, "DETECTED": 2, "CONFIRMED": 3}


# ============================== Adapter ==============================

# Mapa nome-de-scanner-emitido (em `finding["name"]`) → slug de source.
# Como o `name` no finding vem do scanner em formato livre, usamos
# heurística: substring no nome lowercase.

def _source_slug_from_name(scanner_name: str) -> str:
    """Mapeia nome do finding pra slug de SOURCE_WEIGHTS."""
    n = (scanner_name or "").lower()
    # ordem importa — substrings mais específicas primeiro
    rules = [
        ("costura de operador",   "operator_seam"),
        # v3.46.0 — Tier S state-based (roda antes do resto — nomes específicos)
        ("dse / test mode",        "dse_state"),
        ("vbs / hvci",             "vbs_disabled"),
        ("roblox .text page",      "roblox_rwx_page"),
        ("activitiescache",        "activities_cache"),
        # v3.47.0 — Tier A behavioral
        ("scheduled task dropper", "dropper_task"),
        ("amsi bypass",            "amsi_bypass"),
        ("apc injection",          "apc_injection"),
        # v3.44.0 — external technical (mais específicos que "external cheat" genérico)
        ("correlacao de sinais de external", "external_correlation"),
        ("correlação de sinais de external", "external_correlation"),
        ("handles pro roblox",    "external_reader"),
        ("working set de external", "external_footprint"),
        ("thread remota no roblox", "remote_thread"),
        ("rede: processo do sistema", "kernel_only_egress"),
        ("overlay d3d",           "popup_overlay"),
        ("overlay dcomp",         "popup_overlay"),
        ("popup+topmost",         "popup_overlay"),
        ("processo iniciado após o roblox", "post_roblox_proc"),
        ("named pipes suspeitos", "suspicious_pipe"),
        ("executável com nome aleatório", "random_name_exe"),
        ("rede: processo user-path", "user_path_network"),
        ("ancestralidade suspeita", "suspicious_ancestry"),
        # v3.44.0 — forense pós-mortem
        ("defender: histórico de detecções", "defender_history"),
        ("directx shader cache",  "dxshader_burst"),
        ("windows error reporting", "wer_crash"),
        ("reliability monitor",   "reliability_monitor"),
        # existentes
        ("defender: detecção",    "defender_detection"),
        ("event log de execução", "event_log_exec"),
        ("dma",                   "dma_hardware"),
        ("external cheat",        "external_cheat"),
        ("external",              "external_cheat"),
        ("yara",                  "yara_signature"),
        ("assinatura binária",    "yara_signature"),
        ("kernel driver",         "kernel_drivers"),
        ("driver",                "kernel_drivers"),
        ("estrutura de executor",  "executor_structure"),
        ("integridade do launcher", "launcher_integrity"),
        ("usb",                   "removable_media"),
        ("removível",             "removable_media"),
        ("mídia removível",       "removable_media"),
        ("contas de usuário",     "user_accounts"),
        ("conta de windows",      "user_accounts"),
        ("defender",              "defender_tampering"),
        ("exclusão",              "defender_tampering"),
        ("relógio",               "clock_tampering"),
        ("serviços forenses",     "service_state"),
        ("dll injection",         "live_dll_injection"),
        ("sideload",              "live_dll_injection"),
        ("process tree",          "live_processes"),
        ("process",               "live_processes"),
        ("usn",                   "usn_journal"),
        ("background activity",   "bam"),
        ("bam",                   "bam"),
        ("prefetch",              "prefetch"),
        ("amcache",               "amcache"),
        ("userassist",            "userassist"),
        ("muicache",              "muicache"),
        ("shimcache",             "shimcache"),
        ("jumplist",              "jumplists"),
        ("srum",                  "srum"),
        ("roblox log",            "roblox_logs"),
        ("roblox",                "roblox_logs"),
        ("bloxstrap",             "bloxstrap"),
        ("bytecode",              "roblox_bytecode"),
        ("browser",               "browser_history"),
        ("chrome",                "browser_history"),
        ("edge",                  "browser_history"),
        ("firefox",               "browser_history"),
        ("download",              "downloads"),
        ("dns",                   "dns_cache"),
        ("discord",               "discord_cache"),
        ("anti-forense",          "anti_forense"),
        ("anti forense",          "anti_forense"),
        ("alternate data",        "anti_forense"),
        ("time-stomping",         "anti_forense"),
        ("timestamp",             "anti_forense"),
        ("vss",                   "anti_forense"),
        ("shadow",                "anti_forense"),
        ("event log gap",         "anti_forense"),
        ("event log",             "anti_forense"),
        ("powershell",            "powershell_history"),
        ("command",               "command_history"),
        ("history",               "command_history"),
        ("anti-vm",               "anti_evasion"),
        ("anti-sandbox",          "anti_evasion"),
        ("clock",                 "anti_evasion"),
        ("startup",               "persistence"),
        ("scheduled task",        "persistence"),
        ("run key",               "persistence"),
        ("wer",                   "persistence"),
        ("macro",                 "peripherals"),
        ("mouse",                 "peripherals"),
        ("keyboard",              "peripherals"),
        ("network",               "network"),
        ("fresh install",         "fresh_install"),
        ("recent install",        "fresh_install"),
        ("script",                "scripts"),
        ("recycle",               "recycle_bin"),
        ("hidden",                "hidden_files"),
        ("filesystem",            "filesystem"),
    ]
    for needle, slug in rules:
        if needle in n:
            return slug
    return "filesystem"  # fallback genérico


def _parse_ts(s: str) -> Optional[datetime]:
    if not s:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def findings_to_evidences(findings: list[dict]) -> list[Evidence]:
    """
    Adapter: transforma o output atual dos scanners em lista de Evidence.
    Não modifica os scanners — só lê.
    """
    out: list[Evidence] = []
    for finding in findings:
        scanner_name = finding.get("name", "")
        slug = _source_slug_from_name(scanner_name)
        weight = SOURCE_WEIGHTS.get(slug, DEFAULT_SOURCE_WEIGHT)

        for item in finding.get("items", []):
            if item.get("meta_only"):
                continue
            tid, label, kind = compute_target_id(item)
            out.append(Evidence(
                source=slug,
                source_weight=weight,
                severity=item.get("severity", "low"),
                target_id=tid,
                target_label=label,
                target_kind=kind,
                confidence=item.get("confidence", 0),
                timestamp=_parse_ts(item.get("timestamp", "")),
                raw=item,
            ))
    return out


# ============================== Clustering ==============================

# Match de arquivo Prefetch: NOMEEXE-HASH.pf
# Real Prefetch usa 8-16 hex chars; aceitamos alfanum 1+ pra cobrir variantes.
# Extensão .pf + hífen separador são distintivos. Se o `exe` extraído não
# bate com nenhum alias, retornamos None mais embaixo — sem risco de FP.
_PREFETCH_RE = re.compile(r"^(?P<exe>[^\\/]+)-[0-9A-Za-z]+\.pf$")


def _path_to_external_family(path_value: str) -> Optional[str]:
    """Se o path aponta pra família external conhecida, retorna o family id."""
    if not path_value:
        return None
    # basename / prefetch / segmentos — só aceita se for external family
    candidates: list[str] = []
    base = os.path.basename(path_value)
    candidates.append(base)
    stem = base.rsplit(".", 1)[0] if "." in base else base
    candidates.append(stem)
    m = _PREFETCH_RE.match(base)
    if m:
        exe = m.group("exe")
        candidates.append(exe)
        candidates.append(exe.rsplit(".", 1)[0] if "." in exe else exe)
    for seg in path_value.replace("/", "\\").split("\\"):
        seg = seg.strip()
        if seg:
            candidates.append(seg)
            candidates.append(seg.rsplit(".", 1)[0] if "." in seg else seg)
    for c in candidates:
        fam = resolve_external_family(c)
        if fam:
            return fam
    # path inteiro (tokens compostos tipo "matcha beta")
    fam = resolve_external_family(path_value)
    if fam:
        return fam
    # token "matcha beta" no path
    low = path_value.lower().replace("/", "\\")
    for alias, family in EXTERNAL_ALIAS_OVERRIDES.items():
        if " " in alias or "-" in alias:
            if alias in low:
                return family
    return None


def _path_to_canonical_executor(path_value: str) -> Optional[str]:
    """Se um path:* aponta pra executor/external conhecido, retorna o ID canônico.

    Tenta nesta ordem:
      1) basename completo  ('solara.exe')
      2) basename sem extensão  ('solara')
      3) Prefetch: 'SOLARA.EXE-A1B2.pf' → 'solara.exe' → 'solara'
      4) qualquer segmento do path bate com alias (cobre 'AppData\\Solara\\Loader.exe')
    """
    if not path_value:
        return None
    # External first (evita "matcha" cair só como executor genérico)
    ext = _path_to_external_family(path_value)
    if ext:
        return ext

    base = os.path.basename(path_value)

    canon = resolve_alias(base)
    if canon:
        return canon

    stem = base.rsplit(".", 1)[0] if "." in base else base
    canon = resolve_alias(stem)
    if canon:
        return canon

    # Prefetch: SOLARA.EXE-A1B2C3D4.pf → extrai 'solara.exe' → canon
    m = _PREFETCH_RE.match(base)
    if m:
        exe = m.group("exe")
        canon = resolve_alias(exe) or resolve_alias(exe.rsplit(".", 1)[0])
        if canon:
            return canon

    # Qualquer segmento do path bate? (cobre 'Solara\\Loader.exe' onde
    # o basename é 'loader.exe' mas o dir é 'Solara')
    for seg in path_value.replace("/", "\\").split("\\"):
        seg = seg.strip()
        if not seg:
            continue
        canon = resolve_alias(seg)
        if canon:
            return canon

    return None


def _merge_path_into_executor(by_target: dict[TargetId, "Cluster"]) -> dict[TargetId, "Cluster"]:
    """
    Pós-processamento: quando um cluster `path:...` aponta pra executor
    ou external conhecido E existe cluster canônico correspondente,
    funde as evidências.

    Também funde `executor:matcha` residual em `external:matcha` se ambos
    existirem (legado de keyword vs external scanner).
    """
    exec_clusters: dict[str, Cluster] = {
        tid.value: c for tid, c in by_target.items() if tid.scheme == "executor"
    }
    ext_clusters: dict[str, Cluster] = {
        tid.value: c for tid, c in by_target.items() if tid.scheme == "external"
    }

    survivors: dict[TargetId, Cluster] = {}
    for tid, c in by_target.items():
        if tid.scheme == "path":
            canon = _path_to_canonical_executor(tid.value)
            if canon and canon in ext_clusters:
                target = ext_clusters[canon]
                target.evidences.extend(c.evidences)
                if c.label and len(c.label) > len(target.label or ""):
                    target.label = c.label
                continue
            if canon and canon in exec_clusters:
                target = exec_clusters[canon]
                target.evidences.extend(c.evidences)
                if c.label and len(c.label) > len(target.label or ""):
                    target.label = c.label
                continue
            # path de external sem cluster ainda — promove pra external:family
            if canon and (
                canon in EXTERNAL_FAMILY_CANONICALS
                or canon in _EXTERNAL_FAMILY_LABELS
            ):
                new_tid = TargetId("external", canon)
                if new_tid in survivors:
                    survivors[new_tid].evidences.extend(c.evidences)
                elif new_tid in by_target:
                    by_target[new_tid].evidences.extend(c.evidences)
                    survivors[new_tid] = by_target[new_tid]
                    ext_clusters[canon] = survivors[new_tid]
                else:
                    c2 = Cluster(
                        target_id=new_tid,
                        label=external_family_label(canon),
                        kind="external_cheat",
                        evidences=list(c.evidences),
                    )
                    survivors[new_tid] = c2
                    ext_clusters[canon] = c2
                continue
        survivors[tid] = c

    # Funde executor:<family> residual → external:<family>
    final: dict[TargetId, Cluster] = {}
    for tid, c in survivors.items():
        if tid.scheme == "executor" and (
            tid.value in EXTERNAL_FAMILY_CANONICALS
            or tid.value in _EXTERNAL_FAMILY_LABELS
        ):
            ext_tid = TargetId("external", tid.value)
            if ext_tid in survivors:
                survivors[ext_tid].evidences.extend(c.evidences)
                continue
            if ext_tid in final:
                final[ext_tid].evidences.extend(c.evidences)
                continue
            c.kind = "external_cheat"
            c.label = external_family_label(tid.value)
            final[ext_tid] = Cluster(
                target_id=ext_tid,
                label=c.label,
                kind="external_cheat",
                evidences=list(c.evidences),
            )
            continue
        final[tid] = c
    return final


def build_clusters(evidences: Iterable[Evidence]) -> list[Cluster]:
    """
    Agrupa evidências por target_id e devolve clusters ordenados
    pelo verdict (CONFIRMED primeiro, WEAK por último) e dentro do
    verdict por score desc.

    Pós-processamento funde clusters path:* em executor:* quando o path
    aponta pra executor conhecido. Isso elimina o caso de fragmentação
    onde o mesmo executor era detectado em paths diferentes e por nome
    canônico em outras fontes.
    """
    by_target: dict[TargetId, Cluster] = {}
    for e in evidences:
        c = by_target.get(e.target_id)
        if c is None:
            c = Cluster(target_id=e.target_id, label=e.target_label, kind=e.target_kind)
            by_target[e.target_id] = c
        c.evidences.append(e)
        # se a evidência tem label mais informativo (não vazio, não numérico)
        # e o cluster ainda tá com label genérico, promove
        if e.target_label and len(e.target_label) > len(c.label or ""):
            c.label = e.target_label

    by_target = _merge_path_into_executor(by_target)
    by_target = _corroborate_external_clusters(by_target)

    # Para clusters executor:*, força o label a ser o nome canônico Titlecased
    # (em vez de um basename qualquer absorvido durante merge).
    for tid, c in by_target.items():
        if tid.scheme == "executor":
            c.label = tid.value.title()
        elif tid.scheme == "external":
            c.label = external_family_label(tid.value)
            c.kind = "external_cheat"

    clusters = list(by_target.values())
    clusters.sort(
        key=lambda c: (-VERDICT_RANK[c.verdict], -c.score),
    )
    return clusters


# Fontes que reforçam um external (driver/forense forte) — bônus no score
_EXTERNAL_CORROBORATION_SOURCES = frozenset({
    "kernel_drivers", "event_log_exec", "prefetch", "amcache", "bam",
    "usn_journal", "defender_detection", "yara_signature",
})


def _corroborate_external_clusters(
    by_target: dict[TargetId, "Cluster"],
) -> dict[TargetId, "Cluster"]:
    """
    Bônus de score via evidência sintética fraca quando um cluster external
    já tem 1+ fonte forte de forense/driver — reforça DETECTED sem fabricar
    CONFIRMED sozinho (a evidência sintética é low e mesma lógica de diversity).

    Não inventa cluster novo; só reforça os que já existem.
    """
    for tid, c in by_target.items():
        if tid.scheme != "external" and c.kind != "external_cheat":
            continue
        sources = c.sources
        strong = sources & _EXTERNAL_CORROBORATION_SOURCES
        has_live = "external_cheat" in sources or "live_processes" in sources
        if not strong:
            continue
        if not (has_live or len(strong) >= 2):
            continue
        # já bem corroborado — não poluir
        if c.n_sources >= 4:
            continue
        # evidência sintética low em fonte própria (sobe diversity sem inventar cluster)
        c.evidences.append(Evidence(
            source="external_corroboration",
            source_weight=SOURCE_WEIGHTS.get("external_corroboration", 0.55),
            severity="low",
            target_id=tid,
            target_label=c.label,
            target_kind="external_cheat",
            confidence=40,
            timestamp=None,
            raw={
                "label": "Corroboração external+forense",
                "detail": (
                    f"Cluster external com fonte(s) forte(s): "
                    f"{', '.join(sorted(strong))}. "
                    f"Padrão típico de external com loader/driver/prefetch."
                ),
                "matched": f"external-corroboration:{tid.value}",
                "severity": "low",
                "meta_only": False,
            },
        ))
    return by_target


def summarize_clusters(clusters: list[Cluster]) -> dict:
    """Stats agregados sobre todos os clusters — útil pra header do relatório."""
    n_confirmed = sum(1 for c in clusters if c.verdict == "CONFIRMED")
    n_detected  = sum(1 for c in clusters if c.verdict == "DETECTED")
    n_suspect   = sum(1 for c in clusters if c.verdict == "SUSPECT")
    n_weak      = sum(1 for c in clusters if c.verdict == "WEAK")
    top = clusters[0] if clusters else None
    return {
        "n_clusters":   len(clusters),
        "n_confirmed":  n_confirmed,
        "n_detected":   n_detected,
        "n_suspect":    n_suspect,
        "n_weak":       n_weak,
        "top_cluster":  top,
    }
