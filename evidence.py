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
}


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


_aliases_cache: Optional[dict[str, str]] = None


def _build_aliases() -> dict[str, str]:
    """Constrói o mapa alias → canonical a partir de EXECUTOR_KEYWORDS."""
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
        canon = _canonicalize_executor_name(kw)
        if canon:
            mapping[kw.lower()] = canon
            # também mapeia o canon pra si mesmo (idempotência)
            mapping.setdefault(canon, canon)
    _aliases_cache = mapping
    return mapping


def invalidate_aliases() -> None:
    """Limpa cache de aliases (chamar após load_external_signatures)."""
    global _aliases_cache
    _aliases_cache = None


def resolve_alias(matched: str) -> Optional[str]:
    """Retorna o ID canônico do executor, ou None se não bater."""
    if not matched:
        return None
    aliases = _build_aliases()
    key = matched.strip().lower()
    # match direto
    if key in aliases:
        return aliases[key]
    # tenta canonizar e bater de novo (cobre variantes não cadastradas)
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
      1) sha256 do pe_info — agrupa cópias com nome diferente
      2) path normalizado — agrupa por arquivo no disco
      3) executor canônico via aliases — agrupa variantes textuais
      4) raw label — fallback, não agrupa nada com mais nada
    """
    # 0) costura de operador — evento próprio (não é executor/arquivo). Agrupa
    #    todos os seam-* num alvo só, com label e kind dedicados.
    matched0 = (item.get("matched") or "").lower()
    if matched0.startswith("seam-"):
        return TargetId("operator_swap", "costura"), "Troca de operador", "operator_swap"

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
            name = os.path.basename(norm) or norm
            kind = _infer_kind(item.get("label", ""), item.get("matched", ""))
            return TargetId("path", norm), name, kind

    # 3) executor canônico
    canon = resolve_alias(item.get("matched", ""))
    if canon:
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
        ("defender: detecção",    "defender_detection"),
        ("event log de execução", "event_log_exec"),
        ("dma",                   "dma_hardware"),
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


def _path_to_canonical_executor(path_value: str) -> Optional[str]:
    """Se um path:* aponta pra executor conhecido, retorna o ID canônico.

    Tenta nesta ordem:
      1) basename completo  ('solara.exe')
      2) basename sem extensão  ('solara')
      3) Prefetch: 'SOLARA.EXE-A1B2.pf' → 'solara.exe' → 'solara'
      4) qualquer segmento do path bate com alias (cobre 'AppData\\Solara\\Loader.exe')
    """
    if not path_value:
        return None
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
    conhecido E existe um cluster `executor:<canon>` correspondente,
    funde as evidências no executor cluster.

    Isso resolve o caso comum: o mesmo Solara aparece como
      - executor:solara  (do matched='solara' no Amcache)
      - path:c:\\users\\bob\\...\\solara.exe  (do Prefetch que tem o path)
    e deveria ser 1 cluster só com 2+ fontes (= confidence sobe).
    """
    # Mapa: executor canon → cluster executor:* existente
    exec_clusters: dict[str, Cluster] = {
        tid.value: c for tid, c in by_target.items() if tid.scheme == "executor"
    }
    # Também mapa de hash → cluster sha256:* (pra mesma lógica)
    # Mas hash não tem alias, então skip por enquanto.

    survivors: dict[TargetId, Cluster] = {}
    for tid, c in by_target.items():
        if tid.scheme == "path":
            canon = _path_to_canonical_executor(tid.value)
            if canon and canon in exec_clusters:
                # funde evidências dentro do cluster executor
                target = exec_clusters[canon]
                target.evidences.extend(c.evidences)
                # promove o label se o do path for mais informativo
                if c.label and len(c.label) > len(target.label or ""):
                    target.label = c.label
                continue
        survivors[tid] = c
    return survivors


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

    # Para clusters executor:*, força o label a ser o nome canônico Titlecased
    # (em vez de um basename qualquer absorvido durante merge).
    for tid, c in by_target.items():
        if tid.scheme == "executor":
            c.label = tid.value.title()

    clusters = list(by_target.values())
    clusters.sort(
        key=lambda c: (-VERDICT_RANK[c.verdict], -c.score),
    )
    return clusters


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
