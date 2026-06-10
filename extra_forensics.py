"""
Fontes forenses adicionais que cheaters raramente sabem que existem
e por isso não limpam. Cada scanner é independente.

  - ShimCache (AppCompatCache): blob binário no registry com últimos
    execs vistos pelo Application Compatibility. Sobrevive a limpa
    de Prefetch/Amcache/UserAssist.
  - SRUM: System Resource Usage Monitor lembra de rede/CPU por
    programa nos últimos ~30 dias. Mesmo apagando o .exe, o nome
    fica.
  - Script content hashing: SHA1 dos .lua/.luau/.txt encontrados,
    comparado com hashes de hubs públicos. Pega script renomeado
    sem keyword.
  - Anti-forense reforçada: detecta uso recente de Bleachbit/
    CCleaner e a combinação "Prefetch+UserAssist+Recent todos
    vazios juntos" (assinatura de cleaner usado pré-SS).
"""

from models import _result, _item
import os
import re
import time
import hashlib
import threading
import subprocess
from datetime import datetime, timezone

import win_tools

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False


# ============================ helpers ============================

def _match(text):
    """Usa o matching central (word-boundary)."""
    import matching
    return matching.match_keyword(text or "")


def _decode(b) -> str:
    """Decodifica saída de subprocess. Console PT-BR é cp850; cai pra cp1252/utf-8."""
    if not b:
        return ""
    for enc in ("cp850", "cp1252", "utf-8"):
        try:
            return b.decode(enc)
        except UnicodeDecodeError:
            continue
    return b.decode("latin-1", errors="replace")


def _kill_quiet(p):
    try:
        p.kill()
    except OSError:
        pass


# ============================ 1. ShimCache (AppCompatCache) ============================

# Caminho do blob no registry. O parser binário muda entre versões do Windows,
# então usamos strategy resiliente: extrai TODAS as strings UTF-16 do blob e
# casa cada uma contra a base. Não é o parser "correto" de campos, mas pega
# os nomes de executáveis sem depender de offsets específicos.
SHIMCACHE_KEY = r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
SHIMCACHE_VALUES = ("AppCompatCache", "AppCompatibility")


def scan_shimcache() -> dict:
    """
    Lê o blob do ShimCache (HKLM\\SYSTEM\\...\\AppCompatCache). Precisa
    de admin. Extrai strings UTF-16 LE e procura por matches.
    Sobrevive a limpa de Prefetch/Amcache.
    """
    if not HAS_WINREG:
        return _result("ShimCache", "Cache de compatibilidade (execs vistos)",
                       [], error="winreg indisponível")

    blob = None
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SHIMCACHE_KEY)
    except OSError as e:
        return _result("ShimCache", "Cache de compatibilidade (execs vistos)",
                       [], error=f"Sem permissão (precisa admin): {e}")

    try:
        for vname in SHIMCACHE_VALUES:
            try:
                data, _ = winreg.QueryValueEx(key, vname)
                if isinstance(data, (bytes, bytearray)) and len(data) > 64:
                    blob = bytes(data)
                    break
            except OSError:
                continue
    finally:
        winreg.CloseKey(key)

    if not blob:
        return _result("ShimCache", "Cache de compatibilidade (execs vistos)",
                       [], error="Valor não encontrado no registry")

    # Decode UTF-16 LE e extrai trechos imprimíveis
    try:
        text = blob.decode("utf-16-le", errors="replace")
    except UnicodeDecodeError:
        return _result("ShimCache", "Cache de compatibilidade (execs vistos)",
                       [], error="Decode falhou")

    # Só tokens que terminam em .exe/.dll/.sys — corta o volume de candidatos
    # (e o custo do matching) em 10-100x vs extrair toda string imprimível.
    candidates = re.findall(
        r"[A-Za-z0-9_\-\\/.: ]{4,260}\.(?:exe|dll|sys)", text, re.IGNORECASE)
    items = []
    seen = set()
    for cand in candidates:
        kw, sev = _match(cand)
        if not kw:
            continue
        # Deduplica por (keyword, basename) — uma entrada por exec
        base = cand.strip().rsplit("\\", 1)[-1][:80]
        key_id = (kw, base.lower())
        if key_id in seen:
            continue
        seen.add(key_id)
        items.append(_item(
            label=base or kw,
            detail=cand.strip()[:200],
            severity=sev, matched=kw,
        ))
        if len(items) >= 50:
            break

    return _result("ShimCache",
                   "AppCompatCache — execs vistos pelo Windows (sobrevive a limpa)",
                   items)


# ============================ 2. SRUM (uso de recursos) ============================

# SRUDB.dat é um banco ESE (Extensible Storage Engine). Não temos parser ESE em
# stdlib. Estratégia pragmática: ler bytes do arquivo e extrair strings UTF-16
# que pareçam nomes de exe / paths. Não tem timestamp preciso, mas confirma
# que o exec foi visto pelo SRUM nos últimos ~30 dias.

SRUM_PATH = r"C:\Windows\System32\sru\SRUDB.dat"


def scan_srum() -> dict:
    """
    SRUM lembra de uso de rede/CPU dos últimos ~30 dias por exec. O arquivo
    fica locado pelo serviço DPS — copiar com shutil pode falhar. Estratégia
    simples: tentar abrir read-only e extrair strings; se locado, retorna erro.
    """
    if not os.path.isfile(SRUM_PATH):
        return _result("SRUM", "System Resource Usage Monitor", [],
                       error="SRUDB.dat não encontrado")

    try:
        import mmap
        size = os.path.getsize(SRUM_PATH)
        if size == 0:
            return _result("SRUM", "System Resource Usage Monitor", [], error="Arquivo vazio")
        with open(SRUM_PATH, "rb") as fh:
            with mmap.mmap(fh.fileno(), min(size, 30_000_000), access=mmap.ACCESS_READ) as blob:
                try:
                    text = bytes(blob).decode("utf-16-le", errors="replace")
                except UnicodeDecodeError:
                    return _result("SRUM", "System Resource Usage Monitor", [], error="Decode falhou")
    except (PermissionError, OSError, ValueError) as e:
        return _result("SRUM", "System Resource Usage Monitor", [], error=f"Sem acesso (arquivo locado pelo serviço): {e}")

    # Procura por padrões de path (\Windows-style)
    paths = re.findall(r"\\[A-Za-z]:\\[^\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e-\x1f\"<>|]{4,200}", text)
    # Também procura por basenames .exe sem path completo
    bare = re.findall(r"[A-Za-z0-9_\-]{3,40}\.exe", text)

    items = []
    seen = set()
    for cand in list(paths) + list(bare):
        kw, sev = _match(cand)
        if not kw:
            continue
        base = cand.strip().rsplit("\\", 1)[-1][:80].lower()
        if base in seen:
            continue
        seen.add(base)
        items.append(_item(
            label=base,
            detail=cand.strip()[:200],
            severity=sev, matched=kw,
        ))
        if len(items) >= 50:
            break

    return _result("SRUM",
                   "System Resource Usage Monitor — uso por exec nos últimos ~30 dias",
                   items)


# ============================ 3. Hash de scripts conhecidos ============================

# SHA1 do conteúdo de hubs/scripts públicos famosos. Pega script renomeado
# que removeu as keywords óbvias mas manteve o corpo. Vazio por design — a
# comunidade popula via signatures.json ou aditivo direto (KNOWN_SCRIPT_HASHES).
# Formato: "sha1_hex_lowercase": "Nome do script"
KNOWN_SCRIPT_HASHES: dict[str, str] = {
    # exemplos do formato (não são hashes reais — popular conforme samples):
    # "da39a3ee5e6b4b0d3255bfef95601890afd80709": "Owl Hub v1.x",
}

SCRIPT_HASH_EXTS = (".lua", ".luau", ".txt")
SCRIPT_HASH_PATHS = [
    r"%USERPROFILE%\Desktop",
    r"%USERPROFILE%\Documents",
    r"%USERPROFILE%\Downloads",
    r"%APPDATA%",
    r"%LOCALAPPDATA%",
]


def scan_script_hashes() -> dict:
    """
    Calcula SHA1 do conteúdo de cada .lua/.luau/.txt em pastas comuns e
    confronta com KNOWN_SCRIPT_HASHES. Cap em 5MB por arquivo.

    Útil pra detectar hub público renomeado/comentado (mesmo se mudou
    a string de cabeçalho, o resto do conteúdo bate hash).
    """
    if not KNOWN_SCRIPT_HASHES:
        return _result("Hash de scripts conhecidos",
                       "Confronta SHA1 com base de hubs públicos",
                       [], error="base de hashes vazia (popular KNOWN_SCRIPT_HASHES)")

    items = []
    checked = 0

    for path_tpl in SCRIPT_HASH_PATHS:
        base = os.path.expandvars(path_tpl)
        if not os.path.isdir(base):
            continue
        for root, _dirs, files in os.walk(base):
            # Cap de profundidade pra não estourar
            depth = root[len(base):].count(os.sep)
            if depth > 4:
                continue
            for fname in files:
                if not fname.lower().endswith(SCRIPT_HASH_EXTS):
                    continue
                full = os.path.join(root, fname)
                try:
                    size = os.path.getsize(full)
                except OSError:
                    continue
                if size < 100 or size > 5_000_000:
                    continue

                try:
                    import mmap
                    size = os.path.getsize(full)
                    if size == 0: continue
                    with open(full, "rb") as fh:
                        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as blob:
                            h = hashlib.sha1(blob).hexdigest()
                except (OSError, PermissionError, ValueError):
                    continue
                checked += 1

                name = KNOWN_SCRIPT_HASHES.get(h)
                if not name:
                    continue
                try:
                    mtime = datetime.fromtimestamp(os.path.getmtime(full)).strftime("%Y-%m-%d %H:%M:%S")
                except OSError:
                    mtime = ""
                items.append(_item(
                    label=f"{fname}  →  {name}",
                    detail=f"{full}\nSHA1: {h}",
                    severity="high", matched=f"hash:{name}",
                    timestamp=mtime,
                ))
                if len(items) >= 30:
                    return _result("Hash de scripts conhecidos",
                                   f"Confronta SHA1 ({checked} arquivos analisados)",
                                   items)

    return _result("Hash de scripts conhecidos",
                   f"Confronta SHA1 com base de hubs públicos ({checked} arquivos)",
                   items)


# ============================ 4. Anti-forense reforçada ============================
#
# Foca em DOIS sinais que não duplicam o scan_cleaners existente e têm baixo
# falso positivo quando calibrados:
#   (a) Prefetch + Recent + UserAssist TODOS vazios ao mesmo tempo.
#   (b) Log de Security limpo (evento 1102).
#
# Nota de FP: detecção de Bleachbit/CCleaner por mtime de pasta foi REMOVIDA —
# o mtime muda por atualização automática (não só por uso), CCleaner é comum
# demais pra ser sinal forte, e o scan_cleaners já cobre cleaner instalado.


def _count_dir(path, ext=None):
    try:
        files = os.listdir(path)
    except OSError:
        return None
    if ext:
        files = [f for f in files if f.lower().endswith(ext)]
    return len(files)


def _count_userassist():
    """Conta values do UserAssist. None se não deu pra ler."""
    if not HAS_WINREG:
        return None
    total = 0
    try:
        base = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                               r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist")
    except OSError:
        return None
    try:
        i = 0
        while True:
            try:
                guid = winreg.EnumKey(base, i)
            except OSError:
                break
            i += 1
            try:
                count_k = winreg.OpenKey(base, f"{guid}\\Count")
                j = 0
                while True:
                    try:
                        winreg.EnumValue(count_k, j)
                    except OSError:
                        break
                    j += 1
                total += j
                winreg.CloseKey(count_k)
            except OSError:
                continue
    finally:
        winreg.CloseKey(base)
    return total


def scan_anti_forensics() -> dict:
    """
    Sinais de anti-forense, calibrados pra baixo falso positivo:
      - Prefetch + Recent + UserAssist TODOS vazios ao mesmo tempo (medium).
      - Log de Security limpo, evento 1102 (medium).
    """
    items = []

    # --- (a) Fontes históricas vazias simultaneamente ---
    pf_count = _count_dir(r"C:\Windows\Prefetch", ext=".pf")
    rec_count = _count_dir(os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Recent"))
    ua_count = _count_userassist()

    empties = []
    available = 0
    for nome, valor, limite in (("Prefetch", pf_count, 30),
                                ("Recent", rec_count, 10),
                                ("UserAssist", ua_count, 20)):
        if valor is None:
            continue
        available += 1
        if valor < limite:
            empties.append(f"{nome}={valor}")

    # Só dispara se as 3 fontes foram lidas E as 3 estão vazias. Exigir as 3
    # juntas evita o FP de SSD com SysMain off (só Prefetch vazia) ou perfil
    # recém-criado (só 1-2 baixos). Severidade MEDIUM, não HIGH: PC novo ou
    # formatação legítima também zeram tudo — quem confirma é o conjunto.
    if available == 3 and len(empties) == 3:
        items.append(_item(
            label="Prefetch, Recent e UserAssist vazios ao mesmo tempo",
            detail="; ".join(empties) +
                   "  ·  pode ser cleaner pré-SS, mas também PC novo / "
                   "recém-formatado / SysMain desativado — verifique contexto",
            severity="medium", matched="anti-forense:multi-empty",
        ))

    # --- (b) Log de Security limpo (evento 1102) ---
    # Limpar o log de Security é incomum em uso normal, mas acontece em
    # manutenção/reinstalação — por isso MEDIUM, não HIGH.
    try:
        r = subprocess.run(
            [win_tools.tool("wevtutil.exe"), "qe", "Security",
             "/q:*[System[(EventID=1102)]]", "/c:3", "/rd:true", "/f:text"],
            capture_output=True, timeout=10,
        )
        out = ""
        for enc in ("cp850", "cp1252", "utf-8"):
            try:
                out = (r.stdout or b"").decode(enc)
                break
            except UnicodeDecodeError:
                continue
        if "1102" in out and r.returncode == 0:
            m = re.search(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})", out)
            when = m.group(1) if m else ""
            items.append(_item(
                label="Log de Security foi limpo",
                detail="Evento 1102 detectado"
                       + (f" · {when}" if when else "")
                       + "  ·  incomum em uso normal; também ocorre em reinstalação",
                severity="medium", matched="security-log-cleared",
                timestamp=when,
            ))
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    return _result("Anti-forense",
                   "Fontes históricas zeradas em conjunto + limpeza do log de Security",
                   items)


# ============================ 5. USN Journal (execução apagada) ============================
#
# O USN Change Journal do NTFS registra TODA criação/exclusão/rename de arquivo
# no volume, com timestamp, e SOBREVIVE ao arquivo ser apagado. É o que pega o
# bypass clássico de SS: rodar o executor e apagá-lo antes de telar. Mesmo
# limpando Prefetch + Amcache + Recent, o registro "krnl.exe foi criado e depois
# excluído" continua no journal.
#
# Dois sinais:
#   (a) Arquivo com nome de executor que aparece no journal como EXCLUÍDO ou
#       RENOMEADO (high) ou CRIADO (medium). Pega o exec apagado/escondido.
#   (b) Journal desativado / recém-recriado: assinatura de `fsutil usn
#       deletejournal` — alguém apagou o próprio journal pra esconder (a). medium.
#
# readjournal precisa de admin (a ferramenta roda elevada na SS); queryjournal
# não precisa. O parser é por VALOR (extensão do arquivo + bits do código de
# motivo em hex), não por rótulo — o Windows PT-BR traduz os rótulos do fsutil,
# então casar por "File name :" quebraria. Os bits de USN_REASON_* não mudam.

USN_VOLUME = os.environ.get("SystemDrive", "C:")

# Bits de USN_REASON_* (winioctl.h) — independem de idioma do Windows.
_USN_FILE_CREATE = 0x00000100
_USN_FILE_DELETE = 0x00000200
_USN_RENAME_OLD = 0x00001000
_USN_RENAME_NEW = 0x00002000
_USN_STRUCT_BITS = (_USN_FILE_CREATE | _USN_FILE_DELETE
                    | _USN_RENAME_OLD | _USN_RENAME_NEW)

_USN_NAME_RE = re.compile(r',"?([^,]+\.(?:exe|dll|luau|lua|sys))"?,', re.IGNORECASE)
_USN_HEX_RE = re.compile(r"0x([0-9a-fA-F]{1,8})\b")
_USN_DATE_RE = re.compile(
    r"\d{1,2}/\d{1,2}/\d{4}[ T]\d{1,2}:\d{2}(?::\d{2})?"
    r"|\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2})?")

# Janela (segundos) para considerar um par CREATE+DELETE como transitório.
# Executor real roda por minutos/horas antes de ser deletado — gap >> 120s.
# Arquivo que existiu por ≤2 min é provável artefato (teste, download
# cancelado, AV quarentena-e-delete), não uso de cheat.
_USN_TRANSIENT_WINDOW_SEC = 120


def _usn_parse_ts(ts_str: str):
    """Parseia timestamp do USN (vários formatos). Retorna datetime ou None."""
    if not ts_str:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M",
                "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M",
                "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M",
                "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    return None


def _usn_reason_from_line(line: str) -> int:
    """
    Acha, entre os tokens hex da linha CSV, o que é o código de Reason.
    O Usn é decimal (sem 0x) e os File IDs são >8 hex (não casam {1,8}),
    então o token com bit estrutural (create/delete/rename) é o Reason.
    """
    best = 0
    for m in _USN_HEX_RE.finditer(line):
        val = int(m.group(1), 16)
        if val & _USN_STRUCT_BITS:
            return val  # create/delete/rename presente: é o Reason, sem ambiguidade
        if val & 0x80000000:  # bit CLOSE — guarda como fallback
            best = val
    return best


def _usn_classify(reason: int):
    if reason & (_USN_RENAME_OLD | _USN_RENAME_NEW):
        return "renomeado", "high"
    if reason & _USN_FILE_DELETE:
        return "excluído", "high"
    if reason & _USN_FILE_CREATE:
        return "criado", "medium"
    if reason == 0:
        # Não deu pra ler o motivo (formato de CSV diferente do esperado, ou
        # motivo em texto/decimal). O nome de executor ESTÁ no journal — não
        # perde o achado: reporta como média, sem afirmar a operação.
        return "atividade no journal", "medium"
    return "modificado", "low"


def _usn_parse_line(line: str):
    """
    Converte uma linha do readjournal em _item, ou None se não interessa.
    Puro (sem I/O) pra ser testável sem admin.

    Retorna dict com campos extras (prefixo ``_usn_``) que
    ``_usn_merge_transient`` usa e que ``scan_usn_journal`` remove
    antes de retornar.
    """
    mname = _USN_NAME_RE.search(line)
    if not mname:
        return None
    fname = mname.group(1)[:80]
    kw, _sev = _match(fname)
    if not kw:
        return None
    # Lê o motivo SEM o trecho do nome — um exec tipo "0x200loader.exe" não
    # pode injetar um bit de reason falso (FP de "excluído").
    reason_src = line[:mname.start()] + " " + line[mname.end():]
    reason = _usn_reason_from_line(reason_src)
    verbo, sev = _usn_classify(reason)
    mdate = _USN_DATE_RE.search(line)
    it = _item(
        label=f"{fname} — {verbo}",
        detail=f"Nome de executor {verbo} no volume (motivo=0x{reason:08x}, "
               f"match={kw}). USN sobrevive ao arquivo ser apagado.",
        severity=sev, matched=f"usn:{kw}",
        timestamp=mdate.group(0) if mdate else "",
    )
    # Metadata interna — consumida por _usn_merge_transient, removida antes
    # de retornar ao caller final.
    it["_usn_fname"] = fname.lower()
    it["_usn_reason"] = reason
    return it


def _usn_merge_transient(items, window_sec=_USN_TRANSIENT_WINDOW_SEC):
    """
    Detecta pares CREATE+DELETE do mesmo arquivo com gap ≤ ``window_sec``
    e funde numa única entrada com severidade rebaixada.

    Racional forense: executor real roda por minutos/horas antes de ser
    deletado — o gap CREATE→DELETE é sempre >> 120 s. Um arquivo que
    existiu por ≤ 2 min é provável artefato transitório (teste, download
    cancelado, AV quarentena+delete), não uso de cheat.

    A informação NÃO é escondida: o item fundido mantém o matched e o
    timestamp, mas com severidade LOW e label explicativo, evitando que
    infle o veredito.
    """
    if len(items) < 2:
        return items

    # Agrupa por filename (lowercase)
    by_fname: dict[str, list[dict]] = {}
    for it in items:
        fn = it.get("_usn_fname", "")
        by_fname.setdefault(fn, []).append(it)

    result = []
    for fn, group in by_fname.items():
        if len(group) < 2:
            result.extend(group)
            continue

        creates = [it for it in group if it.get("_usn_reason", 0) & _USN_FILE_CREATE]
        deletes = [it for it in group if it.get("_usn_reason", 0) & _USN_FILE_DELETE]
        others  = [it for it in group if it not in creates and it not in deletes]

        if not creates or not deletes:
            result.extend(group)
            continue

        # Tenta parear CREATE+DELETE mais próximos
        used_c: set[int] = set()
        used_d: set[int] = set()
        for ci, c in enumerate(creates):
            c_ts = _usn_parse_ts(c.get("timestamp", ""))
            if c_ts is None or ci in used_c:
                continue
            best_di, best_gap = -1, float("inf")
            for di, d in enumerate(deletes):
                if di in used_d:
                    continue
                d_ts = _usn_parse_ts(d.get("timestamp", ""))
                if d_ts is None:
                    continue
                gap = abs((d_ts - c_ts).total_seconds())
                if gap <= window_sec and gap < best_gap:
                    best_di, best_gap = di, gap
            if best_di >= 0:
                used_c.add(ci)
                used_d.add(best_di)
                d = deletes[best_di]
                gap_int = int(best_gap)
                merged = _item(
                    label=f"{fn} — transitório (criado e apagado em {gap_int}s)",
                    detail=f"Arquivo criado e excluído em {gap_int}s "
                           f"(CREATE→DELETE ≤{window_sec}s). "
                           f"Executor real roda por minutos — arquivo transitório "
                           f"é provável artefato (teste, download cancelado, AV). "
                           f"match={c.get('matched', '').replace('usn:', '')}",
                    severity="low",
                    matched=c.get("matched", ""),
                    timestamp=d.get("timestamp", c.get("timestamp", "")),
                )
                merged["original_severity"] = d.get("severity", "high")
                merged["fp_reason"] = (
                    f"USN transitório: CREATE+DELETE em {gap_int}s "
                    f"(janela ≤{window_sec}s)"
                )
                merged["_usn_fname"] = fn
                merged["_usn_reason"] = 0
                result.append(merged)

        # Items não pareados mantêm severidade original
        for ci, c in enumerate(creates):
            if ci not in used_c:
                result.append(c)
        for di, d in enumerate(deletes):
            if di not in used_d:
                result.append(d)
        result.extend(others)

    return result


def _usn_downgrade_orphan_deletes(items):
    """
    DELETE sem CREATE correspondente no journal = evidência parcial.

    O buffer circular do USN tem tamanho fixo (tipicamente 32 MB).  Quando o
    CREATE já rotacionou pra fora do buffer, sobra apenas o DELETE — e não
    temos como saber QUANDO o arquivo foi criado, se foi usado por minutos
    ou por segundos, nem se a exclusão é recente ou antiga.

    Racional forense:
      - CREATE+DELETE juntos com gap > 120 s  → HIGH (uso real confirmado)
      - CREATE+DELETE juntos com gap ≤ 120 s  → LOW  (transitório / artefato)
      - DELETE sozinho (CREATE rotacionou)     → MEDIUM (evidência parcial)

    A informação NÃO é escondida: o item mantém o matched/timestamp, mas a
    severidade cai pra MEDIUM e o detalhe explica o motivo.  O Confidence
    Engine precisa de corroboração (Prefetch, Amcache, BAM …) pra elevar
    a CONFIRMED — sozinho, um DELETE órfão fica como SUSPECT no máximo.
    """
    # Quais fnames possuem CREATE no lote atual?
    has_create = {it.get("_usn_fname", "")
                  for it in items
                  if it.get("_usn_reason", 0) & _USN_FILE_CREATE}

    for it in items:
        fn = it.get("_usn_fname", "")
        reason = it.get("_usn_reason", 0)
        if (reason & _USN_FILE_DELETE
                and fn not in has_create
                and it["severity"] == "high"):
            it["severity"] = "medium"
            it["original_severity"] = "high"
            it["fp_reason"] = (
                "USN órfão: DELETE sem CREATE no buffer — "
                "evidência parcial (CREATE pode ter rotacionado)"
            )
            it["detail"] += (
                " · Sem registro de criação correspondente no journal "
                "(CREATE pode ter rotacionado do buffer circular) — "
                "evidência parcial, requer corroboração de outra fonte."
            )

    return items


def _usn_strip_internal(items):
    """Remove campos internos ``_usn_*`` antes de devolver ao pipeline."""
    for it in items:
        it.pop("_usn_fname", None)
        it.pop("_usn_reason", None)
    return items


def scan_usn_journal() -> dict:
    """
    Lê o USN Journal do NTFS pra achar arquivos com nome de executor que foram
    criados/excluídos/renomeados — mesmo que o arquivo já não exista. Pega o
    bypass de apagar o exec antes da SS. readjournal exige admin.
    """
    desc = "USN Journal — exec criado/apagado no disco (sobrevive a apagar o arquivo)"

    # --- (b) queryjournal: confirma journal ativo (não precisa admin) ---
    try:
        q = subprocess.run([win_tools.tool("fsutil.exe"), "usn", "queryjournal", USN_VOLUME],
                           capture_output=True, timeout=10)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
        return _result("USN Journal", desc, [], error=f"fsutil indisponível: {e}")

    if q.returncode != 0:
        low = (_decode(q.stdout) + _decode(q.stderr)).lower()
        # Só trata como "desativado" se a msg fala de journal inativo — uma
        # negação de permissão ("acesso negado") NÃO é sinal de bypass.
        if ("não está" in low or "not active" in low or "nao esta" in low
                or "deletejournal" in low):
            return _result("USN Journal", desc, [_item(
                label="USN Journal desativado",
                detail="fsutil usn queryjournal indica journal inativo — pode ter "
                       "sido apagado (fsutil usn deletejournal). Incomum em uso normal.",
                severity="medium", matched="usn:journal-off",
            )])
        # senão: provavelmente permissão/erro transitório — segue pro readjournal

    # --- (a) readjournal: lê os registros (precisa admin) ---
    try:
        proc = subprocess.Popen(
            [win_tools.tool("fsutil.exe"), "usn", "readjournal", USN_VOLUME, "csv"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except (FileNotFoundError, OSError) as e:
        return _result("USN Journal", desc, [], error=f"fsutil indisponível: {e}")

    items = []
    seen = set()
    scanned = 0
    head = []  # primeiras linhas, pra diagnosticar "acesso negado" sem admin
    broke_early = False  # parou por cap/limite (proc ainda vivo) vs. EOF natural
    # Watchdog: o cap de 30s é por-linha; se o fsutil travar SEM emitir linha, o
    # for bloqueia em I/O e o cap nunca dispara. Este timer mata o processo de
    # qualquer jeito (35s), fechando o pipe e desbloqueando o for.
    watchdog = threading.Timer(35.0, _kill_quiet, args=(proc,))
    watchdog.daemon = True
    watchdog.start()
    start = time.time()
    try:
        for raw in proc.stdout:
            scanned += 1
            # Caps: 3M linhas OU 30s — journal no máximo (32MB) tem ~550k linhas.
            if scanned > 3_000_000 or (time.time() - start) > 30:
                broke_early = True
                break
            if len(head) < 5:
                head.append(_decode(raw))
            low = raw.lower()
            if (b".exe" not in low and b".dll" not in low
                    and b".lua" not in low and b".sys" not in low):
                continue
            it = _usn_parse_line(_decode(raw))
            if not it:
                continue
            key_id = it["label"].lower()
            if key_id in seen:
                continue
            seen.add(key_id)
            items.append(it)
            if len(items) >= 60:
                broke_early = True
                break
    finally:
        watchdog.cancel()
        # rc distingue "saiu sozinho" (EOF natural: clean ou erro) de "paramos
        # cedo" (proc ainda vivo). Só esperamos o rc quando NÃO paramos cedo —
        # senão wait() bloquearia. Depois mata e lê o stderr bufferizado.
        rc = None
        if not broke_early:
            try:
                rc = proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                rc = None
        _kill_quiet(proc)

    try:
        err = _decode(proc.stderr.read() or b"") if proc.stderr else ""
    except OSError:
        err = ""

    # Sem achados: distinguir "journal lido, nada encontrado" (clean) de
    # "não consegui ler" (sem admin). Sinais de falha: returncode != 0 (saiu
    # sozinho com erro) OU mensagem de acesso negado (PT/EN) no stdout/stderr.
    if not items:
        blob = (" ".join(head) + " " + err).lower()
        denied = ("negado" in blob or "denied" in blob or "erro 5" in blob
                  or "error 5" in blob)
        failed_rc = rc is not None and rc != 0
        if denied or failed_rc:
            return _result("USN Journal", desc, [],
                           error="readjournal não retornou registros - rode a ferramenta "
                                 "como administrador (acesso ao journal exige elevação)")

    # Pós-processamento:
    #  1. Fundir pares CREATE+DELETE transitórios (≤120s) → LOW
    #  2. Rebaixar DELETEs órfãos (sem CREATE no buffer) → MEDIUM
    items = _usn_merge_transient(items)
    items = _usn_downgrade_orphan_deletes(items)
    items = _usn_strip_internal(items)

    return _result("USN Journal", desc, items)


# ============================ 6. Prefetch / SysMain desativados ============================
#
# O Prefetch é a principal fonte de "este exe rodou em tal hora" — é por isso
# que a maioria dos cheaters tenta apagar arquivos .pf. Desativar Prefetch /
# SysMain de uma vez é um nível acima: nada mais entra no Prefetch a partir
# daquele ponto, então a evidência de execução para de existir antes mesmo
# de ser criada. É a forma "elegante" de bypass.
#
# No Windows 10/11 o padrão é Prefetch=3 (app+boot) e SysMain=Automatic, com
# o próprio Windows decidindo o que fazer em SSD vs HDD. Quem desativa hoje
# repete conselhos de 2014 ou está escondendo execução. Severidade alta
# quando os dois batem; média quando só um.

# HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters
# EnablePrefetcher: 0 = off, 1 = app only, 2 = boot only, 3 = both (padrão)
PREFETCH_KEY = (r"SYSTEM\CurrentControlSet\Control\Session Manager"
                r"\Memory Management\PrefetchParameters")

# HKLM\SYSTEM\CurrentControlSet\Services\SysMain\Start
# 2 = automatic (padrão), 3 = manual, 4 = disabled
SYSMAIN_KEY = r"SYSTEM\CurrentControlSet\Services\SysMain"


def _read_dword(hive, subkey, value_name):
    """Lê um DWORD do registry. None se chave/valor não existe ou sem permissão."""
    if not HAS_WINREG:
        return None
    try:
        k = winreg.OpenKey(hive, subkey)
    except OSError:
        return None
    try:
        try:
            data, _ = winreg.QueryValueEx(k, value_name)
            return int(data) if data is not None else None
        except OSError:
            return None
    finally:
        winreg.CloseKey(k)


def scan_prefetch_disabled() -> dict:
    """
    Detecta Prefetch desativado (EnablePrefetcher=0) e/ou SysMain desativado
    (Start=4). Um dos sinais mais limpos de anti-forense: o padrão do Win11
    é ambos ligados, e desligar exige ação deliberada.
    """
    desc = "Prefetch / SysMain desativados (anti-forense de execução)"
    items = []

    ep = _read_dword(winreg.HKEY_LOCAL_MACHINE if HAS_WINREG else None,
                     PREFETCH_KEY, "EnablePrefetcher")
    sm = _read_dword(winreg.HKEY_LOCAL_MACHINE if HAS_WINREG else None,
                     SYSMAIN_KEY, "Start")

    if ep is None and sm is None:
        return _result("Prefetch/SysMain", desc, [],
                       error="não foi possível ler o registry")

    # Prefetch=0 ou 2 (só boot) significa que apps não geram Prefetch — é o
    # que importa pra cheaters. 1 (só app) e 3 (ambos) registram apps. Já
    # vimos 1 e 3 em produção como configs legítimas; 0 e 2 são raros.
    prefetch_off = ep is not None and ep in (0, 2)
    sysmain_off = sm is not None and sm == 4

    detalhes = []
    if ep is not None:
        rotulo = {0: "off (0)", 1: "só apps (1)", 2: "só boot (2)",
                  3: "completo (3, padrão)"}.get(ep, f"valor inesperado ({ep})")
        if prefetch_off:
            detalhes.append(f"EnablePrefetcher={rotulo}")
    if sm is not None:
        rotulo = {2: "automatic (padrão)", 3: "manual", 4: "disabled"}.get(
            sm, f"valor inesperado ({sm})")
        if sysmain_off:
            detalhes.append(f"SysMain.Start={rotulo}")

    # Os dois desativados ao mesmo tempo: bypass deliberado. Alta.
    # Um só: comum em "guias de otimização" antigas. Média.
    if prefetch_off and sysmain_off:
        items.append(_item(
            label="Prefetch e SysMain desativados ao mesmo tempo",
            detail="; ".join(detalhes) + "  ·  padrão do Windows 11 tem os "
                   "dois ligados; combinação é raríssima fora de uso intencional",
            severity="high", matched="anti-forense:prefetch+sysmain-off",
        ))
    elif prefetch_off:
        items.append(_item(
            label="Prefetch desativado",
            detail="; ".join(detalhes) + "  ·  apps não geram .pf mais; "
                   "Prefetch antigo continua, mas execução nova não é registrada",
            severity="medium", matched="anti-forense:prefetch-off",
        ))
    elif sysmain_off:
        items.append(_item(
            label="SysMain (SuperFetch) desativado",
            detail="; ".join(detalhes) + "  ·  serviço que mantém o Prefetch; "
                   "sem ele, a manutenção do .pf para. Comum em guias antigas de SSD.",
            severity="medium", matched="anti-forense:sysmain-off",
        ))

    return _result("Prefetch/SysMain", desc, items)


# ============================ 7. Gap no log de eventos ============================
#
# Limpar o log de Security gera evento 1102 (já coberto pelo scan_anti_forensics).
# Mas há formas furtivas de zerar logs SEM disparar 1102: deletar o arquivo .evtx
# com o serviço EventLog parado (bypass clássico) ou tools que fazem isso.
#
# O sintoma: o evento mais ANTIGO do log fica anormalmente recente. Num PC com
# semanas de uso, o log de System tem registros de dias atrás. Se o mais antigo
# é de horas atrás, alguém zerou.
#
# Distinguir de PC fresh: cruzo com a contagem do Prefetch. Win11 acabado de
# instalar tem ~50 .pf; PC com semanas tem 100+. Se Prefetch>=80 (PC histórico)
# mas log mais antigo < 6h → bypass furtivo. Severidade média.

# regex tolerante: ISO (2026-06-02T18:30:45) ou com Z; o wevtutil pode emitir
# em UTC, mas "horas atrás" não muda por timezone, então comparamos em UTC.
_EVTX_DATE_RE = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?")


def _oldest_event_age_hours(log_name: str):
    """
    Retorna a idade (em horas) do evento mais antigo do log, ou None se erro.
    Usa wevtutil em modo crescente (/rd:false) e lê só o primeiro evento.
    """
    try:
        r = subprocess.run(
            [win_tools.tool("wevtutil.exe"), "qe", log_name, "/c:1", "/rd:false", "/f:text"],
            capture_output=True, timeout=15)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    if r.returncode != 0:
        return None
    out = _decode(r.stdout)
    m = _EVTX_DATE_RE.search(out)
    if not m:
        return None
    try:
        ts = datetime(*map(int, m.groups()[:6]))
    except (TypeError, ValueError):
        return None
    # Compara em UTC: wevtutil emite UTC (sufixo Z). Usamos now(UTC) naive
    # (utcnow() foi deprecado no 3.12+ e será removido). ts já é naive.
    # Pequeno erro de timezone é aceitável (cap de "horas" é grosso).
    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
    delta = (now_utc - ts).total_seconds() / 3600.0
    return max(delta, 0.0)


def scan_event_log_gap() -> dict:
    """
    Cruza a idade do evento mais antigo dos logs System/Application com a
    contagem de .pf no Prefetch. Log curto + Prefetch volumoso = limpeza
    furtiva (deletou .evtx sem disparar 1102). Severidade média.
    """
    desc = "Log de eventos com gap suspeito (limpeza furtiva sem evento 1102)"
    items = []

    pf_count = _count_dir(r"C:\Windows\Prefetch", ext=".pf")
    age_sys = _oldest_event_age_hours("System")
    age_app = _oldest_event_age_hours("Application")

    # Sem nenhuma das fontes legíveis: degrada limpo
    if age_sys is None and age_app is None:
        return _result("Gap em log de eventos", desc, [],
                       error="wevtutil não acessível (precisa de admin para alguns logs)")

    # Heurística anti-FP: precisa ter sinal de PC NÃO-fresh. Prefetch >= 80 .pf
    # cobre PC com pelo menos algumas semanas de uso. PC recém-instalado raro
    # passa de 50 nas primeiras horas.
    if pf_count is None or pf_count < 80:
        # Sem evidência de PC histórico — não dispara, pra evitar FP em
        # instalação recente. Retorna clean explícito.
        return _result("Gap em log de eventos", desc, [])

    for nome, idade in (("System", age_sys), ("Application", age_app)):
        if idade is None:
            continue
        if idade < 6.0:  # menos de 6h num PC com 80+ Prefetch entries
            items.append(_item(
                label=f"Log de {nome} começa há apenas {idade:.1f}h",
                detail=f"Prefetch tem {pf_count} entradas (PC histórico), mas o "
                       f"evento mais antigo do log de {nome} é de {idade:.1f}h "
                       f"atrás. Compatível com .evtx deletado com o serviço "
                       f"EventLog parado (não dispara o evento 1102).",
                severity="medium", matched=f"event-log-gap:{nome.lower()}",
            ))

    return _result("Gap em log de eventos", desc, items)


# ============================ 8. Volume Shadow Copy zeradas ============================
#
# `vssadmin delete shadows /all` apaga TODAS as cópias sombra do volume,
# destruindo histórico de timeline forense (snapshots semanais do Windows
# guardam versões antigas de arquivos). Cheaters fazem pra esconder mudanças.
#
# O evento 8224 do VSS sozinho NÃO é sinal — o Windows dispara naturalmente
# quando precisa liberar espaço. O que é suspeito:
#   (a) Múltiplos 8224 numa janela curta (delete shadows /all = ~N eventos
#       em poucos segundos), VS um único 8224 (limpeza automática por espaço).
#   (b) Volume com System Protection ativada mas SEM nenhuma shadow copy
#       (vssadmin list shadows volta vazio). Requer admin.
#
# Por enquanto detecto (a). (b) exige admin e parser de duas saídas do
# vssadmin — fica para outra iteração.


def scan_shadow_copy_wipe() -> dict:
    """
    Detecta múltiplos eventos 8224 do VSS (deleção de shadow copies) em janela
    curta — assinatura de `vssadmin delete shadows /all` vs. deleção automática
    do Windows. Severidade média.
    """
    desc = "Shadow copies do VSS apagadas em lote (vssadmin delete shadows)"

    try:
        r = subprocess.run(
            [win_tools.tool("wevtutil.exe"), "qe", "Application",
             "/q:*[System[Provider[@Name='VSS'] and (EventID=8224)]]",
             "/c:30", "/rd:true", "/f:text"],
            capture_output=True, timeout=15)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
        return _result("Shadow copy wipe", desc, [], error=f"wevtutil indisponível: {e}")

    if r.returncode != 0:
        # Permissão negada ou erro: degrade silencioso
        return _result("Shadow copy wipe", desc, [],
                       error="wevtutil não conseguiu ler o log Application")

    text = _decode(r.stdout)
    timestamps = []
    for m in _EVTX_DATE_RE.finditer(text):
        try:
            ts = datetime(*map(int, m.groups()[:6]))
            timestamps.append(ts)
        except (TypeError, ValueError):
            continue

    if not timestamps:
        return _result("Shadow copy wipe", desc, [])

    # Ordena DECRESCENTE (mais recente primeiro) — o wevtutil já retorna assim,
    # mas garantimos pra robustez.
    timestamps.sort(reverse=True)

    # Procura janela de 60s com >=3 eventos: assinatura de delete em lote.
    # Limpeza automática do Windows distribui eventos no tempo (1 por vez).
    items = []
    janela_seg = 60.0
    for i, t0 in enumerate(timestamps):
        em_janela = [t for t in timestamps[i:] if (t0 - t).total_seconds() <= janela_seg]
        if len(em_janela) >= 3:
            mais_recente = em_janela[0]
            mais_antigo = em_janela[-1]
            spread = (mais_recente - mais_antigo).total_seconds()
            items.append(_item(
                label=f"{len(em_janela)} shadow copies apagadas em {spread:.0f}s",
                detail=f"Eventos VSS 8224 em rajada de {spread:.0f}s a partir de "
                       f"{mais_antigo.isoformat()}. Limpeza automática do Windows "
                       f"distribui esses eventos no tempo; rajada curta é "
                       f"compatível com 'vssadmin delete shadows /all'.",
                severity="medium", matched="vss:bulk-delete",
                timestamp=mais_recente.isoformat(),
            ))
            break  # uma rajada já basta de evidência

    return _result("Shadow copy wipe", desc, items)


# ============================ 9. Histórico do PowerShell zerado ============================
#
# O PSReadLine guarda toda linha digitada em PowerShell num arquivo único
# (ConsoleHost_history.txt), append-only, por padrão até 4096 linhas. É o que
# pega "cara rodou comando suspeito no PS antes da SS". Forma comum de bypass:
# apagar o arquivo ou esvaziar o conteúdo. Clear-History limpa a sessão atual,
# mas o ARQUIVO continua — quem realmente quer esconder edita ou deleta.
#
# Sinais:
#   (a) Arquivo existe + size == 0: alguém esvaziou agora. Severidade alta.
#   (b) Arquivo existe + size < 50 bytes + PC histórico (Prefetch >= 80):
#       restaram só 1-2 comandos curtos. Severidade média.
#   (c) Arquivo NÃO existe + Prefetch >= 80: também suspeito (alguém apagou),
#       mas FP em quem só usa CMD/bash. Severidade baixa.

PSREADLINE_HISTORY = r"%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"


def scan_powershell_history_cleared() -> dict:
    """
    Detecta ConsoleHost_history.txt apagado, zerado ou anormalmente curto.
    Distingue PC fresh de bypass cruzando com contagem de Prefetch.
    """
    desc = "Histórico do PowerShell (PSReadLine) apagado ou zerado"
    path = os.path.expandvars(PSREADLINE_HISTORY)
    items = []

    # PC histórico? Mesma heurística do gap em log: Prefetch volumoso ⇒ não-fresh.
    pf_count = _count_dir(r"C:\Windows\Prefetch", ext=".pf")
    pc_historico = pf_count is not None and pf_count >= 80

    if not os.path.exists(path):
        # Sem o arquivo. Em PC fresh, nunca foi criado. Em PC histórico, pode
        # ter sido apagado — ou o user só usa CMD/bash (FP real). Severidade
        # baixa pra refletir essa ambiguidade.
        if pc_historico:
            items.append(_item(
                label="ConsoleHost_history.txt não existe",
                detail=f"Arquivo {path} ausente, mas Prefetch tem {pf_count} entradas "
                       f"(PC histórico). Pode ter sido apagado, ou o usuário usa "
                       f"apenas CMD/Git Bash (FP comum).",
                severity="low", matched="ps-history:missing",
            ))
        return _result("Histórico do PowerShell", desc, items)

    try:
        size = os.path.getsize(path)
        mtime = os.path.getmtime(path)
    except OSError as e:
        return _result("Histórico do PowerShell", desc, [],
                       error=f"sem acesso ao arquivo: {e}")

    age_days = (time.time() - mtime) / 86400.0

    if size == 0:
        # Arquivo zerado: deliberado. Não acontece em uso normal — PowerShell
        # nem cria o arquivo se nunca foi usado, e quando é usado, append.
        items.append(_item(
            label="ConsoleHost_history.txt zerado",
            detail=f"Arquivo de histórico do PowerShell existe mas tem 0 bytes "
                   f"(modificado há {age_days:.1f} dias). Esvaziar o arquivo "
                   f"requer ação deliberada — não acontece em uso normal.",
            severity="high", matched="ps-history:zeroed",
            timestamp=datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S"),
        ))
    elif size < 50 and pc_historico:
        # Arquivo tem 1-2 linhas curtas num PC com muito uso. Provavelmente foi
        # zerado recentemente e voltou a receber comandos da sessão de pós-limpa.
        items.append(_item(
            label=f"ConsoleHost_history.txt com apenas {size} bytes",
            detail=f"Arquivo de histórico extremamente curto ({size} bytes), num "
                   f"PC com Prefetch volumoso ({pf_count} entradas). Compatível "
                   f"com limpeza recente seguida de uso mínimo. Modificado há "
                   f"{age_days:.1f} dias.",
            severity="medium", matched="ps-history:near-empty",
            timestamp=datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S"),
        ))

    return _result("Histórico do PowerShell", desc, items)


# ============================ 10. Drivers do kernel (anti-rootkit / BYOVD) ============================
#
# Cheats avançados pra Roblox (e qualquer jogo com anti-cheat sério) operam em
# KERNEL MODE — porque user-mode anti-cheat não consegue ler kernel. O loader
# carrega um driver .sys que:
#   - patcheia o anti-cheat (Hyperion) pra ignorar processos cheat
#   - lê memória do jogo direto, sem passar pelo anti-cheat
#   - esconde processos via DKOM (Direct Kernel Object Manipulation)
#   - bypass do PsSetCreateProcessNotifyRoutine
#
# Modos comuns:
#   (a) Drop de driver não-assinado em pasta de user (cheater preguiçoso)
#   (b) BYOVD ("Bring Your Own Vulnerable Driver") — usa um driver LEGÍTIMO
#       e assinado mas com vulnerabilidade conhecida (ex: GIGABYTE gdrv, ENE
#       enetechio, Intel iqvw64e, Asus AsIO, MSI RTCore64) pra ganhar exec
#       em ring 0. Esses drivers ficam registrados em HKLM\SYSTEM\.\Services
#       e ficam visíveis no ImagePath.
#   (c) kdmapper / similar — manual map de driver não-assinado via driver
#       vulnerável; o cheat .sys nunca passa pelo Service Manager mas o
#       LOADER (rwdrv, capcom, gdrv) fica registrado.
#
# Estratégia de detecção (user-mode, sem driver próprio):
#   1. Enumerar HKLM\SYSTEM\CurrentControlSet\Services com Type=1/2.
#   2. Whitelist por path: system32\drivers, driverstore, winsxs cobrem
#      ~99% dos drivers legítimos. Se está num desses, ignora.
#   3. Para o que sobra (drivers fora do path-padrão):
#      - Nome bate base de drivers conhecidos como BYOVD/cheat-loader → alta.
#      - Path em pasta de usuário (Temp, Desktop, Downloads, AppData) → alta.
#      - Path normal, mas arquivo existe e NÃO está assinado → alta.
#      - Path normal mas arquivo NÃO existe (entrada órfã) → baixa
#        (FP comum: CPU-Z, ferramentas que carregam driver on-demand).

# Type=1 (kernel driver), Type=2 (filesystem driver). 3 (manual)/4 (disabled)
# também são drivers, mas sem ImagePath inicializado às vezes.
_DRIVER_TYPES = (1, 2)

# Drivers famosos por uso em cheating (BYOVD ou loader de cheat). Lista
# conservadora; falsos positivos aqui custam caro (usuário legítimo de OBS,
# MSI Afterburner, etc.), então só entram nomes com track-record sólido em
# CVE-2018-19320 / kdmapper / hwid spoofer / kernel cheat.
SUSPECT_DRIVER_NAMES = {
    "winring0", "winring0x64",       # CPU/SMBus IO; CVE-2020-14979; banido EAC
    "rwdrv", "rwdrv_x64",             # kdmapper loader
    "gdrv", "gdrv2",                  # GIGABYTE — CVE-2018-19320, BYOVD popular
    "enetechio", "enetechio64",       # ENE — kdmapper alvo
    "eneio", "ene_pchwio",            # ENE variantes
    "iqvw64e", "iqvw32e",             # Intel — CVE BYOVD
    "winio",                          # genérico, abusado
    "asio", "asio64",                 # Asus — vuln BYOVD
    "asrdrv101", "asrdrv102",         # ASRock RGBLed — BYOVD
    "rtcore64",                       # MSI Afterburner — CVE-2019-16098
    "hwrwdrv",                        # Hwinfo write
    "amifldrv",                       # AMI BIOS
    "atszio",                         # Asus
    "mhyprot2",                       # Genshin Impact anti-cheat, abusado
    "capcom",                         # Capcom.sys — BYOVD lendário
    "physmem",                        # genérico de leitura de física
}

# Backslash literal precisa ser escapado com \\ aqui — `r"...\\"` em Python
# resulta em 2 backslashes consecutivos (raw strings não permitem terminar
# com backslash único), o que NUNCA bate um path real.
_DRIVER_WHITELIST_PREFIXES = (
    "c:\\windows\\system32\\drivers",
    "c:\\windows\\system32\\driverstore",
    "c:\\windows\\system32\\",        # cobre cdd.dll, win32k.sys, etc.
    "c:\\windows\\system32",          # sem o sep, defensivo
    "c:\\windows\\syswow64\\",
    "c:\\windows\\winsxs",
    "c:\\windows\\inf",
    "c:\\program files\\windowsapps",
    "c:\\program files\\windowsdefender",
    "c:\\program files (x86)\\windowsdefender",
)

_DRIVER_USER_PATH_TOKENS = (
    "\\users\\",
    "\\appdata\\",
    "\\temp\\",
    "\\downloads\\",
    "\\desktop\\",
    "\\public\\",
)


def _normalize_driver_path(impath: str) -> str:
    """Resolve \\SystemRoot\\, \\??\\, %SystemRoot%, etc. para path real.
    Usa strings non-raw porque raw strings em Python não podem terminar em
    backslash único, e r"...\\" gera 2 backslashes (bug que mascarou
    whitelist no PC do dev — CDD em System32 raiz)."""
    if not impath:
        return ""
    p = impath.strip().strip('"')
    # \SystemRoot\ → C:\Windows\
    p = p.replace("\\SystemRoot", "C:\\Windows").replace("\\systemroot", "C:\\Windows")
    p = p.replace("%SystemRoot%", "C:\\Windows").replace("%systemroot%", "C:\\Windows")
    # \??\ é prefixo NT do Object Manager; strip pra deixar só o path Windows
    if p.startswith("\\??\\"):
        p = p[4:]
    elif p.startswith("\\??/"):
        p = p[4:]
    # Path relativo (System32\drivers\foo.sys sem prefixo) — assume Windows root
    if p.lower().startswith(("system32", "drivers")):
        p = os.path.join("C:\\Windows", p)
    return os.path.normpath(p)


def _is_driver_path_whitelisted(path_lower: str) -> bool:
    return any(path_lower.startswith(pfx) for pfx in _DRIVER_WHITELIST_PREFIXES)


def _has_user_path_token(path_lower: str) -> bool:
    return any(tok in path_lower for tok in _DRIVER_USER_PATH_TOKENS)


def _enumerate_kernel_drivers():
    """Generator: (service_name, image_path_str) para cada kernel/fs driver."""
    if not HAS_WINREG:
        return
    try:
        services = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services")
    except OSError:
        return
    try:
        i = 0
        while True:
            try:
                name = winreg.EnumKey(services, i)
            except OSError:
                break
            i += 1
            try:
                k = winreg.OpenKey(services, name)
            except OSError:
                continue
            try:
                try:
                    svctype, _ = winreg.QueryValueEx(k, "Type")
                except OSError:
                    continue
                if svctype not in _DRIVER_TYPES:
                    continue
                try:
                    impath, _ = winreg.QueryValueEx(k, "ImagePath")
                except OSError:
                    impath = ""
                yield name, impath
            finally:
                winreg.CloseKey(k)
    finally:
        winreg.CloseKey(services)


def _check_driver_signed(path: str):
    """True/False/None — reusa o _is_dll_signed do live_analysis (WinVerifyTrust).
    Falha silenciosa retorna None (não bloqueia o scanner)."""
    try:
        import live_analysis
        return live_analysis._is_dll_signed(path)
    except Exception:  # noqa: BLE001 — qualquer erro vira "desconhecido"
        return None


def scan_kernel_drivers() -> dict:
    """
    Enumera drivers de kernel/fs registrados e flaga os fora do path padrão
    do Windows. Pega rootkit, cheat driver direto e loaders BYOVD que
    sobrevivem com a entrada de Service mesmo após o .sys ser removido.
    """
    desc = "Drivers do kernel suspeitos (anti-rootkit, BYOVD, cheat loader)"
    if not HAS_WINREG:
        return _result("Drivers do kernel", desc, [], error="winreg indisponível")

    items = []
    suspect_seen = set()  # dedupe por (name, path)

    for name, impath in _enumerate_kernel_drivers():
        path = _normalize_driver_path(impath)
        path_lower = path.lower()
        name_lower = name.lower()

        # (a) Nome bate base de driver BYOVD/cheat conhecido — flag IMEDIATA,
        # independente do path (esses drivers nunca deveriam estar carregados
        # em jogador comum).
        if name_lower in SUSPECT_DRIVER_NAMES:
            key = ("byovd", name_lower)
            if key not in suspect_seen:
                suspect_seen.add(key)
                items.append(_item(
                    label=f"Driver de kernel suspeito: {name}",
                    detail=f"{path or '(sem ImagePath)'}  ·  nome bate base de drivers "
                           f"conhecidos por uso em BYOVD / cheat loader / kernel rootkit. "
                           f"Esses drivers raramente são carregados em uso doméstico legítimo.",
                    severity="high", matched=f"driver-byovd:{name_lower}",
                ))
            continue

        # Whitelist por path: 99% dos drivers legítimos caem aqui
        if path_lower and _is_driver_path_whitelisted(path_lower):
            continue
        if not path_lower:
            continue  # sem ImagePath: pula

        # (b) Path em pasta de usuário — flag forte
        if _has_user_path_token(path_lower):
            items.append(_item(
                label=f"Driver carregado de pasta de usuário: {name}",
                detail=f"{path}  ·  drivers legítimos ficam em "
                       f"C:\\Windows\\System32\\drivers ou DriverStore. Carregar de "
                       f"%TEMP%/%APPDATA%/Desktop é assinatura de cheat-loader.",
                severity="high", matched=f"driver-userpath:{name_lower}",
            ))
            continue

        # Path "comum" mas fora da whitelist (ex: C:\ProgramData\xxx, C:\tools\yyy):
        # verifica existência e assinatura.
        if os.path.isfile(path):
            signed = _check_driver_signed(path)
            if signed is False:
                items.append(_item(
                    label=f"Driver não assinado: {name}",
                    detail=f"{path}  ·  WinVerifyTrust reportou assinatura inválida ou "
                           f"ausente. Windows 64-bit exige driver assinado; quem carrega "
                           f"não-assinado usou Test Mode ou bypass de assinatura.",
                    severity="high", matched=f"driver-unsigned:{name_lower}",
                ))
            # signed is True ou None: ignora (assinado = legítimo; None = não
            # consegui checar, evita FP)
        else:
            # Driver órfão: registrado mas arquivo não existe. Caso comum em
            # ferramentas que carregam driver on-demand (CPU-Z, HWInfo) e
            # removem depois sem limpar registry. Baixa.
            items.append(_item(
                label=f"Driver órfão registrado: {name}",
                detail=f"{path}  ·  serviço registrado mas .sys não está mais no disco. "
                       f"Comum em ferramentas que carregam driver on-demand (CPU-Z, HWInfo). "
                       f"Também ocorre após uso de kdmapper que limpou o .sys.",
                severity="low", matched=f"driver-orphan:{name_lower}",
            ))

    return _result("Drivers do kernel", desc, items)


ALL_EXTRA_FORENSIC_SCANNERS = [
    scan_shimcache,
    scan_srum,
    scan_script_hashes,
    scan_anti_forensics,
    scan_usn_journal,
    scan_prefetch_disabled,
    scan_event_log_gap,
    scan_shadow_copy_wipe,
    scan_powershell_history_cleared,
    scan_kernel_drivers,
]
