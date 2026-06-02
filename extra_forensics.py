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

import os
import re
import time
import hashlib
import threading
import subprocess
from datetime import datetime

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False


# ============================ helpers ============================

def _result(name, description, items, error=None):
    if error:
        status = "error"
        summary = f"Erro: {error}"
    elif not items:
        status = "clean"
        summary = "Nada encontrado"
    else:
        status = "suspicious"
        summary = f"{len(items)} item(s) suspeito(s)"
    return {
        "name": name, "description": description, "status": status,
        "items": items, "summary": summary, "error": error,
    }


def _item(label, detail, severity, matched, timestamp=""):
    return {
        "label": label, "detail": detail, "severity": severity,
        "matched": matched, "timestamp": timestamp,
    }


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
        # Cap em 30MB pra limitar memória/tempo do regex (SRUM típico é 5-30MB).
        # Na prática o arquivo costuma estar locado pelo serviço DPS -> skip.
        with open(SRUM_PATH, "rb") as fh:
            blob = fh.read(30_000_000)
    except (PermissionError, OSError) as e:
        return _result("SRUM", "System Resource Usage Monitor", [],
                       error=f"Sem acesso (arquivo locado pelo serviço): {e}")

    # Strings UTF-16 LE dentro do ESE têm length-prefix; ignoramos isso e só
    # decodificamos o blob inteiro. Sobra ruído, mas o matching filtra.
    try:
        text = blob.decode("utf-16-le", errors="replace")
    except UnicodeDecodeError:
        return _result("SRUM", "System Resource Usage Monitor", [],
                       error="Decode falhou")

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
                    with open(full, "rb") as fh:
                        h = hashlib.sha1(fh.read()).hexdigest()
                except (OSError, PermissionError):
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
            ["wevtutil", "qe", "Security",
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

_USN_NAME_RE = re.compile(r"[A-Za-z0-9_.\-]+\.(?:exe|dll|luau|lua|sys)", re.IGNORECASE)
_USN_HEX_RE = re.compile(r"0x([0-9a-fA-F]{1,8})\b")
_USN_DATE_RE = re.compile(
    r"\d{1,2}/\d{1,2}/\d{4}[ T]\d{1,2}:\d{2}(?::\d{2})?"
    r"|\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2})?")


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
    """
    mname = _USN_NAME_RE.search(line)
    if not mname:
        return None
    fname = mname.group(0)[:80]
    kw, _sev = _match(fname)
    if not kw:
        return None
    # Lê o motivo SEM o trecho do nome — um exec tipo "0x200loader.exe" não
    # pode injetar um bit de reason falso (FP de "excluído").
    reason_src = line[:mname.start()] + " " + line[mname.end():]
    reason = _usn_reason_from_line(reason_src)
    verbo, sev = _usn_classify(reason)
    mdate = _USN_DATE_RE.search(line)
    return _item(
        label=f"{fname} — {verbo}",
        detail=f"Nome de executor {verbo} no volume (motivo=0x{reason:08x}, "
               f"match={kw}). USN sobrevive ao arquivo ser apagado.",
        severity=sev, matched=f"usn:{kw}",
        timestamp=mdate.group(0) if mdate else "",
    )


def scan_usn_journal() -> dict:
    """
    Lê o USN Journal do NTFS pra achar arquivos com nome de executor que foram
    criados/excluídos/renomeados — mesmo que o arquivo já não exista. Pega o
    bypass de apagar o exec antes da SS. readjournal exige admin.
    """
    desc = "USN Journal — exec criado/apagado no disco (sobrevive a apagar o arquivo)"

    # --- (b) queryjournal: confirma journal ativo (não precisa admin) ---
    try:
        q = subprocess.run(["fsutil", "usn", "queryjournal", USN_VOLUME],
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
            ["fsutil", "usn", "readjournal", USN_VOLUME, "csv"],
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
            ["wevtutil", "qe", log_name, "/c:1", "/rd:false", "/f:text"],
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
    # Compara em UTC: wevtutil emite UTC (sufixo Z); datetime.utcnow é UTC.
    # Pequeno erro de timezone é aceitável (cap de "horas" é grosso).
    delta = (datetime.utcnow() - ts).total_seconds() / 3600.0
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
            ["wevtutil", "qe", "Application",
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


ALL_EXTRA_FORENSIC_SCANNERS = [
    scan_shimcache,
    scan_srum,
    scan_script_hashes,
    scan_anti_forensics,
    scan_usn_journal,
    scan_prefetch_disabled,
    scan_event_log_gap,
    scan_shadow_copy_wipe,
]
