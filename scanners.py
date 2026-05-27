"""
Scanners individuais. Cada função retorna um dict no formato:
{
    "name": str,
    "description": str,
    "status": "clean" | "suspicious" | "error",
    "items": [ {"label", "detail", "severity", "matched"} ],
    "summary": str,
    "error": str (se status == error)
}
"""

import os
import sys
import json
import struct
import shutil
import sqlite3
import tempfile
import platform
import getpass
import socket
import codecs
from datetime import datetime, timedelta
from pathlib import Path

from database import (
    EXECUTOR_KEYWORDS,
    EXECUTOR_PROCESS_NAMES,
    SUSPICIOUS_DOMAINS,
    SUSPICIOUS_FOLDER_NAMES,
    PATHS_TO_SCAN_FOR_EXECUTORS,
    BROWSER_HISTORY_DBS,
    ROBLOX_LOG_PATHS,
    ROBLOX_LOG_PATTERNS,
    SCRIPT_SEARCH_PATHS,
    SCRIPT_SEARCH_MAX_DEPTH,
    SCRIPT_EXTENSIONS,
    SCRIPT_RED_FLAGS,
    CLEANER_NAMES,
    BLOXSTRAP_PATHS,
    BYTECODE_DUMP_FOLDERS,
    HIDDEN_FILE_PATHS,
)

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False


# Controla se .txt genéricos entram no scanner de scripts.
# False = modo anti-falso-positivo (default)
# True  = modo estrito (comportamento mais agressivo)
SCRIPTS_STRICT_MODE = False


def set_scripts_strict_mode(enabled: bool) -> None:
    """Liga/desliga modo estrito do scanner de scripts."""
    global SCRIPTS_STRICT_MODE
    SCRIPTS_STRICT_MODE = bool(enabled)


# ----------------------------- Helpers -----------------------------

def _expand(path: str) -> str:
    return os.path.expandvars(path)


def _match_keyword(text: str) -> tuple[str | None, str | None]:
    """Retorna (keyword_encontrada, severity) ou (None, None)."""
    if not text:
        return None, None
    lower = text.lower()
    for keyword, severity in EXECUTOR_KEYWORDS.items():
        if keyword in lower:
            return keyword, severity
    return None, None


def _result(name: str, description: str, items: list, status: str = None, error: str = None) -> dict:
    if error:
        status = "error"
    elif status is None:
        status = "suspicious" if items else "clean"

    summary = (
        f"{len(items)} item(s) suspeito(s)" if items
        else "Nenhum vestígio encontrado"
    )
    if error:
        summary = f"Erro: {error}"

    return {
        "name": name,
        "description": description,
        "status": status,
        "items": items,
        "summary": summary,
        "error": error,
    }


def _item(label: str, detail: str, severity: str, matched: str, timestamp: str = "") -> dict:
    return {
        "label": label,
        "detail": detail,
        "severity": severity,
        "matched": matched,
        "timestamp": timestamp,
    }


def _fmt_ts(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OSError, OverflowError):
        return ""


# ----------------------------- System info -----------------------------

def system_info() -> dict:
    """Informações do sistema. Não é uma 'detecção', só contexto."""
    try:
        boot = ""
        if HAS_PSUTIL:
            boot = datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")

        return {
            "host":       socket.gethostname(),
            "user":       getpass.getuser(),
            "os":         f"{platform.system()} {platform.release()} (build {platform.version()})",
            "arch":       platform.machine(),
            "boot_time":  boot,
            "scan_time":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "python":     platform.python_version(),
        }
    except Exception as e:
        return {"error": str(e)}


# ----------------------------- Scanner: Prefetch -----------------------------

def scan_prefetch() -> dict:
    """
    C:\\Windows\\Prefetch\\*.pf — registra todos executáveis rodados nos últimos ~30 dias.
    Mesmo se a pessoa apagou o cheat, o .pf permanece (a menos que tenha limpado prefetch).
    Precisa de admin pra ler o diretório em muitos sistemas.
    """
    prefetch_dir = r"C:\Windows\Prefetch"
    items = []

    if not os.path.isdir(prefetch_dir):
        return _result("Prefetch", "Histórico de execução do Windows", [], error="Pasta não existe")

    try:
        files = os.listdir(prefetch_dir)
    except PermissionError:
        return _result("Prefetch", "Histórico de execução do Windows", [],
                       error="Sem permissão (precisa rodar como administrador)")
    except Exception as e:
        return _result("Prefetch", "Histórico de execução do Windows", [], error=str(e))

    for fname in files:
        if not fname.lower().endswith(".pf"):
            continue
        # Nome do .pf é tipo "KRNL.EXE-1A2B3C4D.pf"
        exe_name = fname.split("-")[0]
        keyword, severity = _match_keyword(exe_name)
        if not keyword:
            continue

        full = os.path.join(prefetch_dir, fname)
        try:
            mtime = os.path.getmtime(full)
            ts = _fmt_ts(mtime)
        except OSError:
            ts = ""

        items.append(_item(
            label=exe_name,
            detail=fname,
            severity=severity,
            matched=keyword,
            timestamp=ts,
        ))

    return _result(
        "Prefetch",
        "Executáveis que rodaram nos últimos ~30 dias (Windows Prefetch)",
        items,
    )


# ----------------------------- Scanner: Recent files -----------------------------

def scan_recent_files() -> dict:
    """
    %APPDATA%\\Microsoft\\Windows\\Recent\\*.lnk — atalhos de arquivos abertos recentemente.
    O nome do .lnk geralmente espelha o nome do arquivo original.
    """
    recent_dir = _expand(r"%APPDATA%\Microsoft\Windows\Recent")
    items = []

    if not os.path.isdir(recent_dir):
        return _result("Arquivos Recentes", "Atalhos recentes do Windows", [],
                       error="Pasta não existe")

    try:
        entries = os.listdir(recent_dir)
    except Exception as e:
        return _result("Arquivos Recentes", "Atalhos recentes do Windows", [], error=str(e))

    for fname in entries:
        keyword, severity = _match_keyword(fname)
        if not keyword:
            continue
        full = os.path.join(recent_dir, fname)
        try:
            mtime = os.path.getmtime(full)
            ts = _fmt_ts(mtime)
        except OSError:
            ts = ""

        items.append(_item(
            label=fname,
            detail=full,
            severity=severity,
            matched=keyword,
            timestamp=ts,
        ))

    return _result(
        "Arquivos Recentes",
        "Atalhos em %APPDATA%\\Microsoft\\Windows\\Recent",
        items,
    )


# ----------------------------- Scanner: Recycle Bin -----------------------------

def scan_recycle_bin() -> dict:
    """
    Lê C:\\$Recycle.Bin\\<SID>\\$I* — cada arquivo deletado deixa um $I com o nome original.
    Cara que apagou o krnl.exe na pressa fica registrado aqui.
    """
    items = []
    base = r"C:\$Recycle.Bin"

    if not os.path.isdir(base):
        return _result("Lixeira", "Arquivos deletados (C:\\$Recycle.Bin)", [],
                       error="Pasta não acessível")

    try:
        sids = os.listdir(base)
    except PermissionError:
        return _result("Lixeira", "Arquivos deletados (C:\\$Recycle.Bin)", [],
                       error="Sem permissão (rode como administrador)")
    except Exception as e:
        return _result("Lixeira", "Arquivos deletados (C:\\$Recycle.Bin)", [], error=str(e))

    for sid in sids:
        sid_path = os.path.join(base, sid)
        if not os.path.isdir(sid_path):
            continue
        try:
            files = os.listdir(sid_path)
        except (PermissionError, OSError):
            continue

        for f in files:
            if not f.startswith("$I"):
                continue
            full = os.path.join(sid_path, f)
            try:
                with open(full, "rb") as fh:
                    data = fh.read()
            except OSError:
                continue

            # $I format: header(24 bytes) + filesize(8) + deletion_time(8) + name_length(4) + name(UTF-16LE)
            try:
                if len(data) < 28:
                    continue
                version = struct.unpack("<Q", data[0:8])[0]
                if version == 2:
                    # Windows 10+
                    name_len = struct.unpack("<I", data[24:28])[0]
                    name_bytes = data[28:28 + name_len * 2]
                    original = name_bytes.decode("utf-16-le", errors="replace").rstrip("\x00")
                    deletion_filetime = struct.unpack("<Q", data[16:24])[0]
                else:
                    # Versão 1 (Win8 e anterior) — nome fixo em offset 24, 260 chars
                    name_bytes = data[24:24 + 260 * 2]
                    original = name_bytes.decode("utf-16-le", errors="replace").split("\x00")[0]
                    deletion_filetime = struct.unpack("<Q", data[16:24])[0]
            except (struct.error, UnicodeDecodeError):
                continue

            keyword, severity = _match_keyword(original)
            if not keyword:
                continue

            # FILETIME (100ns intervals since 1601) -> datetime
            try:
                ts_dt = datetime(1601, 1, 1) + timedelta(microseconds=deletion_filetime // 10)
                ts = ts_dt.strftime("%Y-%m-%d %H:%M:%S")
            except (ValueError, OverflowError):
                ts = ""

            items.append(_item(
                label=os.path.basename(original),
                detail=f"Caminho original: {original}",
                severity=severity,
                matched=keyword,
                timestamp=ts,
            ))

    return _result(
        "Lixeira",
        "Arquivos deletados via Lixeira (C:\\$Recycle.Bin)",
        items,
    )


# ----------------------------- Scanner: Downloads -----------------------------

def scan_downloads() -> dict:
    """Lista arquivos na pasta Downloads com match de keyword."""
    downloads = _expand(r"%USERPROFILE%\Downloads")
    items = []

    if not os.path.isdir(downloads):
        return _result("Downloads", "Pasta Downloads", [], error="Pasta não existe")

    try:
        for root, _dirs, files in os.walk(downloads):
            for f in files:
                keyword, severity = _match_keyword(f)
                if not keyword:
                    continue
                full = os.path.join(root, f)
                try:
                    mtime = os.path.getmtime(full)
                    ts = _fmt_ts(mtime)
                except OSError:
                    ts = ""

                items.append(_item(
                    label=f,
                    detail=full,
                    severity=severity,
                    matched=keyword,
                    timestamp=ts,
                ))
    except Exception as e:
        return _result("Downloads", "Pasta Downloads", [], error=str(e))

    return _result("Downloads", "Arquivos na pasta Downloads do usuário", items)


# ----------------------------- Scanner: Browser history -----------------------------

def _check_browser_db(db_path: str, browser_name: str) -> list:
    """Lê SQLite de histórico do browser. Copia para tmp porque o original pode estar locked."""
    items = []
    if not os.path.isfile(db_path):
        return items

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".sqlite").name
    try:
        shutil.copy2(db_path, tmp)
    except (PermissionError, OSError):
        return items

    try:
        conn = sqlite3.connect(tmp)
        cur = conn.cursor()

        # Tabela urls (visitas)
        try:
            cur.execute("SELECT url, title, last_visit_time FROM urls")
            for url, title, vtime in cur.fetchall():
                target = f"{url or ''} {title or ''}".lower()
                for domain, severity in SUSPICIOUS_DOMAINS.items():
                    if domain in target:
                        # Chrome time: microseconds since 1601-01-01
                        try:
                            visit_dt = datetime(1601, 1, 1) + timedelta(microseconds=vtime)
                            ts = visit_dt.strftime("%Y-%m-%d %H:%M:%S")
                        except (ValueError, OverflowError):
                            ts = ""
                        items.append(_item(
                            label=f"[{browser_name}] {title or url}",
                            detail=url,
                            severity=severity,
                            matched=domain,
                            timestamp=ts,
                        ))
                        break  # uma url, uma flag
        except sqlite3.OperationalError:
            pass

        # Tabela downloads
        try:
            cur.execute("SELECT target_path, tab_url, start_time FROM downloads")
            for tpath, turl, stime in cur.fetchall():
                target = f"{tpath or ''} {turl or ''}".lower()
                kw, severity = _match_keyword(target)
                if not kw:
                    for domain, dsev in SUSPICIOUS_DOMAINS.items():
                        if domain in target:
                            kw, severity = domain, dsev
                            break
                if not kw:
                    continue
                try:
                    dt = datetime(1601, 1, 1) + timedelta(microseconds=stime)
                    ts = dt.strftime("%Y-%m-%d %H:%M:%S")
                except (ValueError, OverflowError):
                    ts = ""
                items.append(_item(
                    label=f"[{browser_name}] DOWNLOAD: {os.path.basename(tpath or '?')}",
                    detail=f"{tpath} (origem: {turl})",
                    severity=severity,
                    matched=kw,
                    timestamp=ts,
                ))
        except sqlite3.OperationalError:
            pass

        conn.close()
    except sqlite3.DatabaseError:
        pass
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass

    return items


def scan_browser_history() -> dict:
    """Procura por domínios e downloads suspeitos no histórico do browser."""
    all_items = []
    checked = []

    for db_template, name in BROWSER_HISTORY_DBS:
        db_path = _expand(db_template)
        if not os.path.isfile(db_path):
            continue
        checked.append(name)
        all_items.extend(_check_browser_db(db_path, name))

    description = "Histórico de URL e downloads dos browsers"
    if checked:
        description += f" (checados: {', '.join(checked)})"
    else:
        description += " (nenhum browser encontrado)"

    return _result("Histórico de Browser", description, all_items)


# ----------------------------- Scanner: Running processes -----------------------------

def scan_running_processes() -> dict:
    """Lista processos rodando agora e marca os suspeitos."""
    if not HAS_PSUTIL:
        return _result("Processos", "Processos em execução", [],
                       error="módulo 'psutil' não instalado (pip install psutil)")

    items = []
    try:
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
            try:
                info = proc.info
                name = (info.get("name") or "").lower()
                exe = (info.get("exe") or "")
                cmd = " ".join(info.get("cmdline") or [])
                blob = f"{name} {exe} {cmd}".lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            severity = EXECUTOR_PROCESS_NAMES.get(name)
            matched = name if severity else None

            if not severity:
                kw, sev = _match_keyword(blob)
                if kw:
                    matched, severity = kw, sev

            if not severity:
                continue

            items.append(_item(
                label=f"PID {info.get('pid')}: {info.get('name')}",
                detail=exe or cmd or "(sem caminho)",
                severity=severity,
                matched=matched,
                timestamp="",
            ))
    except Exception as e:
        return _result("Processos", "Processos em execução", [], error=str(e))

    return _result("Processos", "Processos atualmente em execução", items)


# ----------------------------- Scanner: Known folders -----------------------------

def scan_known_paths() -> dict:
    """Procura por pastas/arquivos com nome de executor em locais comuns."""
    items = []

    for base_template in PATHS_TO_SCAN_FOR_EXECUTORS:
        base = _expand(base_template)
        if not os.path.isdir(base):
            continue
        try:
            entries = os.listdir(base)
        except (PermissionError, OSError):
            continue

        for entry in entries:
            full = os.path.join(base, entry)
            lower = entry.lower()

            # Folder match
            severity = SUSPICIOUS_FOLDER_NAMES.get(lower)
            matched = lower if severity else None

            # Keyword match (cobre arquivos também)
            if not severity:
                kw, sev = _match_keyword(entry)
                if kw:
                    matched, severity = kw, sev

            if not severity:
                continue

            try:
                mtime = os.path.getmtime(full)
                ts = _fmt_ts(mtime)
            except OSError:
                ts = ""

            kind = "PASTA" if os.path.isdir(full) else "ARQUIVO"
            items.append(_item(
                label=f"[{kind}] {entry}",
                detail=full,
                severity=severity,
                matched=matched,
                timestamp=ts,
            ))

    return _result(
        "Pastas e Arquivos Suspeitos",
        "Diretórios comuns onde executores são instalados",
        items,
    )


# ----------------------------- Scanner: UserAssist registry -----------------------------

def _rot13(s: str) -> str:
    return codecs.decode(s, "rot_13")


def scan_userassist() -> dict:
    """
    HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\<GUID>\\Count
    Nomes dos valores estão em ROT13. Lista programas que o usuário executou via Explorer.
    """
    if not HAS_WINREG:
        return _result("UserAssist (Registry)", "Histórico de execução no Registry", [],
                       error="winreg indisponível (não é Windows?)")

    items = []
    base = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
    try:
        root = winreg.OpenKey(winreg.HKEY_CURRENT_USER, base)
    except OSError as e:
        return _result("UserAssist (Registry)", "Histórico de execução no Registry", [],
                       error=f"Não consegui abrir o key: {e}")

    try:
        i = 0
        while True:
            try:
                guid = winreg.EnumKey(root, i)
            except OSError:
                break
            i += 1

            try:
                count_key = winreg.OpenKey(root, f"{guid}\\Count")
            except OSError:
                continue

            j = 0
            while True:
                try:
                    value_name, _data, _typ = winreg.EnumValue(count_key, j)
                except OSError:
                    break
                j += 1

                decoded = _rot13(value_name)
                keyword, severity = _match_keyword(decoded)
                if not keyword:
                    continue
                items.append(_item(
                    label=os.path.basename(decoded) or decoded,
                    detail=decoded,
                    severity=severity,
                    matched=keyword,
                    timestamp="",
                ))
            winreg.CloseKey(count_key)
    finally:
        winreg.CloseKey(root)

    return _result(
        "UserAssist (Registry)",
        "Programas executados via Explorer (HKCU UserAssist, decoded ROT13)",
        items,
    )


# ----------------------------- Scanner: MUICache -----------------------------

def scan_muicache() -> dict:
    """
    HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache
    Cada programa que rodou no usuário deixa entry aqui. Persiste mesmo após deletar.
    """
    if not HAS_WINREG:
        return _result("MUICache (Registry)", "Cache de programas executados", [],
                       error="winreg indisponível")

    items = []
    key_path = r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path)
    except OSError as e:
        return _result("MUICache (Registry)", "Cache de programas executados", [], error=str(e))

    try:
        i = 0
        while True:
            try:
                name, _val, _typ = winreg.EnumValue(key, i)
            except OSError:
                break
            i += 1

            keyword, severity = _match_keyword(name)
            if not keyword:
                continue
            items.append(_item(
                label=os.path.basename(name.split(",")[0]) or name,
                detail=name,
                severity=severity,
                matched=keyword,
                timestamp="",
            ))
    finally:
        winreg.CloseKey(key)

    return _result(
        "MUICache (Registry)",
        "Programas que já rodaram no usuário (HKCU MuiCache)",
        items,
    )


# ----------------------------- Scanner: Roblox logs -----------------------------

def scan_roblox_logs() -> dict:
    """Procura padrões de injeção/anti-tamper nos logs do client Roblox."""
    items = []
    checked_files = 0

    for path_template in ROBLOX_LOG_PATHS:
        log_dir = _expand(path_template)
        if not os.path.isdir(log_dir):
            continue

        try:
            entries = os.listdir(log_dir)
        except (PermissionError, OSError):
            continue

        # Logs muito antigos não interessam — só últimos 60 dias
        cutoff = datetime.now() - timedelta(days=60)

        for entry in entries:
            full = os.path.join(log_dir, entry)
            if not os.path.isfile(full):
                continue
            try:
                if datetime.fromtimestamp(os.path.getmtime(full)) < cutoff:
                    continue
            except OSError:
                continue
            if not entry.lower().endswith((".log", ".txt")):
                continue

            checked_files += 1
            try:
                with open(full, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read(2_000_000)  # cap em 2MB por arquivo
            except OSError:
                continue

            for pattern in ROBLOX_LOG_PATTERNS:
                if pattern.lower() in content.lower():
                    try:
                        ts = _fmt_ts(os.path.getmtime(full))
                    except OSError:
                        ts = ""
                    items.append(_item(
                        label=f"{entry}",
                        detail=f"padrão '{pattern}' encontrado em {full}",
                        severity="medium",
                        matched=pattern,
                        timestamp=ts,
                    ))
                    break  # uma flag por arquivo basta

    desc = f"Logs do Roblox client ({checked_files} arquivo(s) analisado(s))"
    return _result("Logs do Roblox", desc, items)


# ----------------------------- Scanner: Defender exclusions -----------------------------

def scan_defender_exclusions() -> dict:
    """
    HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths
    Excluir pasta do Defender é red flag clássico — gente faz pra rodar cheat sem antivirus pegar.
    Precisa de admin pra ler.
    """
    if not HAS_WINREG:
        return _result("Exclusões do Defender", "Exclusões do Windows Defender", [],
                       error="winreg indisponível")

    items = []
    sources = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths"),
    ]

    found_any = False
    for hive, key_path in sources:
        try:
            key = winreg.OpenKey(hive, key_path)
        except OSError:
            continue
        found_any = True

        try:
            i = 0
            while True:
                try:
                    name, _val, _typ = winreg.EnumValue(key, i)
                except OSError:
                    break
                i += 1

                keyword, severity = _match_keyword(name)
                if not keyword:
                    # Só Downloads e raiz do Roblox são suspeitos genericamente;
                    # \desktop e \appdata são amplos demais (IDEs, projetos, etc.)
                    lower = name.lower()
                    if any(s in lower for s in (r"\downloads\\", r"\roblox\\")):
                        keyword, severity = "exclusão genérica suspeita", "low"
                if not keyword:
                    continue
                items.append(_item(
                    label=name,
                    detail=f"Exclusão registrada em {key_path}",
                    severity=severity,
                    matched=keyword,
                    timestamp="",
                ))
        finally:
            winreg.CloseKey(key)

    if not found_any:
        return _result("Exclusões do Defender", "Exclusões do Windows Defender", [],
                       error="Sem permissão (rode como admin)")

    return _result(
        "Exclusões do Defender",
        "Pastas excluídas do scan do Windows Defender",
        items,
    )


# ----------------------------- Scanner: Scripts Lua/Luau -----------------------------

def scan_scripts() -> dict:
    """
    Procura por arquivos .lua/.luau/.txt em pastas comuns e abre os pequenos
    pra verificar se contém keywords de exploit/cheat (loadstring, getrawmetatable,
    hookfunction, "Owl Hub", "Infinite Yield", etc.).
    """
    items = []
    checked = 0
    matched_files = set()

    def walk_capped(root_path: str, max_depth: int):
        root_depth = root_path.rstrip(os.sep).count(os.sep)
        for dirpath, dirnames, filenames in os.walk(root_path):
            depth = dirpath.count(os.sep) - root_depth
            if depth >= max_depth:
                dirnames[:] = []
                continue
            yield dirpath, filenames

    # Padrão: só formatos que são efetivamente script.
    # Modo estrito: inclui .txt (mais cobertura, porém mais falso positivo).
    script_extensions = (".lua", ".luau")
    if SCRIPTS_STRICT_MODE:
        script_extensions = script_extensions + (".txt",)

    for path_template in SCRIPT_SEARCH_PATHS:
        base = _expand(path_template)
        if not os.path.isdir(base):
            continue

        try:
            for dirpath, filenames in walk_capped(base, SCRIPT_SEARCH_MAX_DEPTH):
                for f in filenames:
                    if not f.lower().endswith(script_extensions):
                        continue
                    full = os.path.join(dirpath, f)

                    try:
                        size = os.path.getsize(full)
                    except OSError:
                        continue

                    # Pula arquivos enormes ou vazios
                    if size < 50 or size > 2_000_000:
                        continue

                    checked += 1
                    try:
                        with open(full, "r", encoding="utf-8", errors="replace") as fh:
                            content = fh.read(1_000_000)
                    except OSError:
                        continue

                    lower = content.lower()
                    worst_severity = None
                    matches_in_file = []

                    for kw, sev in SCRIPT_RED_FLAGS.items():
                        if kw in lower:
                            matches_in_file.append(kw)
                            if worst_severity is None or sev == "high":
                                worst_severity = sev

                    if not matches_in_file:
                        continue

                    if full in matched_files:
                        continue
                    matched_files.add(full)

                    try:
                        mtime = os.path.getmtime(full)
                        ts = _fmt_ts(mtime)
                    except OSError:
                        ts = ""

                    sample = ", ".join(matches_in_file[:5])
                    if len(matches_in_file) > 5:
                        sample += f" (+{len(matches_in_file) - 5})"

                    items.append(_item(
                        label=f"{f}",
                        detail=f"{full}\nkeywords: {sample}",
                        severity=worst_severity or "low",
                        matched=matches_in_file[0],
                        timestamp=ts,
                    ))
        except (PermissionError, OSError):
            continue

    if SCRIPTS_STRICT_MODE:
        ext_desc = ".lua/.luau/.txt"
    else:
        ext_desc = ".lua/.luau"

    desc = f"Arquivos {ext_desc} em pastas comuns ({checked} analisado(s))"
    return _result("Scripts (Lua/Luau)", desc, items)


# ----------------------------- Scanner: Cleaners (anti-forense) -----------------------------

def scan_cleaners() -> dict:
    """
    Detecta uso recente de programas de limpeza (Bleachbit, Privazer, CCleaner).
    Cara que rodou um desses 1h antes da SS provavelmente apagou rastro.

    Sinais:
      - Cleaner aparece em Prefetch/UserAssist com timestamp recente
      - Cleaner instalado em locais comuns
      - Prefetch foi limpa recentemente (count baixo demais)
      - Event Log foi limpa
    """
    items = []
    # 7 dias era largo demais — qualquer usuário que faz limpeza semanal
    # virava HIGH. Só bumpamos se a ferramenta rodou nas últimas 2 horas.
    cutoff = datetime.now() - timedelta(hours=2)

    # 1. Procura nos mesmos lugares dos executores
    for base_template in PATHS_TO_SCAN_FOR_EXECUTORS:
        base = _expand(base_template)
        if not os.path.isdir(base):
            continue
        try:
            entries = os.listdir(base)
        except (PermissionError, OSError):
            continue

        for entry in entries:
            lower = entry.lower()
            for cleaner_kw, severity in CLEANER_NAMES.items():
                if cleaner_kw in lower:
                    full = os.path.join(base, entry)
                    try:
                        mtime = os.path.getmtime(full)
                        ts = _fmt_ts(mtime)
                        recent = datetime.fromtimestamp(mtime) > cutoff
                    except OSError:
                        ts, recent = "", False

                    # Bumpa severity se uso foi recente
                    if recent and severity == "medium":
                        severity = "high"

                    items.append(_item(
                        label=f"[{('PASTA' if os.path.isdir(full) else 'ARQUIVO')}] {entry}",
                        detail=f"{full}{'  ⚠ uso recente (últimas 2h)' if recent else ''}",
                        severity=severity, matched=cleaner_kw, timestamp=ts,
                    ))
                    break

    # 2. Prefetch quase vazia = limpa recentemente
    pf = r"C:\Windows\Prefetch"
    if os.path.isdir(pf):
        try:
            pf_files = [f for f in os.listdir(pf) if f.lower().endswith(".pf")]
            # PCs normais tem 100-500 .pf. < 8 é sinal de limpeza intencional;
            # < 30 dispara em fresh install e PCs de uso leve — muito falso-positivo.
            if len(pf_files) < 8:
                items.append(_item(
                    label=f"Prefetch quase vazia ({len(pf_files)} arquivos)",
                    detail=r"C:\Windows\Prefetch tem menos de 8 entries — normal é 100-500",
                    severity="medium", matched="prefetch-wiped",
                ))
        except (PermissionError, OSError):
            pass

    return _result("Cleaners / Anti-forense",
                   "Programas de limpeza usados (apaga rastros antes da SS)",
                   items)


# ----------------------------- Scanner: Hidden files -----------------------------

def scan_hidden_files() -> dict:
    """
    Procura arquivos com atributo HIDDEN em pastas comuns.
    Cheaters frequentemente escondem executor com 'attrib +h'.
    """
    items = []

    # Windows: usar GetFileAttributesW via ctypes
    import ctypes
    FILE_ATTRIBUTE_HIDDEN = 0x2
    FILE_ATTRIBUTE_SYSTEM = 0x4
    INVALID_FILE_ATTRIBUTES = -1

    GetFileAttributesW = ctypes.windll.kernel32.GetFileAttributesW

    for path_template in HIDDEN_FILE_PATHS:
        base = _expand(path_template)
        if not os.path.isdir(base):
            continue

        try:
            entries = os.listdir(base)
        except (PermissionError, OSError):
            continue

        for entry in entries:
            full = os.path.join(base, entry)
            attrs = GetFileAttributesW(full)
            if attrs == INVALID_FILE_ATTRIBUTES:
                continue
            if not (attrs & FILE_ATTRIBUTE_HIDDEN):
                continue
            # Skip system files conhecidos
            lower_entry = entry.lower()
            sys_files = {
                "desktop.ini", "ntuser.dat", "ntuser.ini", "ntuser.dat.log",
                "thumbs.db", "$recycle.bin", "iconcache.db",
                "usrclass.dat", "usrclass.dat.log", "appdata",
                "application data", "cookies", "local settings",
                "minha música", "minhas imagens", "meus vídeos",
                "my documents", "my music", "my pictures", "my videos",
                "templates", "recent", "send to", "start menu",
            }
            if lower_entry in sys_files:
                continue
            if lower_entry.startswith(("ntuser.", "usrclass.", "iconcache",
                                       "iconcache_", "thumbcache_")):
                continue
            # System + hidden = arquivo de sistema, geralmente OK
            if attrs & FILE_ATTRIBUTE_SYSTEM:
                continue

            # Match keyword se possível, senão flagga como medium
            kw, sev = _match_keyword(entry)
            if not kw:
                kw, sev = "arquivo escondido em local incomum", "low"

            try:
                mtime = os.path.getmtime(full)
                ts = _fmt_ts(mtime)
            except OSError:
                ts = ""

            kind = "PASTA" if os.path.isdir(full) else "ARQUIVO"
            items.append(_item(
                label=f"[OCULTO/{kind}] {entry}",
                detail=full,
                severity=sev, matched=kw, timestamp=ts,
            ))

    return _result("Arquivos Ocultos",
                   "Arquivos com atributo HIDDEN em pastas comuns",
                   items)


# ----------------------------- Scanner: Bloxstrap / bytecode -----------------------------

def scan_bloxstrap_bytecode() -> dict:
    """
    Bloxstrap = client Roblox alternativo (legítimo mas usado por cheaters
    pra customizar e desabilitar checks). E pastas onde executores dumpam
    bytecode / scripts (autoexec, scripts/).
    """
    items = []

    # 1. Bloxstrap
    for path_template in BLOXSTRAP_PATHS:
        full = _expand(path_template)
        if os.path.isdir(full):
            try:
                mtime = os.path.getmtime(full)
                ts = _fmt_ts(mtime)
            except OSError:
                ts = ""
            # Bloxstrap em si é medium (legítimo), mas modificações dentro são high
            sev = "medium"
            label = "Bloxstrap instalado"
            if path_template.endswith("Modifications"):
                # Tem mods customizados — verifica se tem coisa não-default
                try:
                    mods = os.listdir(full)
                    if mods:
                        sev = "high"
                        label = f"Bloxstrap Modifications ({len(mods)} arquivos)"
                except OSError:
                    pass

            items.append(_item(
                label=label,
                detail=full,
                severity=sev, matched="bloxstrap", timestamp=ts,
            ))

    # 2. Bytecode dump folders
    for path_template in BYTECODE_DUMP_FOLDERS:
        full = _expand(path_template)
        if not os.path.isdir(full):
            continue
        try:
            entries = os.listdir(full)
            count = len(entries)
        except (PermissionError, OSError):
            count = 0

        # Detecta executor pelo nome do folder
        kw, sev = _match_keyword(full)
        if not kw:
            kw, sev = "pasta-de-scripts", "medium"

        try:
            mtime = os.path.getmtime(full)
            ts = _fmt_ts(mtime)
        except OSError:
            ts = ""

        items.append(_item(
            label=f"Pasta de scripts: {os.path.basename(full)} ({count} arquivos)",
            detail=full,
            severity=sev, matched=kw, timestamp=ts,
        ))

    return _result("Bloxstrap & Bytecode Dumps",
                   "Cliente alternativo + pastas de scripts/autoexec",
                   items)


# ----------------------------- All scanners (ordem do report) -----------------------------

ALL_SCANNERS = [
    scan_running_processes,
    scan_prefetch,
    scan_userassist,
    scan_muicache,
    scan_recent_files,
    scan_recycle_bin,
    scan_downloads,
    scan_known_paths,
    scan_browser_history,
    scan_roblox_logs,
    scan_scripts,
    scan_cleaners,
    scan_hidden_files,
    scan_bloxstrap_bytecode,
    scan_defender_exclusions,
]
