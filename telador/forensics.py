r"""
Scanners forenses pesados:
  - Amcache.hve   → SHA1 e nome de TODO exe já executado (mesmo deletado)
  - BAM           → Background Activity Moderator: timestamp exato de execução
  - JumpLists     → arquivos abertos por aplicação (Recent\AutomaticDestinations)

Todos precisam de admin pra cobertura total.
"""

from .models import _result, _item
import os
import struct
import subprocess
from datetime import datetime, timedelta

from . import debug
from . import win_tools
try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False


def _match_keyword(text: str):
    # Delega pro matching central (word-boundary, anti-FP). Wrapper mantido
    # pra não tocar nos call sites.
    from . import matching
    return matching.match_keyword(text)


def _filetime_to_str(filetime_int):
    try:
        dt = datetime(1601, 1, 1) + timedelta(microseconds=filetime_int // 10)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OverflowError):
        return ""


# ============================ Amcache ============================

AMCACHE_PATH = r"C:\Windows\appcompat\Programs\Amcache.hve"
AMCACHE_LOG_EXTS = (".LOG1", ".LOG2")  # transaction logs — reg load precisa deles pra recovery
AMCACHE_TEMP_HIVE = r"HKLM\TempAmcache"


def _amcache_copy_path() -> str:
    # Cópia em %TEMP% com PID pra evitar colisão entre execuções paralelas.
    tmp = os.environ.get("TEMP") or os.environ.get("TMP") or r"C:\Windows\Temp"
    return os.path.join(tmp, f"telador_amcache_{os.getpid()}.hve")


def _esentutl_copy_locked(src: str, dst: str) -> tuple[bool, str]:
    """Copia arquivo travado via esentutl /y /vss (Volume Shadow Copy).
    É a técnica padrão do Windows pra ler hives em uso (Amcache, SYSTEM etc).
    Precisa admin, mas contorna o lock do serviço Application Experience."""
    try:
        # Remove destino velho — esentutl não sobrescreve.
        if os.path.isfile(dst):
            try:
                os.remove(dst)
            except OSError:
                pass
        result = subprocess.run(
            [win_tools.tool("esentutl.exe"), "/y", "/vss", src, "/d", dst],
            capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, str(e)
    if result.returncode != 0:
        return False, (result.stderr or result.stdout or "").strip()
    if not os.path.isfile(dst):
        return False, "esentutl retornou 0 mas destino não existe"
    return True, ""


def _copy_amcache_bundle(dst_hive: str) -> tuple[bool, str, list[str]]:
    """Copia Amcache.hve + Amcache.hve.LOG1 + Amcache.hve.LOG2. Sem os logs
    o hive vem 'dirty' e reg load falha com 'Registro corrompido' — Windows
    deixa transactions pendentes nos logs por performance. reg load faz
    soft-recovery automática se os logs estão do lado do hive com mesmo nome
    base (dst.hve → procura dst.hve.LOG1 e dst.hve.LOG2)."""
    ok, err = _esentutl_copy_locked(AMCACHE_PATH, dst_hive)
    if not ok:
        return False, err, []
    extras = [dst_hive]
    src_dir = os.path.dirname(AMCACHE_PATH)
    for ext in AMCACHE_LOG_EXTS:
        src_log = os.path.join(src_dir, "Amcache.hve" + ext)
        if not os.path.isfile(src_log):
            continue  # log pode não existir se hive foi flushed recente
        dst_log = dst_hive + ext
        log_ok, log_err = _esentutl_copy_locked(src_log, dst_log)
        if log_ok:
            extras.append(dst_log)
        else:
            debug.dbg(f"Amcache: falha copiando {ext}", log_err)
    return True, "", extras


def _reg_load(hive_alias: str, hive_path: str) -> tuple[bool, str]:
    try:
        r = subprocess.run(
            [win_tools.tool("reg.exe"), "load", hive_alias, hive_path],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, str(e)
    if r.returncode != 0:
        return False, (r.stderr or r.stdout or "").strip()
    return True, ""


def scan_amcache():
    """
    Amcache.hve registra metadados de TODOS executáveis que rodaram
    (mesmo se foram deletados meses atrás). Cada entry tem hash SHA1.

    Para ler precisamos montar o hive offline via `reg load`. Requer admin.
    Amcache.hve fica travado pelo serviço Application Experience — reg load
    direto quase sempre falha com "arquivo em uso". Fallback: copiar via
    esentutl /y /vss (Volume Shadow Copy) e montar a cópia.
    """
    if not HAS_WINREG:
        return _result("Amcache", "Hive forense de execução", [], error="winreg indisponível")

    if not os.path.isfile(AMCACHE_PATH):
        # isfile pode retornar False por ACL bloqueando listagem do dir pai
        # (sem admin, C:\Windows\appcompat\Programs\ tipicamente é AD).
        # Diferenciar Access Denied de "arquivo realmente ausente" pra não
        # dar mensagem enganosa. os.stat lança PermissionError em ACL bloqueada.
        try:
            os.stat(AMCACHE_PATH)
            return _result("Amcache", "Hive forense de execução", [],
                           error="Amcache.hve não encontrado")
        except PermissionError:
            return _result("Amcache", "Hive forense de execução", [],
                           error="Amcache.hve inacessível — rode como administrador")
        except FileNotFoundError:
            return _result("Amcache", "Hive forense de execução", [],
                           error="Amcache.hve não encontrado")
        except OSError as e:
            return _result("Amcache", "Hive forense de execução", [],
                           error=f"Amcache.hve inacessível: {e}")

    ok, err_direct = _reg_load(AMCACHE_TEMP_HIVE, AMCACHE_PATH)
    copy_paths: list[str] = []

    if not ok:
        # Provavelmente lock do Windows. Tenta cópia VSS bundle (hive + logs).
        copy_hive = _amcache_copy_path()
        cp_ok, cp_err, copy_paths = _copy_amcache_bundle(copy_hive)
        if not cp_ok:
            return _result("Amcache", "Hive forense de execução", [],
                           error=f"reg load falhou ({err_direct}); esentutl /vss falhou ({cp_err}) — precisa admin?")
        ok, err_copy = _reg_load(AMCACHE_TEMP_HIVE, copy_hive)
        if not ok:
            for p in copy_paths:
                try:
                    os.remove(p)
                except OSError:
                    pass
            return _result("Amcache", "Hive forense de execução", [],
                           error=f"reg load na cópia VSS falhou: {err_copy}")

    items = []
    try:
        # Win10/11: Root\InventoryApplicationFile\<key>\
        try:
            root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                  r"TempAmcache\Root\InventoryApplicationFile")
            items.extend(_walk_amcache_inventory(root))
            winreg.CloseKey(root)
        except OSError as e:
            debug.dbg("Amcache: InventoryApplicationFile (Win10/11) ilegível", e)

        # Win7 fallback: Root\File\<volume>\<id>
        try:
            root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"TempAmcache\Root\File")
            items.extend(_walk_amcache_legacy(root))
            winreg.CloseKey(root)
        except OSError as e:
            debug.dbg("Amcache: Root\\File (Win7 legacy) ilegível", e)

    finally:
        # reg unload pode falhar (reg.exe sumiu/timeout) — engole sem propagar
        # pra não impedir o retorno do scanner. Hive ficaria montada até reboot,
        # mas o scanner ainda devolve os items que conseguiu coletar.
        try:
            subprocess.run([win_tools.tool("reg.exe"), "unload", AMCACHE_TEMP_HIVE],
                           capture_output=True, timeout=15)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
        # Se usamos cópia VSS, remover hive + LOG1 + LOG2 pra não deixar
        # ~20MB em %TEMP%.
        for p in copy_paths:
            try:
                os.remove(p)
            except OSError:
                pass

    return _result("Amcache (forense)",
                   "Hashes SHA1 e nomes de TODOS executáveis já rodados", items)


def _walk_amcache_inventory(root_key):
    """Win10/11 - InventoryApplicationFile"""
    items = []
    i = 0
    while True:
        try:
            sub = winreg.EnumKey(root_key, i)
        except OSError:
            break
        i += 1

        try:
            entry = winreg.OpenKey(root_key, sub)
        except OSError:
            continue

        try:
            name = ""
            path = ""
            sha1 = ""
            link_date = ""
            try:
                name, _ = winreg.QueryValueEx(entry, "Name")
            except OSError:
                pass
            try:
                path, _ = winreg.QueryValueEx(entry, "LowerCaseLongPath")
            except OSError:
                pass
            try:
                sha1, _ = winreg.QueryValueEx(entry, "FileId")
                if isinstance(sha1, str) and sha1.startswith("0000"):
                    sha1 = sha1[4:]  # remove prefix
            except OSError:
                pass
            try:
                link_date, _ = winreg.QueryValueEx(entry, "LinkDate")
            except OSError:
                pass

            blob = f"{name} {path}"
            kw, sev = _match_keyword(blob)
            if kw:
                items.append(_item(
                    label=name or os.path.basename(path or ""),
                    detail=f"{path}  SHA1={sha1}",
                    severity=sev, matched=kw, timestamp=link_date,
                ))
        finally:
            winreg.CloseKey(entry)

    return items


def _walk_amcache_legacy(root_key):
    r"""Win7 fallback - estrutura Root\File\<volume>\<fileid>"""
    items = []
    vi = 0
    while True:
        try:
            vol = winreg.EnumKey(root_key, vi)
        except OSError:
            break
        vi += 1
        try:
            vol_key = winreg.OpenKey(root_key, vol)
        except OSError:
            continue
        try:
            fi = 0
            while True:
                try:
                    fid = winreg.EnumKey(vol_key, fi)
                except OSError:
                    break
                fi += 1
                try:
                    file_key = winreg.OpenKey(vol_key, fid)
                    name = ""
                    try:
                        name, _ = winreg.QueryValueEx(file_key, "15")  # ProductName
                    except OSError:
                        pass
                    path = ""
                    try:
                        path, _ = winreg.QueryValueEx(file_key, "0")  # FullPath
                    except OSError:
                        pass
                    blob = f"{name} {path}"
                    kw, sev = _match_keyword(blob)
                    if kw:
                        items.append(_item(
                            label=name or os.path.basename(path or ""),
                            detail=path, severity=sev, matched=kw, timestamp="",
                        ))
                    winreg.CloseKey(file_key)
                except OSError:
                    continue
        finally:
            winreg.CloseKey(vol_key)
    return items


# ============================ BAM ============================

BAM_KEYS = [
    r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
    r"SYSTEM\CurrentControlSet\Services\bam\UserSettings",  # versão mais antiga
    r"SYSTEM\CurrentControlSet\Services\dam\State\UserSettings",  # DAM (Desktop Activity Moderator)
]


def scan_bam():
    """
    Background Activity Moderator. Cada usuário tem subkey por SID,
    e cada value é um path de executável; os primeiros 8 bytes
    dos dados são FILETIME da última execução.

    Precisa admin (HKLM SYSTEM).
    """
    if not HAS_WINREG:
        return _result("BAM", "Background Activity Moderator", [], error="winreg indisponível")

    items = []
    found_any_key = False

    for key_path in BAM_KEYS:
        try:
            root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        except OSError:
            continue
        found_any_key = True

        try:
            i = 0
            while True:
                try:
                    sid = winreg.EnumKey(root, i)
                except OSError:
                    break
                i += 1
                try:
                    sid_key = winreg.OpenKey(root, sid)
                except OSError:
                    continue

                try:
                    j = 0
                    while True:
                        try:
                            name, data, typ = winreg.EnumValue(sid_key, j)
                        except OSError:
                            break
                        j += 1

                        if typ != winreg.REG_BINARY or len(data) < 8:
                            continue
                        if not isinstance(name, str):
                            continue
                        if "\\" not in name:
                            continue  # só interessam paths

                        kw, sev = _match_keyword(name)
                        if not kw:
                            continue

                        ft = struct.unpack("<Q", data[:8])[0]
                        ts = _filetime_to_str(ft)

                        items.append(_item(
                            label=os.path.basename(name) or name,
                            detail=name, severity=sev, matched=kw,
                            timestamp=ts,
                        ))
                finally:
                    winreg.CloseKey(sid_key)
        finally:
            winreg.CloseKey(root)

    if not found_any_key:
        return _result("BAM", "Background Activity Moderator", [],
                       error="Sem permissão (precisa rodar como admin)")

    return _result("BAM (forense)",
                   "Última execução registrada pelo Windows (precisão de segundos)", items)


# ============================ JumpLists ============================

def scan_jumplists():
    """
    %APPDATA%\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\
    Cada arquivo é OLE compound contendo metadados de arquivos recentes
    abertos por uma aplicação. Vamos só extrair strings UTF-16 LE
    e procurar por keywords. Não precisa admin.
    """
    base = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations")
    items = []

    if not os.path.isdir(base):
        return _result("JumpLists", "Arquivos recentes por aplicação", [],
                       error="Pasta não existe")

    try:
        files = os.listdir(base)
    except (PermissionError, OSError) as e:
        return _result("JumpLists", "Arquivos recentes por aplicação", [], error=str(e))

    for fname in files:
        full = os.path.join(base, fname)
        try:
            with open(full, "rb") as fh:
                raw = fh.read(2_000_000)  # cap 2MB
        except OSError:
            continue

        # Extrai strings UTF-16 LE longas (>=4 chars)
        text = raw.decode("utf-16-le", errors="ignore")

        try:
            mtime = os.path.getmtime(full)
            ts = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
        except OSError:
            ts = ""

        # Usa o matching central (word-boundary) em vez de substring manual —
        # senão este loop reintroduzia o FP que o matching.py corrige
        # (ex.: 'argon' casando 'argonauts'). Um match por arquivo já flagga.
        keyword, severity = _match_keyword(text)
        if keyword:
            idx = text.lower().find(keyword)
            if idx < 0:
                idx = 0
            ctx = text[max(0, idx - 20):idx + len(keyword) + 30]
            ctx = "".join(c if 32 <= ord(c) < 127 else "·" for c in ctx)
            items.append(_item(
                label=f"{fname} ({severity.upper()})",
                detail=f"contexto: ...{ctx}...",
                severity=severity, matched=keyword, timestamp=ts,
            ))

    return _result("JumpLists (forense)",
                   "Arquivos recentes registrados por cada aplicação", items)


ALL_FORENSIC_SCANNERS = [
    scan_amcache,
    scan_bam,
    scan_jumplists,
]
