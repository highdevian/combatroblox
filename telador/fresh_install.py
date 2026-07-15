"""
Detecta Windows formatado/reinstalado recentemente.

Cheater clássico: formata o PC antes da SS pra apagar TODOS os rastros.
Combina 6 sinais — mesmo se formatou há 1-2 semanas, vários ficam:

  1. InstallDate do Windows (registry)
  2. Prefetch quase vazia (< 30 entries = formatou ou limpou)
  3. UserAssist quase vazia
  4. Volume C: criado recentemente (fsutil ntfsinfo)
  5. Roblox instalado logo APÓS Windows (gap < 6h = prep pra SS)
  6. Pasta Recent quase vazia

Cada sinal pesa por idade — combinação = HIGH automático.
"""

from .models import _result, _item
import os
import re
import subprocess

from . import win_tools
from datetime import datetime

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False


def _get_install_date():
    if not HAS_WINREG:
        return None
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                              r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        try:
            ts, _ = winreg.QueryValueEx(key, "InstallDate")
            return datetime.fromtimestamp(ts)
        finally:
            winreg.CloseKey(key)
    except OSError:
        return None


def _count_prefetch():
    pf = r"C:\Windows\Prefetch"
    try:
        return len([f for f in os.listdir(pf) if f.lower().endswith(".pf")])
    except (PermissionError, OSError):
        return None


def _count_userassist():
    if not HAS_WINREG:
        return None
    base = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
    try:
        root = winreg.OpenKey(winreg.HKEY_CURRENT_USER, base)
    except OSError:
        return None
    total = 0
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
                j = 0
                while True:
                    try:
                        winreg.EnumValue(count_key, j)
                    except OSError:
                        break
                    j += 1
                total += j
                winreg.CloseKey(count_key)
            except OSError:
                continue
    finally:
        winreg.CloseKey(root)
    return total


def _get_volume_creation(drive="C:"):
    """fsutil fsinfo ntfsinfo c: mostra quando o volume foi criado."""
    try:
        result = subprocess.run(
            [win_tools.tool("fsutil.exe"), "fsinfo", "ntfsinfo", drive],
            capture_output=True, text=True, timeout=10,
            encoding="cp850", errors="replace",
        )
        if result.returncode != 0:
            return None
        for line in result.stdout.split("\n"):
            low = line.lower()
            if "creation" in low or "criação" in low or "criacao" in low:
                # dd/mm/yyyy ou yyyy-mm-dd
                m = re.search(r"(\d{2})/(\d{2})/(\d{4})", line)
                if m:
                    try:
                        return datetime.strptime(m.group(0), "%d/%m/%Y")
                    except ValueError:
                        pass
                m = re.search(r"(\d{4})-(\d{2})-(\d{2})", line)
                if m:
                    try:
                        return datetime.strptime(m.group(0), "%Y-%m-%d")
                    except ValueError:
                        pass
        return None
    except Exception:
        return None


def _get_roblox_install():
    """
    Pega data de instalação do Roblox. Prioridade:
    1. Registry InstallDate (mais confiável, não muda em reinstall)
    2. Versions/ subfolder mais antigo (resistente a reinstall recente)
    3. Pasta raiz creation time (fallback, pode ser enganoso se reinstalou)
    """
    # 1. Registry — Uninstall key tem InstallDate (formato YYYYMMDD)
    if HAS_WINREG:
        for hive_root in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            for key_path in (
                r"Software\Microsoft\Windows\CurrentVersion\Uninstall\RobloxPlayer",
                r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\RobloxPlayer",
            ):
                try:
                    key = winreg.OpenKey(hive_root, key_path)
                    try:
                        install_str, _ = winreg.QueryValueEx(key, "InstallDate")
                        # Formato típico: "20260527"
                        if isinstance(install_str, str) and len(install_str) == 8:
                            return datetime.strptime(install_str, "%Y%m%d")
                    finally:
                        winreg.CloseKey(key)
                except OSError:
                    continue

    # 2. Subfolder mais antigo em Versions/ (não muda em reinstall, só em update)
    versions_dir = os.path.expandvars(r"%LOCALAPPDATA%\Roblox\Versions")
    if os.path.isdir(versions_dir):
        try:
            subdirs = [os.path.join(versions_dir, d) for d in os.listdir(versions_dir)]
            subdirs = [d for d in subdirs if os.path.isdir(d)]
            if subdirs:
                oldest_ctime = min(os.path.getctime(d) for d in subdirs)
                return datetime.fromtimestamp(oldest_ctime)
        except OSError:
            pass

    # 3. Fallback: creation time da pasta raiz (pode ser enganoso)
    for path in (
        os.path.expandvars(r"%LOCALAPPDATA%\Roblox"),
        os.path.expandvars(r"%LOCALAPPDATA%\Bloxstrap"),
    ):
        if os.path.isdir(path):
            try:
                return datetime.fromtimestamp(os.path.getctime(path))
            except OSError:
                continue
    return None


def scan_fresh_install() -> dict:
    """
    Combina 6 sinais pra detectar PC formatado pra SS.

    NOTA: sinais isolados são MEDIUM no máximo — PC novo legítimo, Windows
    Reset por causa de vírus, etc. também acionam vários. Só vira HIGH quando
    há SMOKING GUN: Roblox instalado < 6h após Windows. Multi-sinais combinados
    são detectados via cross-correlation depois.
    """
    items = []
    now = datetime.now()

    install_date = _get_install_date()
    if install_date is None:
        return _result("Formatação Recente", "Detecção de PC recém-formatado", [],
                       error="Não consegui ler InstallDate do registry")

    age_days = (now - install_date).days
    age_str = install_date.strftime("%Y-%m-%d %H:%M:%S")

    # === Sinal 1: Idade do Windows (MEDIUM no máximo isolado) ===
    if age_days < 1:
        items.append(_item(
            label=f"Windows instalado HOJE ({install_date.strftime('%H:%M')})",
            detail=f"InstallDate = {age_str}  ({(now - install_date).total_seconds() / 3600:.1f}h atrás). "
                   f"Pode ser PC novo, reset por vírus, ou formatação pra SS — verifique outros sinais.",
            severity="medium", matched="fresh-install-today",
            timestamp=age_str,
        ))
    elif age_days < 3:
        items.append(_item(
            label=f"Windows instalado há {age_days} dia(s)",
            detail=f"InstallDate = {age_str}",
            severity="medium", matched="fresh-install-3d",
            timestamp=age_str,
        ))
    elif age_days < 7:
        items.append(_item(
            label=f"Windows instalado há {age_days} dia(s)",
            detail=f"InstallDate = {age_str}",
            severity="low", matched="fresh-install-7d",
            timestamp=age_str,
        ))
    elif age_days < 21:
        items.append(_item(
            label=f"Windows relativamente novo ({age_days} dias)",
            detail=f"InstallDate = {age_str}",
            severity="low", matched="fresh-install-21d",
            timestamp=age_str,
        ))

    # === Sinal 2: Prefetch count (MEDIUM no máximo isolado) ===
    pf_count = _count_prefetch()
    if pf_count is not None:
        if pf_count < 10:
            items.append(_item(
                label=f"Prefetch quase VAZIA ({pf_count} entries)",
                detail="Normal: 100-500. < 10 = formatação recente, limpa agressiva, ou Windows Reset.",
                severity="medium", matched="prefetch-empty",
            ))
        elif pf_count < 30:
            items.append(_item(
                label=f"Prefetch baixa ({pf_count} entries)",
                detail="Normal: 100-500. < 30 indica formatação OU cleaner usado.",
                severity="low", matched="prefetch-low",
            ))

    # === Sinal 3: UserAssist count (LOW/MEDIUM isolado) ===
    ua_count = _count_userassist()
    if ua_count is not None and ua_count < 15:
        items.append(_item(
            label=f"UserAssist quase vazia ({ua_count} entries)",
            detail="Normal: 50+ entries. Pouco uso = perfil novo / formatação.",
            severity="medium" if ua_count <= 5 else "low",
            matched="userassist-empty",
        ))

    # === Sinal 4: Volume C: creation date (MEDIUM isolado) ===
    vol_creation = _get_volume_creation("C:")
    if vol_creation is not None:
        vol_age_days = (now - vol_creation).days
        if vol_age_days < 7:
            items.append(_item(
                label=f"Volume C: criado há {vol_age_days} dia(s)",
                detail=f"NTFS Volume Creation Time = {vol_creation.strftime('%Y-%m-%d')}. "
                       f"Confirma formatação física (não só Windows Reset).",
                severity="medium", matched="fresh-volume",
                timestamp=vol_creation.strftime("%Y-%m-%d %H:%M:%S"),
            ))
        elif vol_age_days < 21:
            items.append(_item(
                label=f"Volume C: criado há {vol_age_days} dias",
                detail=f"NTFS Creation = {vol_creation.strftime('%Y-%m-%d')}",
                severity="low", matched="recent-volume",
                timestamp=vol_creation.strftime("%Y-%m-%d %H:%M:%S"),
            ))

    # === Sinal 5: Gap Roblox → Windows install (SMOKING GUN — HIGH justificado) ===
    roblox_install = _get_roblox_install()
    if roblox_install and install_date:
        gap_hours = (roblox_install - install_date).total_seconds() / 3600
        if 0 < gap_hours < 2:
            # Realmente smoking gun: formata + instala Roblox + abre = sequência prep pra cheat
            items.append(_item(
                label=f"Roblox instalado {gap_hours:.1f}h DEPOIS de formatar",
                detail=f"Windows: {age_str}\nRoblox: {roblox_install.strftime('%Y-%m-%d %H:%M:%S')}\n"
                       f"Sequência clássica: formata → instala Roblox → cheata na mesma noite.",
                severity="high", matched="roblox-right-after-format",
            ))
        elif 0 < gap_hours < 12:
            items.append(_item(
                label=f"Roblox instalado {gap_hours:.1f}h depois do Windows",
                detail=f"Windows: {age_str}\nRoblox: {roblox_install.strftime('%Y-%m-%d %H:%M:%S')}",
                severity="medium", matched="roblox-shortly-after",
            ))
        elif 0 < gap_hours < 48:
            items.append(_item(
                label=f"Roblox instalado {gap_hours:.0f}h depois do Windows",
                detail=f"Windows: {age_str}\nRoblox: {roblox_install.strftime('%Y-%m-%d %H:%M:%S')}",
                severity="low", matched="roblox-after-format-48h",
            ))

    # === Sinal 6: Recent files folder (LOW isolado) ===
    recent_count = 0
    recent = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Recent")
    if os.path.isdir(recent):
        try:
            recent_count = len(os.listdir(recent))
        except OSError:
            pass

    if recent_count < 5:
        items.append(_item(
            label=f"Pasta Recent quase vazia ({recent_count} atalhos)",
            detail="Normal: 50+ atalhos. Vazio = formatação recente OU usuário que não abre arquivos.",
            severity="low" if recent_count > 0 else "medium",
            matched="recent-folder-empty",
        ))

    return _result("Formatação Recente",
                   "Detecta PC formatado/reinstalado pra apagar rastros antes da SS",
                   items)


ALL_FRESH_INSTALL_SCANNERS = [scan_fresh_install]
