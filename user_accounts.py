"""
Detecção de múltiplas contas de Windows — "cheata na outra conta".

Um dos métodos dos cursos de telagem ("detectar se há mais usuários no
computador"): o suspeito joga limpo numa conta do Windows e usa o cheat em
OUTRA conta. O Telador varre o usuário atual — este scanner enumera TODAS as
contas reais do PC (via ProfileList) e avisa quando há outra além da telada,
destacando as com atividade recente.

Leitura pura: lê o registro (ProfileList) e o mtime do NTUSER.DAT/perfil.
Contexto, não acusação — conta atual limpa não inocenta o PC inteiro.
"""

import os
import winreg
from datetime import datetime, timedelta


# ----------------------------- helpers -----------------------------

def _result(name, description, items, error=None):
    if error:
        status, summary = "error", f"Erro: {error}"
    elif items:
        status, summary = "suspicious", f"{len(items)} item(s) suspeito(s)"
    else:
        status, summary = "clean", "Nenhum vestígio encontrado"
    return {"name": name, "description": description, "status": status,
            "items": items, "summary": summary, "error": error}


def _item(label, detail, severity, matched, timestamp=""):
    return {"label": label, "detail": detail, "severity": severity,
            "matched": matched, "timestamp": timestamp}


_PROFILELIST = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
_RECENT_HOURS = 48  # outra conta usada nas últimas N horas = mais relevante

# SIDs de contas de sistema/serviço (não são usuários humanos).
_SYSTEM_SID_PREFIXES = (
    "S-1-5-18", "S-1-5-19", "S-1-5-20",          # SYSTEM, LocalService, NetworkService
    "S-1-5-80", "S-1-5-82", "S-1-5-90", "S-1-5-96",  # service/virtual accounts
)
# Nomes de perfil que o Windows cria e não são jogadores.
_SYSTEM_PROFILE_NAMES = {
    "systemprofile", "localservice", "networkservice", "public", "default",
    "default user", "defaultuser0", "all users", "wdagutilityaccount",
}


def _is_system_profile(sid: str, path: str) -> bool:
    if any(sid.startswith(p) for p in _SYSTEM_SID_PREFIXES):
        return True
    name = os.path.basename(path.rstrip("\\/")).lower()
    return name in _SYSTEM_PROFILE_NAMES


def _profile_last_active(path: str):
    """mtime do NTUSER.DAT (ou do diretório do perfil) como 'última atividade'."""
    for cand in (os.path.join(path, "NTUSER.DAT"), path):
        try:
            return datetime.fromtimestamp(os.path.getmtime(cand))
        except OSError:
            continue
    return None


def _profile_item(name: str, path: str, last, current: str, now=None):
    """Item se for OUTRA conta (≠ atual); None se for a própria.
    Isolado pra ser testável sem registro/filesystem."""
    if not name or name.lower() == (current or "").lower():
        return None
    now = now or datetime.now()
    ts = last.strftime("%Y-%m-%d %H:%M:%S") if last else ""
    recent = bool(last) and (now - last) < timedelta(hours=_RECENT_HOURS)
    severity = "medium" if recent else "low"
    if recent:
        recency = f"atividade recente no registro ({ts})"
    elif ts:
        recency = f"última atividade {ts}"
    else:
        recency = "sem data de atividade"
    return _item(
        label=f"Outra conta de Windows: {name}",
        detail=f"{path}\nO PC tem outra conta de usuário ({name}) além da que está sendo "
               f"telada — {recency}. O suspeito pode jogar limpo nesta conta e usar o cheat "
               f"na outra. Tele a outra conta também: conta atual limpa NÃO inocenta o PC.",
        severity=severity, matched=f"conta-windows:{name.lower()}", timestamp=ts,
    )


def scan_user_profiles() -> dict:
    """Enumera as contas reais do Windows (ProfileList) e avisa sobre as que
    não são a atual. Só fica 'sujo' se houver outra conta humana além da telada
    — num PC de uma conta só, fica limpo."""
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _PROFILELIST)
    except OSError as e:
        return _result("Contas de usuário do Windows",
                       "Outras contas de Windows no PC (cheat pode estar na outra)",
                       [], error=f"sem acesso a ProfileList: {e}")

    current = os.environ.get("USERNAME", "")
    items = []
    try:
        i = 0
        while True:
            try:
                sid = winreg.EnumKey(root, i)
            except OSError:
                break
            i += 1
            try:
                k = winreg.OpenKey(root, sid)
                path, _typ = winreg.QueryValueEx(k, "ProfileImagePath")
                winreg.CloseKey(k)
            except OSError:
                continue
            path = os.path.expandvars(path)
            if _is_system_profile(sid, path):
                continue
            name = os.path.basename(path.rstrip("\\/"))
            it = _profile_item(name, path, _profile_last_active(path), current)
            if it:
                items.append(it)
    finally:
        winreg.CloseKey(root)

    return _result("Contas de usuário do Windows",
                   "Outras contas de Windows no PC (cheat pode estar na outra)", items)


ALL_USER_ACCOUNT_SCANNERS = [
    scan_user_profiles,
]
