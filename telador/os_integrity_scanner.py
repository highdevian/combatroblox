"""
Integridade de chaves de boot/autenticação do Windows — vetores de
persistência que carregam ANTES do login e antes de qualquer AV user-mode.
Qualquer coisa que apareça aqui é raríssimo em máquina limpa e o baseline
é bem definido.

  1) Session Manager (BootExecute, KnownDLLs, SetupExecute) — HKLM\\SYSTEM
     Executáveis rodam antes do subsystem Win32 carregar; DLLs em KnownDLLs
     são carregadas por TODOS os processos que as importam.

  2) LSA Packages (Authentication/Security/Notification) — HKLM\\SYSTEM
     DLLs carregadas pelo LSASS. Rodam com o token de LSASS (mais alto que
     SYSTEM em muitos aspectos). Persistência sobrevive até reinstalação do
     Windows sem formatação total.

Ambos requerem admin pra ler HKLM.
"""

from .models import _result, _item

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False


# ============================ Session Manager ============================

_SESSION_MANAGER_KEY = r"SYSTEM\CurrentControlSet\Control\Session Manager"

# Baseline esperado do BootExecute. Windows 10/11 default.
# `autocheck autochk *` é a única linha esperada. Qualquer coisa além = suspeito.
_EXPECTED_BOOT_EXECUTE = {
    "autocheck autochk *",
    "autocheck autochk /r \\??\\c:",  # às vezes aparece após disk check
}

# SetupExecute default é vazio; alguma coisa aqui = criação recente.
_EXPECTED_SETUP_EXECUTE: set[str] = set()

# KnownDLLs padrão Win10/11 (nomes de valor REG, lowercase, sem leading '*').
# Win11 24H2+ inclui wow64*, xtajit64*, *kernel32 etc. Qualquer entrada
# fora desta lista = potencial hijack.
_EXPECTED_KNOWN_DLLS = {
    # Core
    "advapi32", "clbcatq", "combase", "comdlg32", "coml2", "difxapi",
    "gdi32", "gdiplus", "imagehlp", "imm32", "kernel32", "msctf",
    "msvcrt", "normaliz", "nsi", "ole32", "oleaut32", "psapi",
    "rpcrt4", "sechost", "setupapi", "shcore", "shell32", "shlwapi",
    "user32", "wldap32", "ws2_32",
    # WOW64 / ARM / JIT (Win10 2004+ e Win11)
    "wow64", "wow64base", "wow64con", "wow64win", "wow64cpu",
    "_wow64cpu", "_wowarmhw",
    "_xtajit", "_xtajitf", "_xtajitse",
    "xtajit", "xtajitf", "xtajitse", "xtajit64", "xtajit64se",
    # Meta-valores
    "dllfailure", "excludefromknowndlls",
    # Path pra system32 (KnownDLLPath value)
    "dlldirectory", "dlldirectory32",
}


def _normalize_knowndll_name(name: str) -> str:
    """Normaliza nome de valor KnownDLLs: lower + remove leading '*'."""
    n = (name or "").lower().strip()
    # Win11 marca algumas entradas com '*' (ex.: *kernel32)
    while n.startswith("*"):
        n = n[1:]
    return n


def _read_multi_sz(sub, name: str) -> list[str]:
    """Lê um REG_MULTI_SZ e retorna lista de strings. [] se não existe."""
    try:
        val, typ = winreg.QueryValueEx(sub, name)
    except OSError:
        return []
    if isinstance(val, list):
        return [str(x) for x in val if x]
    if isinstance(val, str):
        return [val] if val else []
    return []


def _read_str(sub, name: str) -> str:
    try:
        val, _ = winreg.QueryValueEx(sub, name)
    except OSError:
        return ""
    return val if isinstance(val, str) else ""


def scan_session_manager_abuse() -> dict:
    """
    Verifica Session Manager\\BootExecute, SetupExecute, KnownDLLs.
    Qualquer desvio do baseline = critical.
    """
    name = "Session Manager (Boot/KnownDLLs)"
    desc = ("HKLM\\SYSTEM\\...\\Session Manager — BootExecute, SetupExecute e "
            "KnownDLLs; alterações persistem antes do login e carregam em "
            "todos os processos.")

    if not HAS_WINREG:
        return _result(name, desc, [], error="winreg indisponível")

    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _SESSION_MANAGER_KEY)
    except OSError:
        return _result(name, desc, [],
                       error="Session Manager inacessível (requer admin)")

    items = []
    try:
        # 1. BootExecute
        boot_execute = _read_multi_sz(root, "BootExecute")
        for entry in boot_execute:
            e_low = entry.lower().strip()
            if e_low in _EXPECTED_BOOT_EXECUTE:
                continue
            items.append(_item(
                label=f"[BootExecute] {entry}",
                detail=(f"Entrada extra em Session Manager\\BootExecute: {entry}\n"
                        f"BootExecute roda ANTES do subsystem Win32 carregar. "
                        f"O padrão do Windows é só 'autocheck autochk *'. "
                        f"Qualquer outra entrada = execução pré-boot maliciosa."),
                severity="critical", matched="session-mgr-bootexecute",
            ))

        # 2. SetupExecute
        setup_execute = _read_multi_sz(root, "SetupExecute")
        for entry in setup_execute:
            e_low = entry.lower().strip()
            if e_low in _EXPECTED_SETUP_EXECUTE:
                continue
            items.append(_item(
                label=f"[SetupExecute] {entry}",
                detail=(f"Entrada em Session Manager\\SetupExecute: {entry}\n"
                        f"SetupExecute só é usado durante setup do Windows. "
                        f"Fora do contexto de setup = potencial persistência."),
                severity="high", matched="session-mgr-setupexecute",
            ))

        # 3. KnownDLLs — enumera todos os valores
        try:
            kdll_key = winreg.OpenKey(root, "KnownDLLs")
        except OSError:
            kdll_key = None

        if kdll_key is not None:
            try:
                i = 0
                while True:
                    try:
                        vname, val, _typ = winreg.EnumValue(kdll_key, i)
                        i += 1
                    except OSError:
                        break
                    vname_low = _normalize_knowndll_name(vname)
                    val_low = str(val).lower() if val else ""

                    # Ignora entradas esperadas (nome canônico)
                    if vname_low in _EXPECTED_KNOWN_DLLS:
                        # Path values (DllDirectory) devem apontar pra system32
                        if vname_low in ("dlldirectory", "dlldirectory32"):
                            if val_low and "system32" not in val_low and "syswow64" not in val_low:
                                items.append(_item(
                                    label=f"[KnownDLLs] {vname} = {val}",
                                    detail=(f"Valor KnownDLLs redirecionado: "
                                            f"{vname} → {val}\n"
                                            f"O padrão aponta pra %SystemRoot%\\System32. "
                                            f"Redirect pra outra pasta = hijack."),
                                    severity="critical",
                                    matched="session-mgr-knowndlls-redirect",
                                ))
                        # Valor de DLL esperado: basename deve ser <nome>.dll
                        # (ou o próprio nome). Path absoluto fora de system32 = hijack.
                        elif val_low and ("\\" in val_low or "/" in val_low):
                            if "system32" not in val_low and "syswow64" not in val_low:
                                items.append(_item(
                                    label=f"[KnownDLLs] {vname} = {val}",
                                    detail=(f"KnownDLLs '{vname}' aponta pra path "
                                            f"fora de System32: {val}\n"
                                            f"Baseline é só o basename (ex.: kernel32.dll)."),
                                    severity="critical",
                                    matched="session-mgr-knowndlls-redirect",
                                ))
                        continue

                    # Nome não esperado = DLL nova em KnownDLLs
                    items.append(_item(
                        label=f"[KnownDLLs] {vname} = {val}",
                        detail=(f"DLL não-padrão em KnownDLLs: {vname} → {val}\n"
                                f"KnownDLLs são carregadas por TODOS os processos "
                                f"que importam a DLL. Adicionar entrada = injeção "
                                f"em todos os processos do sistema."),
                        severity="critical", matched="session-mgr-knowndlls-extra",
                    ))
            finally:
                winreg.CloseKey(kdll_key)

        # 4. PendingFileRenameOperations — arquivos marcados pra rename/delete
        # no próximo boot. Cheater usa pra deletar artifacts pós-exec.
        pending = _read_multi_sz(root, "PendingFileRenameOperations")
        if pending:
            # Só flagga se aparecer nome de executor
            from . import matching
            for entry in pending:
                if not entry:
                    continue
                kw, sev = matching.match_keyword(entry)
                if kw:
                    items.append(_item(
                        label=f"[PendingRename] {entry[:80]}",
                        detail=(f"Operação de rename/delete agendada pra próximo "
                                f"boot com nome de executor: {entry}\n"
                                f"Padrão: cheater deleta rastros no próximo boot "
                                f"sem precisar rodar cleaner manual."),
                        severity="high", matched=f"pending-rename:{kw}",
                    ))
    finally:
        winreg.CloseKey(root)

    return _result(name, desc, items)


# ============================ LSA Packages ============================

_LSA_KEY = r"SYSTEM\CurrentControlSet\Control\Lsa"

# Baseline esperado em Win10/11.
_EXPECTED_AUTH_PACKAGES = {
    "msv1_0",
}

_EXPECTED_SECURITY_PACKAGES = {
    "kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u",
    "cloudap",  # Win 10+
    "credssp",  # Win 10+
    "negoexts", "livessp",
    "\"\"",  # empty entry às vezes aparece
    "",
}

_EXPECTED_NOTIFICATION_PACKAGES = {
    "rassfm", "scecli",  # Win 10/11 defaults
}


def scan_lsa_packages() -> dict:
    """
    Verifica HKLM\\...\\Lsa\\Authentication Packages, Security Packages,
    Notification Packages. Qualquer DLL extra = carregada pelo LSASS.
    """
    name = "LSA Packages (LSASS injection)"
    desc = ("DLLs carregadas pelo LSASS (Authentication, Security, "
            "Notification). Qualquer entrada não-padrão = injeção em processo "
            "mais privilegiado que SYSTEM.")

    if not HAS_WINREG:
        return _result(name, desc, [], error="winreg indisponível")

    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _LSA_KEY)
    except OSError:
        return _result(name, desc, [],
                       error="LSA key inacessível (requer admin)")

    items = []
    checks = (
        ("Authentication Packages", _EXPECTED_AUTH_PACKAGES,
         "critical", "auth-package"),
        ("Security Packages", _EXPECTED_SECURITY_PACKAGES,
         "critical", "security-package"),
        ("Notification Packages", _EXPECTED_NOTIFICATION_PACKAGES,
         "critical", "notification-package"),
    )

    try:
        for value_name, baseline, severity, kind in checks:
            entries = _read_multi_sz(root, value_name)
            for entry in entries:
                e_low = entry.lower().strip()
                if e_low in baseline:
                    continue
                if not e_low or e_low in {'""', "''"}:
                    continue
                items.append(_item(
                    label=f"[LSA {value_name}] {entry}",
                    detail=(f"Entrada não-padrão em Lsa\\{value_name}: {entry}\n"
                            f"DLLs em LSA são carregadas pelo LSASS.EXE, o "
                            f"processo mais privilegiado do Windows user-mode. "
                            f"Somente software corporativo específico (Cisco ISE, "
                            f"credential providers customizados) adiciona entradas "
                            f"aqui. Padrão do Windows 11 é: {', '.join(sorted(baseline))}"),
                    severity=severity,
                    matched=f"lsa-{kind}:{e_low}",
                ))
    finally:
        winreg.CloseKey(root)

    return _result(name, desc, items)


ALL_OS_INTEGRITY_SCANNERS = [
    scan_session_manager_abuse,
    scan_lsa_packages,
]
