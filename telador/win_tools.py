"""
Resolve ferramentas nativas do Windows pelo caminho ABSOLUTO em System32.

Por quê: o `subprocess` (CreateProcess) procura o executável primeiro na pasta
do próprio telador.exe e no diretório atual, ANTES do System32. Um suspeito que
roda o telador da pasta Downloads pode plantar um `reg.exe`/`fsutil.exe` falso
ali do lado — e ele seria executado no lugar do real, com admin, justo durante a
perícia. Usar o caminho absoluto do System32 fecha esse PATH/cwd-hijack.

Fallback pro nome puro se o caminho não existir (Windows não-padrão, ou rodando
os testes fora do Windows) — assim nada quebra; só perde o hardening.
"""

import os

_SYSTEM32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")


def tool(name: str) -> str:
    """Caminho absoluto de uma ferramenta do System32 (ex.: 'reg.exe'), ou o
    nome puro como fallback se não existir lá."""
    p = os.path.join(_SYSTEM32, name)
    return p if os.path.isfile(p) else name


def powershell() -> str:
    """powershell.exe vive num subdir do System32, não na raiz."""
    p = os.path.join(_SYSTEM32, "WindowsPowerShell", "v1.0", "powershell.exe")
    return p if os.path.isfile(p) else "powershell"
