"""
Atualização remota da base de assinaturas (opt-in, isolada).

FILOSOFIA — por que isso não fere o "100% local":
  O scan normal do Telador NUNCA toca a rede. Esta atualização só roda
  quando o supervisor pede explicitamente (`telador.exe --update-sigs`).
  É um comando de manutenção separado, não parte da análise. Os dados do
  suspeito continuam nunca saindo do PC — o que sai daqui é só um GET
  pra baixar a LISTA DE ASSINATURAS pública do GitHub.

POR QUE EXISTE:
  As assinaturas embutidas no .exe envelhecem — sai executor novo toda
  semana. Sem isso, adicionar um executor exigiria rebuildar e redistribuir
  o binário de 10 MB. Com isso, basta um commit no signatures.json do repo,
  e quem rodar `--update-sigs` pega a lista nova (arquivo de ~KB), sem
  trocar o .exe.

SEGURANÇA / ROBUSTEZ:
  - URL hardcoded (raw do próprio repo) sobre HTTPS — transporte autêntico.
  - Timeout curto; qualquer falha de rede degrada graciosamente (a base
    embutida continua valendo).
  - Valida que o conteúdo é JSON com estrutura esperada ANTES de salvar.
    Um arquivo corrompido/vazio nunca substitui a base local boa.
  - Sem dependência nova: usa urllib da stdlib.
"""

from __future__ import annotations

import io
import json
import os
import urllib.request
from urllib.parse import urlparse

# Raw do arquivo CANÔNICO de assinaturas no repo oficial. HTTPS = GitHub
# autenticado. É `signatures.dist.json` (versionado no repo), separado do
# `signatures.json` local (cache do usuário, gitignored, que recebe o
# download). Adicionar executor = commit no signatures.dist.json.
SIGNATURES_URL = (
    "https://raw.githubusercontent.com/highdevian/combatroblox/main/signatures.dist.json"
)

_TIMEOUT_S = 8
_MAX_BYTES = 2 * 1024 * 1024  # 2 MB — assinaturas são KB; trava abuso/erro


def _looks_like_valid_signatures(data) -> bool:
    """Confere que o JSON baixado tem a cara de uma base de assinaturas."""
    if not isinstance(data, dict):
        return False
    known_sections = (
        "executor_keywords", "executor_process_names", "suspicious_domains",
        "suspicious_folder_names", "script_red_flags",
    )
    # Precisa ter pelo menos uma seção conhecida, e ela ser um objeto.
    has_section = any(isinstance(data.get(s), dict) for s in known_sections)
    return has_section


def update_signatures(url: str = None, dest: str = None,
                      timeout: int = _TIMEOUT_S) -> tuple[bool, str]:
    """
    Baixa a base de assinaturas e salva localmente. Devolve (ok, mensagem).

    Nunca levanta exceção — qualquer falha vira (False, motivo). A base
    local atual só é sobrescrita se o download for um JSON válido.
    """
    url = url or SIGNATURES_URL
    # A base baixada vira regra de detecção. Sem TLS, um MITM (ou `file:` /
    # `http:` apontado de fora) poderia injetar assinaturas — falso positivo
    # (acusar inocente) ou falso negativo (deixar cheat passar). Exige HTTPS;
    # só libera http pra loopback (mirror local/teste, onde não há MITM).
    _parsed = urlparse(url)
    _loopback = (_parsed.hostname or "") in ("127.0.0.1", "localhost", "::1")
    if not (_parsed.scheme == "https" or (_parsed.scheme == "http" and _loopback)):
        return False, f"URL de assinaturas precisa ser https:// (recebido: {url[:40]})"
    if dest is None:
        try:
            import database
            dest = database.signatures_path()
        except Exception:
            return False, "não consegui resolver o caminho local de destino"

    # 1. Baixa (com timeout, limite de tamanho)
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "telador-sigupdate"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(_MAX_BYTES + 1)
    except Exception as e:
        return False, f"falha de rede ({type(e).__name__}: {e})"

    if len(raw) > _MAX_BYTES:
        return False, "arquivo remoto grande demais (suspeito) — abortado"
    if not raw:
        return False, "resposta vazia do servidor"

    # 2. Valida que é JSON com estrutura de assinaturas
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception as e:
        return False, f"conteúdo remoto não é JSON válido ({e})"
    if not _looks_like_valid_signatures(data):
        return False, "conteúdo remoto não parece uma base de assinaturas — ignorado"

    version = data.get("version") if isinstance(data.get("version"), str) else "?"

    # 3. Conta quantas assinaturas tem (pra reportar)
    total = 0
    for s in ("executor_keywords", "executor_process_names", "suspicious_domains",
              "suspicious_folder_names", "script_red_flags"):
        sec = data.get(s)
        if isinstance(sec, dict):
            total += len(sec)

    # 4. Salva (escreve em tmp e renomeia — atômico, não corrompe se cair no meio)
    try:
        dest_dir = os.path.dirname(os.path.abspath(dest))
        if dest_dir:
            os.makedirs(dest_dir, exist_ok=True)
        tmp = dest + ".tmp"
        with io.open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, dest)
    except Exception as e:
        return False, f"não consegui salvar ({e})"

    return True, f"base atualizada (versao {version}, {total} assinaturas) -> {dest}"
