"""
Assinatura HMAC do relatório + hash SHA256 do próprio executável.

Permite verificar que:
  1. O .exe que rodou é a versão oficial (cara compara SHA256 do banner
     com o publicado na release do GitHub)
  2. O relatório/.tsr não foi adulterado depois de gerado (verifica HMAC)

Chave embedada — pra repos open-source isso é tamper-EVIDENT (cara teria
que recompilar) mas não tamper-PROOF (recompilação burla). Pra real
proof precisa de assinatura digital com cert ($).
"""

import os
import sys
import hmac
import hashlib


# Chave de assinatura. Trocar antes de cada release "estável" pra invalidar
# relatórios assinados por versões antigas.
HMAC_KEY = b"telador-br-v3.2-tamper-evident-2026"


def get_self_hash() -> str | None:
    """SHA256 do próprio executável (frozen) ou do script (.py)."""
    try:
        if getattr(sys, "frozen", False):
            path = sys.executable
        else:
            path = os.path.abspath(__file__)

        h = hashlib.sha256()
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(8192 * 16)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def compute_hmac(content) -> str:
    """HMAC-SHA256 de string ou bytes. Retorna hex."""
    if isinstance(content, str):
        content = content.encode("utf-8")
    return hmac.new(HMAC_KEY, content, hashlib.sha256).hexdigest()


def verify_hmac(content, signature: str) -> bool:
    if not signature:
        return False
    expected = compute_hmac(content)
    return hmac.compare_digest(expected, signature)
