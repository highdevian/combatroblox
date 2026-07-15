"""
Discord cache scanner.

Procura URLs suspeitas no cache binário do Discord
(%APPDATA%\\discord\\Cache_Data + variantes Canary/PTB).

Cheaters mandam link de download por DM — o Chrome embedded do
Discord cacheia tudo, ficando rastro mesmo se mensagem foi apagada.
"""

from .models import _result, _item
import os
import re
from datetime import datetime, timedelta

from .database import SUSPICIOUS_DOMAINS


DISCORD_CACHE_PATHS = [
    r"%APPDATA%\discord\Cache\Cache_Data",
    r"%APPDATA%\discord\Code Cache",
    r"%APPDATA%\discordcanary\Cache\Cache_Data",
    r"%APPDATA%\discordcanary\Code Cache",
    r"%APPDATA%\discordptb\Cache\Cache_Data",
    r"%APPDATA%\Lightcord\Cache\Cache_Data",
    r"%APPDATA%\BetterDiscord\plugins",
]

# Regex pra URLs (rápido, captura essencial)
URL_RE = re.compile(rb"https?://[A-Za-z0-9._\-/?=&%#~+]{8,200}")


def scan_discord_cache() -> dict:
    """Procura URLs de sites de cheat no cache binário do Discord."""
    items = []
    seen_urls = set()
    cutoff = datetime.now() - timedelta(days=60)
    scanned = 0
    found_any_dir = False

    for raw in DISCORD_CACHE_PATHS:
        base = os.path.expandvars(raw)
        if not os.path.isdir(base):
            continue
        found_any_dir = True

        try:
            entries = os.listdir(base)
        except (PermissionError, OSError):
            continue

        # Pega só arquivos modificados nos últimos 60 dias, cap em 200
        files = []
        for fname in entries:
            full = os.path.join(base, fname)
            if not os.path.isfile(full):
                continue
            try:
                mtime = os.path.getmtime(full)
                if datetime.fromtimestamp(mtime) < cutoff:
                    continue
            except OSError:
                continue
            files.append((full, mtime))

        files.sort(key=lambda x: -x[1])
        for full, mtime in files[:200]:
            try:
                with open(full, "rb") as fh:
                    blob = fh.read(2_000_000)
            except OSError:
                continue
            scanned += 1

            for match in URL_RE.findall(blob):
                try:
                    url = match.decode("ascii", errors="replace").lower()
                except Exception:
                    continue
                if url in seen_urls:
                    continue
                seen_urls.add(url)

                # Match contra database — usa matching central (fronteira de
                # domínio + word-boundary de keyword), evita FP de substring.
                from . import matching
                matched_kw = None
                severity = None
                ulow = url.lower()
                for dom, sev in SUSPICIOUS_DOMAINS.items():
                    if matching.domain_in_text(dom, ulow):
                        matched_kw, severity = dom, sev
                        break
                if not matched_kw:
                    kw, sev = matching.match_keyword(url)
                    if kw:
                        matched_kw, severity = kw, sev

                if not matched_kw:
                    continue

                # Rebaixa severity: ver URL em cache ≠ baixar. Cara entra em
                # servidor de cheats por curiosidade/moderação tem cache cheio.
                # Só mantém HIGH se URL termina em .exe / .dll / .zip / .rar
                # (download direto, não só visita de página).
                is_download = any(url.endswith(ext) for ext in
                                  (".exe", ".dll", ".zip", ".rar", ".7z", ".msi"))
                if not is_download and severity == "high":
                    severity = "medium"

                ts = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
                # Trunca URL pra exibir
                display = url if len(url) < 80 else url[:77] + "..."
                detail_note = "" if is_download else "\n⚠ Apenas visita em cache — não confirma download."
                items.append(_item(
                    label=display,
                    detail=f"Cache: {os.path.basename(full)}\nURL: {url[:300]}{detail_note}",
                    severity=severity, matched=matched_kw, timestamp=ts,
                ))

    if not found_any_dir:
        return _result("Discord Cache", "Cache do Discord (links em DMs)", [],
                       error="Discord não instalado / cache não encontrado")

    desc = f"Cache do Discord ({scanned} arquivos analisados)"
    return _result("Discord Cache", desc, items)


ALL_DISCORD_SCANNERS = [scan_discord_cache]
