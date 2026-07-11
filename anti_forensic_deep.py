"""
Forense pós-mortem — pega resíduos que sobrevivem a "fechei o cheat e passei
o CCleaner". Complementa cleaner_tools/anti_forensics existentes.

Cenário-alvo: cheater mostra o external funcionando, fecha, roda cleaner,
depois libera acesso via AnyDesk pra "provar" que tá limpo. Os scanners
convencionais (processos vivos, Prefetch, Amcache) já foram esvaziados.
Aqui pegamos rastros em fontes que cleaner popular NÃO cobre:

  1) scan_defender_detection_history — parse dos binários de detecção do
     Windows Defender em C:\\ProgramData\\Microsoft\\Windows Defender\\Scans\\
     History\\Service\\DetectionHistory. Se o Defender viu o cheat alguma
     vez (mesmo o cara clicando "Allowed"/"Removed"), a detecção fica
     ETERNAMENTE gravada num .bin binário — cleaner popular NÃO limpa.

  2) scan_dxshader_cache — recente compilação de shader no cache do driver
     GPU (%LOCALAPPDATA%\\NVIDIA\\DXCache, %LOCALAPPDATA%\\D3DSCache, etc).
     External com ESP renderizado via Direct3D obriga o driver a compilar
     shader → arquivo .bin com timestamp recente fica no cache. Cleaner
     não sabe limpar esses. Uma explosão de shaders novos correlacionada
     com sessões do Roblox é sinal comportamental de external com ESP.

  3) scan_wer_reports — %ProgramData%\\Microsoft\\Windows\\WER\\ReportArchive
     e ReportQueue. TODO exe que crashou (mesmo silenciosamente) fica
     registrado com FULL PATH + hash + versão. Cheat que já crashou uma
     vez fica gravado — cleaner popular não mexe aí.

  4) scan_reliability_monitor — %ProgramData%\\Microsoft\\RAC\\StateData\\
     RacWmiEventData.dat + %WINDIR%\\System32\\LogFiles\\Sum\\Current.mdb.
     Log de instalações/execuções/crashes usado pelo Reliability Monitor
     (perfmon /rel). Persistente por padrão — só limpa reinstalando o SO.

Todos são LOW/MEDIUM sozinhos (heurísticos) mas alimentam o Confidence
Engine. Combinados com sinais do external_scanner cravam.
"""

from __future__ import annotations

from models import _result, _item, _fmt_ts
import os
import re
import struct
import time
from datetime import datetime, timedelta

import debug

try:
    from database import EXECUTOR_KEYWORDS
except ImportError:
    EXECUTOR_KEYWORDS = []

try:
    import matching
    HAS_MATCHING = True
except ImportError:
    HAS_MATCHING = False


# ============================ (1) Windows Defender Detection History ============================

_DEFENDER_HISTORY_ROOTS = (
    r"C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory",
    r"C:\ProgramData\Microsoft\Windows Defender\Scans\History\CacheManager\Backup",
)

# Extraímos strings ASCII/UTF-16 do binário MpBinaryFormat — não vale a pena
# implementar o parser completo (é um formato proprietário de blob), a
# extração de strings resolve pro forense. Padrões que interessam:
# Regex de string (aplicados tanto no ASCII quanto no UTF-16 decodificado).
_RE_PATH = re.compile(
    r"([A-Za-z]:\\[^\x00\r\n]{4,255}\.(?:exe|dll|sys|scr|com|bat|cmd))",
    re.IGNORECASE,
)
_RE_THREAT = re.compile(
    r"(HackTool|Trojan|PUA|Backdoor|Exploit|VirTool|RemoteAdmin|SecurityRisk)"
    r"[:.][A-Za-z0-9/_.-]+",
    re.IGNORECASE,
)
_RE_HASH = re.compile(r"\b([A-Fa-f0-9]{40,64})\b")


def _extract_defender_strings(data: bytes) -> dict:
    """Extrai path, threat name, hash do blob binário. Roda os regex de string
    em dois passes: (1) ASCII com null-strip, (2) UTF-16 LE decodificado. Rodar
    regex direto em bytes UTF-16 quebra por causa dos metacaracteres serem
    bytes crus — decodificar resolve."""
    out = {"paths": set(), "threats": set(), "hashes": set()}

    def _sweep(text: str):
        for m in _RE_PATH.finditer(text):
            out["paths"].add(m.group(1))
        for m in _RE_THREAT.finditer(text):
            out["threats"].add(m.group(0))
        for m in _RE_HASH.finditer(text):
            out["hashes"].add(m.group(1))

    # Pass 1: ASCII (bytes → latin-1 preserva 0-255 sem perda)
    try:
        _sweep(data.decode("latin-1", errors="replace"))
    except Exception as e:
        debug.dbg("defender ASCII sweep falhou", e)
    # Pass 2: UTF-16 LE
    try:
        _sweep(data.decode("utf-16-le", errors="replace"))
    except Exception as e:
        debug.dbg("defender UTF-16 sweep falhou", e)

    return out


# Tokens fortes de cheat/external (elevam pra HIGH).
_FORENSIC_STRONG_TOKENS = (
    "cheat", "bypass", "aimbot", "esp", "injector", "inject",
    "external", "executor", "scriptware", "script-ware", "seliware",
    "winter", "valex", "skript", "robloxexternal", "rbxexternal",
    "cheat engine", "cheatengine",
)

# Dual-use: macro/clicker/debugger — legítimos em dev, cheaters usam igual.
# Reporta MEDIUM (revisar), não crava sozinho.
_FORENSIC_DUALUSE_TOKENS = (
    "autoclicker", "auto clicker", "tinytask", "macro recorder",
    "processhacker", "systeminformer", "process hacker", "system informer",
)

# Categorias de ameaça do Defender relevantes pra cheat/tooling.
# Trojan genérico é ruído (qualquer download flaggado) — só eleva se o path
# do mesmo blob for de interesse.
_DEFENDER_STRONG_THREAT = (
    "hacktool", "remoteadmin", "virtool", "securityrisk", "pua",
)


def _is_cheat_related(text: str) -> tuple[bool, str, str]:
    """Match keyword de executor/cheat no texto.
    Retorna (True, keyword, severity) se bater; senão (False, '', '')."""
    if not text:
        return False, "", ""
    if HAS_MATCHING:
        kw, sev = matching.match_keyword(text)
        if kw:
            return True, kw, (sev or "high")
    try:
        import external_scanner as _ext
        hit = _ext.classify_path_or_text(text) or _ext.classify_process_name(
            os.path.basename(text)
        )
        if hit:
            return True, hit[2], hit[0]  # matched, sev from catalog
    except Exception:
        pass
    low = text.lower()
    for tok in _FORENSIC_STRONG_TOKENS:
        if tok in low:
            return True, tok, "high"
    for tok in _FORENSIC_DUALUSE_TOKENS:
        if tok in low:
            return True, tok, "medium"
    return False, "", ""


def scan_defender_detection_history() -> dict:
    """Enumera detecções históricas do Defender (persistem mesmo após 'Clear
    History' no UI). Se algum dia o cheat foi detectado, aparece aqui — mesmo
    que o usuário tenha clicado 'Allowed'. Não precisa que o cheat esteja
    rodando agora. Um dos poucos rastros que cleaner popular NÃO limpa.
    """
    name = "Defender: histórico de detecções (persistente)"
    desc = "Detecções gravadas em MpBinaryFormat — sobrevive a 'Clear History' + cleaner"

    all_files = []
    for root in _DEFENDER_HISTORY_ROOTS:
        if not os.path.isdir(root):
            continue
        try:
            for dirpath, _, filenames in os.walk(root):
                for f in filenames:
                    full = os.path.join(dirpath, f)
                    all_files.append(full)
        except (OSError, PermissionError):
            pass

    if not all_files:
        return _result(name, desc, [],
                       error="Detection history vazio ou sem acesso (rode como admin)")

    items = []
    seen_paths = set()
    seen_threats = set()

    for f in all_files:
        try:
            with open(f, "rb") as fh:
                data = fh.read(2 * 1024 * 1024)  # 2 MB máximo por arquivo
        except (OSError, PermissionError):
            continue

        extracted = _extract_defender_strings(data)

        try:
            mtime = _fmt_ts(os.path.getmtime(f))
        except OSError:
            mtime = ""

        # Paths: só reporta se for de interesse forense (executor/cheat/dual-use).
        # Path genérico (python.exe, installer qualquer) vira ruído sem isso.
        interesting_paths_in_blob = []
        for p in extracted["paths"]:
            p_low = p.lower()
            if p_low in seen_paths:
                continue
            if any(t in p_low for t in (
                "\\windows\\", "\\program files\\", "\\programdata\\microsoft\\",
                "\\windows defender\\", "\\microsoft\\", "\\system32\\",
            )):
                continue
            hit, kw, sev = _is_cheat_related(p)
            if not hit:
                continue
            seen_paths.add(p_low)
            interesting_paths_in_blob.append(p)

            items.append(_item(
                label=f"Defender viu (histórico): {os.path.basename(p)}",
                detail=f"Path detectado: {p}\n"
                       f"Registro em: {os.path.basename(f)}\n"
                       f"Última modificação do registro: {mtime}\n"
                       f"Keyword forense: {kw}\n"
                       f"O Defender REGISTROU esse arquivo alguma vez — mesmo após "
                       f"o usuário clicar 'Allowed' ou 'Removed' no UI, a entrada "
                       f"binária persiste (cleaner popular não limpa).",
                severity=sev or "high",
                matched=kw,
                timestamp=mtime,
            ))

        # Threats: HackTool/RemoteAdmin/VirTool/PUA/SecurityRisk = forte.
        # Trojan/Backdoor genérico só se o MESMO blob tem path de interesse
        # (senão vira FP com qualquer download flaggado no Defender).
        for t in extracted["threats"]:
            t_low = t.lower()
            if t_low in seen_threats:
                continue
            strong = any(k in t_low for k in _DEFENDER_STRONG_THREAT)
            weak_trojan = any(k in t_low for k in ("trojan", "backdoor", "exploit"))
            if not strong and not (weak_trojan and interesting_paths_in_blob):
                continue
            seen_threats.add(t_low)
            items.append(_item(
                label=f"Threat name histórico: {t}",
                detail=f"Registro em: {os.path.basename(f)}\n"
                       f"Última modificação: {mtime}\n"
                       f"Nome de ameaça registrado pelo Defender. Categoria "
                       f"'HackTool/RemoteAdmin' cobre executores/cheats — "
                       f"persistente. Trojan genérico só sobe se o path do "
                       f"mesmo registro for de interesse forense.",
                severity="high" if strong else "medium",
                matched=f"defender-threat:{t_low[:32]}",
                timestamp=mtime,
            ))

    return _result(name, desc, items)


# ============================ (2) DirectX Shader Cache ============================

_DX_SHADER_CACHE_ROOTS = (
    r"%LOCALAPPDATA%\NVIDIA\DXCache",
    r"%LOCALAPPDATA%\NVIDIA\GLCache",
    r"%LOCALAPPDATA%\NVIDIA\ComputeCache",
    r"%LOCALAPPDATA%\AMD\DxCache",
    r"%LOCALAPPDATA%\AMD\GLCache",
    r"%LOCALAPPDATA%\D3DSCache",
    r"%LOCALAPPDATA%\ATI\Cache",
    r"%LOCALAPPDATA%\Intel\ShaderCache",
    # Windows 11 D3D cache
    r"%LOCALAPPDATA%\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\LocalCache\Local\D3DSCache",
)

# Janela relevante: últimas 24h (cobre a sessão do dia). Dentro dela, procuramos
# BURSTS — muitos shaders comprimidos em janela pequena (15 min) = renderização
# nova. Threshold conservador pra não FP com sessão longa do Roblox.
_DXCACHE_RECENT_WINDOW_SEC = 48 * 60 * 60  # últimas 48h (SS no dia seguinte)
_DXCACHE_BURST_WINDOW_SEC  = 20 * 60       # janela de burst: 20 min
_DXCACHE_BURST_THRESHOLD   = 3             # 3+ shaders em 20 min = burst (ESP fino)


def scan_dxshader_cache() -> dict:
    """Detecta burst recente de shader compilation. External renderizando
    ESP via D3D força o driver GPU a compilar shaders — cada compilação
    gera .bin no cache. Um burst grande de arquivos novos em janela pequena,
    especialmente quando o Roblox está aberto, é sinal comportamental.

    Sozinho é MEDIUM (jogo novo também gera burst). No correlation, se o
    processo do external também aparece em outros sinais, eleva.
    """
    name = "DirectX Shader Cache (burst recente)"
    desc = "Compilação de shader D3D recente — hint de ESP renderizado via Direct3D"

    now = time.time()
    cutoff = now - _DXCACHE_RECENT_WINDOW_SEC

    per_root = {}
    all_recent_files = []

    for raw_root in _DX_SHADER_CACHE_ROOTS:
        root = os.path.expandvars(raw_root)
        if not os.path.isdir(root):
            continue
        try:
            for dirpath, _, filenames in os.walk(root):
                for fn in filenames:
                    full = os.path.join(dirpath, fn)
                    try:
                        mtime = os.path.getmtime(full)
                    except OSError:
                        continue
                    if mtime >= cutoff:
                        per_root.setdefault(root, []).append((full, mtime))
                        all_recent_files.append((full, mtime, root))
        except (OSError, PermissionError):
            continue

    if not per_root:
        return _result(name, desc, [])

    items = []
    seen_bursts = set()

    # Burst detection dentro da janela de 24h: sliding window de 15 min, se
    # tiver >= 5 shaders na mesma janela = burst reportado. Um item por root.
    for root, files in per_root.items():
        files.sort(key=lambda t: t[1])
        best_burst = None  # (start_ts, end_ts, count)
        for i, (_, ts_i) in enumerate(files):
            window_end = ts_i + _DXCACHE_BURST_WINDOW_SEC
            count = 0
            end_ts = ts_i
            for _, ts_j in files[i:]:
                if ts_j > window_end:
                    break
                count += 1
                end_ts = ts_j
            if count >= _DXCACHE_BURST_THRESHOLD:
                if best_burst is None or count > best_burst[2]:
                    best_burst = (ts_i, end_ts, count)

        if best_burst is None:
            continue

        key = os.path.basename(root)
        if key in seen_bursts:
            continue
        seen_bursts.add(key)

        start_ts, end_ts, n = best_burst
        window_min = max(1, int((end_ts - start_ts) / 60))
        items.append(_item(
            label=f"Burst de shader D3D: {n} em {window_min} min",
            detail=f"Cache: {root}\n"
                   f"Janela: {_fmt_ts(start_ts)} → {_fmt_ts(end_ts)}\n"
                   f"Rate: {n} shaders em ~{window_min} min. Compilation burst "
                   f"sugere renderização D3D nova nesta janela — se coincidiu com "
                   f"sessão do Roblox e você suspeita de external ESP, é sinal "
                   f"corroborante. Sozinho é comportamental (jogo novo também "
                   f"gera burst).",
            severity="low",  # sozinho é LOW; correlation eleva
            matched=f"dxcache-burst:{key}",
            timestamp=_fmt_ts(end_ts),
        ))

    return _result(name, desc, items)


# ============================ (3) WER Reports ============================

_WER_ROOTS = (
    r"C:\ProgramData\Microsoft\Windows\WER\ReportArchive",
    r"C:\ProgramData\Microsoft\Windows\WER\ReportQueue",
    r"C:\Users\%USERNAME%\AppData\Local\Microsoft\Windows\WER\ReportArchive",
    r"C:\Users\%USERNAME%\AppData\Local\Microsoft\Windows\WER\ReportQueue",
)


def _parse_wer_report_wer(path: str) -> dict:
    """Parse superficial de Report.wer — INI-style file com AppPath, AppName,
    Sig[N].Value, etc."""
    out = {"app_path": "", "app_name": "", "sig_values": [], "params": {}}
    try:
        with open(path, "r", encoding="utf-16", errors="replace") as f:
            for line in f:
                line = line.strip()
                if "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip()
                if k == "AppPath":
                    out["app_path"] = v
                elif k == "AppName":
                    out["app_name"] = v
                elif k.startswith("Sig") and k.endswith(".Value"):
                    out["sig_values"].append(v)
                elif k.startswith("Sig") and k.endswith(".Name"):
                    out["params"][v] = None
    except (OSError, UnicodeError):
        pass
    return out


def scan_wer_reports() -> dict:
    """Enumera Report.wer / WERInternalMetadata em ReportArchive/Queue.
    Todo exe que crashou fica gravado com FULL PATH + versão + hash. Cheat
    que já crashou uma vez fica registrado — cleaner popular não mexe aí.

    Reporta paths fora do Windows/Program Files (candidatos a cheat).
    Match keyword de executor eleva severity.
    """
    name = "Windows Error Reporting (WER crash cache)"
    desc = "Reports de crash com full path — sobrevive a cleaner"

    all_reports = []
    for raw_root in _WER_ROOTS:
        root = os.path.expandvars(raw_root)
        if not os.path.isdir(root):
            continue
        try:
            for dirpath, _, filenames in os.walk(root):
                for fn in filenames:
                    low = fn.lower()
                    if low == "report.wer" or low.endswith(".wer"):
                        all_reports.append(os.path.join(dirpath, fn))
        except (OSError, PermissionError):
            continue

    if not all_reports:
        return _result(name, desc, [], error="Sem reports do WER (limpou ou sem acesso)")

    items = []
    seen = set()

    for rep in all_reports:
        info = _parse_wer_report_wer(rep)
        app_path = info.get("app_path", "")
        if not app_path:
            continue
        low = app_path.lower().replace("/", "\\")
        if low in seen:
            continue
        seen.add(low)

        # Ignora paths do Windows/Program Files/Roblox/Chrome/etc
        if any(t in low for t in (
            "\\windows\\", "\\program files\\", "\\program files (x86)\\",
            "\\microsoft\\edgeupdate\\", "\\google\\chrome\\",
            "\\microsoft\\onedrive\\", "\\packages\\microsoft.",
        )):
            continue

        try:
            mtime = _fmt_ts(os.path.getmtime(rep))
        except OSError:
            mtime = ""

        # Só flagga se está em user path
        if not any(t in low for t in (
            "\\appdata\\", "\\downloads\\", "\\desktop\\", "\\documents\\",
            "\\users\\public\\", "\\$recycle.bin\\", "\\programdata\\",
            "\\temp\\",
        )):
            continue

        # Skip instaladores genéricos / droppers de setup (Inno/NSIS temp).
        base = os.path.basename(low)
        hit, kw, sev = _is_cheat_related(app_path)
        if any(x in base for x in (
            "setup", "uninstall", "installer", ".tmp", "is-", "nsis",
        )) and not hit:
            continue

        if not hit:
            # Random hex/GUID name: ainda reporta MEDIUM (revisar).
            try:
                import external_scanner as _ext
                name_for_check = base if base.endswith(".exe") else base + ".exe"
                if not _ext._is_random_exe_name(name_for_check):
                    continue
                kw = "wer-random-name"
                sev = "medium"
            except Exception:
                continue
        matched = kw or "wer-crash-path"

        items.append(_item(
            label=f"WER crash: {info.get('app_name') or os.path.basename(app_path)}",
            detail=f"App path: {app_path}\n"
                   f"Report: {rep}\n"
                   f"Timestamp: {mtime}\n"
                   f"Keyword forense: {kw or '(nome random)'}\n"
                   f"Um exe rodou e crashou (mesmo silenciosamente) deste path. "
                   f"WER guarda o path completo — sobrevive a cleaner.",
            severity=sev,
            matched=matched,
            timestamp=mtime,
        ))

    return _result(name, desc, items)


# ============================ (4) Reliability Monitor / RAC ============================

# Reliability Analysis Component (RAC) — o Perfmon /rel usa isso. Persistente,
# raramente limpado por cleaner popular. Log de instalação/execução/erro/crash.
_RAC_ROOT = r"C:\ProgramData\Microsoft\RAC\StateData"

# Sum log — User Access Logging. Fica em System32\LogFiles\Sum. Log de acesso
# de usuário a serviços — inclui hostnames, timestamps. Requer admin pra ler.
_SUM_ROOT = r"C:\Windows\System32\LogFiles\Sum"


def scan_reliability_monitor() -> dict:
    """Enumera arquivos do Reliability Analysis Component (RAC) e do User
    Access Logging (SUM). Ambos são raramente limpados por cleaner popular
    e mantêm timeline de execuções/instalações. Não implementamos parser
    completo (RacWmiEventData.dat é WMI binário; Sum é ESE/JET); reportamos
    arquivos com timestamp recente que sugerem atividade da janela do incidente.
    """
    name = "Reliability Monitor / User Access Log"
    desc = "RAC + SUM — timeline de execuções resistente a cleaner"

    items = []
    now = time.time()
    cutoff = now - 7 * 24 * 3600  # última semana

    for root in (_RAC_ROOT, _SUM_ROOT):
        if not os.path.isdir(root):
            continue
        try:
            entries = os.listdir(root)
        except (OSError, PermissionError):
            items.append(_item(
                label=f"Sem acesso: {root}",
                detail="Rode como admin pra ler o log.",
                severity="low", matched="rac-access-denied", meta_only=True,
            ))
            continue

        recent_files = []
        for fn in entries:
            full = os.path.join(root, fn)
            try:
                if not os.path.isfile(full):
                    continue
                mt = os.path.getmtime(full)
                if mt >= cutoff:
                    recent_files.append((full, mt))
            except OSError:
                continue

        if not recent_files:
            continue

        recent_files.sort(key=lambda t: t[1], reverse=True)
        newest = recent_files[0]
        items.append(_item(
            label=f"{os.path.basename(root)}: {len(recent_files)} log(s) recentes",
            detail=f"Root: {root}\n"
                   f"Newest: {os.path.basename(newest[0])} @ {_fmt_ts(newest[1])}\n"
                   f"Reliability/Sum logs recentes — abra perfmon /rel (Reliability "
                   f"Monitor) pra ver instalações/execuções/crashes na janela do "
                   f"incidente. Não é evidência sozinha, é PONTEIRO pra investigação "
                   f"manual complementar.",
            severity="low",
            matched=f"rac-recent:{os.path.basename(root).lower()}",
            timestamp=_fmt_ts(newest[1]),
        ))

    return _result(name, desc, items)


# ============================ Chain ============================

ALL_ANTI_FORENSIC_DEEP_SCANNERS = [
    scan_defender_detection_history,
    scan_dxshader_cache,
    scan_wer_reports,
    scan_reliability_monitor,
]
