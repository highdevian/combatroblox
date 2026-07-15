"""
PE header analysis + SHA256 hash matching.

Pega cheat RENOMEADO (hash bate independente do nome) e detecta
packers usados pra esconder cheat (UPX/Themida/VMProtect/Enigma).
"""

import os
import re
import struct
import hashlib
from datetime import datetime


# Caminho de arquivo PE (drive-letter ou UNC) terminando em exe/dll/ocx/sys,
# seguido de fim, espaço, aspas ou pipe. Casa o path mesmo quando vem com
# sufixo depois da extensão — ex.: Amcache reporta "C:\x\cheat.exe SHA1=...".
_PE_PATH_RE = re.compile(
    r'(?:[A-Za-z]:\\|\\\\)[^\n"|]*?\.(?:exe|dll|ocx|sys)(?=$|[\s"|])',
    re.IGNORECASE,
)


def _extract_pe_path(detail: str) -> str | None:
    """Extrai o caminho de um PE de um campo 'detail'. Casa "C:\\x\\cheat.exe"
    sozinho e "C:\\x\\cheat.exe SHA1=..." (Amcache anexa o hash depois do path).
    O .endswith() antigo, que exigia a linha inteira terminar na extensão, cegava
    nesse 2º caso e deixava o Amcache sem PE analysis."""
    for raw in detail.split("\n"):
        token = raw.strip().strip('"').strip()
        if not token:
            continue
        m = _PE_PATH_RE.search(token)
        if m:
            return m.group(0)
        # Fallback: linha que já é só o path (comportamento antigo preservado,
        # cobre path relativo/sem drive que o regex acima não casa).
        if token.lower().endswith((".exe", ".dll", ".ocx", ".sys")):
            return token
    return None


def compute_sha256(path: str, max_size: int = 100_000_000) -> str | None:
    """SHA256 de um arquivo. Skip se > 100MB pra não travar."""
    try:
        if os.path.getsize(path) > max_size:
            return None
    except OSError:
        return None

    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(8192 * 16)
                if not chunk:
                    break
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


# Section names usadas por packers conhecidos
PACKER_SIGNATURES = {
    ".upx0":     "UPX",
    ".upx1":     "UPX",
    ".upx2":     "UPX",
    ".themida":  "Themida",
    ".vmp0":     "VMProtect",
    ".vmp1":     "VMProtect",
    ".vmp2":     "VMProtect",
    ".enigma1":  "Enigma Protector",
    ".enigma2":  "Enigma Protector",
    ".aspack":   "ASPack",
    ".adata":    "ASPack",
    ".pec1":     "PECompact",
    ".pec2":     "PECompact",
    ".mpress1":  "MPRESS",
    ".mpress2":  "MPRESS",
    ".pelock":   "PELock",
    ".petite":   "Petite",
    ".y0da":     "yoda's Crypter",
    ".reloc7":   "MoleBox",
}


def parse_pe_header(path: str) -> dict:
    """
    Parser básico de PE header SEM dependências externas.
    Retorna: is_pe, compile_timestamp, sections, is_packed, packer_name, size.
    """
    result = {
        "is_pe": False, "compile_timestamp": None, "sections": [],
        "is_packed": False, "packer_name": None, "size": 0,
        "machine": None,
    }

    try:
        result["size"] = os.path.getsize(path)
    except OSError:
        return result
    if result["size"] < 64:
        return result

    try:
        with open(path, "rb") as fh:
            dos = fh.read(64)
            if dos[:2] != b"MZ":
                return result
            pe_offset = struct.unpack("<I", dos[0x3C:0x40])[0]
            if pe_offset >= result["size"] - 24:
                return result

            fh.seek(pe_offset)
            if fh.read(4) != b"PE\x00\x00":
                return result

            result["is_pe"] = True
            coff = fh.read(20)
            if len(coff) < 20:
                return result

            machine = struct.unpack("<H", coff[0:2])[0]
            num_sections = struct.unpack("<H", coff[2:4])[0]
            timestamp = struct.unpack("<I", coff[4:8])[0]
            opt_hdr_size = struct.unpack("<H", coff[16:18])[0]

            result["machine"] = {0x14c: "x86", 0x8664: "x64", 0xaa64: "ARM64"}.get(machine, f"0x{machine:x}")

            try:
                # PE timestamps válidos: 2000-01-01 até 2050-01-01
                if 946684800 < timestamp < 2524608000:
                    result["compile_timestamp"] = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
            except (ValueError, OSError, OverflowError):
                pass

            fh.seek(pe_offset + 4 + 20 + opt_hdr_size)

            for _ in range(min(num_sections, 96)):
                sec = fh.read(40)
                if len(sec) < 40:
                    break
                name = sec[:8].split(b"\x00")[0].decode("latin-1", errors="replace").strip()
                if name:
                    result["sections"].append(name)

            for sec_name in result["sections"]:
                key = sec_name.lower()
                if key in PACKER_SIGNATURES:
                    result["is_packed"] = True
                    result["packer_name"] = PACKER_SIGNATURES[key]
                    break
    except (OSError, struct.error, IndexError):
        pass

    return result


# Hashes SHA256 de executores conhecidos. Lista comunitária — adicionar conforme samples sejam analisadas.
# Formato: "hash_lowercase": "nome do executor / versão"
KNOWN_EXECUTOR_HASHES = {
    # Placeholder — pra produção, popular com hashes reais coletados da comunidade.
    # Exemplo (ESSES HASHES SÃO FICTÍCIOS, NÃO USAR):
    # "a1b2c3...": "Krnl v1.x bootstrapper",
    # "d4e5f6...": "Wave Executor v3.2",
}


def check_known_hash(sha256: str | None) -> str | None:
    if not sha256:
        return None
    return KNOWN_EXECUTOR_HASHES.get(sha256.lower())


def analyze_executable(path: str) -> dict:
    """Combina SHA256 + PE header + hash DB lookup."""
    if not os.path.isfile(path):
        return {}
    sha256 = compute_sha256(path)
    pe = parse_pe_header(path)
    hash_match = check_known_hash(sha256)
    return {
        "path": path,
        "sha256": sha256,
        "pe": pe,
        "hash_match": hash_match,
    }


def enrich_findings_with_pe(findings: list, max_items: int = 30) -> list:
    """
    Pra cada item cujo detail aponta pra um arquivo .exe/.dll existente,
    anexa PE analysis ao item (campo 'pe_info').

    Items recebem severity bump se: packed, compiled recentemente, ou hash match.
    Cap em max_items pra não travar.
    """
    enriched = 0
    for f in findings:
        for item in f.get("items", []):
            if enriched >= max_items:
                return findings
            detail = item.get("detail") or ""
            path = _extract_pe_path(detail)
            if not path:
                continue
            if not os.path.isfile(path):
                continue

            info = analyze_executable(path)
            if not info or not info.get("pe", {}).get("is_pe"):
                continue

            item["pe_info"] = info
            enriched += 1

            # Severity bumps
            pe = info["pe"]
            if pe.get("is_packed"):
                # Packer detectado é red flag forte
                if item.get("severity") in ("low", "medium"):
                    item["original_severity"] = item.get("severity")
                    item["severity"] = "high"
                    item["fp_reason"] = (item.get("fp_reason") or "") + \
                        f" | UPGRADE: packed com {pe['packer_name']}"

            ts = pe.get("compile_timestamp")
            if ts:
                try:
                    dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                    age_days = (datetime.now() - dt).days
                    if age_days < 30:
                        # Compilado nos últimos 30 dias = bem suspeito
                        if item.get("severity") == "low":
                            item["original_severity"] = "low"
                            item["severity"] = "medium"
                            item["fp_reason"] = (item.get("fp_reason") or "") + \
                                f" | UPGRADE: compilado há {age_days}d"
                except ValueError:
                    pass

            if info.get("hash_match"):
                item["original_severity"] = item.get("severity")
                item["severity"] = "high"
                item["fp_reason"] = (item.get("fp_reason") or "") + \
                    f" | HASH MATCH: {info['hash_match']}"

    return findings
