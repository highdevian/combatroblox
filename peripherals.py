"""
Detecção de software de periférico (mouse/teclado) com motor de macros.

Logitech G HUB tem motor Lua interno IDÊNTICO ao Roblox — cara cria
macro de recoil control, auto headshot, anti-recoil, rapid fire, etc.
Razer Synapse, Bloody, X-Mouse e outros têm sistemas similares.

Quase ninguém checa isso, mas é onde MUITOS escondem o cheat real.
"""

from models import _result, _item, _fmt_ts
import os
import sqlite3
import tempfile
import shutil

from database import MOUSE_SOFTWARE, MACRO_RED_FLAGS


def _scan_macro_content(content: str) -> list[tuple[str, str]]:
    """Procura red flags de macro num blob de texto."""
    hits = []
    lower = content.lower()
    for kw, sev in MACRO_RED_FLAGS.items():
        if kw in lower:
            hits.append((kw, sev))
    return hits


# ============================ Detecção de instalação ============================

def scan_mouse_software_installed() -> dict:
    """
    Detecta software de mouse instalado. Detecção em si já é informativa
    (especialmente Logitech G HUB que é o mais usado pra macros pesadas).
    """
    items = []

    for soft_id, info in MOUSE_SOFTWARE.items():
        installed_in = None
        for raw_path in info["paths"]:
            path = os.path.expandvars(raw_path)
            if os.path.isdir(path):
                installed_in = path
                break

        if not installed_in:
            continue

        try:
            mtime = os.path.getmtime(installed_in)
            ts = _fmt_ts(mtime)
        except OSError:
            ts = ""

        # G HUB instalado sozinho = CONTEXTO, não anti-cheat.
        # Todo dono de Logitech G-series tem G HUB — FP em milhões de PCs.
        # Bloody = mais suspeito historicamente (macros de aim vendidas)
        # mas ainda é software legítimo — só flagga MEDIUM se script real
        # com red flag aparecer (scan_logitech_ghub_scripts / bloody).
        # X-Mouse idem: profile com red flag vira MEDIUM no scan próprio.
        if soft_id == "bloody":
            sev = "low"  # historicamente mais usado por cheat, mas ainda legit
            meta_only = False
        else:
            # Logitech/Razer/Corsair/SteelSeries/etc: contexto puro
            sev = "low"
            meta_only = True  # não conta pro veredito, aparece como info

        items.append(_item(
            label=f"{info['name']} instalado",
            detail=installed_in,
            severity=sev, matched=soft_id, timestamp=ts,
            meta_only=meta_only,
        ))

    return _result("Mouse Software (instalado)",
                   "Software de mouse com motor de macros (Lua/scripting)",
                   items)


# ============================ Logitech G HUB - Lua scripts ============================

def _read_ghub_scripts_from_db(db_path: str) -> list[tuple[str, str]]:
    """
    Logitech G HUB guarda scripts Lua dentro de settings.db (SQLite).
    Tabela 'data' tem JSON com 'profiles' que contém 'scripts'.
    Vou ler como blob e procurar por keywords.
    """
    if not os.path.isfile(db_path):
        return []

    # Copia (DB pode estar locked se G HUB tá rodando)
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db").name
    try:
        shutil.copy2(db_path, tmp)
    except (PermissionError, OSError):
        # Tmp file leak fix
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return []

    findings = []
    conn = None
    try:
        conn = sqlite3.connect(tmp)
        cur = conn.cursor()
        try:
            cur.execute("SELECT _id, _date, file FROM data")
            for row_id, _row_date, blob in cur.fetchall():
                if not blob:
                    continue
                # blob é JSON (bytes ou str)
                if isinstance(blob, bytes):
                    try:
                        text = blob.decode("utf-8", errors="replace")
                    except Exception:
                        continue
                else:
                    text = str(blob)

                hits = _scan_macro_content(text)
                for kw, sev in hits:
                    # Extrai contexto
                    idx = text.lower().find(kw)
                    ctx = text[max(0, idx - 40):idx + len(kw) + 60]
                    ctx = ctx.replace("\n", " ")[:200]
                    findings.append((kw, sev, f"row {row_id}: ...{ctx}..."))
        except sqlite3.OperationalError:
            pass
    except sqlite3.DatabaseError:
        pass
    finally:
        # Garante close (sem isso, arquivo tmp fica lockado no Windows)
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error:
                pass
        try:
            os.unlink(tmp)
        except OSError:
            pass

    # Dedupe por keyword
    seen = set()
    dedup = []
    for kw, sev, ctx in findings:
        if kw in seen:
            continue
        seen.add(kw)
        dedup.append((kw, sev, ctx))
    return dedup


def scan_logitech_ghub_scripts() -> dict:
    """Lê scripts Lua armazenados no G HUB settings.db."""
    db_path = os.path.expandvars(r"%LOCALAPPDATA%\LGHUB\settings.db")
    if not os.path.isfile(db_path):
        return _result("Logitech G HUB - Scripts Lua",
                       "Macros Lua salvas no G HUB", [],
                       error="G HUB não está instalado")

    findings = _read_ghub_scripts_from_db(db_path)
    items = []
    try:
        mtime = os.path.getmtime(db_path)
        ts = _fmt_ts(mtime)
    except OSError:
        ts = ""

    for kw, sev, ctx in findings:
        items.append(_item(
            label=f"Macro G HUB com '{kw}'",
            detail=ctx, severity=sev, matched=kw, timestamp=ts,
        ))

    return _result("Logitech G HUB - Scripts Lua",
                   "Macros Lua salvas no G HUB (recoil control, auto fire, etc.)",
                   items)


# ============================ X-Mouse Button Control ============================

def scan_xmouse_profiles() -> dict:
    """X-Mouse Button Control salva profiles em XML/INI."""
    base = os.path.expandvars(r"%APPDATA%\Highresolution Enterprises\XMouseButtonControl")
    if not os.path.isdir(base):
        return _result("X-Mouse Profiles",
                       "Profiles do X-Mouse Button Control", [],
                       error="X-Mouse não está instalado")

    items = []
    for root, _dirs, files in os.walk(base):
        for f in files:
            if not f.lower().endswith((".xml", ".ini", ".txt", ".cfg")):
                continue
            full = os.path.join(root, f)
            try:
                with open(full, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read(500_000)
            except OSError:
                continue

            hits = _scan_macro_content(content)
            if not hits:
                continue

            try:
                ts = _fmt_ts(os.path.getmtime(full))
            except OSError:
                ts = ""

            seen = set()
            for kw, sev in hits:
                if kw in seen:
                    continue
                seen.add(kw)
                items.append(_item(
                    label=f"X-Mouse '{kw}' em {f}",
                    detail=full, severity=sev, matched=kw, timestamp=ts,
                ))

    return _result("X-Mouse Profiles",
                   "Profiles do X-Mouse Button Control",
                   items)


# ============================ Razer Synapse ============================

def scan_razer_synapse() -> dict:
    """Razer Synapse guarda profiles em JSON em %APPDATA%\\Razer\\Synapse3."""
    base = os.path.expandvars(r"%APPDATA%\Razer\Synapse3")
    if not os.path.isdir(base):
        return _result("Razer Synapse - Profiles",
                       "Profiles do Synapse", [],
                       error="Razer Synapse não detectado")

    items = []
    for root, _dirs, files in os.walk(base):
        for f in files:
            if not f.lower().endswith((".json", ".xml", ".cfg", ".lua")):
                continue
            full = os.path.join(root, f)
            try:
                with open(full, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read(500_000)
            except OSError:
                continue

            hits = _scan_macro_content(content)
            if not hits:
                continue

            try:
                ts = _fmt_ts(os.path.getmtime(full))
            except OSError:
                ts = ""

            seen = set()
            for kw, sev in hits:
                if kw in seen:
                    continue
                seen.add(kw)
                items.append(_item(
                    label=f"Razer '{kw}' em {f}",
                    detail=full, severity=sev, matched=kw, timestamp=ts,
                ))

    return _result("Razer Synapse - Profiles",
                   "Profiles do Razer Synapse (macros podem incluir recoil/aim)",
                   items)


ALL_PERIPHERAL_SCANNERS = [
    scan_mouse_software_installed,
    scan_logitech_ghub_scripts,
    scan_xmouse_profiles,
    scan_razer_synapse,
]
