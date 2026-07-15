"""
GUI do Telador - software de seguranca desktop premium (Fluent / Malwarebytes).

Filosofia: um produto comercial de analise forense. Nao e dashboard SaaS.
Estrutura minima: header, status, modo, CTA, rodape.

Entry: telador-gui.exe | python gui.py | telador.exe --gui
"""
from __future__ import annotations

import ctypes
import os
import platform
import queue
import secrets
import sys
import threading
import time
import webbrowser
from datetime import datetime

try:
    import customtkinter as ctk
    HAS_CTK = True
except ImportError:
    HAS_CTK = False

import version
import database
import matching
import fp_filter
import redaction
import pe_analysis
import scan_coverage as coverage_mod
import evidence as ev_engine
import report
import report_md
import scanners
import telador


# =========================================================================
# Design tokens (spec corporativa)
# amber = azul principal (chave estavel p/ testes)
# Grade 8px
# =========================================================================

BRAND = {
    "bg":         "#0F1115",
    "bg_card":    "#171A20",   # surface
    "bg_elev":    "#1C2028",
    "bg_hover":   "#232833",
    "bg_input":   "#12151A",
    "border":     "#262B33",
    "border_hi":  "#3A4150",
    "border_soft":"#1C2028",   # separadores quase imperceptiveis
    "amber":      "#2D8CFF",   # azul principal (chave estavel p/ testes)
    "amber_hi":   "#3B96FF",   # hover suave
    "amber_dim":  "#1A5AAB",
    "amber_soft": "#152238",
    "text":       "#FFFFFF",
    "muted":      "#A7AFB8",
    "muted2":     "#6B7380",
    "muted3":     "#4A5160",   # versao / rodape baixa opacidade
    "green":      "#2ECC71",
    "green_soft": "#0F2A1A",
    "yellow":     "#F4B400",
    "yellow_soft":"#2A2208",
    "red":        "#FF4D4F",
    "red_hi":     "#FF4D4F",
    "red_soft":   "#2A1010",
    "shadow":     "#080A0D",
    "focus":      "#2D8CFF",
}

# 8px grid
G = 8

# Escala tipografica (px). Hierarquia unica em toda a GUI.
TYPE = {
    "display": 32,   # veredito
    "title":   20,   # marca / hero de secao
    "hero":    15,   # titulo do CTA block
    "cta":     15,   # botao principal
    "body":    13,   # corpo
    "label":   12,   # labels / status
    "meta":    11,   # meta, subtítulos
    "caption": 10,   # versao, rodape
}

# Fluent UI Icons (Segoe Fluent Icons / MDL2) - mesmo tamanho optico
ICON_FONT = "Segoe Fluent Icons"
ICON_FALLBACK = "Segoe MDL2 Assets"
ICONS = {
    "check":  "\uE73E",
    "shield": "\uE72E",
    "desktop":"\uE7F4",
    "search": "\uE721",
    "warning":"\uE7BA",
}

VERDICT_STYLES = {
    "LIMPO": {
        "emoji": "OK", "color": BRAND["green"], "label": "LIMPO",
        "subtitle": "Nenhum artefato acima do limite de falso positivo",
    },
    "SUSPECT": {
        "emoji": "!", "color": BRAND["yellow"], "label": "SUSPEITO",
        "subtitle": "Sinal parcial, sem confirmação cruzada",
    },
    "SUSPEITO": {
        "emoji": "!", "color": BRAND["yellow"], "label": "SUSPEITO",
        "subtitle": "Sinal parcial, sem confirmação cruzada",
    },
    "DETECTED": {
        "emoji": "X", "color": BRAND["red"], "label": "DETECTADO",
        "subtitle": "Múltiplas fontes cruzadas apontam para o mesmo alvo",
    },
    "CHEATER": {
        "emoji": "X", "color": BRAND["red"], "label": "CHEATER",
        "subtitle": "Executor detectado com alta confiança",
    },
    "CONFIRMED": {
        "emoji": "X", "color": BRAND["red_hi"], "label": "CONFIRMADO",
        "subtitle": "3 ou mais fontes independentes casam",
    },
    "ALTAMENTE": {
        "emoji": "!", "color": BRAND["red"], "label": "ALTAMENTE SUSPEITO",
        "subtitle": "Múltiplos sinais convergem",
    },
    # startswith("POSS") casa "POSSÍVEIS PISTAS" do compute_verdict
    "POSS": {
        "emoji": "!", "color": BRAND["yellow"], "label": "POSSÍVEIS PISTAS",
        "subtitle": "Sinais fracos ou isolados; nao confirma cheat",
    },
    "INCONCLUSIVO": {
        "emoji": "?", "color": BRAND["muted"], "label": "INCONCLUSIVO",
        "subtitle": "Cobertura forense incompleta",
    },
    "?": {
        "emoji": "?", "color": BRAND["muted"], "label": "-", "subtitle": "",
    },
}

SCAN_PROFILES = {
    "full": {
        "title": "Completo",
        "scanners": getattr(version, "SCANNER_COUNT", 113),
        "eta": "2-3 min",
        "hint": "Todas as fontes forenses",
    },
    "fast": {
        "title": "Rápido",
        "scanners": 71,
        "eta": "30-45 s",
        "hint": "SS ao vivo, parsers leves",
    },
}


def _verdict_style(verdict_str: str) -> dict:
    v = (verdict_str or "?").upper()
    for key, style in VERDICT_STYLES.items():
        if v.startswith(key):
            return style
    return VERDICT_STYLES["?"]


def _human_scanner_name(name: str) -> str:
    """scan_prefetch_executables -> Prefetch executables"""
    s = (name or "").strip()
    if not s or s == "iniciando":
        return "Preparando motores..."
    s = s.replace("scan_", "").replace("_", " ").strip()
    if not s:
        return name
    return s[0].upper() + s[1:]


def _format_eta(seconds: float) -> str:
    """Formata tempo restante legivel."""
    if seconds < 0 or seconds != seconds:  # NaN
        return ""
    sec = int(round(seconds))
    if sec < 5:
        return "quase lá"
    if sec < 60:
        return f"~{sec}s restantes"
    mins = sec // 60
    rem = sec % 60
    if mins < 3 and rem:
        return f"~{mins}m {rem:02d}s restantes"
    return f"~{mins} min restantes"


def _staff_next_step(label: str, *, has_admin: bool) -> tuple[str, str]:
    """Retorna (texto, cor_key) da acao recomendada ao staff."""
    lab = (label or "").upper()
    if lab == "LIMPO":
        return "Pode liberar o suspeito.", "green"
    if lab in ("CONFIRMADO", "CHEATER", "DETECTADO"):
        return "Nao liberar. Documente e aplique a politica da liga.", "red"
    if lab in ("SUSPEITO", "ALTAMENTE SUSPEITO") or "PISTA" in lab or lab.startswith("POSS"):
        return "Nao liberar ainda. Revisar o relatorio HTML e os sinais LOW/MEDIUM.", "yellow"
    if lab == "INCONCLUSIVO":
        if not has_admin:
            return "Rode como administrador e repita a analise.", "yellow"
        return "Cobertura incompleta. Repita a SS ou use modo Completo.", "muted"
    return "Abra o relatorio e avalie as evidencias.", "muted"


def _top_target_labels(clusters, limit: int = 4) -> list[str]:
    """Nomes de alvos acionaveis (CONFIRMED/DETECTED primeiro)."""
    if not clusters:
        return []
    rank = {"CONFIRMED": 0, "DETECTED": 1, "SUSPECT": 2, "WEAK": 3}

    def _key(c):
        v = getattr(c, "verdict", "") or ""
        if callable(v):
            try:
                v = c.verdict
            except Exception:
                v = ""
        conf = getattr(c, "confidence_pct", None)
        if callable(conf):
            try:
                conf = c.confidence_pct
            except Exception:
                conf = 0
        return (rank.get(str(v), 9), -(conf or 0))

    ordered = sorted(clusters, key=_key)
    out = []
    for c in ordered:
        lab = getattr(c, "label", None) or "?"
        if lab not in out:
            out.append(lab)
        if len(out) >= limit:
            break
    return out


def _collect_hits_by_severity(
    findings,
    severities: tuple[str, ...] = ("low",),
    *,
    limit: int = 24,
) -> list[dict]:
    """Hits reais por severidade (ignora meta_only).

    Usado na tela de veredito pra staff ver tambem os LOWs - nao so HIGH.
    """
    want = {s.lower() for s in severities}
    out: list[dict] = []
    for f in findings or []:
        scanner = f.get("name") or "?"
        for it in f.get("items") or []:
            if it.get("meta_only"):
                continue
            sev = (it.get("severity") or "low").lower()
            if sev not in want:
                continue
            label = (it.get("label") or it.get("matched") or "?").strip()
            matched = (it.get("matched") or "").strip()
            out.append({
                "severity": sev,
                "scanner": scanner,
                "label": label,
                "matched": matched,
            })
            if len(out) >= limit:
                return out
    return out


def _resource_path(name: str) -> str:
    if getattr(sys, "frozen", False):
        base = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, name)


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _try_elevate() -> bool:
    if _is_admin():
        return False
    try:
        argv = list(sys.argv[1:])
        if "--_relaunched" in argv:
            return False
        import subprocess
        if getattr(sys, "frozen", False):
            exe = sys.executable
            params = subprocess.list2cmdline(argv + ["--_relaunched"])
        else:
            exe = sys.executable
            script = os.path.abspath(sys.argv[0])
            params = subprocess.list2cmdline([script] + argv + ["--_relaunched"])
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        if int(rc) > 32:
            sys.exit(0)
    except Exception:
        pass
    return False


def _build_sys_info(session_code: str = "") -> dict:
    """sys_info estavel por scan (mesmo session_id no HTML e no Discord).

    Espelha a CLI: base em scanners.system_info() + prova de sessao.
    """
    try:
        info = dict(scanners.system_info() or {})
    except Exception:
        info = {}
    if not info or info.get("error"):
        info = {
            "host": platform.node(),
            "user": os.environ.get("USERNAME", "?"),
            "os": f"{platform.system()} {platform.release()}",
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
    # Congela prova de sessao UMA vez por SS
    info["session_id"] = secrets.token_hex(4).upper()
    info["session_code"] = (session_code or "").strip()
    info["admin"] = _is_admin()
    info["telador_version"] = version.VERSION_DISPLAY
    # scan_time unico (nao regenerar no copy Discord)
    info["scan_time"] = info.get("scan_time") or datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S")
    return info


def _minimal_sys_info(session_code: str = "") -> dict:
    """Alias estavel p/ testes e callers legados."""
    return _build_sys_info(session_code)


def _run_scan_thread(
    msg_queue: queue.Queue,
    mode: str = "full",
    sys_info: dict | None = None,
) -> None:
    """Pipeline alinhado com a CLI: run_scanners_parallel + _run_one.

    sys_info DEVE ser o mesmo objeto usado no HTML e no Copiar Discord.
    """
    try:
        if sys_info is None:
            sys_info = _build_sys_info()

        n_sigs, _ = database.load_external_signatures()
        if n_sigs:
            matching.invalidate()
            msg_queue.put(('log', f'{n_sigs} assinatura(s) externa(s)'))

        if mode == "full":
            chain = telador.assemble_scanners(
                skip_forensics=False, skip_antievasion=False,
                skip_persistence=False, skip_live=False,
                skip_history=False, skip_peripherals=False,
            )
            skipped_groups = []
        else:
            chain = telador.assemble_ss_live_scanners()
            skipped_groups = [
                "yara", "winevent", "extra_forensics", "anti_forensic_deep",
                "pca", "task_execlog", "mplog", "cert_store", "shellbag",
                "peripherals", "antievasion", "command_history",
            ]

        total = len(chain)
        msg_queue.put(('progress', 0, total, 'iniciando'))

        def _on_result(result, done, total_n):
            # Nome vem do scanner (ou label humanizado do _run_one em crash)
            label = (result or {}).get("name") or "scanner"
            msg_queue.put(('progress', done, total_n, label))

        # Mesmo executor / crash handler da CLI (telador._run_one)
        findings = telador.run_scanners_parallel(
            chain, max_workers=4, on_result=_on_result,
        )

        findings, fp_stats = fp_filter.post_process_findings(findings)
        findings, _ = redaction.redact_findings(findings)
        findings = pe_analysis.enrich_findings_with_pe(findings)

        # Ordem CLI: clusters -> coverage -> verdict
        evidences = ev_engine.findings_to_evidences(findings)
        clusters = ev_engine.build_clusters(evidences)
        cov = coverage_mod.build_coverage(
            findings, is_admin=bool(sys_info.get("admin", _is_admin())),
            quick=False,
            skipped_groups=skipped_groups, only=None,
            sig_version=getattr(database, "LOADED_SIG_VERSION", None),
        )
        verdict_obj = fp_filter.compute_verdict(findings)
        verdict_obj = coverage_mod.apply_coverage_to_verdict(verdict_obj, cov)

        html_path = report.generate_html_report(
            findings, sys_info, screenshots={},
            verdict=verdict_obj, fp_stats=fp_stats,
            clusters=clusters, coverage=cov,
        )
        msg_queue.put((
            'done', findings, verdict_obj, clusters, cov, html_path, sys_info,
        ))
    except Exception as e:
        import traceback
        msg_queue.put((
            'error',
            f'{type(e).__name__}: {e}\n\n{traceback.format_exc()[:600]}',
        ))


# =========================================================================
# GUI
# =========================================================================

if HAS_CTK:
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")


class TeladorGUI(ctk.CTk if HAS_CTK else object):
    """
    Shell corporativo premium (Fluent / Windows Security).

    Home (estrutura fixa - so refinamos qualidade visual):
      [Header] logo + nome + versao
      [Status] indicadores de sistema
      [CTA]    botao principal
      [Modo]   segmented Completo | Rapido
      [Footer] host · user · sair
    """

    # Margem externa na grade 8px
    PAD_X = 5 * G   # 40
    PAD_Y = 4 * G   # 32
    # Logo home: 32 * 1.15 ~= 37
    LOGO_HOME = 37
    LOGO_COMPACT = 24
    ICON_PX = 14

    def __init__(self):
        super().__init__()
        self.title("Telador")
        # Altura +40px pra caber o campo opcional de codigo da SS
        self.geometry("760x620")
        self.minsize(760, 620)
        self.maxsize(760, 620)
        # Janela de tamanho fixo: sem redimensionar e sem maximizar
        self.resizable(False, False)
        self.configure(fg_color=BRAND["bg"])

        ico = _resource_path("icon.ico")
        if os.path.isfile(ico):
            try:
                self.iconbitmap(ico)
            except Exception:
                pass

        # Windows: remove o botao Maximizar da title bar (WS_MAXIMIZEBOX)
        self.after(16, self._disable_maximize)

        self.msg_queue: queue.Queue = queue.Queue()
        self.scan_thread: threading.Thread | None = None
        self.findings = None
        self.verdict_obj = None
        self.clusters = None
        self.coverage = None
        self.html_path = None
        self.sys_info: dict | None = None  # congelado por scan
        self.scan_start_time = None
        self.scan_mode_var = None
        self.session_code_var = None
        self._mode_cards: dict = {}
        self._logo_cache: dict = {}
        self._seg_btns: dict = {}
        self._screen = "initial"
        self._scan_done = 0
        self._scan_total = 0
        self._copy_clear_job = None
        self._pulse_job = None
        self._pulse_on = False
        self._analyzing_lbl = None
        self._cta_btn = None
        self._icon_font_family = self._resolve_icon_font()

        self.container = ctk.CTkFrame(self, fg_color=BRAND["bg"], corner_radius=0)
        self.container.pack(fill="both", expand=True)

        # Atalhos de analista (Enter / Esc / Ctrl+C)
        self.bind("<Return>", self._on_enter)
        self.bind("<KP_Enter>", self._on_enter)
        self.bind("<Escape>", self._on_escape)
        self.bind("<Control-c>", self._on_ctrl_c)
        self.bind("<Control-C>", self._on_ctrl_c)

        self._show_initial()
        self.after(16, self._fade_in)
        self.after(100, self._poll_queue)

    # ----- type scale (Segoe UI) -----

    def _f(self, size: int, weight: str = "normal", mono: bool = False):
        return ctk.CTkFont(
            family="Consolas" if mono else "Segoe UI",
            size=size,
            weight=weight,
        )

    def _resolve_icon_font(self) -> str:
        try:
            from tkinter import font as tkfont
            families = set(tkfont.families())
            if ICON_FONT in families:
                return ICON_FONT
            if ICON_FALLBACK in families:
                return ICON_FALLBACK
        except Exception:
            pass
        return "Segoe UI Symbol"

    def _icon_font(self, size: int | None = None):
        return ctk.CTkFont(
            family=self._icon_font_family,
            size=size or self.ICON_PX,
        )

    def _clear(self):
        if self._pulse_job is not None:
            try:
                self.after_cancel(self._pulse_job)
            except Exception:
                pass
            self._pulse_job = None
        self._analyzing_lbl = None
        self._cta_btn = None
        for w in self.container.winfo_children():
            w.destroy()
        self._mode_cards = {}
        self._seg_btns = {}

    def _load_logo(self, size: int = 28):
        if size in self._logo_cache:
            return self._logo_cache[size]
        for name in ("logo.png", "logo_256.png", "icon.ico"):
            path = _resource_path(name)
            if not os.path.isfile(path):
                continue
            try:
                from PIL import Image
                img = Image.open(path).convert("RGBA")
                logo = ctk.CTkImage(
                    light_image=img, dark_image=img, size=(size, size))
                self._logo_cache[size] = logo
                return logo
            except Exception:
                continue
        return None

    def _txt(self, parent, text, size=13, weight="normal", color=None,
             mono=False, **pack):
        lbl = ctk.CTkLabel(
            parent, text=text,
            font=self._f(size, weight, mono=mono),
            text_color=color or BRAND["text"],
            anchor="w",
        )
        if pack:
            lbl.pack(**pack)
        return lbl

    def _icon_label(self, parent, glyph: str, *, color: str | None = None,
                    size: int | None = None):
        """Icone Fluent com tamanho optico fixo."""
        return ctk.CTkLabel(
            parent,
            text=glyph,
            font=self._icon_font(size),
            text_color=color or BRAND["muted"],
            width=(size or self.ICON_PX) + 4,
            anchor="center",
        )

    def _toplevel_hwnd(self) -> int:
        """HWND da janela toplevel (title bar do Windows)."""
        try:
            hwnd = int(self.winfo_id())
            user32 = ctypes.windll.user32
            parent = user32.GetParent(hwnd)
            while parent:
                hwnd = parent
                parent = user32.GetParent(hwnd)
            return int(hwnd)
        except Exception:
            return 0

    def _disable_maximize(self):
        """Remove Maximizar da title bar e bloqueia estado zoomed."""
        try:
            hwnd = self._toplevel_hwnd()
            if not hwnd:
                return
            user32 = ctypes.windll.user32
            GWL_STYLE = -16
            WS_MAXIMIZEBOX = 0x00010000
            style = user32.GetWindowLongW(hwnd, GWL_STYLE)
            user32.SetWindowLongW(hwnd, GWL_STYLE, style & ~WS_MAXIMIZEBOX)
            # Redesenha a frame da janela para o botao sumir de imediato
            SWP_NOSIZE = 0x0001
            SWP_NOMOVE = 0x0002
            SWP_NOZORDER = 0x0004
            SWP_FRAMECHANGED = 0x0020
            user32.SetWindowPos(
                hwnd, 0, 0, 0, 0, 0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED,
            )
        except Exception:
            pass
        # Cinto de seguranca: se algo forcar zoomed, volta ao tamanho fixo
        try:
            self.bind("<Configure>", self._on_configure_guard)
        except Exception:
            pass

    def _on_configure_guard(self, _event=None):
        try:
            if self.state() == "zoomed":
                self.state("normal")
                self.geometry("760x620")
        except Exception:
            pass

    def _fade_in(self, step: int = 0, steps: int = 10, total_ms: int = 150):
        """Fade de abertura ~150ms (layered window)."""
        try:
            hwnd = self._toplevel_hwnd() or self.winfo_id()
            GWL_EXSTYLE = -20
            WS_EX_LAYERED = 0x00080000
            LWA_ALPHA = 0x2
            style = ctypes.windll.user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
            ctypes.windll.user32.SetWindowLongW(
                hwnd, GWL_EXSTYLE, style | WS_EX_LAYERED)
            if step == 0:
                ctypes.windll.user32.SetLayeredWindowAttributes(
                    hwnd, 0, 0, LWA_ALPHA)
            alpha = int(255 * min(1.0, (step + 1) / steps))
            ctypes.windll.user32.SetLayeredWindowAttributes(
                hwnd, 0, alpha, LWA_ALPHA)
            if step + 1 < steps:
                self.after(max(1, total_ms // steps),
                           lambda: self._fade_in(step + 1, steps, total_ms))
        except Exception:
            pass

    def _hairline(self, parent, *, padx: int = 0):
        """Separador 1px quase imperceptivel."""
        line = ctk.CTkFrame(
            parent, fg_color=BRAND["border"], height=1, corner_radius=0,
        )
        line.pack(fill="x", padx=padx)
        return line

    def _ghost(self, parent, text, command, color=None, *, bold: bool = False,
               size: int = 12, underline: bool = False):
        """Link clicavel com hover suave."""
        base = color or BRAND["muted"]
        hover = BRAND["text"]
        if base in (BRAND["amber"], BRAND["amber_hi"]):
            hover = BRAND["amber_hi"]
        elif base == BRAND["yellow"]:
            hover = "#FFC933"

        try:
            font = ctk.CTkFont(
                family="Segoe UI",
                size=size,
                weight="bold" if bold else "normal",
                underline=bool(underline),
            )
        except TypeError:
            font = self._f(size, "bold" if bold else "normal")

        lbl = ctk.CTkLabel(
            parent, text=text,
            font=font,
            text_color=base,
            cursor="hand2",
            anchor="w",
        )

        def _click(_e=None):
            command()

        def _enter(_e=None):
            try:
                lbl.configure(text_color=hover)
            except Exception:
                pass

        def _leave(_e=None):
            try:
                lbl.configure(text_color=base)
            except Exception:
                pass

        lbl.bind("<Button-1>", _click)
        lbl.bind("<Enter>", _enter)
        lbl.bind("<Leave>", _leave)
        lbl.bind("<FocusIn>", _enter)
        lbl.bind("<FocusOut>", _leave)
        return lbl

    def _primary_button(self, parent, text: str, command, *,
                        width: int = 320, height: int = 56):
        """
        CTA hero: azul solido, raio 8, hover suave, sombra discreta.
        Transicao de cor e instantanea no CTk (~150ms e percepcao de hover).
        """
        # sombra 2px inferior (camada extra, sem gradiente)
        shell = ctk.CTkFrame(
            parent, fg_color=BRAND["shadow"], corner_radius=G + 1,
        )
        btn = ctk.CTkButton(
            shell,
            text=text,
            command=command,
            font=self._f(TYPE["cta"], "bold"),
            fg_color=BRAND["amber"],
            hover_color=BRAND["amber_hi"],
            text_color=BRAND["text"],
            corner_radius=G,
            height=height,
            width=width,
            border_width=0,
            cursor="hand2",
        )
        btn.pack(padx=0, pady=(0, 2))

        def _focus_in(_e=None):
            try:
                btn.configure(border_width=1, border_color=BRAND["focus"])
            except Exception:
                pass

        def _focus_out(_e=None):
            try:
                btn.configure(border_width=0)
            except Exception:
                pass

        btn.bind("<FocusIn>", _focus_in)
        btn.bind("<FocusOut>", _focus_out)
        self._cta_btn = btn
        return shell

    # =====================================================================
    # HOME
    # =====================================================================

    def _show_initial(self):
        self._clear()
        self.scan_mode_var = ctk.StringVar(value="full")
        c = self.container
        px, py = self.PAD_X, self.PAD_Y
        self._screen = "initial"

        # ---- FOOTER primeiro (side=bottom) - nunca cortado ----
        self._build_footer(
            c, px, py,
            left=self._footer_left_text(),
        )

        # ---- HEADER: logo + titulo + subtitulo alinhados; versao discreta ----
        header = ctk.CTkFrame(c, fg_color="transparent")
        header.pack(fill="x", padx=px, pady=(py, 0))

        brand = ctk.CTkFrame(header, fg_color="transparent")
        brand.pack(side="left")

        logo = self._load_logo(self.LOGO_HOME)
        if logo is not None:
            # alinhamento optico: logo + bloco de texto na mesma linha
            ctk.CTkLabel(
                brand, text="", image=logo, width=self.LOGO_HOME,
            ).pack(side="left", padx=(0, 2 * G), pady=0)

        titles = ctk.CTkFrame(brand, fg_color="transparent")
        titles.pack(side="left", pady=0)
        self._txt(
            titles, "Telador",
            size=TYPE["title"], weight="bold", color=BRAND["text"],
        ).pack(anchor="w")
        self._txt(
            titles,
            getattr(version, "PRODUCT_TAGLINE", "SS forense para Roblox"),
            size=TYPE["meta"], color=BRAND["muted"],
        ).pack(anchor="w", pady=(2, 0))

        # Versao: baixa importancia visual (caption + cor muted3)
        self._txt(
            header, version.VERSION_DISPLAY,
            size=TYPE["caption"], mono=True, color=BRAND["muted3"],
        ).pack(side="right", anchor="n", pady=(4, 0))

        # ---- STATUS: indicadores de sistema (icone + texto), nao badges ----
        status = ctk.CTkFrame(c, fg_color="transparent")
        status.pack(fill="x", padx=px, pady=(3 * G, 0))

        n_scan = getattr(version, "SCANNER_COUNT", 113)
        if _is_admin():
            self._status_item(
                status, ICONS["check"], "Administrador",
                icon_color=BRAND["green"], text_color=BRAND["text"],
            ).pack(side="left", padx=(0, 3 * G))
        else:
            self._status_item(
                status, ICONS["warning"], "Sem administrador",
                icon_color=BRAND["yellow"], text_color=BRAND["text"],
            ).pack(side="left", padx=(0, G))
            self._ghost(
                status, "Rodar como administrador", self._request_admin,
                color=BRAND["yellow"], bold=False, size=TYPE["label"],
                underline=True,
            ).pack(side="left", padx=(0, 3 * G))
        self._status_item(
            status, ICONS["desktop"], "Execução local",
            icon_color=BRAND["muted"], text_color=BRAND["muted"],
        ).pack(side="left", padx=(0, 3 * G))
        self._status_item(
            status, ICONS["search"], f"{n_scan} scanners carregados",
            icon_color=BRAND["muted"], text_color=BRAND["muted"],
        ).pack(side="left")

        # ---- HERO: CTA + modo (estrutura inalterada) ----
        hero = ctk.CTkFrame(c, fg_color="transparent")
        hero.pack(fill="both", expand=True, padx=px)

        ctk.CTkFrame(hero, fg_color="transparent", height=3 * G).pack()

        center = ctk.CTkFrame(hero, fg_color="transparent")
        center.pack(anchor="center")

        self._txt(
            center,
            "Análise forense local",
            size=TYPE["hero"], weight="bold", color=BRAND["text"],
        ).pack(pady=(0, G))

        self._txt(
            center,
            "Varredura 100% local. Nada é enviado para a rede.",
            size=TYPE["meta"], color=BRAND["muted"],
        ).pack(pady=(0, 2 * G))

        # Codigo da SS (opcional) - mesma prova de sessao da CLI --codigo
        self.session_code_var = ctk.StringVar(value="")
        code_row = ctk.CTkFrame(center, fg_color="transparent")
        code_row.pack(pady=(0, 2 * G))
        self._txt(
            code_row, "Codigo da SS",
            size=TYPE["caption"], color=BRAND["muted2"],
        ).pack(anchor="w")
        ctk.CTkEntry(
            code_row,
            textvariable=self.session_code_var,
            placeholder_text="Opcional - codigo ditado pelo supervisor",
            width=320,
            height=32,
            corner_radius=G,
            border_width=1,
            border_color=BRAND["border"],
            fg_color=BRAND["bg_card"],
            text_color=BRAND["text"],
            placeholder_text_color=BRAND["muted3"],
            font=self._f(TYPE["label"]),
        ).pack(pady=(4, 0))

        # BOTAO PRINCIPAL - centro da aplicacao
        self._primary_button(
            center, "Iniciar análise forense", self._start_scan,
            width=320, height=56,
        ).pack(pady=(0, G))

        if not _is_admin():
            self._txt(
                center,
                "Sem admin a cobertura fica incompleta (Prefetch / Amcache / BAM).",
                size=TYPE["meta"], color=BRAND["yellow"],
            ).pack(pady=(G, 0))

        ctk.CTkFrame(center, fg_color="transparent", height=3 * G).pack()

        # ---- MODO: segmented control Win11 (compacto) ----
        self._txt(
            center, "Modo de análise",
            size=TYPE["caption"], color=BRAND["muted2"],
        ).pack(pady=(0, G))

        seg = ctk.CTkFrame(
            center,
            fg_color=BRAND["bg_card"],
            corner_radius=G,
            border_width=1,
            border_color=BRAND["border"],
        )
        seg.pack()

        inner = ctk.CTkFrame(seg, fg_color="transparent")
        inner.pack(padx=2, pady=2)

        for key in ("full", "fast"):
            self._seg_btn(inner, key)

        self._refresh_seg()

        self._mode_meta = self._txt(
            center, "", size=TYPE["caption"], color=BRAND["muted2"],
        )
        self._mode_meta.pack(pady=(2 * G, 0))
        self._update_mode_meta()

    def _footer_left_text(self) -> str:
        user = os.environ.get("USERNAME", "?")
        os_name = f"{platform.system()} {platform.release()}"
        return f"{os_name}  ·  {user}"

    def _build_footer(self, parent, px: int, py: int, *, left: str):
        """Rodape elegante: texto baixo contraste + Sair como acao quieta."""
        foot_wrap = ctk.CTkFrame(parent, fg_color="transparent")
        foot_wrap.pack(side="bottom", fill="x")
        self._hairline(foot_wrap, padx=px)
        foot = ctk.CTkFrame(foot_wrap, fg_color="transparent")
        foot.pack(fill="x", padx=px, pady=(2 * G, py))
        self._txt(
            foot, left,
            size=TYPE["caption"], color=BRAND["muted3"],
        ).pack(side="left")
        # "Sair" no fluxo do rodape (baixa opacidade, hover revela)
        self._ghost(
            foot, "Sair", self.destroy,
            color=BRAND["muted3"], bold=False, size=TYPE["caption"],
        ).pack(side="right", padx=(G, 0))

    def _status_item(self, parent, glyph: str, text: str, *,
                     icon_color: str, text_color: str):
        """Indicador de sistema: icone Fluent + label. Sem capsula/pill."""
        row = ctk.CTkFrame(parent, fg_color="transparent")
        self._icon_label(
            row, glyph, color=icon_color, size=self.ICON_PX,
        ).pack(side="left", padx=(0, 6))
        ctk.CTkLabel(
            row, text=text,
            font=self._f(TYPE["label"], "normal"),
            text_color=text_color,
        ).pack(side="left")
        return row

    def _dot_item(self, parent, text: str, color: str, *, emphasize: bool = False):
        """Compat: mapeia para status item com check generico."""
        glyph = ICONS["check"] if emphasize else ICONS["desktop"]
        return self._status_item(
            parent, glyph, text,
            icon_color=color,
            text_color=BRAND["text"] if emphasize else BRAND["muted"],
        )

    def _seg_btn(self, parent, key: str):
        """Segmented Win11: track unico, segmentos compactos."""
        prof = SCAN_PROFILES[key]
        btn = ctk.CTkButton(
            parent,
            text=prof["title"],
            command=lambda k=key: self._pick_mode(k),
            font=self._f(TYPE["label"], "normal"),
            fg_color="transparent",
            hover_color=BRAND["bg_hover"],
            text_color=BRAND["muted"],
            corner_radius=G - 2,  # 6px no track de 8
            height=32,
            width=112,
            border_width=0,
            cursor="hand2",
        )
        btn.pack(side="left", padx=0)
        self._seg_btns[key] = btn
        self._mode_cards[key] = {"card": btn, "title": btn}

    def _pick_mode(self, key: str):
        if self.scan_mode_var is not None:
            self.scan_mode_var.set(key)
        self._refresh_seg()
        self._update_mode_meta()

    def _refresh_seg(self):
        """Segmento ativo: surface elevada + texto claro (nao azul cheio)."""
        selected = self.scan_mode_var.get() if self.scan_mode_var else "full"
        for key, btn in self._seg_btns.items():
            on = key == selected
            btn.configure(
                fg_color=BRAND["bg_elev"] if on else "transparent",
                text_color=BRAND["text"] if on else BRAND["muted"],
                font=self._f(TYPE["label"], "bold" if on else "normal"),
                hover_color=BRAND["bg_hover"],
            )

    def _update_mode_meta(self):
        if not hasattr(self, "_mode_meta") or self._mode_meta is None:
            return
        key = self.scan_mode_var.get() if self.scan_mode_var else "full"
        p = SCAN_PROFILES[key]
        self._mode_meta.configure(
            text=f"{p['scanners']} scanners  ·  {p['eta']}  ·  {p['hint']}")

    def _request_admin(self):
        _try_elevate()

    def _start_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            return
        mode = self.scan_mode_var.get() if self.scan_mode_var else "full"
        code = ""
        if self.session_code_var is not None:
            try:
                code = (self.session_code_var.get() or "").strip()
            except Exception:
                code = ""
        # Congela sys_info ANTES do thread (HTML + Discord usam o mesmo)
        self.sys_info = _build_sys_info(code)
        self._show_scanning(mode)
        self.scan_start_time = time.time()
        self.scan_thread = threading.Thread(
            target=_run_scan_thread,
            args=(self.msg_queue, mode, self.sys_info),
            daemon=True,
        )
        self.scan_thread.start()

    # =====================================================================
    # SCANNING
    # =====================================================================

    def _show_scanning(self, mode: str):
        self._clear()
        self._screen = "scanning"
        self._scan_done = 0
        self._scan_total = 0
        c = self.container
        px, py = self.PAD_X, self.PAD_Y
        p = SCAN_PROFILES.get(mode, SCAN_PROFILES["fast"])

        head = ctk.CTkFrame(c, fg_color="transparent")
        head.pack(fill="x", padx=px, pady=(py, 0))
        logo = self._load_logo(self.LOGO_COMPACT)
        if logo is not None:
            ctk.CTkLabel(head, text="", image=logo).pack(
                side="left", padx=(0, G))
        self._txt(
            head, "Telador", size=TYPE["body"], weight="bold",
        ).pack(side="left")
        self._analyzing_lbl = self._txt(
            head, "Analisando", size=TYPE["label"], color=BRAND["amber"],
        )
        self._analyzing_lbl.pack(side="right")
        self._start_pulse()

        self._txt(
            c,
            f"Modo {p['title'].lower()}  ·  {p['scanners']} scanners  ·  local",
            size=TYPE["meta"], color=BRAND["muted"],
        ).pack(anchor="w", padx=px, pady=(G, 4 * G))

        # progresso
        row = ctk.CTkFrame(c, fg_color="transparent")
        row.pack(fill="x", padx=px)

        self.pct_lbl = self._txt(
            row, "0%", size=TYPE["display"], weight="bold", mono=True)
        self.pct_lbl.pack(side="left")

        right = ctk.CTkFrame(row, fg_color="transparent")
        right.pack(side="right")
        self.progress_lbl = self._txt(
            right, "0 / ?", size=TYPE["body"], mono=True, color=BRAND["muted"])
        self.progress_lbl.pack(anchor="e")
        self.timer_lbl = self._txt(
            right, "0.0s", size=TYPE["meta"], mono=True, color=BRAND["muted2"])
        self.timer_lbl.pack(anchor="e")
        self.eta_lbl = self._txt(
            right, "", size=TYPE["caption"], mono=True, color=BRAND["amber"],
        )
        self.eta_lbl.pack(anchor="e")

        self.progress_bar = ctk.CTkProgressBar(
            c, height=4, corner_radius=2,
            progress_color=BRAND["amber"],
            fg_color=BRAND["border"],
        )
        self.progress_bar.set(0)
        self.progress_bar.pack(fill="x", padx=px, pady=(2 * G, G))

        self.current_scanner_lbl = self._txt(
            c, "Preparando motores...",
            size=TYPE["body"], color=BRAND["text"],
        )
        self.current_scanner_lbl.pack(anchor="w", padx=px, pady=(0, 2 * G))

        # log flat - borda discreta
        self.log_box = ctk.CTkTextbox(
            c,
            font=self._f(TYPE["meta"], mono=True),
            text_color=BRAND["muted"],
            fg_color=BRAND["bg_card"],
            corner_radius=G,
            border_width=1,
            border_color=BRAND["border"],
            scrollbar_button_color=BRAND["border"],
            scrollbar_button_hover_color=BRAND["muted2"],
        )
        self.log_box.pack(
            fill="both", expand=True, padx=px, pady=(0, py))
        self.log_box.configure(state="disabled")

    def _start_pulse(self):
        self._pulse_on = False
        self._tick_pulse()

    def _tick_pulse(self):
        if self._screen != "scanning" or self._analyzing_lbl is None:
            return
        self._pulse_on = not self._pulse_on
        try:
            # pulso suave de opacidade de cor (sem glyphs decorativos)
            self._analyzing_lbl.configure(
                text="Analisando",
                text_color=BRAND["amber"] if self._pulse_on else BRAND["amber_dim"],
            )
        except Exception:
            return
        self._pulse_job = self.after(150, self._tick_pulse)

    def _append_log(self, text: str):
        if not hasattr(self, "log_box"):
            return
        # evita spam de "iniciando"
        if text and "iniciando" in text.lower() and text.strip().endswith("iniciando"):
            return
        self.log_box.configure(state="normal")
        self.log_box.insert("end", text + "\n")
        n = int(self.log_box.index("end-1c").split(".")[0])
        if n > 120:
            self.log_box.delete("1.0", f"{n - 90}.0")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    # =====================================================================
    # VERDICT
    # =====================================================================

    def _show_verdict(self):
        self._clear()
        self._screen = "verdict"
        c = self.container
        px, py = self.PAD_X, self.PAD_Y

        v = (self.verdict_obj or {}).get("verdict", "?")
        style = _verdict_style(v)
        confirmed = []
        detected = []
        for x in (self.clusters or []):
            xv = getattr(x, "verdict", "")
            if callable(xv):
                try:
                    xv = x.verdict
                except Exception:
                    xv = ""
            if xv == "CONFIRMED":
                confirmed.append(x)
            elif xv == "DETECTED":
                detected.append(x)
        if confirmed:
            style = _verdict_style("CONFIRMED")
        elif detected:
            style = _verdict_style("DETECTED")

        head = ctk.CTkFrame(c, fg_color="transparent")
        head.pack(fill="x", padx=px, pady=(py, 0))
        logo = self._load_logo(self.LOGO_COMPACT)
        if logo is not None:
            ctk.CTkLabel(head, text="", image=logo).pack(
                side="left", padx=(0, G))
        self._txt(
            head, "Telador", size=TYPE["body"], weight="bold",
        ).pack(side="left")
        self._txt(
            head, "Concluído", size=TYPE["label"], color=BRAND["muted"],
        ).pack(side="right")

        # resultado = tipografia, nao caixa
        self._txt(
            c, style["label"], size=TYPE["display"], weight="bold",
            color=style["color"],
        ).pack(anchor="w", padx=px, pady=(4 * G, G))
        self._txt(
            c, style["subtitle"], size=TYPE["body"], color=BRAND["muted"],
        ).pack(anchor="w", padx=px)

        next_txt, next_key = _staff_next_step(
            style["label"], has_admin=_is_admin())
        next_color = BRAND.get(next_key, BRAND["muted"])
        self._txt(
            c, next_txt, size=TYPE["body"], weight="bold", color=next_color,
        ).pack(anchor="w", padx=px, pady=(2 * G, G))

        targets = _top_target_labels(self.clusters or [], limit=6)
        if targets:
            self._txt(
                c,
                "Alvos:  " + "  ·  ".join(targets),
                size=TYPE["body"], weight="bold", color=BRAND["text"],
            ).pack(anchor="w", padx=px, pady=(0, G))

        score = (self.verdict_obj or {}).get("score", 0)
        conf = (self.verdict_obj or {}).get("highest_confidence", 0)
        n_t = len(confirmed) + len(detected)
        n_low = int((self.verdict_obj or {}).get("low", 0) or 0)
        n_med = int((self.verdict_obj or {}).get("medium", 0) or 0)
        n_high = int((self.verdict_obj or {}).get("high", 0) or 0)
        n_crit = int((self.verdict_obj or {}).get("critical", 0) or 0)
        self._txt(
            c,
            f"score {score}  ·  conf {conf}%  ·  alvos {n_t}  ·  "
            f"crit {n_crit}  high {n_high}  med {n_med}  low {n_low}",
            size=TYPE["meta"], mono=True, color=BRAND["muted"],
        ).pack(anchor="w", padx=px, pady=(G, 3 * G))

        self._hairline(c, padx=px)

        try:
            o, p, a = report.build_staff_verdict_bullets(
                self.clusters or [], self.verdict_obj or {}, self.coverage)
        except Exception:
            o = p = a = "?"

        grid = ctk.CTkFrame(c, fg_color="transparent")
        grid.pack(fill="x", padx=px, pady=(3 * G, 0))

        for lab, val in (("O quê", o), ("Por quê", p), ("Fazer", a)):
            row = ctk.CTkFrame(grid, fg_color="transparent")
            row.pack(fill="x", pady=G // 2)
            ctk.CTkLabel(
                row, text=lab,
                font=self._f(TYPE["label"]),
                text_color=BRAND["muted2"],
                width=72, anchor="w",
            ).pack(side="left", anchor="n")
            ctk.CTkLabel(
                row, text=val,
                font=self._f(TYPE["body"]),
                text_color=BRAND["text"],
                justify="left", wraplength=540, anchor="w",
            ).pack(side="left", fill="x", expand=True)

        # ---- Hits LOW (e MEDIUM) visiveis na GUI, nao so no HTML ----
        low_hits = _collect_hits_by_severity(
            self.findings, ("low",), limit=20)
        med_hits = _collect_hits_by_severity(
            self.findings, ("medium",), limit=12)
        if low_hits or med_hits:
            self._hairline(c, padx=px)
            hits_wrap = ctk.CTkFrame(c, fg_color="transparent")
            hits_wrap.pack(fill="x", padx=px, pady=(2 * G, 0))

            if med_hits:
                self._txt(
                    hits_wrap,
                    f"Sinais MEDIUM  ({len(med_hits)}"
                    f"{'+' if n_med > len(med_hits) else ''})",
                    size=TYPE["label"], weight="bold", color=BRAND["yellow"],
                ).pack(anchor="w", pady=(0, 4))
                for h in med_hits[:8]:
                    match = f"  ·  {h['matched']}" if h.get("matched") else ""
                    self._txt(
                        hits_wrap,
                        f"  {h['label']}{match}  [{h['scanner']}]",
                        size=TYPE["caption"], color=BRAND["muted"],
                    ).pack(anchor="w")

            if low_hits:
                pad_top = G if med_hits else 0
                self._txt(
                    hits_wrap,
                    f"Sinais LOW  ({len(low_hits)}"
                    f"{'+' if n_low > len(low_hits) else ''})",
                    size=TYPE["label"], weight="bold", color=BRAND["muted"],
                ).pack(anchor="w", pady=(pad_top, 4))
                # lista rolavel se tiver muitos LOWs
                if len(low_hits) > 6:
                    box = ctk.CTkTextbox(
                        hits_wrap,
                        height=7 * G * 2,
                        font=self._f(TYPE["caption"], mono=True),
                        text_color=BRAND["muted"],
                        fg_color=BRAND["bg_card"],
                        corner_radius=G,
                        border_width=1,
                        border_color=BRAND["border"],
                        scrollbar_button_color=BRAND["border"],
                        scrollbar_button_hover_color=BRAND["muted2"],
                    )
                    box.pack(fill="x", pady=(0, G))
                    lines = []
                    for h in low_hits:
                        match = f"  |  {h['matched']}" if h.get("matched") else ""
                        lines.append(f"{h['label']}{match}  [{h['scanner']}]")
                    if n_low > len(low_hits):
                        lines.append(f"... +{n_low - len(low_hits)} no relatorio HTML")
                    box.insert("1.0", "\n".join(lines))
                    box.configure(state="disabled")
                else:
                    for h in low_hits:
                        match = f"  ·  {h['matched']}" if h.get("matched") else ""
                        self._txt(
                            hits_wrap,
                            f"  {h['label']}{match}  [{h['scanner']}]",
                            size=TYPE["caption"], color=BRAND["muted2"],
                        ).pack(anchor="w")

        actions = ctk.CTkFrame(c, fg_color="transparent")
        actions.pack(fill="x", padx=px, pady=(4 * G, 0))

        inconclusive = style["label"] == "INCONCLUSIVO" and not _is_admin()
        if inconclusive:
            ctk.CTkButton(
                actions, text="Rodar como administrador",
                command=self._request_admin,
                font=self._f(TYPE["body"], "bold"),
                fg_color=BRAND["yellow"],
                hover_color="#FFC933",
                text_color="#0A0A0A",
                corner_radius=G, height=40, width=220,
                border_width=0, cursor="hand2",
            ).pack(side="left", padx=(0, 2 * G))
            self._ghost(
                actions, "Abrir relatório", self._open_html,
                color=BRAND["amber"], bold=True, size=TYPE["body"],
            ).pack(side="left", padx=(G, 0))
        else:
            ctk.CTkButton(
                actions, text="Abrir relatório",
                command=self._open_html,
                font=self._f(TYPE["body"], "bold"),
                fg_color=BRAND["amber"],
                hover_color=BRAND["amber_hi"],
                text_color=BRAND["text"],
                corner_radius=G, height=40, width=160,
                border_width=0, cursor="hand2",
            ).pack(side="left", padx=(0, 2 * G))

        self._ghost(
            actions, "Copiar Discord", self._copy_discord,
            color=BRAND["amber"], bold=True, size=TYPE["body"],
        ).pack(side="left", padx=(G, 0))
        self._ghost(
            actions, "Nova SS", self._show_initial,
            color=BRAND["muted"], bold=False, size=TYPE["body"],
        ).pack(side="left", padx=(3 * G, 0))

        self.copy_status = self._txt(
            c, "", size=TYPE["label"], color=BRAND["green"])
        self.copy_status.pack(anchor="w", padx=px, pady=(2 * G, 0))

        ctk.CTkFrame(c, fg_color="transparent").pack(fill="both", expand=True)

        self._build_footer(
            c, px, py,
            left=f"{self._footer_left_text()}  ·  {version.VERSION_DISPLAY}",
        )

    def _open_html(self):
        if not hasattr(self, "copy_status"):
            return
        if self.html_path and os.path.isfile(self.html_path):
            try:
                webbrowser.open(
                    f"file:///{self.html_path.replace(os.sep, '/')}")
            except Exception as e:
                self.copy_status.configure(
                    text=f"Falhou: {e}", text_color=BRAND["red"])
        else:
            self.copy_status.configure(
                text="HTML não encontrado", text_color=BRAND["red"])

    def _copy_discord(self):
        if not hasattr(self, "copy_status"):
            return
        try:
            # MESMO sys_info do HTML (session_id / scan_time / codigo)
            info = self.sys_info or _build_sys_info()
            md_path = report_md.generate_markdown_report(
                self.findings or [], info,
                verdict=self.verdict_obj,
                clusters=self.clusters,
                coverage=self.coverage,
            )
            with open(md_path, "r", encoding="utf-8") as fh:
                text = fh.read()
            self.clipboard_clear()
            self.clipboard_append(text)
            self.update()
            self.copy_status.configure(
                text="✓  Copiado. Cole no Discord da liga.",
                text_color=BRAND["green"],
            )
            if self._copy_clear_job is not None:
                try:
                    self.after_cancel(self._copy_clear_job)
                except Exception:
                    pass
            self._copy_clear_job = self.after(2500, self._clear_copy_status)
        except Exception as e:
            self.copy_status.configure(
                text=f"Falhou: {e}", text_color=BRAND["red"])

    def _clear_copy_status(self):
        self._copy_clear_job = None
        try:
            if hasattr(self, "copy_status") and self.copy_status.winfo_exists():
                self.copy_status.configure(text="")
        except Exception:
            pass

    # =====================================================================
    # ERROR
    # =====================================================================

    def _show_error(self, msg: str):
        self._clear()
        self._screen = "error"
        c = self.container
        px, py = self.PAD_X, self.PAD_Y

        self._txt(
            c, "Telador", size=TYPE["body"], weight="bold",
        ).pack(anchor="w", padx=px, pady=(py, 0))
        self._txt(
            c, "Falha na análise", size=TYPE["title"] + 4, weight="bold",
            color=BRAND["red"],
        ).pack(anchor="w", padx=px, pady=(3 * G, 2 * G))

        err = ctk.CTkTextbox(
            c, font=self._f(TYPE["meta"], mono=True),
            text_color=BRAND["muted"],
            fg_color=BRAND["bg_card"],
            corner_radius=G,
            border_width=1, border_color=BRAND["border"],
        )
        err.pack(fill="both", expand=True, padx=px, pady=(0, 2 * G))
        err.insert("1.0", msg)
        err.configure(state="disabled")

        ctk.CTkButton(
            c, text="Voltar",
            command=self._show_initial,
            font=self._f(TYPE["body"], "bold"),
            fg_color=BRAND["amber"],
            hover_color=BRAND["amber_hi"],
            text_color=BRAND["text"],
            corner_radius=G, height=40, width=120,
            cursor="hand2",
        ).pack(anchor="w", padx=px, pady=(0, py))

    # =====================================================================
    # Atalhos
    # =====================================================================

    def _on_enter(self, _event=None):
        if self._screen == "initial":
            self._start_scan()
        elif self._screen == "verdict":
            # INCONCLUSIVO sem admin: Enter eleva; senao abre HTML
            v = (self.verdict_obj or {}).get("verdict", "")
            style = _verdict_style(v)
            if style["label"] == "INCONCLUSIVO" and not _is_admin():
                self._request_admin()
            else:
                self._open_html()
        elif self._screen == "error":
            self._show_initial()
        return "break"

    def _on_escape(self, _event=None):
        if self._screen == "initial":
            self.destroy()
        elif self._screen in ("verdict", "error"):
            self._show_initial()
        # scanning: sem cancelamento seguro (thread daemon)
        return "break"

    def _on_ctrl_c(self, _event=None):
        if self._screen == "verdict":
            self._copy_discord()
            return "break"
        return None

    # =====================================================================
    # Queue
    # =====================================================================

    def _poll_queue(self):
        try:
            while True:
                self._handle_msg(self.msg_queue.get_nowait())
        except queue.Empty:
            pass
        if self.scan_thread and self.scan_thread.is_alive() and self.scan_start_time:
            try:
                elapsed = time.time() - self.scan_start_time
                self.timer_lbl.configure(text=f"{elapsed:.1f}s")
                # ETA a partir do ritmo medio
                if self._scan_done > 0 and self._scan_total > self._scan_done:
                    per = elapsed / self._scan_done
                    rem = per * (self._scan_total - self._scan_done)
                    if hasattr(self, "eta_lbl"):
                        self.eta_lbl.configure(text=_format_eta(rem))
            except Exception:
                pass
        self.after(100, self._poll_queue)

    def _handle_msg(self, msg):
        kind = msg[0]
        if kind == 'progress':
            _, done, total, scanner_name = msg
            try:
                self._scan_done = done
                self._scan_total = total
                human = _human_scanner_name(scanner_name)
                if total > 0:
                    self.progress_bar.set(done / total)
                    self.pct_lbl.configure(text=f"{int(100 * done / total)}%")
                self.progress_lbl.configure(text=f"{done} / {total}")
                self.current_scanner_lbl.configure(text=human)
                if done and scanner_name != 'iniciando':
                    self._append_log(f"{done:>3}/{total}  {human}")
            except Exception:
                pass
        elif kind == 'log':
            try:
                self._append_log(msg[1])
            except Exception:
                pass
        elif kind == 'done':
            # (done, findings, verdict, clusters, cov, html, sys_info)
            findings = msg[1]
            verdict_obj = msg[2]
            clusters = msg[3]
            coverage = msg[4]
            html_path = msg[5]
            if len(msg) > 6 and isinstance(msg[6], dict):
                self.sys_info = msg[6]
            self.findings = findings
            self.verdict_obj = verdict_obj
            self.clusters = clusters
            self.coverage = coverage
            self.html_path = html_path
            self._show_verdict()
        elif kind == 'error':
            self._show_error(msg[1])


def main():
    if not HAS_CTK:
        print("customtkinter não instalado. Rode: pip install customtkinter")
        print("Caindo para a CLI clássica...")
        telador.main()
        return
    TeladorGUI().mainloop()


if __name__ == "__main__":
    main()
