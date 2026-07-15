"""
GUI do Telador (v3.55.0+): janela nativa em CustomTkinter com cores de marca
(ambar), layout grid, hero visual pro veredito e toggle Rapido/Completo.

Entry-point separado do CLI: quando buildado como telador-gui.exe (console=False
no .spec), abre so a janela, sem console flash. `telador.exe --gui` continua
funcionando pra quem preferir.
"""
from __future__ import annotations

import ctypes
import os
import queue
import sys
import threading
import time
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed

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
import telador


# =========================================================================
# Cores de marca (alinhadas com o CLI: ambar/gold)
# =========================================================================

BRAND = {
    "bg":        "#0f0f11",   # fundo geral
    "bg_card":   "#1a1a1e",   # cards
    "bg_hover":  "#2a2a2e",
    "border":    "#333336",
    "amber":     "#d8a24f",   # cor de marca (banner do CLI)
    "amber_hi":  "#f0c070",
    "text":      "#e8e0d2",   # texto principal
    "muted":     "#888",
    "muted2":    "#666",
    "green":     "#3fbf7f",   # LIMPO
    "yellow":    "#f0b400",   # SUSPEITO/INCONCLUSIVO
    "red":       "#ff5555",   # DETECTADO
    "red_hi":    "#e83a3a",   # CONFIRMADO (mais forte)
}


VERDICT_STYLES = {
    "LIMPO":         {"emoji": "OK",     "color": BRAND["green"],  "label": "LIMPO",         "subtitle": "Nenhum artefato acima do limite de FP"},
    "SUSPECT":       {"emoji": "!",      "color": BRAND["yellow"], "label": "SUSPEITO",      "subtitle": "Sinal parcial, sem confirmacao cruzada"},
    "SUSPEITO":      {"emoji": "!",      "color": BRAND["yellow"], "label": "SUSPEITO",      "subtitle": "Sinal parcial, sem confirmacao cruzada"},
    "DETECTED":      {"emoji": "X",      "color": BRAND["red"],    "label": "DETECTADO",     "subtitle": "Multiplas fontes cruzadas apontam pro mesmo target"},
    "CHEATER":       {"emoji": "X",      "color": BRAND["red"],    "label": "CHEATER",       "subtitle": "Executor detectado com alta confianca"},
    "CONFIRMED":     {"emoji": "X",      "color": BRAND["red_hi"], "label": "CONFIRMADO",    "subtitle": "3+ fontes independentes casam"},
    "ALTAMENTE":     {"emoji": "!",      "color": BRAND["red"],    "label": "ALTAMENTE SUSPEITO", "subtitle": "Multiplos sinais convergem"},
    "INCONCLUSIVO":  {"emoji": "?",      "color": BRAND["muted"],  "label": "INCONCLUSIVO",  "subtitle": "Cobertura forense incompleta"},
    "?":             {"emoji": "?",      "color": BRAND["muted"],  "label": "-",             "subtitle": ""},
}


def _verdict_style(verdict_str: str) -> dict:
    v = (verdict_str or "?").upper()
    for key, style in VERDICT_STYLES.items():
        if v.startswith(key):
            return style
    return VERDICT_STYLES["?"]


# =========================================================================
# UAC / admin
# =========================================================================

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
        if getattr(sys, "frozen", False):
            exe = sys.executable
            import subprocess
            params = subprocess.list2cmdline(argv + ["--_relaunched"])
        else:
            exe = sys.executable
            import subprocess
            script = os.path.abspath(sys.argv[0])
            params = subprocess.list2cmdline([script] + argv + ["--_relaunched"])
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        if int(rc) > 32:
            sys.exit(0)
    except Exception:
        pass
    return False


# =========================================================================
# Scan orchestration (roda em thread)
# =========================================================================

def _run_scan_thread(msg_queue: queue.Queue, mode: str = "fast") -> None:
    """
    mode: 'fast' (ss-live, 71 scanners) ou 'full' (113 scanners).
    """
    try:
        n_sigs, sig_err = database.load_external_signatures()
        if n_sigs:
            matching.invalidate()
            msg_queue.put(('log', f'{n_sigs} assinatura(s) externa(s) carregada(s)'))

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

        results_by_fn = {}
        completed = [0]

        def _run_one_safe(fn):
            try:
                return fn.__name__, fn()
            except Exception as e:
                return fn.__name__, {
                    "name": fn.__name__, "description": "(crash)",
                    "status": "error", "items": [],
                    "summary": f"Erro: {e}", "error": str(e),
                }

        with ThreadPoolExecutor(max_workers=4) as ex:
            futures = {ex.submit(_run_one_safe, fn): fn for fn in chain}
            for future in as_completed(futures):
                fn_name, result = future.result()
                results_by_fn[fn_name] = result
                completed[0] += 1
                label = fn_name.replace("scan_", "").replace("_", " ")
                msg_queue.put(('progress', completed[0], total, label))

        findings = [results_by_fn[fn.__name__]
                    for fn in chain if fn.__name__ in results_by_fn]

        findings, fp_stats = fp_filter.post_process_findings(findings)
        findings, _redacted = redaction.redact_findings(findings)
        findings = pe_analysis.enrich_findings_with_pe(findings)

        cov = coverage_mod.build_coverage(
            findings,
            is_admin=_is_admin(),
            quick=False,
            skipped_groups=skipped_groups,
            only=None,
            sig_version=getattr(database, "LOADED_SIG_VERSION", None),
        )
        verdict_obj = fp_filter.compute_verdict(findings)
        verdict_obj = coverage_mod.apply_coverage_to_verdict(verdict_obj, cov)

        evidences = ev_engine.findings_to_evidences(findings)
        clusters = ev_engine.build_clusters(evidences)

        sys_info = _minimal_sys_info()
        html_path = report.generate_html_report(
            findings, sys_info, screenshots={},
            verdict=verdict_obj, fp_stats=fp_stats,
            clusters=clusters, coverage=cov,
        )

        msg_queue.put(('done', findings, verdict_obj, clusters, cov, html_path))

    except Exception as e:
        import traceback
        msg_queue.put(('error', f'{type(e).__name__}: {e}\n\n{traceback.format_exc()[:600]}'))


def _minimal_sys_info() -> dict:
    import platform, secrets
    from datetime import datetime
    return {
        "host": platform.node(),
        "user": os.environ.get("USERNAME", "?"),
        "os": f"{platform.system()} {platform.release()}",
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "admin": _is_admin(),
        "session_id": secrets.token_hex(4).upper(),
        "session_code": "",
        "telador_version": version.VERSION_DISPLAY,
    }


# =========================================================================
# GUI
# =========================================================================

if HAS_CTK:
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")


class TeladorGUI(ctk.CTk if HAS_CTK else object):
    """Janela principal: dark, cores ambar de marca, layout grid."""

    def __init__(self):
        super().__init__()
        self.title(f"Telador {version.VERSION_DISPLAY}")
        self.geometry("880x640")
        self.minsize(760, 560)
        self.configure(fg_color=BRAND["bg"])

        # State
        self.msg_queue: queue.Queue = queue.Queue()
        self.scan_thread: threading.Thread | None = None
        self.findings = None
        self.verdict_obj = None
        self.clusters = None
        self.coverage = None
        self.html_path = None
        self.scan_start_time = None
        self.scan_mode_var = None  # StringVar; setado no _show_initial

        # Container principal (grid)
        self.container = ctk.CTkFrame(
            self, fg_color=BRAND["bg"], corner_radius=0)
        self.container.pack(fill="both", expand=True, padx=0, pady=0)

        self._show_initial()
        self.after(100, self._poll_queue)

    # ---------- helpers ----------
    def _clear_container(self):
        for widget in self.container.winfo_children():
            widget.destroy()

    # ---------- tela 1: INITIAL ----------
    def _show_initial(self):
        self._clear_container()

        # Brand header (ambar)
        header = ctk.CTkFrame(self.container, fg_color=BRAND["bg"], corner_radius=0)
        header.pack(fill="x", padx=40, pady=(28, 8))

        brand_lbl = ctk.CTkLabel(
            header, text="TELADOR",
            font=ctk.CTkFont(family="Segoe UI", size=42, weight="bold"),
            text_color=BRAND["amber"],
        )
        brand_lbl.pack(anchor="center")

        tag_lbl = ctk.CTkLabel(
            header, text="SS forense pra Roblox",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=BRAND["muted"],
        )
        tag_lbl.pack(anchor="center", pady=(0, 2))

        ver_lbl = ctk.CTkLabel(
            header, text=version.VERSION_DISPLAY,
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=BRAND["muted2"],
        )
        ver_lbl.pack(anchor="center")

        # Card explicativo (fica compacto)
        card = ctk.CTkFrame(
            self.container, fg_color=BRAND["bg_card"],
            corner_radius=8, border_width=1, border_color=BRAND["border"],
        )
        card.pack(fill="x", padx=60, pady=(20, 12))

        info = ctk.CTkLabel(
            card,
            text=("Roda todas as checagens LOCAIS no PC procurando rastros de\n"
                  "executor / bypass. Nada sai do PC. Precisa de admin (UAC)\n"
                  "pras fontes forenses fortes (Prefetch/Amcache/BAM)."),
            justify="center",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=BRAND["text"],
        )
        info.pack(padx=20, pady=14)

        # Status admin (compacto, colorido)
        admin_frame = ctk.CTkFrame(self.container, fg_color=BRAND["bg"])
        admin_frame.pack(fill="x", padx=60, pady=(0, 12))

        if _is_admin():
            admin_dot = ctk.CTkLabel(
                admin_frame, text="●", text_color=BRAND["green"],
                font=ctk.CTkFont(size=16, weight="bold"),
            )
            admin_dot.pack(side="left", padx=(0, 8))
            admin_txt = ctk.CTkLabel(
                admin_frame, text="Rodando como Administrador",
                font=ctk.CTkFont(size=12), text_color=BRAND["text"],
            )
            admin_txt.pack(side="left")
        else:
            admin_dot = ctk.CTkLabel(
                admin_frame, text="●", text_color=BRAND["yellow"],
                font=ctk.CTkFont(size=16, weight="bold"),
            )
            admin_dot.pack(side="left", padx=(0, 8))
            admin_txt = ctk.CTkLabel(
                admin_frame,
                text="Sem admin. Resultado sera INCONCLUSIVO.",
                font=ctk.CTkFont(size=12), text_color=BRAND["yellow"],
            )
            admin_txt.pack(side="left")
            elev_btn = ctk.CTkButton(
                admin_frame, text="Pedir permissao",
                command=self._request_admin,
                font=ctk.CTkFont(size=11),
                fg_color="transparent", border_width=1,
                border_color=BRAND["yellow"], text_color=BRAND["yellow"],
                hover_color=BRAND["bg_hover"],
                width=140, height=26,
            )
            elev_btn.pack(side="right")

        # Perfil de scan (radio)
        profile_frame = ctk.CTkFrame(
            self.container, fg_color=BRAND["bg_card"],
            corner_radius=8, border_width=1, border_color=BRAND["border"],
        )
        profile_frame.pack(fill="x", padx=60, pady=(0, 16))

        pf_title = ctk.CTkLabel(
            profile_frame, text="PERFIL DE SCAN",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=BRAND["amber"],
        )
        pf_title.pack(anchor="w", padx=16, pady=(12, 4))

        self.scan_mode_var = ctk.StringVar(value="full")

        radios_wrap = ctk.CTkFrame(profile_frame, fg_color=BRAND["bg_card"])
        radios_wrap.pack(fill="x", padx=16, pady=(0, 12))

        rb_full = ctk.CTkRadioButton(
            radios_wrap, text="Completo (113 scanners, ~2-3 min)",
            variable=self.scan_mode_var, value="full",
            font=ctk.CTkFont(size=12), text_color=BRAND["text"],
            fg_color=BRAND["amber"], border_color=BRAND["muted"],
            hover_color=BRAND["amber_hi"],
        )
        rb_full.pack(anchor="w", pady=3)

        rb_fast = ctk.CTkRadioButton(
            radios_wrap, text="Rapido (71 scanners, ~30-45 s)",
            variable=self.scan_mode_var, value="fast",
            font=ctk.CTkFont(size=12), text_color=BRAND["text"],
            fg_color=BRAND["amber"], border_color=BRAND["muted"],
            hover_color=BRAND["amber_hi"],
        )
        rb_fast.pack(anchor="w", pady=3)

        pf_hint = ctk.CTkLabel(
            profile_frame,
            text="Completo pega tudo (recomendado pra SS de verdade). "
                 "Rapido pula log parsers pesados (PCA/WinEvent/YARA/etc).",
            font=ctk.CTkFont(size=10),
            text_color=BRAND["muted"], justify="left", wraplength=680,
        )
        pf_hint.pack(anchor="w", padx=16, pady=(0, 12))

        # Botao gigante Iniciar SS (cor ambar)
        start_btn = ctk.CTkButton(
            self.container,
            text="INICIAR SS",
            command=self._start_scan,
            font=ctk.CTkFont(size=20, weight="bold"),
            fg_color=BRAND["amber"], hover_color=BRAND["amber_hi"],
            text_color="#111", corner_radius=6,
            width=300, height=56,
        )
        start_btn.pack(pady=(6, 10))

        exit_btn = ctk.CTkButton(
            self.container, text="Sair",
            command=self.destroy,
            font=ctk.CTkFont(size=11),
            fg_color="transparent", text_color=BRAND["muted"],
            hover_color=BRAND["bg_hover"],
            width=80, height=26,
        )
        exit_btn.pack(pady=(0, 20))

    def _request_admin(self):
        _try_elevate()

    # ---------- tela 2: SCANNING ----------
    def _start_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            return
        mode = self.scan_mode_var.get() if self.scan_mode_var else "fast"
        self._show_scanning(mode)
        self.scan_start_time = time.time()
        self.scan_thread = threading.Thread(
            target=_run_scan_thread, args=(self.msg_queue, mode), daemon=True)
        self.scan_thread.start()

    def _show_scanning(self, mode: str):
        self._clear_container()

        # Header compacto
        header = ctk.CTkFrame(self.container, fg_color=BRAND["bg"])
        header.pack(fill="x", padx=40, pady=(28, 8))

        brand_lbl = ctk.CTkLabel(
            header, text="TELADOR",
            font=ctk.CTkFont(family="Segoe UI", size=24, weight="bold"),
            text_color=BRAND["amber"],
        )
        brand_lbl.pack(anchor="center")

        mode_txt = "Rapido" if mode == "fast" else "Completo"
        sub_lbl = ctk.CTkLabel(
            header, text=f"Rodando scan {mode_txt}. Nada sai do PC.",
            font=ctk.CTkFont(size=12), text_color=BRAND["muted"],
        )
        sub_lbl.pack(pady=(4, 20))

        # Progresso central
        progress_wrap = ctk.CTkFrame(
            self.container, fg_color=BRAND["bg_card"],
            corner_radius=8, border_width=1, border_color=BRAND["border"],
        )
        progress_wrap.pack(fill="x", padx=60, pady=(0, 12))

        self.progress_bar = ctk.CTkProgressBar(
            progress_wrap, width=560, height=14, corner_radius=4,
            progress_color=BRAND["amber"],
            fg_color=BRAND["bg_hover"],
        )
        self.progress_bar.set(0)
        self.progress_bar.pack(padx=24, pady=(20, 10), fill="x")

        counters_row = ctk.CTkFrame(progress_wrap, fg_color=BRAND["bg_card"])
        counters_row.pack(fill="x", padx=24, pady=(0, 12))

        self.progress_lbl = ctk.CTkLabel(
            counters_row, text="0 / ?",
            font=ctk.CTkFont(family="Consolas", size=16, weight="bold"),
            text_color=BRAND["text"],
        )
        self.progress_lbl.pack(side="left")

        self.timer_lbl = ctk.CTkLabel(
            counters_row, text="0.0s",
            font=ctk.CTkFont(family="Consolas", size=13),
            text_color=BRAND["amber"],
        )
        self.timer_lbl.pack(side="right")

        self.current_scanner_lbl = ctk.CTkLabel(
            progress_wrap, text="iniciando...",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=BRAND["muted"],
        )
        self.current_scanner_lbl.pack(padx=24, pady=(0, 16), anchor="w")

        # Log rolante
        log_wrap = ctk.CTkFrame(
            self.container, fg_color=BRAND["bg_card"],
            corner_radius=8, border_width=1, border_color=BRAND["border"],
        )
        log_wrap.pack(fill="both", expand=True, padx=60, pady=(0, 20))

        log_title = ctk.CTkLabel(
            log_wrap, text="LOG",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=BRAND["amber"],
        )
        log_title.pack(anchor="w", padx=16, pady=(10, 4))

        self.log_box = ctk.CTkTextbox(
            log_wrap, height=180,
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=BRAND["muted"], fg_color=BRAND["bg"],
            corner_radius=4, border_width=0,
        )
        self.log_box.pack(fill="both", expand=True, padx=16, pady=(0, 12))
        self.log_box.configure(state="disabled")

    def _append_log(self, text: str):
        if not hasattr(self, "log_box"):
            return
        self.log_box.configure(state="normal")
        self.log_box.insert("end", text + "\n")
        n_lines = int(self.log_box.index("end-1c").split(".")[0])
        if n_lines > 100:
            self.log_box.delete("1.0", f"{n_lines - 80}.0")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    # ---------- tela 3: VERDICT ----------
    def _show_verdict(self):
        self._clear_container()

        v = (self.verdict_obj or {}).get("verdict", "?")
        style = _verdict_style(v)

        # Refina: se ha cluster CONFIRMED, sobe pra CONFIRMADO
        confirmed = [c for c in (self.clusters or [])
                     if getattr(c, "verdict", "") == "CONFIRMED"]
        detected = [c for c in (self.clusters or [])
                    if getattr(c, "verdict", "") == "DETECTED"]
        if confirmed:
            style = _verdict_style("CONFIRMED")
        elif detected:
            style = _verdict_style("DETECTED")

        # Brand header pequeno (mantem identidade)
        brand_lbl = ctk.CTkLabel(
            self.container, text="TELADOR",
            font=ctk.CTkFont(family="Segoe UI", size=16, weight="bold"),
            text_color=BRAND["amber"],
        )
        brand_lbl.pack(pady=(20, 2))

        stamp_lbl = ctk.CTkLabel(
            self.container, text=f"scan concluido  ·  {version.VERSION_DISPLAY}",
            font=ctk.CTkFont(size=10), text_color=BRAND["muted2"],
        )
        stamp_lbl.pack(pady=(0, 12))

        # Hero card do veredito (colorido, grande)
        hero = ctk.CTkFrame(
            self.container, fg_color=BRAND["bg_card"],
            corner_radius=12, border_width=2, border_color=style["color"],
        )
        hero.pack(fill="x", padx=60, pady=(0, 16))

        # Emoji/badge grande
        badge = ctk.CTkLabel(
            hero, text=f"[ {style['emoji']} ]",
            font=ctk.CTkFont(family="Consolas", size=32, weight="bold"),
            text_color=style["color"],
        )
        badge.pack(pady=(20, 6))

        # Label do veredito
        v_lbl = ctk.CTkLabel(
            hero, text=style["label"],
            font=ctk.CTkFont(family="Segoe UI", size=36, weight="bold"),
            text_color=style["color"],
        )
        v_lbl.pack(pady=(0, 4))

        # Subtitulo
        sub_lbl = ctk.CTkLabel(
            hero, text=style["subtitle"],
            font=ctk.CTkFont(size=12), text_color=BRAND["muted"],
        )
        sub_lbl.pack(pady=(0, 8))

        # Score + confidence row
        score = (self.verdict_obj or {}).get("score", 0)
        conf = (self.verdict_obj or {}).get("highest_confidence", 0)
        meta_row = ctk.CTkFrame(hero, fg_color=BRAND["bg_card"])
        meta_row.pack(pady=(0, 16))

        for label_txt, val_txt, val_color in (
                ("score",       str(score),                BRAND["text"]),
                ("confidence",  f"{conf}%",                style["color"]),
                ("targets",     str(len(confirmed) + len(detected)), BRAND["text"]),
        ):
            box = ctk.CTkFrame(meta_row, fg_color=BRAND["bg_card"])
            box.pack(side="left", padx=18)
            v_num = ctk.CTkLabel(
                box, text=val_txt,
                font=ctk.CTkFont(family="Consolas", size=20, weight="bold"),
                text_color=val_color,
            )
            v_num.pack()
            v_txt = ctk.CTkLabel(
                box, text=label_txt,
                font=ctk.CTkFont(size=9),
                text_color=BRAND["muted2"],
            )
            v_txt.pack()

        # 3 bullets do staff
        try:
            o, p, a = report.build_staff_verdict_bullets(
                self.clusters or [], self.verdict_obj or {}, self.coverage)
        except Exception:
            o = p = a = "?"

        bullets = ctk.CTkFrame(
            self.container, fg_color=BRAND["bg_card"],
            corner_radius=8, border_width=1, border_color=BRAND["border"],
        )
        bullets.pack(fill="x", padx=60, pady=(0, 16))

        for label_txt, value_txt in (("O QUE", o),
                                       ("POR QUE", p),
                                       ("O QUE FAZER", a)):
            row = ctk.CTkFrame(bullets, fg_color=BRAND["bg_card"])
            row.pack(fill="x", padx=18, pady=8)
            key = ctk.CTkLabel(
                row, text=label_txt,
                font=ctk.CTkFont(size=10, weight="bold"),
                text_color=BRAND["amber"], width=110, anchor="w",
            )
            key.pack(side="left", padx=(0, 14), anchor="n")
            val = ctk.CTkLabel(
                row, text=value_txt,
                font=ctk.CTkFont(size=12), text_color=BRAND["text"],
                justify="left", wraplength=560, anchor="w",
            )
            val.pack(side="left", anchor="w", fill="x", expand=True)

        # Botoes de acao
        btns_frame = ctk.CTkFrame(self.container, fg_color=BRAND["bg"])
        btns_frame.pack(pady=(4, 8))

        html_btn = ctk.CTkButton(
            btns_frame, text="Abrir relatorio HTML",
            command=self._open_html,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color=BRAND["amber"], hover_color=BRAND["amber_hi"],
            text_color="#111", corner_radius=4,
            width=190, height=38,
        )
        html_btn.grid(row=0, column=0, padx=6)

        copy_btn = ctk.CTkButton(
            btns_frame, text="Copiar resumo Discord",
            command=self._copy_discord,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color=BRAND["amber"], hover_color=BRAND["amber_hi"],
            text_color="#111", corner_radius=4,
            width=190, height=38,
        )
        copy_btn.grid(row=0, column=1, padx=6)

        new_btn = ctk.CTkButton(
            btns_frame, text="Nova SS",
            command=self._show_initial,
            font=ctk.CTkFont(size=12),
            fg_color="transparent", border_width=1,
            border_color=BRAND["muted"], text_color=BRAND["text"],
            hover_color=BRAND["bg_hover"],
            width=100, height=38,
        )
        new_btn.grid(row=0, column=2, padx=6)

        exit_btn = ctk.CTkButton(
            btns_frame, text="Sair",
            command=self.destroy,
            font=ctk.CTkFont(size=12),
            fg_color="transparent", text_color=BRAND["muted"],
            hover_color=BRAND["bg_hover"],
            width=70, height=38,
        )
        exit_btn.grid(row=0, column=3, padx=6)

        self.copy_status = ctk.CTkLabel(
            self.container, text="", font=ctk.CTkFont(size=11),
            text_color=BRAND["green"],
        )
        self.copy_status.pack(pady=(6, 0))

    def _open_html(self):
        if self.html_path and os.path.isfile(self.html_path):
            try:
                webbrowser.open(f"file:///{self.html_path.replace(os.sep, '/')}")
            except Exception as e:
                self.copy_status.configure(text=f"Falhou: {e}", text_color=BRAND["red"])
        else:
            self.copy_status.configure(text="HTML nao encontrado", text_color=BRAND["red"])

    def _copy_discord(self):
        try:
            md_path = report_md.generate_markdown_report(
                self.findings or [], _minimal_sys_info(),
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
                text="Copiado. Cole no Discord da liga.",
                text_color=BRAND["green"],
            )
        except Exception as e:
            self.copy_status.configure(text=f"Falhou: {e}", text_color=BRAND["red"])

    # ---------- error state ----------
    def _show_error(self, msg: str):
        self._clear_container()

        brand_lbl = ctk.CTkLabel(
            self.container, text="TELADOR",
            font=ctk.CTkFont(family="Segoe UI", size=24, weight="bold"),
            text_color=BRAND["amber"],
        )
        brand_lbl.pack(pady=(28, 20))

        card = ctk.CTkFrame(
            self.container, fg_color=BRAND["bg_card"],
            corner_radius=8, border_width=2, border_color=BRAND["red"],
        )
        card.pack(fill="both", expand=True, padx=60, pady=(0, 20))

        title = ctk.CTkLabel(
            card, text="[ X ] SCAN FALHOU",
            font=ctk.CTkFont(family="Consolas", size=20, weight="bold"),
            text_color=BRAND["red"],
        )
        title.pack(pady=(20, 12))

        err_box = ctk.CTkTextbox(
            card,
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=BRAND["muted"], fg_color=BRAND["bg"],
            corner_radius=4, border_width=0,
        )
        err_box.pack(fill="both", expand=True, padx=16, pady=(0, 12))
        err_box.insert("1.0", msg)
        err_box.configure(state="disabled")

        back_btn = ctk.CTkButton(
            self.container, text="Voltar",
            command=self._show_initial,
            fg_color=BRAND["amber"], hover_color=BRAND["amber_hi"],
            text_color="#111",
            width=140, height=36,
        )
        back_btn.pack(pady=(0, 20))

    # ---------- queue polling ----------
    def _poll_queue(self):
        try:
            while True:
                msg = self.msg_queue.get_nowait()
                self._handle_msg(msg)
        except queue.Empty:
            pass

        if self.scan_thread and self.scan_thread.is_alive() and self.scan_start_time:
            elapsed = time.time() - self.scan_start_time
            try:
                self.timer_lbl.configure(text=f"{elapsed:.1f}s")
            except Exception:
                pass

        self.after(100, self._poll_queue)

    def _handle_msg(self, msg):
        kind = msg[0]
        if kind == 'progress':
            _, done, total, scanner_name = msg
            try:
                if total > 0:
                    self.progress_bar.set(done / total)
                self.progress_lbl.configure(text=f"{done} / {total}")
                self.current_scanner_lbl.configure(text=f"rodando: {scanner_name}")
                if done and scanner_name != 'iniciando':
                    self._append_log(f"[{done:>3}/{total}] {scanner_name}")
            except Exception:
                pass
        elif kind == 'log':
            _, text = msg
            try:
                self._append_log(text)
            except Exception:
                pass
        elif kind == 'done':
            _, findings, verdict_obj, clusters, coverage, html_path = msg
            self.findings = findings
            self.verdict_obj = verdict_obj
            self.clusters = clusters
            self.coverage = coverage
            self.html_path = html_path
            self._show_verdict()
        elif kind == 'error':
            _, err_msg = msg
            self._show_error(err_msg)


def main():
    if not HAS_CTK:
        print("customtkinter nao instalado. Rode: pip install customtkinter")
        print("Caindo pra CLI classica...")
        telador.main()
        return

    app = TeladorGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
