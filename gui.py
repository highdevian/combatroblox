"""
GUI mínima do Telador — janela nativa (CustomTkinter) que envelopa o motor.

Objetivo (PLANO_ECHO_TIER Semana 2 P0): staff/suspeito NÃO precisa terminal.
Fluxo: [Iniciar SS] → progresso streaming → veredito grande → [HTML][Discord][Sair].

Chama diretamente os helpers do telador.py sem duplicar orquestração — o main()
CLI continua sendo o gold standard, a GUI é envelope leve pra distribuição.
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
import telador  # assemble_ss_live_scanners, _run_one


# =========================================================================
# UAC / admin
# =========================================================================

def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _try_elevate() -> bool:
    """Tenta relançar como admin. Retorna True se o relaunch começou (esta
    instância deve encerrar). False se usuário negou UAC ou já é admin."""
    if _is_admin():
        return False
    try:
        # Preserva --gui pra abrir GUI de novo depois da elevação
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
            sys.exit(0)  # elevated instance took over
    except Exception:
        pass
    return False


# =========================================================================
# Cores do veredito (semáforo)
# =========================================================================

VERDICT_STYLES = {
    "LIMPO":         {"emoji": "🟢", "color": "#3fbf7f", "label": "LIMPO"},
    "SUSPECT":       {"emoji": "🟡", "color": "#f0b400", "label": "SUSPEITO"},
    "SUSPEITO":      {"emoji": "🟡", "color": "#f0b400", "label": "SUSPEITO"},
    "DETECTED":      {"emoji": "🔴", "color": "#ff5555", "label": "DETECTADO"},
    "CHEATER":       {"emoji": "🔴", "color": "#ff5555", "label": "CHEATER"},
    "CONFIRMED":     {"emoji": "🔴", "color": "#e83a3a", "label": "CONFIRMADO"},
    "ALTAMENTE":     {"emoji": "🔴", "color": "#ff5555", "label": "SUSPEITO"},
    "INCONCLUSIVO":  {"emoji": "⚫", "color": "#888888", "label": "INCONCLUSIVO"},
    "?":             {"emoji": "⚫", "color": "#888888", "label": "—"},
}


def _verdict_style(verdict_str: str) -> dict:
    v = (verdict_str or "?").upper()
    for key, style in VERDICT_STYLES.items():
        if v.startswith(key):
            return style
    return VERDICT_STYLES["?"]


# =========================================================================
# Scan orchestration (roda em thread)
# =========================================================================

def _run_scan_thread(msg_queue: queue.Queue) -> None:
    """
    Roda scan --ss-live equivalente em thread. Empurra mensagens pra queue:
      ('progress', done, total, scanner_name)
      ('log', text)
      ('done', findings, verdict_obj, clusters, coverage, html_path)
      ('error', str)
    """
    try:
        # 1. Signatures
        n_sigs, sig_err = database.load_external_signatures()
        if n_sigs:
            matching.invalidate()
            msg_queue.put(('log', f'[SIG] {n_sigs} assinatura(s) externa(s) carregada(s)'))

        # 2. Chain — sempre ss-live pra GUI (< 45s alvo)
        chain = telador.assemble_ss_live_scanners()
        total = len(chain)
        msg_queue.put(('progress', 0, total, 'iniciando'))

        # 3. Execução paralela com callback
        results_by_fn = {}
        completed = [0]  # lista pra fechar sobre closure

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

        # Ordena resultados na ordem do chain (pro report ficar consistente)
        findings = [results_by_fn[fn.__name__] for fn in chain if fn.__name__ in results_by_fn]

        # 4. FP filter
        findings, fp_stats = fp_filter.post_process_findings(findings)

        # 5. Redaction (sempre — GUI vai copiar pro clipboard)
        findings, _redacted = redaction.redact_findings(findings)

        # 6. PE enrichment
        findings = pe_analysis.enrich_findings_with_pe(findings)

        # 7. Coverage + verdict
        cov = coverage_mod.build_coverage(
            findings,
            is_admin=_is_admin(),
            quick=False,
            skipped_groups=["yara", "winevent", "extra_forensics",
                             "anti_forensic_deep", "pca", "task_execlog",
                             "mplog", "cert_store", "shellbag",
                             "peripherals", "antievasion", "command_history"],
            only=None,
            sig_version=getattr(database, "LOADED_SIG_VERSION", None),
        )
        verdict_obj = fp_filter.compute_verdict(findings)
        verdict_obj = coverage_mod.apply_coverage_to_verdict(verdict_obj, cov)

        # 8. Clusters
        evidences = ev_engine.findings_to_evidences(findings)
        clusters = ev_engine.build_clusters(evidences)

        # 9. Gera HTML report
        sys_info = _minimal_sys_info()
        html_path = report.generate_html_report(
            findings, sys_info, screenshots={},
            verdict=verdict_obj, fp_stats=fp_stats,
            clusters=clusters, coverage=cov,
        )

        msg_queue.put(('done', findings, verdict_obj, clusters, cov, html_path))

    except Exception as e:
        import traceback
        msg_queue.put(('error', f'{type(e).__name__}: {e}\n{traceback.format_exc()[:400]}'))


def _minimal_sys_info() -> dict:
    """sys_info reduzido pra GUI — hostname + user + OS + admin flag + timestamp."""
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
    ctk.set_default_color_theme("blue")


class TeladorGUI(ctk.CTk if HAS_CTK else object):
    """Janela principal do Telador GUI."""

    def __init__(self):
        super().__init__()
        self.title(f"Telador {version.VERSION_DISPLAY} — SS forense pra Roblox")
        self.geometry("820x600")
        self.minsize(720, 520)

        self.msg_queue: queue.Queue = queue.Queue()
        self.scan_thread: threading.Thread | None = None
        self.findings = None
        self.verdict_obj = None
        self.clusters = None
        self.coverage = None
        self.html_path = None
        self.scan_start_time = None

        # Container principal
        self.container = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.container.pack(fill="both", expand=True, padx=24, pady=24)

        self._show_initial()

        # Poll da queue pra receber updates da thread
        self.after(100, self._poll_queue)

    # ---------- helpers ----------
    def _clear_container(self):
        for widget in self.container.winfo_children():
            widget.destroy()

    def _header(self, subtitle: str = None):
        title = ctk.CTkLabel(
            self.container,
            text="Telador",
            font=ctk.CTkFont(size=32, weight="bold"),
        )
        title.pack(pady=(0, 4))
        sub_text = subtitle or f"SS forense pra Roblox · {version.VERSION_DISPLAY}"
        subtitle_lbl = ctk.CTkLabel(
            self.container,
            text=sub_text,
            font=ctk.CTkFont(size=13),
            text_color="#888",
        )
        subtitle_lbl.pack(pady=(0, 24))

    # ---------- tela 1: INITIAL ----------
    def _show_initial(self):
        self._clear_container()
        self._header()

        # Card explicativo
        card = ctk.CTkFrame(self.container, corner_radius=12)
        card.pack(fill="x", padx=40, pady=(0, 24))

        info = (
            "Roda uma bateria de checagens LOCAIS no PC do suspeito procurando\n"
            "rastros de executor / bypass. Nada sai do PC.\n\n"
            "• Modo SS ao vivo (< 45 s) · 71 scanners rápidos\n"
            "• Veredito grande + botão de copiar pro Discord\n"
            "• Precisa de admin (pede UAC) — sem admin resultado é INCONCLUSIVO"
        )
        info_lbl = ctk.CTkLabel(
            card, text=info, justify="left",
            font=ctk.CTkFont(size=13), text_color="#c8c8c8",
        )
        info_lbl.pack(padx=24, pady=20, anchor="w")

        # Status admin
        admin_status = "✓ Rodando como Administrador" if _is_admin() \
            else "⚠ NÃO está como Administrador (resultado limitado)"
        admin_color = "#3fbf7f" if _is_admin() else "#f0b400"
        admin_lbl = ctk.CTkLabel(
            self.container,
            text=admin_status,
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=admin_color,
        )
        admin_lbl.pack(pady=(0, 16))

        # Botão gigante Iniciar
        start_btn = ctk.CTkButton(
            self.container,
            text="Iniciar SS",
            command=self._start_scan,
            font=ctk.CTkFont(size=22, weight="bold"),
            width=280, height=64, corner_radius=32,
        )
        start_btn.pack(pady=(0, 12))

        if not _is_admin():
            elev_btn = ctk.CTkButton(
                self.container,
                text="Pedir permissão de administrador (UAC)",
                command=self._request_admin,
                font=ctk.CTkFont(size=13),
                fg_color="transparent", border_width=1,
                width=280, height=32,
            )
            elev_btn.pack(pady=(0, 12))

        exit_btn = ctk.CTkButton(
            self.container, text="Sair",
            command=self.destroy,
            font=ctk.CTkFont(size=12),
            fg_color="transparent", text_color="#888",
            width=80, height=28,
        )
        exit_btn.pack(pady=(8, 0))

    def _request_admin(self):
        """Tenta relançar como admin. Se der certo, esta instância sai."""
        _try_elevate()  # sai via sys.exit(0) se elevou; senão volta e não faz nada

    # ---------- tela 2: SCANNING ----------
    def _start_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            return
        self._show_scanning()
        self.scan_start_time = time.time()
        self.scan_thread = threading.Thread(
            target=_run_scan_thread, args=(self.msg_queue,), daemon=True)
        self.scan_thread.start()

    def _show_scanning(self):
        self._clear_container()
        self._header(subtitle="Rodando checagem local — nada sai do PC")

        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(
            self.container, width=560, height=16, corner_radius=8)
        self.progress_bar.set(0)
        self.progress_bar.pack(pady=(20, 12))

        # Contador
        self.progress_lbl = ctk.CTkLabel(
            self.container, text="0 / ? scanners",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        self.progress_lbl.pack(pady=(0, 8))

        # Scanner atual
        self.current_scanner_lbl = ctk.CTkLabel(
            self.container, text="iniciando...",
            font=ctk.CTkFont(size=12), text_color="#888",
        )
        self.current_scanner_lbl.pack(pady=(0, 24))

        # Timer
        self.timer_lbl = ctk.CTkLabel(
            self.container, text="0.0s",
            font=ctk.CTkFont(size=11), text_color="#666",
        )
        self.timer_lbl.pack()

        # Log rolante (últimas linhas)
        self.log_box = ctk.CTkTextbox(
            self.container, height=200, width=680,
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color="#aaa", fg_color="#1a1a1a",
        )
        self.log_box.pack(pady=(24, 0), fill="x", padx=20)
        self.log_box.configure(state="disabled")

    def _append_log(self, text: str):
        self.log_box.configure(state="normal")
        self.log_box.insert("end", text + "\n")
        # Trunca se ficar gigante
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

        # Refina veredito com base nos clusters
        confirmed = [c for c in (self.clusters or [])
                     if getattr(c, "verdict", "") == "CONFIRMED"]
        detected = [c for c in (self.clusters or [])
                    if getattr(c, "verdict", "") == "DETECTED"]
        if confirmed:
            style = _verdict_style("CONFIRMED")
        elif detected:
            style = _verdict_style("DETECTED")

        # Header sem título grande — o veredito é o título
        subtitle_lbl = ctk.CTkLabel(
            self.container, text="Veredito da SS",
            font=ctk.CTkFont(size=12), text_color="#888",
        )
        subtitle_lbl.pack(pady=(0, 4))

        # Semáforo gigante
        emoji_lbl = ctk.CTkLabel(
            self.container, text=style["emoji"],
            font=ctk.CTkFont(size=72),
        )
        emoji_lbl.pack(pady=(4, 0))

        # Label do veredito
        verdict_lbl = ctk.CTkLabel(
            self.container, text=style["label"],
            font=ctk.CTkFont(size=32, weight="bold"),
            text_color=style["color"],
        )
        verdict_lbl.pack(pady=(0, 8))

        # Score + confidence
        score = (self.verdict_obj or {}).get("score", 0)
        conf = (self.verdict_obj or {}).get("highest_confidence", 0)
        meta_txt = f"score {score}  ·  confidence {conf}%"
        meta_lbl = ctk.CTkLabel(
            self.container, text=meta_txt,
            font=ctk.CTkFont(size=13), text_color="#888",
        )
        meta_lbl.pack(pady=(0, 20))

        # 3 bullets veredito staff
        try:
            o, p, a = report.build_staff_verdict_bullets(
                self.clusters or [], self.verdict_obj or {}, self.coverage)
        except Exception:
            o = p = a = "—"

        bullets_frame = ctk.CTkFrame(self.container, corner_radius=12)
        bullets_frame.pack(fill="x", padx=40, pady=(0, 20))

        for label_txt, value_txt in (("O quê", o), ("Por quê", p), ("O que fazer", a)):
            row = ctk.CTkFrame(bullets_frame, fg_color="transparent")
            row.pack(fill="x", padx=20, pady=8, anchor="w")
            key = ctk.CTkLabel(
                row, text=label_txt.upper(),
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color="#d8a24f", width=110, anchor="w",
            )
            key.pack(side="left", padx=(0, 12), anchor="n")
            val = ctk.CTkLabel(
                row, text=value_txt,
                font=ctk.CTkFont(size=13), text_color="#e8e0d2",
                justify="left", wraplength=560, anchor="w",
            )
            val.pack(side="left", anchor="w", fill="x", expand=True)

        # Botões de ação
        btns_frame = ctk.CTkFrame(self.container, fg_color="transparent")
        btns_frame.pack(pady=(4, 0))

        html_btn = ctk.CTkButton(
            btns_frame, text="Abrir relatório HTML",
            command=self._open_html,
            font=ctk.CTkFont(size=13, weight="bold"),
            width=190, height=40,
        )
        html_btn.grid(row=0, column=0, padx=6)

        copy_btn = ctk.CTkButton(
            btns_frame, text="Copiar resumo Discord",
            command=self._copy_discord,
            font=ctk.CTkFont(size=13, weight="bold"),
            width=190, height=40,
        )
        copy_btn.grid(row=0, column=1, padx=6)

        new_btn = ctk.CTkButton(
            btns_frame, text="Nova SS",
            command=self._show_initial,
            font=ctk.CTkFont(size=13),
            fg_color="transparent", border_width=1,
            width=100, height=40,
        )
        new_btn.grid(row=0, column=2, padx=6)

        exit_btn = ctk.CTkButton(
            btns_frame, text="Sair",
            command=self.destroy,
            font=ctk.CTkFont(size=13),
            fg_color="transparent", border_width=1,
            text_color="#888",
            width=80, height=40,
        )
        exit_btn.grid(row=0, column=3, padx=6)

        # Feedback do copy
        self.copy_status = ctk.CTkLabel(
            self.container, text="", font=ctk.CTkFont(size=11),
            text_color="#3fbf7f",
        )
        self.copy_status.pack(pady=(10, 0))

    def _open_html(self):
        if self.html_path and os.path.isfile(self.html_path):
            try:
                webbrowser.open(f"file:///{self.html_path.replace(os.sep, '/')}")
            except Exception as e:
                self.copy_status.configure(text=f"Falhou: {e}", text_color="#ff5555")
        else:
            self.copy_status.configure(text="HTML não encontrado", text_color="#ff5555")

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
            self.update()  # Windows precisa disso pra clipboard persistir
            self.copy_status.configure(
                text="✓ Copiado! Cole no Discord da liga.",
                text_color="#3fbf7f",
            )
        except Exception as e:
            self.copy_status.configure(text=f"Falhou: {e}", text_color="#ff5555")

    # ---------- error state ----------
    def _show_error(self, msg: str):
        self._clear_container()
        self._header(subtitle="Erro durante o scan")

        icon = ctk.CTkLabel(
            self.container, text="⚠",
            font=ctk.CTkFont(size=64), text_color="#ff5555",
        )
        icon.pack(pady=(20, 12))

        title_lbl = ctk.CTkLabel(
            self.container, text="Scan falhou",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color="#ff5555",
        )
        title_lbl.pack(pady=(0, 12))

        err_box = ctk.CTkTextbox(
            self.container, height=200, width=680,
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color="#aaa", fg_color="#1a1a1a",
        )
        err_box.pack(pady=(0, 20), fill="x", padx=20)
        err_box.insert("1.0", msg)
        err_box.configure(state="disabled")

        back_btn = ctk.CTkButton(
            self.container, text="Voltar",
            command=self._show_initial,
            width=140, height=36,
        )
        back_btn.pack()

    # ---------- queue polling ----------
    def _poll_queue(self):
        try:
            while True:
                msg = self.msg_queue.get_nowait()
                self._handle_msg(msg)
        except queue.Empty:
            pass

        # Atualiza timer se estiver escaneando
        if self.scan_thread and self.scan_thread.is_alive() and self.scan_start_time:
            elapsed = time.time() - self.scan_start_time
            try:
                self.timer_lbl.configure(text=f"{elapsed:.1f}s (alvo <45s)")
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
                self.progress_lbl.configure(text=f"{done} / {total} scanners")
                self.current_scanner_lbl.configure(text=f"rodando: {scanner_name}")
                if done and scanner_name != 'iniciando':
                    self._append_log(f"[{done:>2}/{total}] {scanner_name}")
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
        # Fallback: cair pra CLI se CTk não estiver disponível
        print("customtkinter não instalado — abrindo CLI clássica.")
        print("Rode: pip install customtkinter")
        telador.main()
        return

    app = TeladorGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
