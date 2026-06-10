"""
Telador BR - Roblox SS Tool

Roda uma bateria de checagens locais (read-only) procurando por traços de
executores Roblox e ferramentas auxiliares de cheating. Gera um relatório
HTML que abre no browser. Tudo fica LOCAL — nada sai do PC.

USO:
    python telador.py                     # roda normal (com screenshot + tudo)
    python telador.py --no-open           # gera relatório mas não abre
    python telador.py --no-screenshot     # pula captura de tela
    python telador.py --no-forensics      # pula Amcache/BAM/JumpLists (são pesadas)
    python telador.py --no-antievasion    # pula VM/Sandbox/Clock checks
    python telador.py --no-persistence    # pula Startup/Run/Tasks/WER
    python telador.py --no-parallel       # roda sequencial (debug)
    python telador.py --threads N         # ajusta threads paralelas (default 4)
    python telador.py --json              # também salva um .json bruto
    python telador.py --only X,Y          # roda só checagens específicas
"""

import os
import sys
import time
import json
import ctypes
import secrets
import argparse
import tempfile
import threading
import webbrowser
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import database
import scanners
import forensics
import extra_forensics
import antievasion
import persistence
import live_analysis
import command_history
import peripherals
import discord_cache
import network_scanners
import fresh_install
import removable_media
import user_accounts
import defender_tampering
import clock_tampering
import cleaner_tools
import capture
import fp_filter
import pe_analysis
import report_signing
import diff_tool
import redaction
import report
import report_md
import evidence as ev_engine
import debug


# --------------------------- ANSI / UTF-8 setup ---------------------------

if os.name == "nt":
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        kernel32.SetConsoleOutputCP(65001)
    except Exception:
        pass

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

RESET   = "\033[0m"
BOLD    = "\033[1m"
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
CYAN    = "\033[96m"
GREY    = "\033[90m"
AMBER   = "\033[33m"   # dourado/âmbar — cor de marca (terminal forense)


BANNER = r"""
████████╗███████╗██╗      █████╗ ██████╗  ██████╗ ██████╗     ██████╗ ██████╗
╚══██╔══╝██╔════╝██║     ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗    ██╔══██╗██╔══██╗
   ██║   █████╗  ██║     ███████║██║  ██║██║   ██║██████╔╝    ██████╔╝██████╔╝
   ██║   ██╔══╝  ██║     ██╔══██║██║  ██║██║   ██║██╔══██╗    ██╔══██╗██╔══██╗
   ██║   ███████╗███████╗██║  ██║██████╔╝╚██████╔╝██║  ██║    ██████╔╝██║  ██║
   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝    ╚═════╝ ╚═╝  ╚═╝
                          SS / Tela tool para Roblox
"""


def print_banner():
    print(f"{AMBER}{BANNER}{RESET}")
    print(f"{GREEN}  >_ {RESET}{GREY}screenshare forense · veredito por correlação de evidências{RESET}")
    print(f"{GREY}  v3.35.0  ·  Confidence Engine  ·  100% local{RESET}\n")
    self_hash = report_signing.get_self_hash()
    if self_hash:
        print(f"{GREY}  SHA256 deste exe: {self_hash[:16]}...{self_hash[-16:]}{RESET}")
        print(f"{GREY}  Compare com a release oficial no GitHub pra confirmar autenticidade.{RESET}\n")


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def maybe_elevate() -> None:
    """Se não estiver como admin, tenta RELANÇAR elevado via UAC.

    Motivo: sem admin, as fontes forenses mais fortes (Prefetch, Amcache,
    BAM, Defender) falham e o scan fica cego. Em vez de depender do
    supervisor saber 'botão direito → Executar como administrador', o
    programa pede a elevação sozinho ao abrir.

    Comportamento:
      - Já é admin → não faz nada.
      - `--no-elevate` ou já relançado → não faz nada (evita loop).
      - Usuário aceita o UAC → relança elevado e ESTA instância encerra.
      - Usuário recusa o UAC (ou falha) → segue sem admin (com aviso forte).
    """
    if os.name != "nt" or is_admin():
        return
    argv = sys.argv[1:]
    if "--no-elevate" in argv or "--_relaunched" in argv:
        return
    try:
        import subprocess
        if getattr(sys, "frozen", False):
            exe = sys.executable
            params = subprocess.list2cmdline(argv + ["--_relaunched"])
        else:
            exe = sys.executable  # python.exe
            script = os.path.abspath(sys.argv[0])
            params = subprocess.list2cmdline([script] + argv + ["--_relaunched"])
        print(f"{CYAN}[ADMIN]{RESET} Pedindo permissão de administrador "
              f"{GREY}(necessário pra cobertura completa)...{RESET}")
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        if int(rc) > 32:
            # Relançou elevado com sucesso — encerra a instância não-admin.
            sys.exit(0)
        # rc <= 32: usuário clicou "Não" no UAC ou houve erro → segue sem admin.
    except Exception:
        pass


def confirm_consent() -> bool:
    print(f"{BOLD}Esta ferramenta vai escanear seu sistema procurando por:{RESET}")
    print(f"  {GREY}- Histórico de execução (Prefetch, UserAssist, MUICache, Amcache, BAM){RESET}")
    print(f"  {GREY}- Arquivos recentes, Lixeira, JumpLists{RESET}")
    print(f"  {GREY}- Pasta Downloads e histórico de browser{RESET}")
    print(f"  {GREY}- Processos rodando agora{RESET}")
    print(f"  {GREY}- Logs do client Roblox{RESET}")
    print(f"  {GREY}- Scripts .lua / .luau salvos em pastas comuns{RESET}")
    print(f"  {GREY}- Indicadores de VM/Sandbox/relógio mexido{RESET}")
    print(f"  {GREY}- Capturas de tela (desktop + janela do Roblox){RESET}\n")
    print(f"{GREY}Tudo é local. Nada é enviado pra internet.{RESET}\n")

    resp = input(f"{YELLOW}Iniciar a tela? [s/N]: {RESET}").strip().lower()
    return resp in ("s", "sim", "y", "yes")


def severity_to_color(sev: str) -> str:
    return {"critical": RED, "high": RED, "medium": YELLOW, "low": MAGENTA}.get(sev, GREY)


def assemble_scanners(skip_forensics: bool, skip_antievasion: bool,
                       skip_persistence: bool = False,
                       skip_live: bool = False,
                       skip_history: bool = False,
                       skip_peripherals: bool = False) -> list:
    chain = list(scanners.ALL_SCANNERS)
    if not skip_live:
        chain.extend(live_analysis.ALL_LIVE_ANALYSIS_SCANNERS)
    if not skip_history:
        chain.extend(command_history.ALL_COMMAND_HISTORY_SCANNERS)
    if not skip_peripherals:
        chain.extend(peripherals.ALL_PERIPHERAL_SCANNERS)
    if not skip_persistence:
        chain.extend(persistence.ALL_PERSISTENCE_SCANNERS)
    if not skip_antievasion:
        chain.extend(antievasion.ALL_ANTIEVASION_SCANNERS)
    if not skip_forensics:
        chain.extend(forensics.ALL_FORENSIC_SCANNERS)
        chain.extend(extra_forensics.ALL_EXTRA_FORENSIC_SCANNERS)
    # Network + Discord + Fresh install — sempre incluídos no modo full
    chain.extend(network_scanners.ALL_NETWORK_SCANNERS)
    chain.extend(discord_cache.ALL_DISCORD_SCANNERS)
    chain.extend(fresh_install.ALL_FRESH_INSTALL_SCANNERS)
    chain.extend(removable_media.ALL_REMOVABLE_SCANNERS)
    chain.extend(user_accounts.ALL_USER_ACCOUNT_SCANNERS)
    chain.extend(defender_tampering.ALL_DEFENDER_SCANNERS)
    chain.extend(clock_tampering.ALL_CLOCK_SCANNERS)
    chain.extend(cleaner_tools.ALL_CLEANER_SCANNERS)
    return chain


_print_lock = threading.Lock()


def _run_one(fn) -> dict:
    """Roda um scanner com proteção contra crash."""
    label = fn.__name__.replace("scan_", "").replace("_", " ")
    try:
        return fn()
    except Exception as e:
        return {
            "name": label, "description": "(crash inesperado)",
            "status": "error", "items": [],
            "summary": f"Erro: {e}", "error": str(e),
        }


def run_scanners_parallel(chain: list, only: list = None, max_workers: int = 4,
                          high_only: bool = False, on_result=None) -> list:
    """Roda scanners em paralelo (até max_workers ao mesmo tempo).

    on_result(result, done, total): callback opcional chamado a cada scanner
    que termina — usado pelo dashboard --watch pra streamar ao vivo.
    """
    to_run = []
    for fn in chain:
        label = fn.__name__.replace("scan_", "").replace("_", " ")
        if only and label not in only:
            continue
        to_run.append(fn)

    total = len(to_run)
    print(f"{GREY}  Rodando {total} checagens em {max_workers} threads...{RESET}\n")

    order = {fn.__name__: i for i, fn in enumerate(to_run)}
    results_by_fn = {}
    durations = {}
    completed = 0

    start_total = time.time()

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        future_to_fn = {}
        for fn in to_run:
            t0 = time.time()
            fut = ex.submit(_run_one, fn)
            future_to_fn[fut] = (fn, t0)

        for future in as_completed(future_to_fn):
            fn, t0 = future_to_fn[future]
            label = fn.__name__.replace("scan_", "").replace("_", " ")
            result = future.result()
            completed += 1
            dur = time.time() - t0
            durations[fn.__name__] = dur
            results_by_fn[fn.__name__] = result

            status = result["status"]
            n_items = len(result["items"])
            if status == "suspicious":
                tag = f"{RED}{n_items} SUSPEITO(S){RESET}"
            elif status == "error":
                tag = f"{GREY}skip{RESET}"
            else:
                tag = f"{GREEN}ok{RESET}"

            with _print_lock:
                print(f"{CYAN}[{completed:>2}/{total}]{RESET} {BOLD}{label}{RESET}... "
                      f"{tag} {GREY}({dur:.1f}s){RESET}")
                shown = _filter_items_for_display(result["items"], high_only)
                for item in shown[:3]:
                    sev = item.get("severity", "low")
                    color = severity_to_color(sev)
                    print(f"      {color}● [{sev.upper()}]{RESET} {item['label']}  "
                          f"{GREY}→ match: {item['matched']}{RESET}")
                if len(shown) > 3:
                    print(f"      {GREY}... +{len(shown) - 3} mais{RESET}")
                hidden = len(result["items"]) - len(shown)
                if high_only and hidden > 0 and not shown:
                    print(f"      {GREY}({hidden} item(s) abaixo de high ocultados){RESET}")

            # Streama pro dashboard ao vivo (--watch), se ligado.
            if on_result is not None:
                try:
                    on_result(result, completed, total)
                except Exception:
                    pass  # dashboard nunca pode derrubar o scan

    elapsed = time.time() - start_total
    print(f"\n{GREY}  Total: {elapsed:.1f}s (paralelo){RESET}")

    # Ordena pela ordem original do chain
    ordered = sorted(results_by_fn.items(), key=lambda kv: order.get(kv[0], 999))
    return [r for _name, r in ordered]


def cross_correlate(findings: list) -> dict:
    """
    Para cada keyword (matched), conta em quantas categorias diferentes apareceu.
    Se aparece em 3+ categorias = ALTA CONFIANÇA = praticamente certeza de cheat.

    Pega o cheater que limpou alguns rastros mas esqueceu outros.
    """
    by_keyword = {}
    for f in findings:
        scanner_name = f["name"]
        seen_in_scanner = set()
        for item in f["items"]:
            kw = (item.get("matched") or "").strip()
            if not kw or kw in seen_in_scanner:
                continue
            seen_in_scanner.add(kw)

            entry = by_keyword.setdefault(kw, {
                "sources": [],
                "items": [],
                "worst_severity": "low",
            })
            entry["sources"].append(scanner_name)
            entry["items"].append(item)
            # Pior severidade
            sev = item.get("severity", "low")
            order = {"low": 1, "medium": 2, "high": 3}
            if order.get(sev, 0) > order.get(entry["worst_severity"], 0):
                entry["worst_severity"] = sev

    # Filtra: só keywords que aparecem em 3+ scanners
    high_confidence = {
        kw: info for kw, info in by_keyword.items()
        if len(info["sources"]) >= 3
    }
    return high_confidence


_HIGH_LEVELS = ("high", "critical")


def _filter_items_for_display(items, high_only: bool):
    """Aplica o filtro do --high-only só na saída do console. Items originais
    nunca são alterados — relatório HTML/JSON e veredicto continuam completos."""
    if not high_only:
        return items
    return [it for it in items if it.get("severity", "low") in _HIGH_LEVELS]


def run_scanners(chain: list, only: list = None, high_only: bool = False) -> list:
    findings = []
    total = len(chain)

    for i, fn in enumerate(chain, 1):
        label = fn.__name__.replace("scan_", "").replace("_", " ")
        if only and label not in only:
            continue

        print(f"{CYAN}[{i:>2}/{total}]{RESET} Rodando {BOLD}{label}{RESET}...", end=" ", flush=True)
        start = time.time()
        try:
            result = fn()
        except Exception as e:
            result = {
                "name": label, "description": "(crash inesperado)",
                "status": "error", "items": [],
                "summary": f"Erro: {e}", "error": str(e),
            }
        dur = time.time() - start

        status = result["status"]
        n_items = len(result["items"])
        if status == "suspicious":
            tag = f"{RED}{n_items} SUSPEITO(S){RESET}"
        elif status == "error":
            tag = f"{GREY}skip{RESET}"
        else:
            tag = f"{GREEN}ok{RESET}"

        print(f"{tag} {GREY}({dur:.1f}s){RESET}")

        shown = _filter_items_for_display(result["items"], high_only)
        for item in shown[:5]:
            sev = item.get("severity", "low")
            color = severity_to_color(sev)
            print(f"      {color}● [{sev.upper()}]{RESET} {item['label']}  "
                  f"{GREY}→ match: {item['matched']}{RESET}")
        if len(shown) > 5:
            print(f"      {GREY}... +{len(shown) - 5} mais (ver relatório HTML){RESET}")
        # No modo --high-only, sinaliza quando há items escondidos pra não
        # parecer que o scanner ficou "vazio" embora tenha achados de baixa.
        hidden = len(result["items"]) - len(shown)
        if high_only and hidden > 0 and not shown:
            print(f"      {GREY}({hidden} item(s) abaixo de high ocultados — ver HTML){RESET}")

        findings.append(result)

    return findings


def print_overview(findings: list) -> None:
    verdict = fp_filter.compute_verdict(findings)

    print(f"\n{BOLD}═══════════════════════════════════════════════════════════════{RESET}")
    print(f"{BOLD}                            RESUMO{RESET}")
    print(f"{BOLD}═══════════════════════════════════════════════════════════════{RESET}\n")

    crit_n = verdict.get("critical", 0)
    if crit_n:
        print(f"  {RED}{BOLD}CRIT  {RESET}  {crit_n:>3}   (prova forense forte — hash/BYOVD)")
    print(f"  {RED}HIGH  {RESET}  {verdict['high']:>3}   (match direto de executor conhecido)")
    print(f"  {YELLOW}MEDIUM{RESET}  {verdict['medium']:>3}   (ferramenta auxiliar ou bypass)")
    print(f"  {MAGENTA}LOW   {RESET}  {verdict['low']:>3}   (palavra-chave ambígua)")
    print(f"  {GREY}Score:{RESET}  {verdict['score']:>5.1f}   (ponderado por severidade × confidence × recência)")
    if verdict["most_recent_hit"]:
        print(f"  {GREY}Mais recente: {verdict['most_recent_hit']}{RESET}")
    print()

    color_map = {
        "CHEATER CONFIRMADO":   RED,
        "ALTAMENTE SUSPEITO":   RED,
        "SUSPEITO (REVISAR)":   YELLOW,
        "POSSÍVEIS PISTAS":     MAGENTA,
        "LIMPO":                GREEN,
    }
    color = color_map.get(verdict["verdict"], GREY)
    print(f"{color}{BOLD}>>> VEREDITO: {verdict['verdict']} (score {verdict['score']}) <<<{RESET}\n")


def save_json(findings: list, sys_info: dict) -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(tempfile.gettempdir(), f"telador_relatorio_{ts}.json")
    payload = {"system": sys_info, "findings": findings}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    return path


def main():
    parser = argparse.ArgumentParser(description="Telador BR - SS para Roblox")
    parser.add_argument("--no-open",       action="store_true", help="Não abrir HTML no navegador")
    parser.add_argument("--no-confirm",    action="store_true", help="Pular prompt de confirmação")
    parser.add_argument("--no-screenshot", action="store_true", help="Pular captura de tela")
    parser.add_argument("--no-forensics",  action="store_true", help="Pular Amcache/BAM/JumpLists")
    parser.add_argument("--no-antievasion",action="store_true", help="Pular VM/Sandbox/Clock checks")
    parser.add_argument("--no-persistence",action="store_true", help="Pular Startup/Run/Tasks/WER")
    parser.add_argument("--no-live",       action="store_true", help="Pular DLL injection scan + process tree")
    parser.add_argument("--no-history",    action="store_true", help="Pular PowerShell/RunMRU/TypedPaths")
    parser.add_argument("--no-peripherals",action="store_true", help="Pular detecção de macros de mouse")
    parser.add_argument("--strict",        action="store_true", help="Desliga filtro de falsos positivos (modo paranoia)")
    parser.add_argument("--high-only",     action="store_true", help="Mostra no console apenas itens de severidade alta/crítica (relatorio HTML/JSON nao muda)")
    parser.add_argument("--no-pe",         action="store_true", help="Pula PE analysis dos executáveis")
    parser.add_argument("--save-tsr",      type=str, default=None, help="Salva relatório em .tsr (JSON+HMAC)")
    parser.add_argument("--diff",          type=str, default=None, help="Compara este SS com um .tsr anterior")
    parser.add_argument("--no-redact",     action="store_true", help="Desliga redação de credenciais/emails/tokens no relatório")
    parser.add_argument("--force-screenshot", action="store_true", help="Captura tela mesmo se gerenciador de senhas estiver aberto")
    parser.add_argument("--md",            action="store_true", help="Também salva relatório em Markdown (colável no Discord)")
    parser.add_argument("--quick",         action="store_true", help="Modo rápido: só scanners base (pula forensics/persistence/live/etc)")
    parser.add_argument("--watch",         action="store_true",
                        help="Abre um dashboard LOCAL ao vivo (127.0.0.1) mostrando scanners e veredito em tempo real. Nada sai do PC.")
    parser.add_argument("--update-sigs",   action="store_true",
                        help="Baixa a base de assinaturas mais recente do GitHub e sai. Comando de manutenção — o scan normal nunca toca a rede.")
    parser.add_argument("--no-elevate",    action="store_true",
                        help="Não pedir permissão de administrador (UAC). Roda com cobertura limitada.")
    parser.add_argument("--_relaunched",   action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--no-parallel",   action="store_true", help="Rodar sequencial (debug)")
    parser.add_argument("--verbose", "-v",  action="store_true",
                        help="Loga no stderr as exceções engolidas pelos leitores de artefato "
                             "(diagnostica scanner que falha calado e reduz cobertura).")
    parser.add_argument("--threads",       type=int, default=4, help="Threads em paralelo (default 4)")
    parser.add_argument("--json",          action="store_true", help="Também salvar relatório JSON")
    parser.add_argument("--strict-scripts",action="store_true",
                        help="Modo agressivo no scanner de scripts (.txt genérico também entra)")
    parser.add_argument("--only",          type=str, default=None,
                        help="Rodar só checagens específicas (separadas por vírgula)")
    parser.add_argument("--codigo",        type=str, default=None,
                        help="Código de verificação ditado pelo supervisor no início da SS "
                             "(prova que o relatório é desta sessão ao vivo)")
    args = parser.parse_args()

    if args.verbose:
        debug.enable()

    # Auto-elevação: tenta virar admin via UAC ANTES de tudo (a não ser que
    # seja --update-sigs, que não precisa, ou o usuário tenha pedido
    # --no-elevate). Se relançar elevado, esta instância encerra aqui.
    if not args.update_sigs:
        maybe_elevate()

    print_banner()

    # --update-sigs: comando de manutenção. Baixa a base do GitHub e SAI.
    # O scan normal nunca passa por aqui — só este modo explícito toca a rede.
    if args.update_sigs:
        print(f"{CYAN}[UPDATE]{RESET} Baixando base de assinaturas mais recente do GitHub...")
        try:
            import sigupdate
            ok, msg = sigupdate.update_signatures()
        except Exception as e:
            ok, msg = False, f"erro inesperado ({e})"
        if ok:
            print(f"{GREEN}✓ {msg}{RESET}")
            print(f"{GREY}  Pronto. Rode o telador normalmente — a base nova já vale.{RESET}")
        else:
            print(f"{YELLOW}✗ Não atualizou: {msg}{RESET}")
            print(f"{GREY}  Sem problema — a base embutida no .exe continua valendo.{RESET}")
        sys.exit(0 if ok else 1)

    # Mescla assinaturas externas (signatures.json) antes de qualquer scan.
    sig_added, sig_err = database.load_external_signatures()
    if sig_added:
        import matching
        matching.invalidate()  # recompila patterns com as assinaturas extras
        ver = database.LOADED_SIG_VERSION
        ver_txt = f" (versão {ver})" if ver else ""
        print(f"{CYAN}[SIG]{RESET} {GREY}{sig_added} assinatura(s) extra(s) de signatures.json{ver_txt}{RESET}")
    elif sig_err:
        print(f"{YELLOW}[SIG]{RESET} {GREY}{sig_err}{RESET}")

    running_as_admin = is_admin()
    if not running_as_admin:
        print(f"{RED}{BOLD}╔══════════════════════════════════════════════════════════════╗{RESET}")
        print(f"{RED}{BOLD}║  ⚠  SCAN LIMITADO — NÃO ESTÁ COMO ADMINISTRADOR              ║{RESET}")
        print(f"{RED}{BOLD}╚══════════════════════════════════════════════════════════════╝{RESET}")
        print(f"{YELLOW}   Sem admin, as fontes MAIS IMPORTANTES falham: Prefetch, Amcache,{RESET}")
        print(f"{YELLOW}   BAM, Defender, Lixeira. Um resultado 'LIMPO' aqui NÃO é confiável —{RESET}")
        print(f"{YELLOW}   o cheat pode estar lá e o scan simplesmente não conseguiu ler.{RESET}")
        print(f"{GREY}   Feche e rode de novo como administrador (o programa pede sozinho){RESET}\n")

    if not args.no_confirm:
        if not confirm_consent():
            print(f"\n{GREY}Cancelado pelo usuário.{RESET}")
            sys.exit(0)

    print(f"\n{BOLD}Iniciando varredura...{RESET}\n")

    # 1. Screenshot (antes das checagens, no estado "fresh")
    screenshots = {}
    if not args.no_screenshot:
        sensitive = redaction.detect_sensitive_processes()
        if sensitive and not args.force_screenshot:
            print(f"{YELLOW}[SS]{RESET} Gerenciador de senhas aberto "
                  f"({GREY}{', '.join(sensitive)}{RESET}{YELLOW}). "
                  f"Capture pulado pra preservar privacidade.{RESET}")
            print(f"      {GREY}Feche o programa e rode de novo, ou use --force-screenshot.{RESET}")
        else:
            print(f"{CYAN}[SS]{RESET} Capturando TODOS os monitores + janela do Roblox...", end=" ", flush=True)
            try:
                screenshots = capture.capture_all()
                took = sum(1 for v in screenshots.values() if v)
                total = len(screenshots)
                print(f"{GREEN}{took}/{total} ok{RESET}")
            except Exception as e:
                print(f"{YELLOW}falhou: {e}{RESET}")
                screenshots = {}

    # 2. Checagens
    only_list = None
    if args.only:
        only_list = [s.strip().lower() for s in args.only.split(",")]

    scanners.set_scripts_strict_mode(args.strict_scripts)
    if args.strict_scripts:
        print(f"{YELLOW}● Modo de scripts: estrito{RESET} {GREY}(.txt genérico será analisado){RESET}")
    else:
        print(f"{GREEN}● Modo de scripts: anti-falso-positivo{RESET}")

    sys_info = scanners.system_info()
    # Prova de SS ao vivo: session_id aleatório (sempre) + código do supervisor
    # (opcional). Ambos entram no sys_info, que é assinado no .tsr e exibido
    # no relatório. Garante que o relatório é DESTA sessão, não reaproveitado.
    sys_info["session_id"] = secrets.token_hex(4).upper()
    sys_info["session_code"] = (args.codigo or "").strip()
    sys_info["admin"] = running_as_admin  # relatório avisa se foi scan limitado

    # --quick: só scanners base, skip todos os extras
    if args.quick:
        chain = list(scanners.ALL_SCANNERS)
        print(f"{CYAN}[QUICK]{RESET} {GREY}Modo rápido — só {len(chain)} scanners base{RESET}")
    else:
        chain = assemble_scanners(
            skip_forensics=args.no_forensics,
            skip_antievasion=args.no_antievasion,
            skip_persistence=args.no_persistence,
            skip_live=args.no_live,
            skip_history=args.no_history,
            skip_peripherals=args.no_peripherals,
        )

    # Dashboard local ao vivo (--watch). Sobe servidor em loopback antes do
    # scan; cada scanner que termina é streamado. Nada sai do PC.
    watch_cb = None
    watch_url = None
    if args.watch:
        try:
            import watch_server
            total_scanners = len(chain) if not only_list else sum(
                1 for fn in chain
                if fn.__name__.replace("scan_", "").replace("_", " ") in only_list
            )
            watch_url = watch_server.start(total_scanners, open_browser=not args.no_open)
            if watch_url:
                print(f"{CYAN}[WATCH]{RESET} Dashboard ao vivo: {GREEN}{watch_url}{RESET} "
                      f"{GREY}(local, nada sai do PC){RESET}")
                watch_cb = watch_server.push_scanner
            else:
                print(f"{YELLOW}[WATCH]{RESET} {GREY}Não consegui subir o servidor local — seguindo sem dashboard.{RESET}")
        except Exception as e:
            print(f"{YELLOW}[WATCH]{RESET} {GREY}Falhou: {e} — seguindo sem dashboard.{RESET}")

    if args.no_parallel:
        findings = run_scanners(chain, only=only_list, high_only=args.high_only)
        # Modo sequencial não streama incremental; empurra tudo de uma vez.
        if watch_cb:
            for i, r in enumerate(findings, 1):
                watch_cb(r, i, len(findings))
    else:
        findings = run_scanners_parallel(chain, only=only_list, max_workers=args.threads,
                                         high_only=args.high_only, on_result=watch_cb)

    # Aviso de cobertura: scanner que deu status="error" não contribuiu com a
    # fonte dele. Um "LIMPO" com fontes faltando é cobertura reduzida, não
    # inocência — o supervisor precisa saber. (Detalhes só com --verbose.)
    errored = [f for f in findings if f.get("status") == "error"]
    if errored:
        print(f"\n{YELLOW}[!]{RESET} {BOLD}{len(errored)} checagem(ns) falharam{RESET} "
              f"{GREY}— cobertura reduzida. Rode com --verbose pra ver o motivo.{RESET}")
        for f in errored:
            print(f"      {YELLOW}● {f.get('name', '?')}{RESET} {GREY}— {f.get('error', 'erro desconhecido')}{RESET}")

    # Filtro de falsos positivos (a menos que --strict)
    fp_stats = None
    if not args.strict:
        findings, fp_stats = fp_filter.post_process_findings(findings)
        print(f"\n{CYAN}[FP]{RESET} Filtro de falso-positivo: "
              f"{GREY}{fp_stats['items_whitelisted']} whitelistados, "
              f"{fp_stats['items_downgraded']} rebaixados "
              f"({fp_stats['total_items_in']} → {fp_stats['total_items_out']}){RESET}")
        if fp_stats['is_dev_env']:
            print(f"      {GREY}● Ambiente de dev detectado "
                  f"({len(fp_stats['dev_evidence'])} indicadores). "
                  f"Cheat Engine/IDA/etc serão LOW.{RESET}")

    # Redação de credenciais/tokens/emails antes de gerar relatório
    if not args.no_redact:
        findings, redacted_count = redaction.redact_findings(findings)
        if redacted_count:
            print(f"{CYAN}[RD]{RESET} Redação aplicada: "
                  f"{GREY}{redacted_count} campo(s) com credenciais/tokens/emails mascarados{RESET}")

    # PE analysis dos executáveis encontrados
    if not args.no_pe:
        print(f"{CYAN}[PE]{RESET} Analisando PE headers + hashes dos executáveis...", end=" ", flush=True)
        findings = pe_analysis.enrich_findings_with_pe(findings)
        enriched = sum(1 for f in findings for i in f["items"] if i.get("pe_info"))
        print(f"{GREEN}{enriched} executável(is) analisado(s){RESET}")

    # Cross-correlation legado (por keyword): mantido por compat com HTML atual
    high_confidence = cross_correlate(findings)
    if high_confidence:
        print(f"\n{RED}{BOLD}>>> CROSS-CORRELATION: ALTA CONFIANÇA <<<{RESET}")
        for kw, info in sorted(high_confidence.items(),
                                key=lambda kv: -len(kv[1]["sources"])):
            print(f"  {RED}● '{kw}'{RESET} {GREY}aparece em {len(info['sources'])} fontes:{RESET}")
            for src in info["sources"]:
                print(f"      {GREY}- {src}{RESET}")

    # Confidence Engine: agrupa evidências por target (executor/byovd/etc)
    # e gera veredictos por cluster. É o que vai protagonizar o relatório
    # novo. Aqui no console, mostramos só os clusters CONFIRMED e DETECTED
    # — os WEAK/SUSPECT ficam pro HTML.
    evidences = ev_engine.findings_to_evidences(findings)
    clusters  = ev_engine.build_clusters(evidences)
    cluster_summary = ev_engine.summarize_clusters(clusters)

    if cluster_summary["n_confirmed"] or cluster_summary["n_detected"]:
        print(f"\n{RED}{BOLD}>>> CONFIDENCE ENGINE: TARGETS DETECTADOS <<<{RESET}")
        for c in clusters:
            if c.verdict not in ("CONFIRMED", "DETECTED"):
                continue
            color = RED if c.verdict == "CONFIRMED" else YELLOW
            print(f"  {color}● [{c.verdict}]{RESET} {BOLD}{c.label}{RESET} "
                  f"{GREY}({c.kind}){RESET}  "
                  f"{color}{c.confidence_pct}%{RESET} confidence  "
                  f"{GREY}score={c.score:.1f} · {c.n_sources} fonte(s){RESET}")
            for src in sorted(c.sources):
                # 1 hit por fonte é o caso comum; se tiver mais, mostra contagem
                n = sum(1 for e in c.evidences if e.source == src)
                hint = f" ×{n}" if n > 1 else ""
                print(f"      {GREY}✓ {src}{hint}{RESET}")

    print_overview(findings)

    # Aviso CRÍTICO: scan sem admin que não achou nada é INCONCLUSIVO, não
    # "limpo". É o erro que mais confunde supervisor (cara parece inocente
    # mas o scan só não conseguiu ler as fontes boas).
    verdict_obj = fp_filter.compute_verdict(findings)
    if not running_as_admin and verdict_obj["verdict"] == "LIMPO":
        print(f"{RED}{BOLD}>>> ATENÇÃO: resultado INCONCLUSIVO, não 'limpo'.{RESET}")
        print(f"{YELLOW}    O scan rodou SEM admin — Prefetch/Amcache/BAM não foram lidos.{RESET}")
        print(f"{YELLOW}    'Nada encontrado' aqui NÃO inocenta. Rode de novo como admin.{RESET}\n")

    # 3. HTML report

    # Trava o veredito final no dashboard ao vivo (--watch). Os clusters
    # aqui já passaram pelo FP-filter, então substituem a prévia ao vivo.
    if watch_cb:
        try:
            import watch_server
            watch_server.finalize(clusters, verdict_obj)
        except Exception:
            pass

    html_path = report.generate_html_report(findings, sys_info,
                                             screenshots=screenshots,
                                             high_confidence=high_confidence,
                                             verdict=verdict_obj,
                                             fp_stats=fp_stats,
                                             clusters=clusters)
    print(f"{GREEN}✓ Relatório HTML:{RESET} {html_path}")

    json_path = None
    if args.json:
        json_path = save_json(findings, sys_info)
        print(f"{GREEN}✓ Relatório JSON:{RESET} {json_path}")

    # Markdown export
    if args.md:
        md_path = report_md.generate_markdown_report(
            findings, sys_info, verdict=verdict_obj, high_confidence=high_confidence
        )
        print(f"{GREEN}✓ Relatório Markdown:{RESET} {md_path}  {GREY}(colável no Discord){RESET}")

    # Salva .tsr (formato comparável + selo HMAC de integridade — detecta
    # adulteração casual, não é prova contra um forjador motivado; ver
    # report_signing.py)
    tsr_path = None
    if args.save_tsr:
        tsr_path = diff_tool.save_tsr(findings, sys_info, args.save_tsr)
        print(f"{GREEN}✓ Relatório .tsr:{RESET} {tsr_path}  {GREY}(selo HMAC de integridade){RESET}")

    # Diff contra .tsr anterior
    if args.diff:
        old_payload, err = diff_tool.load_tsr(args.diff)
        if err:
            print(f"{RED}Erro ao carregar diff: {err}{RESET}")
        else:
            new_payload = {"timestamp": datetime.now().isoformat(),
                           "system": sys_info, "findings": findings}
            diff = diff_tool.diff_reports(old_payload, new_payload)
            print(diff_tool.format_diff_console(diff))

    # 4. Abrir browser
    if not args.no_open:
        try:
            webbrowser.open(f"file:///{html_path}")
        except Exception as e:
            print(f"{YELLOW}Não consegui abrir no browser: {e}{RESET}")

    print(f"\n{GREY}Pressione ENTER para fechar...{RESET}")
    try:
        input()
    except (EOFError, KeyboardInterrupt):
        pass


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{GREY}Interrompido pelo usuário.{RESET}")
        sys.exit(1)
