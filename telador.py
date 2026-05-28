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
import argparse
import tempfile
import threading
import webbrowser
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import scanners
import forensics
import antievasion
import persistence
import live_analysis
import command_history
import peripherals
import capture
import fp_filter
import pe_analysis
import report_signing
import diff_tool
import redaction
import report
import report_md


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
    print(f"{RED}{BANNER}{RESET}")
    print(f"{GREY}  Versão 3.3.0  ·  34 scanners  ·  Markdown export  ·  Quick mode{RESET}\n")
    self_hash = report_signing.get_self_hash()
    if self_hash:
        print(f"{GREY}  SHA256 deste exe: {self_hash[:16]}...{self_hash[-16:]}{RESET}")
        print(f"{GREY}  Compare com a release oficial no GitHub pra confirmar autenticidade.{RESET}\n")


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


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
    return {"high": RED, "medium": YELLOW, "low": MAGENTA}.get(sev, GREY)


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


def run_scanners_parallel(chain: list, only: list = None, max_workers: int = 4) -> list:
    """Roda scanners em paralelo (até max_workers ao mesmo tempo)."""
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
                for item in result["items"][:3]:
                    sev = item.get("severity", "low")
                    color = severity_to_color(sev)
                    print(f"      {color}● [{sev.upper()}]{RESET} {item['label']}  "
                          f"{GREY}→ match: {item['matched']}{RESET}")
                if len(result["items"]) > 3:
                    print(f"      {GREY}... +{len(result['items']) - 3} mais{RESET}")

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


def run_scanners(chain: list, only: list = None) -> list:
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

        for item in result["items"][:5]:
            sev = item.get("severity", "low")
            color = severity_to_color(sev)
            print(f"      {color}● [{sev.upper()}]{RESET} {item['label']}  "
                  f"{GREY}→ match: {item['matched']}{RESET}")
        if len(result["items"]) > 5:
            print(f"      {GREY}... +{len(result['items']) - 5} mais (ver relatório HTML){RESET}")

        findings.append(result)

    return findings


def print_overview(findings: list) -> None:
    verdict = fp_filter.compute_verdict(findings)

    print(f"\n{BOLD}═══════════════════════════════════════════════════════════════{RESET}")
    print(f"{BOLD}                            RESUMO{RESET}")
    print(f"{BOLD}═══════════════════════════════════════════════════════════════{RESET}\n")

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
    parser.add_argument("--no-pe",         action="store_true", help="Pula PE analysis dos executáveis")
    parser.add_argument("--save-tsr",      type=str, default=None, help="Salva relatório em .tsr (JSON+HMAC)")
    parser.add_argument("--diff",          type=str, default=None, help="Compara este SS com um .tsr anterior")
    parser.add_argument("--no-redact",     action="store_true", help="Desliga redação de credenciais/emails/tokens no relatório")
    parser.add_argument("--force-screenshot", action="store_true", help="Captura tela mesmo se gerenciador de senhas estiver aberto")
    parser.add_argument("--md",            action="store_true", help="Também salva relatório em Markdown (colável no Discord)")
    parser.add_argument("--quick",         action="store_true", help="Modo rápido: só scanners base (pula forensics/persistence/live/etc)")
    parser.add_argument("--no-parallel",   action="store_true", help="Rodar sequencial (debug)")
    parser.add_argument("--threads",       type=int, default=4, help="Threads em paralelo (default 4)")
    parser.add_argument("--json",          action="store_true", help="Também salvar relatório JSON")
    parser.add_argument("--strict-scripts",action="store_true",
                        help="Modo agressivo no scanner de scripts (.txt genérico também entra)")
    parser.add_argument("--only",          type=str, default=None,
                        help="Rodar só checagens específicas (separadas por vírgula)")
    args = parser.parse_args()

    print_banner()

    if not is_admin():
        print(f"{YELLOW}⚠  AVISO: Não está rodando como administrador.{RESET}")
        print(f"{GREY}   Cobertura limitada — Prefetch, Lixeira, Amcache, BAM, Defender vão falhar.{RESET}")
        print(f"{GREY}   Recomendado: botão direito → 'Executar como administrador'.{RESET}\n")

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

    if args.no_parallel:
        findings = run_scanners(chain, only=only_list)
    else:
        findings = run_scanners_parallel(chain, only=only_list, max_workers=args.threads)

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
        before_pe = sum(len(f["items"]) for f in findings)
        findings = pe_analysis.enrich_findings_with_pe(findings)
        enriched = sum(1 for f in findings for i in f["items"] if i.get("pe_info"))
        print(f"{GREEN}{enriched} executável(is) analisado(s){RESET}")

    # Cross-correlation: keywords que apareceram em 3+ fontes
    high_confidence = cross_correlate(findings)
    if high_confidence:
        print(f"\n{RED}{BOLD}>>> CROSS-CORRELATION: ALTA CONFIANÇA <<<{RESET}")
        for kw, info in sorted(high_confidence.items(),
                                key=lambda kv: -len(kv[1]["sources"])):
            print(f"  {RED}● '{kw}'{RESET} {GREY}aparece em {len(info['sources'])} fontes:{RESET}")
            for src in info["sources"]:
                print(f"      {GREY}- {src}{RESET}")

    print_overview(findings)

    # 3. HTML report
    verdict_obj = fp_filter.compute_verdict(findings)
    html_path = report.generate_html_report(findings, sys_info,
                                             screenshots=screenshots,
                                             high_confidence=high_confidence,
                                             verdict=verdict_obj,
                                             fp_stats=fp_stats)
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

    # Salva .tsr (formato comparável + assinado HMAC)
    tsr_path = None
    if args.save_tsr:
        tsr_path = diff_tool.save_tsr(findings, sys_info, args.save_tsr)
        print(f"{GREEN}✓ Relatório .tsr:{RESET} {tsr_path}  {GREY}(assinado HMAC){RESET}")

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
