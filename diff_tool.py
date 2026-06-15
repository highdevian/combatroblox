"""
Comparação entre 2 SS (.tsr).

Caso de uso: cara já foi telado antes? Veio com hits NOVOS desde a última SS?
Save em .tsr (JSON com HMAC). Reload, valida HMAC, compara.
"""

import json
from datetime import datetime

from report_signing import compute_hmac, verify_hmac


APP_VERSION = "3.36.2"


def save_tsr(findings: list, sys_info: dict, output_path: str) -> str:
    """Salva relatório em formato .tsr (JSON com HMAC)."""
    payload = {
        "version": APP_VERSION,
        "timestamp": datetime.now().isoformat(),
        "system": sys_info,
        "findings": findings,
    }
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    wrapper = {
        "signature": compute_hmac(body),
        "payload": payload,
    }
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(wrapper, fh, ensure_ascii=False, indent=2)
    return output_path


def load_tsr(path: str) -> tuple[dict | None, str | None]:
    """Carrega .tsr e verifica HMAC. Retorna (payload, erro_msg)."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            wrapper = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        return None, f"Não consegui ler: {e}"

    sig = wrapper.get("signature", "")
    payload = wrapper.get("payload", {})
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

    if not verify_hmac(body, sig):
        return None, "HMAC INVÁLIDO — relatório foi adulterado ou gerado em outra versão"
    return payload, None


def _item_key(item: dict) -> tuple:
    """Chave única dum item (pra detectar mesmo item entre 2 SS)."""
    return (
        item.get("matched", ""),
        item.get("label", "")[:120],
        item.get("detail", "")[:200],
    )


def diff_reports(old_payload: dict, new_payload: dict) -> dict:
    """Compara 2 .tsr. Retorna dict com added/removed/persistent."""
    def all_items(payload):
        out = {}
        for finding in payload.get("findings", []):
            for item in finding.get("items", []):
                k = _item_key(item)
                out[k] = (finding["name"], item)
        return out

    old_items = all_items(old_payload)
    new_items = all_items(new_payload)

    added     = [v for k, v in new_items.items() if k not in old_items]
    removed   = [v for k, v in old_items.items() if k not in new_items]
    persistent = [v for k, v in new_items.items() if k in old_items]

    return {
        "old_ts":      old_payload.get("timestamp", "?"),
        "new_ts":      new_payload.get("timestamp", "?"),
        "old_host":    old_payload.get("system", {}).get("host", "?"),
        "new_host":    new_payload.get("system", {}).get("host", "?"),
        "added":       added,
        "removed":     removed,
        "persistent":  persistent,
    }


def format_diff_console(diff: dict) -> str:
    """Formata diff pra exibir no console (com cores ANSI)."""
    RED, GREEN, YELLOW, GREY, RESET, BOLD = (
        "\033[91m", "\033[92m", "\033[93m", "\033[90m", "\033[0m", "\033[1m"
    )
    lines = []
    lines.append(f"\n{BOLD}═══════════════════════════════════════════════════════════════{RESET}")
    lines.append(f"{BOLD}                       DIFF ENTRE 2 SS{RESET}")
    lines.append(f"{BOLD}═══════════════════════════════════════════════════════════════{RESET}\n")
    lines.append(f"  {GREY}Antiga: {diff['old_ts']} ({diff['old_host']}){RESET}")
    lines.append(f"  {GREY}Nova:   {diff['new_ts']} ({diff['new_host']}){RESET}\n")

    lines.append(f"  {RED}+ {len(diff['added'])} hits NOVOS{RESET} (apareceram desde a última SS)")
    lines.append(f"  {GREEN}- {len(diff['removed'])} hits SUMIRAM{RESET}")
    lines.append(f"  {YELLOW}● {len(diff['persistent'])} hits PERSISTENTES{RESET}\n")

    if diff["added"]:
        lines.append(f"{RED}{BOLD}>>> NOVOS HITS (red flag){RESET}")
        for source, item in diff["added"][:20]:
            sev = item.get("severity", "low").upper()
            lines.append(f"  {RED}+{RESET} [{sev}] {source}: {item.get('label', '')} "
                          f"{GREY}→ {item.get('matched', '')}{RESET}")
        if len(diff["added"]) > 20:
            lines.append(f"  {GREY}... +{len(diff['added']) - 20} mais{RESET}")

    if diff["removed"]:
        lines.append(f"\n{GREEN}{BOLD}>>> HITS QUE SUMIRAM{RESET}")
        for source, item in diff["removed"][:10]:
            lines.append(f"  {GREEN}-{RESET} {source}: {item.get('label', '')}")
        if len(diff["removed"]) > 10:
            lines.append(f"  {GREY}... +{len(diff['removed']) - 10} mais{RESET}")

    if not diff["added"] and not diff["removed"]:
        lines.append(f"{GREEN}{BOLD}>>> Nenhuma mudança entre as 2 SS.{RESET}")

    return "\n".join(lines)
