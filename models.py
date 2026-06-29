import datetime

def _result(name: str, description: str, items: list, status: str = None, error: str = None) -> dict:
    # meta_only itens (headers como [PROCESSO], cabeçalhos de config como
    # [CONFIG] allowlist) NÃO são achados — são contexto. evidence.py e
    # fp_filter.py já pulam eles na agregação; aqui garantimos que o
    # status/summary do scanner também não os conte (senão um scanner sem
    # achados reais mas com header diz "1 item suspeito" e mente).
    real_items = [i for i in items if not i.get("meta_only")]

    if error:
        status = "error"
    elif status is None:
        status = "suspicious" if real_items else "clean"

    if error:
        summary = f"Erro: {error}"
    elif status == "clean":
        summary = "Nenhum vestígio encontrado"
    else:
        summary = f"{len(real_items)} item(s) suspeito(s)"

    return {
        "name": name,
        "description": description,
        "status": status,
        "items": items,
        "summary": summary,
        "error": error,
    }

def _item(label: str, detail: str, severity: str, matched: str, timestamp: str = "", meta_only: bool = False) -> dict:
    return {
        "label": label, 
        "detail": detail, 
        "severity": severity,
        "matched": matched, 
        "timestamp": timestamp, 
        "meta_only": meta_only,
    }

def _fmt_ts(ts: float) -> str:
    try:
        return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OSError, OverflowError, TypeError):
        return ""
