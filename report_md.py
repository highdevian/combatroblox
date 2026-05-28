"""
Gera relatório em Markdown pra colar direto no Discord.

Mantém só o essencial: veredito + score + top hits agrupados por fonte.
"""

import os
import tempfile
from datetime import datetime


SEVERITY_EMOJI = {"high": "🔴", "medium": "🟠", "low": "🟡"}


def _truncate(text, n=80):
    if not text:
        return ""
    text = str(text).replace("\n", " ").replace("`", "'")
    return text if len(text) <= n else text[:n - 3] + "..."


def generate_markdown_report(findings, sys_info,
                              verdict=None, high_confidence=None,
                              output_path=None):
    """Gera Markdown e retorna o path. Tamanho cap em ~6KB pra caber em msg Discord."""
    if output_path is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(tempfile.gettempdir(), f"telador_{ts}.md")

    lines = []
    lines.append("# 🎯 Relatório do Telador BR")
    lines.append("")

    if verdict:
        v = verdict.get("verdict", "?")
        score = verdict.get("score", 0)
        lines.append(f"## Veredito: **{v}** (score {score})")
    lines.append("")

    lines.append(f"- **Host:** `{sys_info.get('host', '?')}` · "
                 f"**User:** `{sys_info.get('user', '?')}`")
    lines.append(f"- **OS:** {sys_info.get('os', '?')}")
    lines.append(f"- **Scan:** {sys_info.get('scan_time', '?')}")
    if verdict and verdict.get("most_recent_hit"):
        lines.append(f"- **Hit mais recente:** `{verdict['most_recent_hit']}`")
    lines.append("")

    if verdict:
        lines.append(f"### Stats")
        lines.append(f"🔴 **{verdict.get('high', 0)}** high · "
                     f"🟠 **{verdict.get('medium', 0)}** medium · "
                     f"🟡 **{verdict.get('low', 0)}** low")
        lines.append("")

    # Cross-correlation
    if high_confidence:
        lines.append("## 🎯 Alta Confiança (Cross-correlation)")
        for kw, info in sorted(high_confidence.items(),
                               key=lambda kv: -len(kv[1]["sources"]))[:10]:
            sources = ", ".join(info["sources"][:5])
            lines.append(f"- `{kw}` apareceu em **{len(info['sources'])}** fontes: {sources}")
        lines.append("")

    # Findings agrupados (só os que têm items)
    findings_with_hits = [f for f in findings if f.get("items")]
    if findings_with_hits:
        lines.append("## Findings")
        lines.append("")
        for f in findings_with_hits:
            lines.append(f"### ⚠ {f['name']} ({len(f['items'])} hits)")
            for item in f["items"][:5]:
                sev = item.get("severity", "low")
                emoji = SEVERITY_EMOJI.get(sev, "⚪")
                ts = item.get("timestamp", "")
                ts_str = f" ({ts})" if ts else ""
                label = _truncate(item.get("label", ""), 80)
                matched = _truncate(item.get("matched", ""), 40)
                lines.append(f"- {emoji} **{sev.upper()}** `{matched}` — {label}{ts_str}")
            if len(f["items"]) > 5:
                lines.append(f"- *... +{len(f['items']) - 5} hits*")
            lines.append("")
    else:
        lines.append("## ✅ Nenhum hit encontrado")
        lines.append("")

    lines.append("---")
    lines.append("*Telador BR · 100% local · zero envio de dados*")

    content = "\n".join(lines)

    # Cap em ~6KB pra não estourar limite do Discord
    if len(content) > 6000:
        content = content[:5900] + "\n\n*... (truncado, ver HTML pra completo)*"

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return output_path
