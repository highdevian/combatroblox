"""
Gera relatório em Markdown pra colar direto no Discord.

Mantém só o essencial: veredito + cobertura + top hits / clusters.
"""

import os
import tempfile
from datetime import datetime

SEVERITY_EMOJI = {"critical": "🟣", "high": "🔴", "medium": "🟠", "low": "🟡"}


def _truncate(text, n=80):
    if not text:
        return ""
    text = str(text).replace("\n", " ").replace("`", "'")
    return text if len(text) <= n else text[: n - 3] + "..."


def generate_markdown_report(
    findings,
    sys_info,
    verdict=None,
    high_confidence=None,
    clusters=None,
    coverage=None,
    output_path=None,
):
    """Gera Markdown e retorna o path. Cap ~6KB pra caber em msg Discord."""
    if output_path is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(tempfile.gettempdir(), f"telador_{ts}.md")

    lines = []
    lines.append("# Telador — SS forense Roblox")
    lines.append("")

    if verdict:
        v = verdict.get("verdict", "?")
        score = verdict.get("score", 0)
        lines.append(f"## Veredito: **{v}** (score {score})")
        if verdict.get("inconclusive"):
            lines.append("")
            lines.append(
                f"> **INCONCLUSIVO:** {verdict.get('inconclusive_reason') or 'cobertura incompleta'}"
            )
    lines.append("")

    # Veredito staff 3-bullets — mesma mensagem do console/HTML (o que fecha SS)
    try:
        import report as _report_mod
        o_que, por_que, o_que_fazer = _report_mod.build_staff_verdict_bullets(
            clusters or [], verdict or {}, coverage)
        lines.append("### Veredito do staff")
        lines.append(f"- **O quê:** {o_que}")
        lines.append(f"- **Por quê:** {por_que}")
        lines.append(f"- **O que fazer:** {o_que_fazer}")
        lines.append("")
    except Exception:
        pass

    lines.append(
        f"- **Host:** `{sys_info.get('host', '?')}` · "
        f"**User:** `{sys_info.get('user', '?')}`"
    )
    lines.append(f"- **OS:** {sys_info.get('os', '?')}")
    lines.append(f"- **Scan:** {sys_info.get('scan_time', '?')}")
    lines.append(
        f"- **Admin:** {'sim' if sys_info.get('admin') else '**NÃO**'}"
    )
    if sys_info.get("session_code"):
        lines.append(f"- **Código SS:** `{sys_info.get('session_code')}`")
    if verdict and verdict.get("most_recent_hit"):
        lines.append(f"- **Hit mais recente:** `{verdict['most_recent_hit']}`")
    lines.append("")

    if coverage:
        lines.append("### Cobertura")
        lines.append(
            f"- scanners ok: **{coverage.get('n_ok', 0)}** · "
            f"erro: **{coverage.get('n_error', 0)}** · "
            f"total: **{coverage.get('total_scanners', 0)}**"
        )
        if coverage.get("sig_version"):
            lines.append(f"- assinaturas: `{coverage.get('sig_version')}`")
        for r in (coverage.get("reasons") or [])[:4]:
            lines.append(f"- ⚠ {r}")
        lines.append("")

    if verdict:
        lines.append("### Stats")
        lines.append(
            f"🟣 **{verdict.get('critical', 0)}** crit · "
            f"🔴 **{verdict.get('high', 0)}** high · "
            f"🟠 **{verdict.get('medium', 0)}** medium · "
            f"🟡 **{verdict.get('low', 0)}** low"
        )
        lines.append("")

    # Confidence Engine clusters
    actionable = []
    if clusters:
        actionable = [
            c
            for c in clusters
            if getattr(c, "verdict", "") in ("CONFIRMED", "DETECTED", "SUSPECT")
        ]
    if actionable:
        lines.append("## Confidence Engine")
        for c in actionable[:8]:
            srcs = ", ".join(sorted(c.sources)[:6])
            lines.append(
                f"- **{c.label}** `[{c.verdict} {c.confidence_pct}%]` — "
                f"{c.n_sources} fonte(s): {srcs}"
            )
        lines.append("")

    if high_confidence:
        lines.append("## Alta confiança (cross-correlation)")
        for kw, info in sorted(
            high_confidence.items(), key=lambda kv: -len(kv[1]["sources"])
        )[:8]:
            sources = ", ".join(info["sources"][:5])
            lines.append(
                f"- `{kw}` em **{len(info['sources'])}** fontes: {sources}"
            )
        lines.append("")

    findings_with_hits = [
        f
        for f in findings
        if f.get("status") != "error"
        and any(not i.get("meta_only") for i in f.get("items", []))
    ]
    if findings_with_hits:
        lines.append("## Findings (top)")
        lines.append("")
        for f in findings_with_hits[:12]:
            real = [i for i in f.get("items", []) if not i.get("meta_only")]
            lines.append(f"### {f['name']} ({len(real)} hits)")
            for item in real[:4]:
                sev = item.get("severity", "low")
                emoji = SEVERITY_EMOJI.get(sev, "⚪")
                ts = item.get("timestamp", "")
                ts_str = f" ({ts})" if ts else ""
                label = _truncate(item.get("label", ""), 80)
                matched = _truncate(item.get("matched", ""), 40)
                lines.append(
                    f"- {emoji} **{sev.upper()}** `{matched}` — {label}{ts_str}"
                )
            if len(real) > 4:
                lines.append(f"- *... +{len(real) - 4} hits*")
            lines.append("")
    elif not actionable:
        lines.append("## Nenhum hit acionável")
        if coverage and coverage.get("incomplete"):
            lines.append(
                "_Cobertura incompleta — não interprete como inocente._"
            )
        lines.append("")

    # Erros de scanner
    errored = [f for f in findings if f.get("status") == "error"]
    if errored:
        lines.append("## Checagens com erro")
        for f in errored[:8]:
            lines.append(
                f"- `{f.get('name', '?')}` — {_truncate(f.get('error', ''), 100)}"
            )
        lines.append("")

    lines.append("---")
    lines.append(
        "**Telador** · SS forense pra Roblox · 100% local · "
        "<https://github.com/highdevian/combatroblox>"
    )

    content = "\n".join(lines)
    if len(content) > 6000:
        content = content[:5900] + "\n\n*... (truncado — ver HTML)*"

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return output_path
