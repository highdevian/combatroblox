"""
Gera um relatório HTML standalone (sem dependências externas, sem CDN).
Tudo inline pra funcionar offline e ser fácil de mandar pelo Discord.
"""

import os
import html
import base64
import tempfile
from datetime import datetime

try:
    import report_signing
    HAS_SIGNING = True
except ImportError:
    HAS_SIGNING = False


SEVERITY_COLORS = {
    "high":   "#ff4d4f",
    "medium": "#ffb020",
    "low":    "#ffe066",
}

STATUS_BADGE = {
    "clean":      ("LIMPO",     "#3fbf7f"),
    "suspicious": ("SUSPEITO",  "#ff4d4f"),
    "error":      ("ERRO/SKIP", "#888888"),
}


def _escape(s) -> str:
    return html.escape(str(s)) if s is not None else ""


def _render_section(finding: dict) -> str:
    name = _escape(finding["name"])
    desc = _escape(finding["description"])
    status = finding["status"]
    badge_text, badge_color = STATUS_BADGE.get(status, ("?", "#888"))
    summary = _escape(finding["summary"])

    rows = []
    sev_rank = {"high": 3, "medium": 2, "low": 1}
    for item in finding.get("items", []):
        sev = item.get("severity", "low")
        color = SEVERITY_COLORS.get(sev, "#888")
        conf = item.get("confidence")
        fp_reason = item.get("fp_reason")
        orig_sev = item.get("original_severity")

        downgrade_badge = ""
        if orig_sev and orig_sev != sev:
            downgrade_badge = (f'<span class="fp-badge" title="{_escape(fp_reason or "")}">'
                                f'↓ era {_escape(orig_sev.upper())}</span>')

        conf_html = ""
        if conf is not None:
            conf_color = "#3fbf7f" if conf >= 70 else ("#ffb020" if conf >= 40 else "#888")
            conf_html = (f'<div class="conf-bar"><div class="conf-fill" '
                          f'style="width:{conf}%; background:{conf_color}"></div>'
                          f'<span class="conf-val">{conf}</span></div>')

        detail_text = item.get('detail', '')
        if fp_reason:
            detail_text = f"{detail_text}\n[FP-filter: {fp_reason}]"

        ts_val = item.get('timestamp', '') or ''
        rows.append(f"""
        <tr class="row-{sev}" data-sev="{sev_rank.get(sev, 0)}" data-conf="{conf or 0}" data-ts="{_escape(ts_val)}">
            <td class="sev"><span class="sev-dot" style="background:{color}" aria-hidden="true"></span>{_escape(sev.upper())}{downgrade_badge}</td>
            <td class="label">{_escape(item.get('label', ''))}</td>
            <td class="detail"><code>{_escape(detail_text)}</code></td>
            <td class="match"><code>{_escape(item.get('matched', ''))}</code></td>
            <td class="conf">{conf_html}</td>
            <td class="ts"><time>{_escape(ts_val)}</time></td>
        </tr>""")

    if rows:
        table = f"""
        <table class="sortable">
            <thead>
                <tr>
                    <th class="sort-col" data-sort="sev" tabindex="0" role="button" aria-label="Ordenar por severidade">Severidade <span class="sort-indicator">↓</span></th>
                    <th class="sort-col" data-sort="label" tabindex="0" role="button" aria-label="Ordenar por item">Item</th>
                    <th>Detalhe</th>
                    <th class="sort-col" data-sort="match" tabindex="0" role="button" aria-label="Ordenar por match">Match</th>
                    <th class="sort-col" data-sort="conf" tabindex="0" role="button" aria-label="Ordenar por confidence">Conf.</th>
                    <th class="sort-col" data-sort="ts" tabindex="0" role="button" aria-label="Ordenar por data">Quando</th>
                </tr>
            </thead>
            <tbody>{''.join(rows)}</tbody>
        </table>
        """
    else:
        msg = finding.get("error") or "Nenhum vestígio encontrado nesta categoria."
        table = f'<p class="empty">{_escape(msg)}</p>'

    slug = finding["name"].lower().replace(" ", "-").replace("(", "").replace(")", "").replace("/", "-")
    n_items = len(finding.get("items", []))
    # Sections sem hits começam fechadas; com hits, abertas
    open_attr = " open" if n_items > 0 else ""
    return f"""
    <section class="card status-{status}" id="scan-{slug}">
        <details{open_attr}>
            <summary class="card-head">
                <h2>{name}</h2>
                <span class="badge" style="background:{badge_color}">{badge_text}</span>
            </summary>
            <p class="desc">{desc}</p>
            <p class="summary">{summary}</p>
            {table}
        </details>
    </section>
    """


def _render_system(info: dict) -> str:
    rows = "".join(
        f"<tr><th>{_escape(k)}</th><td>{_escape(v)}</td></tr>"
        for k, v in info.items()
    )
    return f"""
    <section class="card sysinfo">
        <h2>Informações do Sistema</h2>
        <table class="sys">{rows}</table>
    </section>
    """


def _render_summary(findings: list[dict], verdict: dict = None) -> str:
    total = sum(len(f["items"]) for f in findings)
    errors = sum(1 for f in findings if f["status"] == "error")

    if verdict is None:
        # Fallback: usa contagem simples se não passou verdict
        high = sum(1 for f in findings for i in f["items"] if i.get("severity") == "high")
        med  = sum(1 for f in findings for i in f["items"] if i.get("severity") == "medium")
        low  = sum(1 for f in findings for i in f["items"] if i.get("severity") == "low")
        verdict = {
            "verdict": "LIMPO" if not (high + med + low) else "REVISAR",
            "color": "#3fbf7f",
            "score": 0,
            "high": high, "medium": med, "low": low,
        }

    score_html = f'<div class="stat"><div class="num" style="color:{verdict["color"]}">{verdict["score"]}</div><div>Score</div></div>'
    recent = verdict.get("most_recent_hit") or "—"

    return f"""
    <section class="card overview">
        <h2>Resumo</h2>
        <div class="big-verdict" style="color:{verdict['color']}">{verdict['verdict']}</div>
        <div class="verdict-sub">Hit mais recente: <code>{_escape(recent)}</code></div>
        <div class="stats">
            <div class="stat"><div class="num" style="color:#ff4d4f">{verdict['high']}</div><div>High</div></div>
            <div class="stat"><div class="num" style="color:#ffb020">{verdict['medium']}</div><div>Medium</div></div>
            <div class="stat"><div class="num" style="color:#ffe066">{verdict['low']}</div><div>Low</div></div>
            {score_html}
            <div class="stat"><div class="num">{total}</div><div>Total</div></div>
            <div class="stat"><div class="num" style="color:#888">{errors}</div><div>Skips/Erros</div></div>
        </div>
    </section>
    """


def _render_fp_stats(fp_stats: dict) -> str:
    """Mostra info do filtro de falso-positivo se rodou."""
    if not fp_stats:
        return ""

    dev_note = ""
    if fp_stats.get("is_dev_env"):
        ev_list = "<br>".join(f"<code>{_escape(p)}</code>" for p in fp_stats["dev_evidence"][:5])
        dev_note = f"""
        <p><strong style="color:#ffb020">⚠ Ambiente de dev detectado.</strong>
        Ferramentas como Cheat Engine, IDA, dnSpy, etc. foram rebaixadas pra LOW
        (uso legítimo provável). Indicadores:</p>
        <div class="dev-evidence">{ev_list}</div>
        """

    return f"""
    <section class="card fp-stats">
        <h2>🛡️ Filtro de Falsos Positivos</h2>
        <p class="desc">Pós-processamento removeu/rebaixou hits prováveis-FP. Use <code>--strict</code> pra desligar.</p>
        <div class="stats">
            <div class="stat"><div class="num">{fp_stats['total_items_in']}</div><div>Hits brutos</div></div>
            <div class="stat"><div class="num" style="color:#3fbf7f">{fp_stats['items_whitelisted']}</div><div>Whitelistados</div></div>
            <div class="stat"><div class="num" style="color:#ffb020">{fp_stats['items_downgraded']}</div><div>Rebaixados</div></div>
            <div class="stat"><div class="num">{fp_stats['total_items_out']}</div><div>Finais</div></div>
        </div>
        {dev_note}
    </section>
    """


CSS = """
* { box-sizing: border-box; }
body {
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    background: #0e0e10; color: #e8e8e8; margin: 0; padding: 24px;
    font-size: 14px;
}
header { text-align: center; margin-bottom: 32px; }
header h1 {
    margin: 0; font-size: 36px; font-weight: 800;
    letter-spacing: 4px;
    background: linear-gradient(90deg, #ff4d4f 0%, #ffb020 50%, #ff4d4f 100%);
    -webkit-background-clip: text; background-clip: text; color: transparent;
}
header .sub { color: #888; margin-top: 6px; }
.card {
    background: #1a1a1d; border: 1px solid #2a2a2e; border-radius: 8px;
    padding: 20px; margin-bottom: 20px;
}
.card-head { display: flex; justify-content: space-between; align-items: center; gap: 12px; }
.card h2 { margin: 0; font-size: 18px; color: #fff; }
.desc { color: #888; margin: 4px 0 8px; font-size: 13px; }
.summary { color: #c0c0c0; margin: 4px 0 12px; font-weight: 600; }
.badge {
    padding: 4px 10px; border-radius: 4px; color: #000;
    font-weight: 700; font-size: 11px; letter-spacing: 1px;
}
.status-suspicious { border-color: #ff4d4f44; }
.status-suspicious h2::before { content: "⚠ "; color: #ff4d4f; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #2a2a2e; vertical-align: top; }
th { background: #232327; color: #aaa; font-weight: 600; text-transform: uppercase; font-size: 11px; }
tr.row-high { background: rgba(255, 77, 79, 0.06); }
tr.row-medium { background: rgba(255, 176, 32, 0.05); }
.sev { white-space: nowrap; font-weight: 700; font-size: 11px; }
.sev-dot {
    display: inline-block; width: 8px; height: 8px; border-radius: 50%;
    margin-right: 6px; vertical-align: middle;
}
code {
    background: #0a0a0c; padding: 2px 6px; border-radius: 3px;
    color: #ffb020; font-family: 'Consolas', 'Courier New', monospace; font-size: 12px;
    word-break: break-all;
}
.empty { color: #555; font-style: italic; margin: 8px 0; }
.sys th { width: 140px; }
.overview .big-verdict {
    text-align: center; font-size: 28px; font-weight: 800;
    letter-spacing: 2px; margin: 16px 0;
}
.stats { display: flex; gap: 16px; justify-content: center; flex-wrap: wrap; }
.stat {
    background: #0e0e10; border: 1px solid #2a2a2e; border-radius: 6px;
    padding: 14px 24px; min-width: 90px; text-align: center;
}
.stat .num { font-size: 24px; font-weight: 700; }
footer {
    text-align: center; color: #555; margin-top: 32px; font-size: 12px;
}
footer code { background: transparent; color: #888; }
"""


def _render_screenshots(screenshots: dict) -> str:
    """
    `screenshots` = {"desktop": "/path.png", "roblox": "/path.png" or None}
    Embed PNGs em base64 pra ficar tudo num arquivo único.
    """
    if not screenshots:
        return ""

    pieces = []
    label_map = {"desktop": "Desktop primário", "roblox": "Janela do Roblox"}
    for key, path in screenshots.items():
        if not path or not os.path.isfile(path):
            continue
        try:
            with open(path, "rb") as fh:
                b64 = base64.b64encode(fh.read()).decode("ascii")
        except OSError:
            continue

        if key.startswith("monitor_"):
            num = key.split("_", 1)[1]
            label = f"Monitor {num}"
        else:
            label = label_map.get(key, key)

        pieces.append(f"""
        <div class="shot">
            <div class="shot-label">{_escape(label)}</div>
            <img src="data:image/png;base64,{b64}" alt="{_escape(key)}" />
        </div>
        """)

    if not pieces:
        return ""

    return f"""
    <section class="card screenshots">
        <h2>Capturas de tela (no momento da SS)</h2>
        <p class="desc">Tiradas em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.
        Clique pra ampliar.</p>
        <div class="shots">{''.join(pieces)}</div>
    </section>
    """


def _render_timeline(findings: list) -> str:
    """Plota todos os hits com timestamp num gráfico horizontal."""
    items = []
    for f in findings:
        for item in f.get("items", []):
            ts_str = item.get("timestamp", "")
            if not ts_str:
                continue
            try:
                ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                continue
            items.append((ts, item, f["name"]))

    if not items:
        return ""

    items.sort(key=lambda x: x[0])
    min_ts = items[0][0]
    max_ts = items[-1][0]
    span = (max_ts - min_ts).total_seconds() or 1

    dots = []
    for ts, item, source in items:
        pos = (ts - min_ts).total_seconds() / span * 100
        sev = item.get("severity", "low")
        color = SEVERITY_COLORS.get(sev, "#888")
        tip = f"{ts.strftime('%Y-%m-%d %H:%M')} · {source}\n{item.get('label', '')}\nmatch: {item.get('matched', '')}"
        dots.append(f'<div class="tl-dot row-{sev}" style="left:{pos:.2f}%; background:{color}" title="{_escape(tip)}"></div>')

    duration = max_ts - min_ts
    duration_str = (
        f"{duration.days}d" if duration.days >= 1
        else f"{duration.seconds // 3600}h {(duration.seconds % 3600) // 60}m"
        if duration.seconds >= 3600
        else f"{duration.seconds // 60}m"
    )

    return f"""
    <section class="card timeline">
        <h2>🕐 Timeline de Atividade ({len(items)} hits)</h2>
        <p class="desc">Cada ponto = 1 hit. Cluster denso = burst suspeito (ex: baixou cheat,
        rodou, deletou tudo em 5 min).</p>
        <div class="tl-range">
            <span>{min_ts.strftime('%Y-%m-%d %H:%M')}</span>
            <span style="color:#888">← {duration_str} →</span>
            <span>{max_ts.strftime('%Y-%m-%d %H:%M')}</span>
        </div>
        <div class="tl-track">{''.join(dots)}</div>
    </section>
    """


def _render_pe_section(findings: list) -> str:
    """Section dedicada a PE analysis dos executáveis encontrados."""
    pe_items = []
    for f in findings:
        for item in f.get("items", []):
            if item.get("pe_info"):
                pe_items.append((f["name"], item))

    if not pe_items:
        return ""

    rows = []
    for source, item in pe_items:
        info = item["pe_info"]
        pe = info.get("pe", {})
        sha = info.get("sha256") or ""
        hash_match = info.get("hash_match")
        packed = pe.get("is_packed")
        packer = pe.get("packer_name")
        compile_ts = pe.get("compile_timestamp", "—")
        machine = pe.get("machine", "?")
        sections = ", ".join(pe.get("sections", [])[:8])

        flags = []
        if hash_match:
            flags.append(f'<span class="pe-flag pe-flag-high">HASH MATCH: {_escape(hash_match)}</span>')
        if packed:
            flags.append(f'<span class="pe-flag pe-flag-high">PACKED ({_escape(packer or "?")})</span>')

        rows.append(f"""
        <tr>
            <td><code>{_escape(os.path.basename(info.get('path', '')))}</code></td>
            <td><code style="font-size:10px">{_escape(sha[:32] + '...' if sha else '?')}</code></td>
            <td>{_escape(compile_ts)}</td>
            <td>{_escape(machine)}</td>
            <td><code style="font-size:11px">{_escape(sections)}</code></td>
            <td>{''.join(flags) or '<span style="color:#888">—</span>'}</td>
        </tr>""")

    return f"""
    <section class="card pe-analysis">
        <h2>🔬 PE Analysis ({len(pe_items)} executáveis)</h2>
        <p class="desc">SHA256 + PE header dos .exe/.dll suspeitos. Packed/compile date recente = red flag.</p>
        <table>
            <thead><tr><th>Arquivo</th><th>SHA256</th><th>Compilado</th><th>Arch</th><th>Sections</th><th>Flags</th></tr></thead>
            <tbody>{''.join(rows)}</tbody>
        </table>
    </section>
    """


LOGO_SVG = """
<svg viewBox="0 0 64 64" class="brand-logo" xmlns="http://www.w3.org/2000/svg">
    <defs>
        <linearGradient id="brandGrad" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stop-color="#ff4d4f"/>
            <stop offset="0.5" stop-color="#ff7a3f"/>
            <stop offset="1" stop-color="#ffb020"/>
        </linearGradient>
        <filter id="glow"><feGaussianBlur stdDeviation="1.5"/></filter>
    </defs>
    <path d="M32 4 L56 14 L56 34 Q56 50 32 60 Q8 50 8 34 L8 14 Z"
          fill="url(#brandGrad)" stroke="#0e0e10" stroke-width="0.5"/>
    <circle cx="26" cy="28" r="9" fill="none" stroke="#0e0e10" stroke-width="3"/>
    <line x1="33" y1="35" x2="42" y2="44" stroke="#0e0e10" stroke-width="3" stroke-linecap="round"/>
    <text x="32" y="56" font-size="6" font-weight="800" fill="#0e0e10"
          text-anchor="middle" font-family="Inter, system-ui, sans-serif"
          letter-spacing="1.5">TELADOR</text>
</svg>
"""


def _render_sidebar(findings: list, verdict: dict = None) -> str:
    """Sidebar sticky com TOC e contador por section."""
    links = [
        ('summary', '📊 Resumo', None),
        ('high-confidence', '🎯 Cross-Correlation', None),
        ('fp-stats', '🛡️ FP Filter', None),
        ('timeline', '🕐 Timeline', None),
        ('pe-analysis', '🔬 PE Analysis', None),
        ('charts', '📈 Charts', None),
        ('sysinfo', '💻 Sistema', None),
        ('screenshots', '📸 Screenshots', None),
    ]
    main_links = "".join(
        f'<a href="#{anchor}" class="nav-link">{label}</a>'
        for anchor, label, _ in links
    )

    scanner_links = []
    for f in findings:
        n_items = len(f.get("items", []))
        slug = f["name"].lower().replace(" ", "-").replace("(", "").replace(")", "").replace("/", "-")
        # Mini-mapa: dot mostra pior severidade da section
        items = f.get("items", [])
        worst = "none"
        if any(i.get("severity") == "high" for i in items):
            worst = "high"
        elif any(i.get("severity") == "medium" for i in items):
            worst = "medium"
        elif any(i.get("severity") == "low" for i in items):
            worst = "low"
        mini_dot = f'<span class="mini-sev mini-{worst}" aria-hidden="true"></span>'
        if n_items > 0:
            badge = f'<span class="nav-badge">{n_items}</span>'
            scanner_links.append(f'<a href="#scan-{slug}" class="nav-link nav-hit">{mini_dot}<span class="nav-link-label">{_escape(f["name"])}</span>{badge}</a>')
        else:
            scanner_links.append(f'<a href="#scan-{slug}" class="nav-link nav-clean">{mini_dot}<span class="nav-link-label">{_escape(f["name"])}</span></a>')

    score_badge = ""
    if verdict:
        score_badge = f'<div class="nav-score" style="background:{verdict.get("color", "#888")}">' \
                       f'Score {verdict.get("score", 0)}</div>'

    return f"""
    <aside class="sidebar">
        <div class="sidebar-head">
            <div class="brand-row">{LOGO_SVG}<h3>TELADOR BR</h3></div>
            {score_badge}
        </div>
        <nav class="sidebar-nav">
            <div class="nav-group">
                <div class="nav-group-title">Visão geral</div>
                {main_links}
            </div>
            <div class="nav-group">
                <div class="nav-group-title">Scanners ({len(findings)})</div>
                {''.join(scanner_links)}
            </div>
        </nav>
    </aside>
    """


def _render_charts(findings: list, verdict: dict) -> str:
    """Donut do score + bar chart de hits por scanner."""
    if not verdict:
        return ""

    high = verdict.get("high", 0)
    med = verdict.get("medium", 0)
    low = verdict.get("low", 0)
    total = max(1, high + med + low)

    # Donut chart com SVG inline (stroke-dasharray)
    circumference = 2 * 3.14159 * 50  # raio 50
    high_pct = high / total
    med_pct = med / total
    low_pct = low / total
    high_dash = circumference * high_pct
    med_dash = circumference * med_pct
    low_dash = circumference * low_pct

    donut = f"""
    <div class="chart-card">
        <h3>Distribuição de Severidade</h3>
        <svg viewBox="0 0 140 140" class="donut">
            <circle cx="70" cy="70" r="50" fill="none" stroke="#2a2a2e" stroke-width="14"/>
            <circle cx="70" cy="70" r="50" fill="none" stroke="#ff4d4f" stroke-width="14"
                stroke-dasharray="{high_dash:.1f} {circumference:.1f}" transform="rotate(-90 70 70)"/>
            <circle cx="70" cy="70" r="50" fill="none" stroke="#ffb020" stroke-width="14"
                stroke-dasharray="{med_dash:.1f} {circumference:.1f}"
                stroke-dashoffset="{-high_dash:.1f}" transform="rotate(-90 70 70)"/>
            <circle cx="70" cy="70" r="50" fill="none" stroke="#ffe066" stroke-width="14"
                stroke-dasharray="{low_dash:.1f} {circumference:.1f}"
                stroke-dashoffset="{-(high_dash + med_dash):.1f}" transform="rotate(-90 70 70)"/>
            <text x="70" y="68" text-anchor="middle" fill="{verdict.get('color', '#fff')}"
                font-size="22" font-weight="800">{verdict.get('score', 0)}</text>
            <text x="70" y="86" text-anchor="middle" fill="#888" font-size="10">SCORE</text>
        </svg>
        <div class="donut-legend">
            <span><span class="dot" style="background:#ff4d4f"></span> High {high}</span>
            <span><span class="dot" style="background:#ffb020"></span> Medium {med}</span>
            <span><span class="dot" style="background:#ffe066"></span> Low {low}</span>
        </div>
    </div>
    """

    # Bar chart top scanners
    scanner_counts = [(f["name"], len(f.get("items", []))) for f in findings]
    scanner_counts = [(n, c) for n, c in scanner_counts if c > 0]
    scanner_counts.sort(key=lambda x: -x[1])
    top = scanner_counts[:10]
    max_c = max((c for _, c in top), default=1)

    bars = "".join(
        f'<div class="bar-row">'
        f'<span class="bar-label">{_escape(name)}</span>'
        f'<div class="bar-track"><div class="bar-fill" style="width:{(c/max_c)*100:.1f}%"></div></div>'
        f'<span class="bar-count">{c}</span>'
        f'</div>'
        for name, c in top
    )
    bar_chart = f"""
    <div class="chart-card">
        <h3>Hits por Scanner (top {len(top)})</h3>
        <div class="bars">{bars or '<p class="empty">Sem hits</p>'}</div>
    </div>
    """

    return f"""
    <section class="card charts" id="charts">
        <h2>📈 Visualizações</h2>
        <div class="charts-grid">
            {donut}
            {bar_chart}
        </div>
    </section>
    """


def _render_empty_state() -> str:
    """Sistema limpo — SVG vector, sem emoji."""
    return """
    <section class="card empty-state" aria-label="Sistema limpo">
        <svg class="empty-svg" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
            <circle cx="32" cy="32" r="28" fill="none" stroke="#3fbf7f" stroke-width="2" opacity="0.4"/>
            <circle cx="32" cy="32" r="22" fill="none" stroke="#3fbf7f" stroke-width="1.5" opacity="0.25"/>
            <path d="M20 33 L29 42 L45 25" fill="none" stroke="#3fbf7f"
                  stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        <h2>Sistema limpo</h2>
        <p>Nenhum hit nas categorias de detecção. Este sistema não apresenta
        indícios de executores Roblox conhecidos, scripts de exploit,
        ou ferramentas de cheating.</p>
        <p class="empty-sub">Detecção é heurística — cheat novo ou renomeado pode escapar.
        Conduza SS visual também.</p>
    </section>
    """


def _render_high_confidence(high_confidence: dict) -> str:
    """Section destacada com keywords que aparecem em 3+ fontes."""
    if not high_confidence:
        return ""

    rows = []
    sorted_kws = sorted(
        high_confidence.items(),
        key=lambda kv: -len(kv[1]["sources"]),
    )
    for kw, info in sorted_kws:
        sources_str = ", ".join(_escape(s) for s in info["sources"])
        sev = info.get("worst_severity", "high")
        color = SEVERITY_COLORS.get(sev, "#ff4d4f")
        rows.append(f"""
        <tr>
            <td class="hc-kw"><code style="color:{color}; font-weight:700">{_escape(kw)}</code></td>
            <td class="hc-count">{len(info['sources'])} fontes</td>
            <td class="hc-sources">{sources_str}</td>
        </tr>""")

    return f"""
    <section class="card high-confidence">
        <div class="card-head">
            <h2>🎯 Cross-Correlation — ALTA CONFIANÇA</h2>
            <span class="badge" style="background:#ff4d4f">CHEATER</span>
        </div>
        <p class="desc">Keywords que apareceram em 3+ categorias diferentes. Praticamente
        impossível ser falso positivo — cara tentou apagar mas deixou rastro em várias fontes.</p>
        <table>
            <thead>
                <tr>
                    <th>Keyword</th>
                    <th>Cobertura</th>
                    <th>Onde apareceu</th>
                </tr>
            </thead>
            <tbody>{''.join(rows)}</tbody>
        </table>
    </section>
    """


def _render_controls() -> str:
    """Barra de search, filtros, e ações em massa."""
    return """
    <section class="card controls" role="search">
        <div class="controls-row">
            <label for="search" class="sr-only">Buscar nos hits</label>
            <input type="text" id="search"
                   placeholder="Buscar (krnl, wave, .lua, downloads...)   ·   atalho: /"
                   aria-label="Buscar nos hits" />
            <div class="filters" role="group" aria-label="Filtrar por severidade">
                <button class="filter-btn" data-sev="high"   aria-pressed="true" style="--c:#ff4d4f">High</button>
                <button class="filter-btn" data-sev="medium" aria-pressed="true" style="--c:#ffb020">Medium</button>
                <button class="filter-btn" data-sev="low"    aria-pressed="true" style="--c:#ffe066">Low</button>
                <button id="show-all" class="filter-btn solid">Reset</button>
                <span class="control-divider" aria-hidden="true"></span>
                <button id="expand-all"   class="filter-btn ghost" type="button">Expandir tudo</button>
                <button id="collapse-all" class="filter-btn ghost" type="button">Recolher</button>
            </div>
        </div>
        <div class="controls-meta" aria-live="polite">
            <span id="visible-count"></span>
            <span class="kbd-hint">
                <kbd>/</kbd> buscar · <kbd>J</kbd>/<kbd>K</kbd> próximo/anterior · <kbd>Esc</kbd> limpar
            </span>
        </div>
    </section>
    """


CONTROLS_JS = """
<script>
(function() {
    const search = document.getElementById('search');
    const filters = {high: true, medium: true, low: true};

    function applyAll() {
        document.querySelectorAll('tbody tr').forEach(tr => {
            // Filtro de severidade
            let sevOk = false;
            for (const sev of Object.keys(filters)) {
                if (tr.classList.contains('row-' + sev) && filters[sev]) {
                    sevOk = true; break;
                }
            }
            if (!tr.classList.contains('row-high') && !tr.classList.contains('row-medium') && !tr.classList.contains('row-low')) {
                sevOk = true;  // linhas sem severidade (system info, high-conf) sempre visíveis
            }

            // Filtro de search
            const q = (search.value || '').toLowerCase();
            const textOk = !q || tr.textContent.toLowerCase().includes(q);

            tr.style.display = (sevOk && textOk) ? '' : 'none';
        });

        // Esconde cards que ficaram sem linhas visíveis
        document.querySelectorAll('section.card').forEach(card => {
            const tbody = card.querySelector('tbody');
            if (!tbody) return;
            if (card.classList.contains('overview') || card.classList.contains('sysinfo')
                || card.classList.contains('screenshots') || card.classList.contains('controls')
                || card.classList.contains('high-confidence')) return;
            const visible = Array.from(tbody.querySelectorAll('tr')).some(tr => tr.style.display !== 'none');
            card.style.display = visible ? '' : 'none';
        });
    }

    search.addEventListener('input', applyAll);

    document.querySelectorAll('.filter-btn[data-sev]').forEach(btn => {
        btn.addEventListener('click', () => {
            const sev = btn.dataset.sev;
            filters[sev] = !filters[sev];
            btn.classList.toggle('off', !filters[sev]);
            applyAll();
        });
    });

    document.getElementById('show-all').addEventListener('click', () => {
        for (const k of Object.keys(filters)) filters[k] = true;
        document.querySelectorAll('.filter-btn[data-sev]').forEach(b => b.classList.remove('off'));
        search.value = '';
        applyAll();
    });

    // Click pra copiar em code blocks (com toast)
    function showToast(msg) {
        const t = document.createElement('div');
        t.className = 'toast'; t.textContent = msg;
        document.body.appendChild(t);
        setTimeout(() => t.remove(), 1600);
    }
    document.querySelectorAll('code').forEach(c => {
        c.style.cursor = 'pointer';
        c.title = 'Clique pra copiar';
        c.addEventListener('click', (e) => {
            if (e.target.closest('.lightbox')) return;
            navigator.clipboard.writeText(c.textContent).then(() => {
                showToast('✓ Copiado');
            }).catch(() => {});
        });
    });

    // === Lightbox pra screenshots ===
    const lb = document.createElement('div');
    lb.className = 'lightbox';
    lb.innerHTML = '<button class="lightbox-close" aria-label="Fechar">✕</button>' +
                   '<img alt="" />' +
                   '<div class="lightbox-hint">Clique fora ou ESC pra fechar</div>';
    document.body.appendChild(lb);
    const lbImg = lb.querySelector('img');
    const lbClose = lb.querySelector('.lightbox-close');

    function openLightbox(src, alt) {
        lbImg.src = src;
        lbImg.alt = alt || '';
        lb.classList.add('active');
        document.body.style.overflow = 'hidden';
    }
    function closeLightbox() {
        lb.classList.remove('active');
        document.body.style.overflow = '';
    }
    lb.addEventListener('click', (e) => {
        if (e.target === lb || e.target === lbClose) closeLightbox();
    });
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeLightbox();
    });

    document.querySelectorAll('.screenshots img').forEach(img => {
        img.style.cursor = 'zoom-in';
        img.addEventListener('click', () => openLightbox(img.src, img.alt));
    });

    // === Number counter pros stats ===
    function animateNumber(el, target, duration = 1000) {
        const start = performance.now();
        const startVal = 0;
        function tick(now) {
            const elapsed = now - start;
            const progress = Math.min(elapsed / duration, 1);
            // easeOutCubic
            const eased = 1 - Math.pow(1 - progress, 3);
            const current = startVal + (target - startVal) * eased;
            el.textContent = Number.isInteger(target)
                ? Math.round(current)
                : current.toFixed(1);
            if (progress < 1) requestAnimationFrame(tick);
            else el.textContent = target;
        }
        requestAnimationFrame(tick);
    }

    document.querySelectorAll('.stat .num').forEach(el => {
        const raw = el.textContent.trim();
        const target = parseFloat(raw);
        if (isNaN(target)) return;
        // Aguarda animação de entrada terminar antes do counter
        setTimeout(() => animateNumber(el, target, 1200), 300);
    });

    // === Scroll reveal pra sections fora da viewport inicial ===
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.animation = 'fadeUp 0.6s cubic-bezier(0.16, 1, 0.3, 1) both';
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.1, rootMargin: '0px 0px -80px 0px' });

    // Observa cards que entram via scroll (não os primeiros 6 que já animam no load)
    document.querySelectorAll('.main-content > .card').forEach((card, i) => {
        if (i < 6) return;
        card.style.opacity = '0';
        observer.observe(card);
    });

    // ============== Filtered counter ==============
    function updateVisibleCount() {
        const all = document.querySelectorAll('tbody tr');
        const visible = Array.from(all).filter(tr => {
            const display = window.getComputedStyle(tr).display;
            return display !== 'none';
        }).length;
        const el = document.getElementById('visible-count');
        if (el) {
            el.textContent = all.length === visible
                ? `${all.length.toLocaleString('pt-BR')} hits`
                : `${visible.toLocaleString('pt-BR')} de ${all.length.toLocaleString('pt-BR')} hits visíveis`;
        }
    }
    updateVisibleCount();
    // Hook nas mudanças de filtro
    const originalSearch = search;
    if (originalSearch) {
        originalSearch.addEventListener('input', () => setTimeout(updateVisibleCount, 0));
    }
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', () => setTimeout(updateVisibleCount, 0));
    });

    // ============== Expand / Collapse all ==============
    function setAllDetails(open) {
        document.querySelectorAll('section.card details').forEach(d => d.open = open);
    }
    const expandBtn = document.getElementById('expand-all');
    const collapseBtn = document.getElementById('collapse-all');
    if (expandBtn) expandBtn.addEventListener('click', () => setAllDetails(true));
    if (collapseBtn) collapseBtn.addEventListener('click', () => setAllDetails(false));

    // ============== Column sort ==============
    function sortTable(table, colKey, asc) {
        const tbody = table.querySelector('tbody');
        if (!tbody) return;
        const rows = Array.from(tbody.querySelectorAll('tr'));
        const getKey = (row) => {
            if (colKey === 'sev')  return parseInt(row.dataset.sev || '0', 10);
            if (colKey === 'conf') return parseInt(row.dataset.conf || '0', 10);
            if (colKey === 'ts')   return row.dataset.ts || '';
            // label / match: pega texto da td correspondente
            const idx = { label: 1, match: 3 }[colKey];
            return row.children[idx]?.textContent.trim().toLowerCase() || '';
        };
        rows.sort((a, b) => {
            const ka = getKey(a), kb = getKey(b);
            if (typeof ka === 'number') return asc ? ka - kb : kb - ka;
            return asc ? ka.localeCompare(kb) : kb.localeCompare(ka);
        });
        rows.forEach(r => tbody.appendChild(r));
    }

    document.querySelectorAll('table.sortable').forEach(table => {
        const headers = table.querySelectorAll('th.sort-col');
        headers.forEach(th => {
            const action = () => {
                const key = th.dataset.sort;
                const wasAsc = th.classList.contains('sort-asc');
                headers.forEach(h => h.classList.remove('sort-active', 'sort-asc'));
                th.classList.add('sort-active');
                if (!wasAsc) th.classList.add('sort-asc');
                sortTable(table, key, !wasAsc);
            };
            th.addEventListener('click', action);
            th.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    action();
                }
            });
        });
    });

    // ============== Keyboard navigation ==============
    let currentCardIdx = -1;
    const cardsWithHits = Array.from(document.querySelectorAll('section.card[id^="scan-"]'))
        .filter(c => c.querySelector('tbody tr'));

    function scrollToCard(idx) {
        if (idx < 0 || idx >= cardsWithHits.length) return;
        currentCardIdx = idx;
        const card = cardsWithHits[idx];
        const details = card.querySelector('details');
        if (details) details.open = true;
        card.scrollIntoView({ behavior: 'smooth', block: 'start' });
        // Highlight curto
        card.style.transition = 'outline 0.4s';
        card.style.outline = '2px solid rgba(255,77,79,0.4)';
        card.style.outlineOffset = '2px';
        setTimeout(() => { card.style.outline = ''; }, 800);
    }

    document.addEventListener('keydown', (e) => {
        // Skip se em input/textarea
        if (e.target.matches('input, textarea')) {
            // Esc no search reseta
            if (e.key === 'Escape' && e.target.id === 'search') {
                e.target.value = '';
                e.target.dispatchEvent(new Event('input'));
                e.target.blur();
            }
            return;
        }
        if (e.key === '/' && !e.ctrlKey && !e.metaKey) {
            e.preventDefault();
            const s = document.getElementById('search');
            if (s) { s.focus(); s.select(); }
        } else if (e.key === 'j' || e.key === 'J') {
            e.preventDefault();
            scrollToCard(Math.min(currentCardIdx + 1, cardsWithHits.length - 1));
        } else if (e.key === 'k' || e.key === 'K') {
            e.preventDefault();
            scrollToCard(Math.max(currentCardIdx - 1, 0));
        } else if (e.key === 'Escape') {
            // Reset filters
            const showAll = document.getElementById('show-all');
            if (showAll) showAll.click();
        } else if (e.key === 'e' || e.key === 'E') {
            // E expand all, Shift+E collapse
            if (e.shiftKey) setAllDetails(false);
            else setAllDetails(true);
        }
    });
})();
</script>
"""


def generate_html_report(findings: list[dict], sys_info: dict,
                          screenshots: dict = None,
                          high_confidence: dict = None,
                          verdict: dict = None,
                          fp_stats: dict = None,
                          output_path: str = None) -> str:
    """Gera HTML e retorna o caminho do arquivo salvo."""
    if output_path is None:
        ts_tag = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(
            tempfile.gettempdir(),
            f"telador_relatorio_{ts_tag}.html",
        )

    summary_html = _render_summary(findings, verdict)
    fp_html = _render_fp_stats(fp_stats or {})
    sys_html = _render_system(sys_info)
    screens_html = _render_screenshots(screenshots or {})
    hc_html = _render_high_confidence(high_confidence or {})
    timeline_html = _render_timeline(findings)
    pe_html = _render_pe_section(findings)
    controls_html = _render_controls()
    charts_html = _render_charts(findings, verdict or {})
    sidebar_html = _render_sidebar(findings, verdict)
    sections = "\n".join(_render_section(f) for f in findings)

    # Empty state quando ZERO hits totais
    total_hits = sum(len(f.get("items", [])) for f in findings)
    empty_html = _render_empty_state() if total_hits == 0 else ""

    # Banner com hash do exe
    exe_hash = ""
    if HAS_SIGNING:
        h = report_signing.get_self_hash()
        if h:
            exe_hash = f'<div class="exe-hash">SHA256 do telador: <code>{h}</code></div>'

    extra_css = """
    .screenshots .shots { display: flex; flex-wrap: wrap; gap: 16px; margin-top: 12px; }
    .screenshots .shot { flex: 1 1 480px; max-width: 100%; }
    .screenshots .shot-label { color: #aaa; font-size: 12px; margin-bottom: 4px; }
    .screenshots img {
        max-width: 100%; height: auto; border: 1px solid #2a2a2e;
        border-radius: 6px; cursor: zoom-in; transition: transform .15s;
    }
    .screenshots img:hover { transform: scale(1.02); }

    .high-confidence {
        border: 2px solid #ff4d4f; box-shadow: 0 0 24px rgba(255, 77, 79, 0.2);
    }
    .high-confidence h2 { color: #ff4d4f; }
    .hc-count { color: #ffb020; font-weight: 700; white-space: nowrap; }
    .hc-sources { color: #aaa; font-size: 12px; }

    .controls { position: sticky; top: 0; z-index: 50; }
    .controls-row { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
    .controls input {
        flex: 1; min-width: 260px;
        background: #0e0e10; border: 1px solid #2a2a2e; color: #e8e8e8;
        padding: 10px 14px; border-radius: 6px; font-size: 14px;
        font-family: inherit;
    }
    .controls input:focus { outline: none; border-color: #ff4d4f; }
    .filters { display: flex; gap: 6px; }
    .filter-btn {
        background: var(--c, #444); color: #000; border: none;
        padding: 8px 14px; border-radius: 6px; font-weight: 700;
        cursor: pointer; font-size: 12px; transition: opacity .15s;
    }
    .filter-btn:hover { opacity: 0.85; }
    .filter-btn.off { opacity: 0.3; }
    .filter-btn.solid { background: #2a2a2e; color: #e8e8e8; }

    .fp-badge {
        display: inline-block; margin-left: 6px;
        background: #ffb020; color: #000;
        padding: 1px 6px; border-radius: 3px;
        font-size: 9px; font-weight: 700;
        cursor: help;
    }
    .conf-bar {
        position: relative; width: 60px; height: 14px;
        background: #0a0a0c; border-radius: 3px; overflow: hidden;
    }
    .conf-fill {
        height: 100%; transition: width .3s;
    }
    .conf-val {
        position: absolute; top: 0; left: 0; width: 100%;
        text-align: center; font-size: 10px; line-height: 14px;
        color: #fff; font-weight: 700;
        text-shadow: 0 0 2px #000;
    }
    .verdict-sub {
        text-align: center; color: #888; margin: -8px 0 16px;
        font-size: 13px;
    }
    .fp-stats { border-left: 4px solid #3fbf7f; }
    .dev-evidence {
        background: #0a0a0c; padding: 10px; border-radius: 6px;
        margin-top: 8px; font-size: 12px;
    }
    .timeline .tl-range {
        display: flex; justify-content: space-between;
        color: #aaa; font-size: 12px; margin: 8px 0 4px;
    }
    .timeline .tl-track {
        position: relative; height: 48px;
        background: linear-gradient(90deg, #1a1a1d, #2a2a2e, #1a1a1d);
        border-radius: 24px; margin: 6px 0 12px;
        border: 1px solid #2a2a2e;
    }
    .timeline .tl-dot {
        position: absolute; top: 50%; transform: translate(-50%, -50%);
        width: 12px; height: 12px; border-radius: 50%;
        cursor: help; box-shadow: 0 0 8px currentColor;
        transition: transform .15s, box-shadow .15s;
    }
    .timeline .tl-dot:hover {
        transform: translate(-50%, -50%) scale(2);
        z-index: 10;
        box-shadow: 0 0 16px currentColor;
    }
    .pe-analysis { border-left: 4px solid #ffb020; }
    .pe-flag {
        display: inline-block; padding: 2px 8px; border-radius: 3px;
        font-size: 10px; font-weight: 700; margin-right: 4px;
    }
    .pe-flag-high { background: #ff4d4f; color: #000; }
    .exe-hash {
        text-align: center; color: #666; font-size: 11px;
        margin-top: 24px; padding: 12px; background: #0a0a0c;
        border-radius: 6px;
    }
    .exe-hash code { color: #888; word-break: break-all; }

    /* === Layout com sidebar === */
    body { display: flex; padding: 0; min-height: 100vh; }
    .sidebar {
        position: sticky; top: 0; height: 100vh;
        width: 260px; flex-shrink: 0;
        background: #08080a; border-right: 1px solid #1f1f23;
        padding: 20px 0; overflow-y: auto;
    }
    .sidebar-head {
        padding: 0 20px 20px; border-bottom: 1px solid #1f1f23;
    }
    .sidebar-head h3 {
        margin: 0 0 12px; font-size: 18px; letter-spacing: 2px;
        background: linear-gradient(90deg, #ff4d4f, #ffb020);
        -webkit-background-clip: text; background-clip: text; color: transparent;
    }
    .nav-score {
        display: inline-block; padding: 6px 12px;
        color: #000; font-weight: 800; font-size: 12px;
        border-radius: 4px; letter-spacing: 1px;
    }
    .sidebar-nav { padding: 12px 0; }
    .nav-group { margin-bottom: 20px; }
    .nav-group-title {
        padding: 8px 20px; color: #555; font-size: 10px;
        text-transform: uppercase; letter-spacing: 2px; font-weight: 700;
    }
    .nav-link {
        display: flex; justify-content: space-between; align-items: center;
        padding: 8px 20px; color: #aaa; text-decoration: none;
        font-size: 13px; transition: background .1s, color .1s;
        border-left: 3px solid transparent;
    }
    .nav-link:hover { background: #131316; color: #fff; border-left-color: #ff4d4f; }
    .nav-link.nav-hit { color: #e8e8e8; font-weight: 600; }
    .nav-link.nav-clean { color: #555; }
    .nav-badge {
        background: #ff4d4f; color: #000; padding: 2px 8px;
        border-radius: 10px; font-size: 11px; font-weight: 700;
    }
    .main-content {
        flex: 1; padding: 24px; max-width: calc(100% - 260px);
        scroll-padding-top: 20px;
    }
    .page-header {
        margin-bottom: 24px; padding-bottom: 16px;
        border-bottom: 1px solid #1f1f23;
    }
    .page-header h1 {
        margin: 0; font-size: 32px; font-weight: 800; letter-spacing: 3px;
        background: linear-gradient(90deg, #ff4d4f 0%, #ffb020 50%, #ff4d4f 100%);
        -webkit-background-clip: text; background-clip: text; color: transparent;
    }
    .page-header .sub { color: #666; margin-top: 4px; font-size: 13px; }
    .page-footer {
        margin-top: 32px; padding: 20px; border-top: 1px solid #1f1f23;
        color: #555; font-size: 12px; text-align: center;
    }

    /* === Collapsible sections === */
    details > summary {
        cursor: pointer; list-style: none; user-select: none;
    }
    details > summary::-webkit-details-marker { display: none; }
    details > summary::before {
        content: "▶"; display: inline-block; margin-right: 10px;
        color: #555; font-size: 10px;
        transition: transform .15s;
    }
    details[open] > summary::before { transform: rotate(90deg); }
    details > summary:hover h2 { color: #ff4d4f; }

    /* === Charts === */
    .charts-grid {
        display: grid; grid-template-columns: 1fr 1fr; gap: 20px;
    }
    @media (max-width: 900px) {
        .charts-grid { grid-template-columns: 1fr; }
    }
    .chart-card {
        background: #0e0e10; border: 1px solid #2a2a2e;
        border-radius: 8px; padding: 16px;
    }
    .chart-card h3 {
        margin: 0 0 12px; font-size: 13px; color: #aaa;
        text-transform: uppercase; letter-spacing: 1px;
    }
    .donut { width: 100%; max-width: 220px; height: auto; display: block; margin: 0 auto; }
    .donut-legend {
        display: flex; justify-content: center; gap: 16px;
        font-size: 12px; color: #aaa; margin-top: 12px; flex-wrap: wrap;
    }
    .donut-legend .dot {
        display: inline-block; width: 8px; height: 8px; border-radius: 50%;
        margin-right: 6px; vertical-align: middle;
    }
    .bars { display: flex; flex-direction: column; gap: 8px; }
    .bar-row { display: flex; align-items: center; gap: 8px; font-size: 12px; }
    .bar-label {
        flex: 0 0 35%; color: #ccc; text-align: right; overflow: hidden;
        text-overflow: ellipsis; white-space: nowrap;
    }
    .bar-track {
        flex: 1; height: 16px; background: #0a0a0c; border-radius: 3px;
        overflow: hidden;
    }
    .bar-fill {
        height: 100%; background: linear-gradient(90deg, #ff4d4f, #ffb020);
        transition: width .5s;
    }
    .bar-count {
        flex: 0 0 30px; text-align: left; color: #ffb020; font-weight: 700;
    }

    /* === Empty state === */
    .empty-state {
        text-align: center; padding: 40px 20px;
        border: 2px dashed #3fbf7f44;
    }
    .empty-icon { font-size: 64px; margin-bottom: 16px; }
    .empty-state h2 {
        color: #3fbf7f; margin: 0 0 12px;
        font-size: 28px; letter-spacing: 1px;
    }
    .empty-state p { color: #aaa; max-width: 540px; margin: 0 auto 8px; }
    .empty-state .empty-sub { color: #666; font-size: 12px; margin-top: 16px; }

    /* === Print === */
    @media print {
        body { background: white; color: black; display: block; }
        .sidebar, .controls { display: none !important; }
        .main-content { max-width: 100%; padding: 0; }
        .card { break-inside: avoid; border-color: #ccc; background: white; }
        .card h2 { color: black; }
        code { color: #c5780b; background: #f5f5f5; }
        details { open: true; }
        details > summary::before { display: none; }
    }

    /* === Mobile === */
    @media (max-width: 700px) {
        body { flex-direction: column; }
        .sidebar { position: relative; width: 100%; height: auto; }
        .main-content { max-width: 100%; }
    }

    /* === Custom scrollbar === */
    * { scrollbar-width: thin; scrollbar-color: #ff4d4f #0a0a0c; }
    ::-webkit-scrollbar { width: 10px; height: 10px; }
    ::-webkit-scrollbar-track { background: #0a0a0c; }
    ::-webkit-scrollbar-thumb {
        background: linear-gradient(180deg, #ff4d4f, #ffb020);
        border-radius: 10px; border: 2px solid #0a0a0c;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: linear-gradient(180deg, #ff6668, #ffc040);
    }
    ::-webkit-scrollbar-corner { background: #0a0a0c; }
    .sidebar::-webkit-scrollbar { width: 6px; }
    .sidebar::-webkit-scrollbar-thumb { background: #ff4d4f55; border: none; }

    /* === Espaçamento refinado === */
    body {
        font-size: 14px; line-height: 1.5;
    }
    .main-content {
        padding: 32px 40px 24px;
        max-width: calc(100% - 260px);
    }
    .card {
        padding: 24px 28px; margin-bottom: 16px;
        border-radius: 10px;
    }
    .card h2 { font-size: 17px; margin: 0; line-height: 1.4; }
    .card .desc {
        margin: 8px 0 12px; font-size: 13px; line-height: 1.55;
    }
    .card .summary { margin: 8px 0 16px; font-size: 13px; }
    .card-head { padding: 4px 0; gap: 16px; }
    details > summary { padding: 4px 0; }
    details[open] > summary { margin-bottom: 4px; }
    table { margin-top: 4px; }
    th, td { padding: 10px 12px; }
    .stats { gap: 12px; margin: 8px 0 4px; }
    .stat { padding: 16px 24px; min-width: 96px; }
    .stat .num { font-size: 26px; line-height: 1.2; margin-bottom: 4px; }
    .stat > div:last-child { font-size: 11px; color: #888; text-transform: uppercase; letter-spacing: 1px; }
    .page-header { margin-bottom: 20px; padding-bottom: 16px; }
    .page-header h1 { font-size: 28px; letter-spacing: 4px; }

    /* Sidebar refinements */
    .sidebar { padding: 24px 0 32px; }
    .sidebar-head { padding: 0 24px 20px; }
    .sidebar-head h3 { font-size: 17px; letter-spacing: 3px; margin: 0 0 14px; }
    .sidebar-nav { padding: 16px 0 8px; }
    .nav-group { margin-bottom: 24px; }
    .nav-group-title {
        padding: 10px 24px; font-size: 10px; letter-spacing: 2px;
    }
    .nav-link {
        padding: 9px 24px; font-size: 13px; line-height: 1.4;
        margin: 1px 0;
    }
    .nav-badge { padding: 2px 9px; font-size: 10px; margin-left: 8px; }

    /* Charts spacing */
    .charts-grid { gap: 16px; margin-top: 8px; }
    .chart-card { padding: 20px; }
    .chart-card h3 { margin: 0 0 16px; font-size: 12px; letter-spacing: 1.5px; }
    .donut-legend { margin-top: 16px; gap: 20px; }
    .bars { gap: 10px; }
    .bar-row { font-size: 12px; }
    .bar-label { padding-right: 4px; }
    .bar-track { height: 14px; border-radius: 4px; }

    /* Timeline refinement */
    .timeline .tl-range { margin: 12px 0 6px; padding: 0 4px; }
    .timeline .tl-track { margin: 8px 0 16px; height: 44px; }

    /* Sections code refinement */
    code { padding: 2px 7px; font-size: 12px; }
    .empty { padding: 12px 0; font-size: 13px; }

    /* FP-stats and high-confidence padding */
    .fp-stats, .high-confidence { padding: 24px 28px; }
    .verdict-sub { margin: -4px 0 18px; }
    .overview .big-verdict { font-size: 32px; margin: 18px 0 10px; }

    /* ================================================================
       === 10/10 PASS: design tokens, typography, animations, lightbox
       ================================================================ */

    :root {
        /* Spacing scale (4-8-12-16-24-32-48-64) */
        --s-1: 4px; --s-2: 8px; --s-3: 12px; --s-4: 16px;
        --s-6: 24px; --s-8: 32px; --s-12: 48px; --s-16: 64px;

        /* Color tokens */
        --c-red: #ff4d4f;
        --c-red-soft: rgba(255, 77, 79, 0.08);
        --c-orange: #ffb020;
        --c-orange-soft: rgba(255, 176, 32, 0.07);
        --c-yellow: #ffe066;
        --c-green: #3fbf7f;
        --c-green-soft: rgba(63, 191, 127, 0.08);

        /* Neutral scale */
        --c-bg-0: #08080a;
        --c-bg-1: #0e0e10;
        --c-bg-2: #16161a;
        --c-bg-3: #1a1a1d;
        --c-bg-4: #232327;
        --c-border: #1f1f23;
        --c-border-soft: #15151a;

        /* Text scale */
        --c-text: #f0f0f2;
        --c-text-mute: #aaa;
        --c-text-soft: #777;
        --c-text-faint: #555;

        /* Motion */
        --ease-out: cubic-bezier(0.16, 1, 0.3, 1);
        --ease: cubic-bezier(0.4, 0, 0.2, 1);
    }

    /* Typography upgrade — Segoe UI Variable (Win11) cai bonito */
    body, .nav-link, .sidebar-head h3, .page-header h1, button, input {
        font-family: 'Inter', 'Segoe UI Variable', -apple-system,
                     BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
        font-feature-settings: "cv02", "cv03", "cv04", "cv11", "ss01";
        -webkit-font-smoothing: antialiased;
        -moz-osx-font-smoothing: grayscale;
        text-rendering: optimizeLegibility;
    }
    code, .conf-val, pre {
        font-family: 'JetBrains Mono', 'Cascadia Code', 'Consolas',
                     'SF Mono', monospace;
        font-feature-settings: "calt", "liga", "ss01", "ss02";
    }
    body { color: var(--c-text); letter-spacing: -0.005em; }
    h1, h2, h3 { letter-spacing: -0.015em; font-weight: 700; }

    /* === Animations === */
    @keyframes fadeUp {
        from { opacity: 0; transform: translateY(8px); }
        to   { opacity: 1; transform: translateY(0); }
    }
    @keyframes pulse {
        0%, 100% { box-shadow: 0 0 0 0 rgba(255, 77, 79, 0.5); }
        50%      { box-shadow: 0 0 0 14px rgba(255, 77, 79, 0); }
    }
    @keyframes shimmer {
        0%   { background-position: -200% 0; }
        100% { background-position: 200% 0; }
    }
    @keyframes scaleIn {
        from { opacity: 0; transform: scale(0.96); }
        to   { opacity: 1; transform: scale(1); }
    }

    /* Apply stagger to cards */
    .card {
        animation: fadeUp 0.5s var(--ease-out) both;
        transition: border-color 0.2s var(--ease), transform 0.15s var(--ease);
    }
    .card:nth-child(1) { animation-delay: 0ms; }
    .card:nth-child(2) { animation-delay: 40ms; }
    .card:nth-child(3) { animation-delay: 80ms; }
    .card:nth-child(4) { animation-delay: 120ms; }
    .card:nth-child(5) { animation-delay: 160ms; }
    .card:nth-child(6) { animation-delay: 200ms; }
    .card:nth-child(7) { animation-delay: 240ms; }
    .card:nth-child(n+8) { animation-delay: 280ms; }
    .sidebar { animation: fadeUp 0.4s var(--ease-out) both; }
    .page-header h1 {
        background-size: 200% 100%;
        animation: shimmer 8s linear infinite;
    }

    /* Big verdict pulse for CHEATER */
    .big-verdict {
        animation: scaleIn 0.6s var(--ease-out) both;
        text-shadow: 0 0 24px currentColor;
    }

    /* === Hovers refined === */
    .card:hover {
        transform: translateY(-1px);
        border-color: var(--c-border);
    }
    .stat {
        transition: transform 0.15s var(--ease), background 0.15s var(--ease);
    }
    .stat:hover {
        transform: translateY(-2px);
        background: var(--c-bg-3) !important;
    }
    code {
        transition: background 0.15s var(--ease), color 0.15s var(--ease);
    }
    code:hover { background: var(--c-bg-4); color: #ffd680; }

    /* === Better neutrals on existing components === */
    body { background: var(--c-bg-1); }
    .sidebar { background: var(--c-bg-0); border-color: var(--c-border); }
    .card { background: var(--c-bg-3); border-color: var(--c-border); }
    .chart-card, .stat, code { background: var(--c-bg-1); }
    .stat { border-color: var(--c-border); }
    th { background: var(--c-bg-4); color: var(--c-text-mute); }
    .controls input { background: var(--c-bg-1); border-color: var(--c-border); }

    /* === Lightbox for screenshots === */
    .lightbox {
        position: fixed; inset: 0; z-index: 1000;
        background: rgba(0, 0, 0, 0.92);
        backdrop-filter: blur(8px);
        display: none; align-items: center; justify-content: center;
        padding: 32px;
        animation: scaleIn 0.2s var(--ease-out);
        cursor: zoom-out;
    }
    .lightbox.active { display: flex; }
    .lightbox img {
        max-width: 100%; max-height: 100%;
        object-fit: contain;
        border-radius: 8px;
        box-shadow: 0 24px 72px rgba(0, 0, 0, 0.6);
        cursor: default;
    }
    .lightbox-close {
        position: absolute; top: 24px; right: 24px;
        background: rgba(255, 255, 255, 0.1); color: #fff;
        border: none; width: 40px; height: 40px;
        border-radius: 50%; cursor: pointer;
        font-size: 20px;
        transition: background 0.15s;
    }
    .lightbox-close:hover { background: rgba(255, 255, 255, 0.2); }
    .lightbox-hint {
        position: absolute; bottom: 24px;
        color: var(--c-text-soft); font-size: 12px;
        letter-spacing: 1px;
    }

    /* Toast for copy feedback */
    .toast {
        position: fixed; bottom: 24px; right: 24px; z-index: 999;
        background: var(--c-green); color: #000;
        padding: 12px 20px; border-radius: 8px;
        font-weight: 600; font-size: 13px;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
        animation: fadeUp 0.3s var(--ease-out);
    }

    /* Focus visible (a11y) */
    *:focus-visible {
        outline: 2px solid var(--c-red);
        outline-offset: 2px;
        border-radius: 4px;
    }
    *:focus:not(:focus-visible) { outline: none; }

    /* Selection */
    ::selection { background: var(--c-red); color: #000; }

    /* Reduced motion */
    @media (prefers-reduced-motion: reduce) {
        *, *::before, *::after {
            animation-duration: 0.01ms !important;
            transition-duration: 0.01ms !important;
        }
    }

    /* Brand */
    .brand-row {
        display: flex; align-items: center; gap: 10px;
        margin-bottom: 14px;
    }
    .brand-logo {
        width: 32px; height: 32px; flex-shrink: 0;
        opacity: 0.95;
    }
    .brand-row h3 { margin: 0; line-height: 1; }

    /* ================================================================
       === Calm pass — quieter, more deliberate
       ================================================================ */

    color-scheme: dark;

    :root {
        accent-color: var(--c-red);
    }

    /* Tabular figures + slashed zero — números alinhados verticalmente,
       sem confundir 0/O. Diferença sutil mas notável em stats grandes. */
    .stat .num, .conf-val, .hc-count, code, time,
    .verdict-sub, .donut text, .bar-count,
    .stats, .verdict-sub code {
        font-variant-numeric: tabular-nums lining-nums slashed-zero;
    }

    /* Headings — peso mais variado, tracking refinado */
    h1, h2, h3 {
        font-weight: 600;
        letter-spacing: -0.011em;
        text-wrap: balance;
    }
    .page-header h1 {
        font-weight: 700;
        letter-spacing: -0.02em;
        color: var(--c-text);
        background: none;
        -webkit-text-fill-color: var(--c-text);
        margin: 0;
    }
    .page-header h1::first-letter {
        color: var(--c-red);
    }

    /* Animations mínimas — só de entrada, sem loops infinitos */
    @keyframes drift {
        from { opacity: 0; transform: translateY(6px); }
        to   { opacity: 1; transform: translateY(0); }
    }
    @keyframes barGrow {
        from { width: 0; }
        to   { width: var(--final-width, 100%); }
    }
    @keyframes donutDraw {
        from { stroke-dashoffset: 314; }
    }

    /* Cards — sem hover lift, sem ring, sem gradient. Só border-color shift. */
    .card {
        position: relative;
        animation: drift 0.45s var(--ease-out) both;
        transition: border-color 0.2s var(--ease);
    }
    .card:hover {
        border-color: var(--c-bg-4);
    }
    .card.status-suspicious {
        border-color: rgba(255, 77, 79, 0.18);
    }
    .card.status-suspicious::after {
        content: ''; position: absolute; top: 16px; bottom: 16px; left: 0;
        width: 2px;
        background: var(--c-red);
        border-radius: 0 1px 1px 0;
    }

    /* Sidebar — entrada simples, sem stagger */
    .sidebar { animation: drift 0.4s var(--ease-out) both; }
    .nav-link {
        position: relative;
        transition: background 0.12s var(--ease), color 0.12s, border-left-color 0.12s;
    }
    .nav-link:hover {
        background: rgba(255, 255, 255, 0.025);
    }
    .nav-badge {
        font-variant-numeric: tabular-nums;
    }
    .nav-score {
        font-variant-numeric: tabular-nums;
        font-weight: 700;
    }

    /* Stats — pop simples, sem shimmer overlay */
    .stat { animation: drift 0.4s var(--ease-out) both; }
    .stat:nth-child(1) { animation-delay: 30ms; }
    .stat:nth-child(2) { animation-delay: 60ms; }
    .stat:nth-child(3) { animation-delay: 90ms; }
    .stat:nth-child(4) { animation-delay: 120ms; }
    .stat:nth-child(5) { animation-delay: 150ms; }
    .stat:nth-child(6) { animation-delay: 180ms; }
    .stat:hover {
        background: var(--c-bg-2) !important;
        transform: none;
    }
    .stat .num {
        font-weight: 600;
        letter-spacing: -0.02em;
        font-feature-settings: "tnum", "lnum", "zero";
    }

    /* Verdict — sem 3D, sem halo, sem magnet. Só uma entrada limpa. */
    .big-verdict {
        animation: drift 0.5s var(--ease-out) both;
        font-weight: 700;
        letter-spacing: -0.025em;
    }

    /* Bars — cor sólida quente, anima 1x */
    .bar-fill {
        background: var(--c-red);
        animation: barGrow 1s 0.2s var(--ease-out) both;
        will-change: width;
    }
    .bar-row .bar-count {
        font-weight: 600;
        color: var(--c-text-mute);
    }

    /* Donut — fade + draw 1x, sem loops */
    .donut circle:not(:first-child) {
        stroke-dasharray: 314;
        animation: donutDraw 0.9s 0.3s var(--ease-out) both;
        animation-fill-mode: backwards;
    }

    /* Timeline dots — apenas hover scale, sem pop entry confuso */
    .timeline .tl-dot {
        transition: transform 0.15s var(--ease), box-shadow 0.15s;
    }
    .timeline .tl-dot:hover {
        transform: translate(-50%, -50%) scale(1.6);
        box-shadow: 0 0 12px currentColor;
        z-index: 50;
    }

    /* Empty state — sem float infinito */
    .empty-state .empty-icon { display: inline-block; opacity: 0.9; }

    /* Charts — entry simples */
    .chart-card { animation: drift 0.5s var(--ease-out) both; }
    .chart-card:nth-child(2) { animation-delay: 80ms; }
    .chart-card:hover { border-color: var(--c-bg-4); }

    /* Filter buttons — sem ::before sweep, hover só com opacity */
    .filter-btn {
        transition: opacity 0.12s, background 0.12s;
    }
    .filter-btn:hover { opacity: 0.85; }
    .filter-btn:active { transform: scale(0.97); }

    /* Search input focus — só border, sem ring */
    .controls input {
        transition: border-color 0.15s, background 0.15s;
    }
    .controls input:focus {
        border-color: var(--c-text-mute);
        background: var(--c-bg-2);
    }

    /* Rows */
    tbody tr { transition: background 0.12s; }
    tbody tr:hover { background: rgba(255, 255, 255, 0.02); }
    tbody tr.row-high:hover { background: rgba(255, 77, 79, 0.06); }

    /* Code — sem ripple, hover só com bg shift */
    code {
        transition: background 0.12s, color 0.12s;
    }

    /* High-confidence card — borda vermelha sólida, sem gradient animado */
    .high-confidence {
        border-color: rgba(255, 77, 79, 0.5);
    }

    /* Details summary — só rotate do triângulo, sem slide do título */
    details > summary::before {
        transition: transform 0.2s var(--ease);
    }
    details summary h2 {
        transition: color 0.15s;
    }
    details summary:hover h2 { color: var(--c-text); }

    /* FP badge */
    .fp-badge {
        cursor: help;
        font-weight: 500;
        letter-spacing: 0;
    }

    /* Lightbox close — sem rotate gimmick */
    .lightbox-close {
        transition: background 0.15s;
    }
    .lightbox-close:hover { background: rgba(255, 255, 255, 0.18); }

    /* Toast — sombra discreta */
    .toast {
        animation: drift 0.25s var(--ease-out) both;
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4);
    }

    /* Smooth scroll — só se user não preferir reduzido */
    @media (prefers-reduced-motion: no-preference) {
        html { scroll-behavior: smooth; }
    }

    /* Selection refinada */
    ::selection {
        background: rgba(255, 77, 79, 0.25);
        color: var(--c-text);
    }

    /* Borders mais consistentes em tudo */
    .card, .chart-card, .stat, .controls input {
        border-color: var(--c-border);
    }

    /* Spacing scale aplicada onde tava off */
    .stats { gap: 8px; }
    .chart-card { padding: 24px; }
    .nav-group { margin-bottom: 28px; }
    .nav-link { padding: 8px 24px; }

    /* Detalhes tipográficos finais */
    .desc { color: var(--c-text-mute); line-height: 1.6; }
    .summary { color: var(--c-text); font-weight: 500; }
    code {
        background: var(--c-bg-1);
        border: 1px solid var(--c-border);
        color: #ffc266;
        padding: 1px 6px;
        font-size: 12px;
        border-radius: 4px;
    }

    /* ================================================================
       === Functional pass — usability features
       ================================================================ */

    /* Skip link (a11y) */
    .skip-link {
        position: absolute; top: -100px; left: 0; z-index: 9999;
        background: var(--c-red); color: #000;
        padding: 12px 20px; font-weight: 600;
        text-decoration: none;
        transition: top 0.15s;
    }
    .skip-link:focus { top: 0; }

    /* Screen reader only */
    .sr-only {
        position: absolute; width: 1px; height: 1px;
        padding: 0; margin: -1px; overflow: hidden;
        clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0;
    }

    /* Controls meta row */
    .controls-meta {
        display: flex; justify-content: space-between; align-items: center;
        margin-top: 14px;
        font-size: 12px; color: var(--c-text-soft);
        flex-wrap: wrap; gap: 8px;
    }
    #visible-count { font-variant-numeric: tabular-nums; }
    .control-divider {
        width: 1px; height: 20px;
        background: var(--c-border);
        margin: 0 4px;
    }
    .filter-btn.ghost {
        background: transparent;
        color: var(--c-text-mute);
        border: 1px solid var(--c-border);
    }
    .filter-btn.ghost:hover {
        color: var(--c-text);
        border-color: var(--c-bg-4);
        opacity: 1;
    }

    /* Keyboard hints */
    .kbd-hint { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
    kbd {
        display: inline-block;
        padding: 2px 6px;
        background: var(--c-bg-1);
        border: 1px solid var(--c-border);
        border-bottom-width: 2px;
        border-radius: 3px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 10px;
        color: var(--c-text);
        line-height: 1;
    }

    /* Mini-mapa de severidade na sidebar */
    .nav-link {
        display: flex; align-items: center; gap: 8px;
    }
    .nav-link-label {
        flex: 1; overflow: hidden; text-overflow: ellipsis;
        white-space: nowrap;
    }
    .mini-sev {
        width: 6px; height: 6px;
        border-radius: 50%; flex-shrink: 0;
    }
    .mini-high   { background: var(--c-red);    }
    .mini-medium { background: var(--c-orange); }
    .mini-low    { background: var(--c-yellow); }
    .mini-none   { background: transparent; border: 1px solid var(--c-border); }

    /* Zebra stripes sutis nas tabelas */
    tbody tr:nth-child(even) {
        background: rgba(255, 255, 255, 0.012);
    }

    /* Sort headers */
    .sortable th.sort-col {
        cursor: pointer;
        user-select: none;
        transition: color 0.12s, background 0.12s;
    }
    .sortable th.sort-col:hover {
        color: var(--c-text);
        background: var(--c-bg-3);
    }
    .sort-indicator {
        opacity: 0.4;
        font-size: 10px;
        margin-left: 4px;
        transition: opacity 0.15s, transform 0.15s;
    }
    th.sort-col.sort-active .sort-indicator { opacity: 1; }
    th.sort-col.sort-asc .sort-indicator { transform: rotate(180deg); }

    /* Empty state SVG */
    .empty-svg {
        width: 80px; height: 80px;
        margin: 0 auto 12px;
        display: block;
    }

    /* Focus styles refinados */
    .nav-link:focus-visible {
        outline: none;
        background: rgba(255, 77, 79, 0.08);
        box-shadow: inset 3px 0 0 var(--c-red);
    }
    button:focus-visible, [tabindex]:focus-visible {
        outline: 2px solid var(--c-red);
        outline-offset: 1px;
    }

    /* Hidden state pra elementos filtrados (com transition smooth) */
    [data-hidden="true"] {
        display: none !important;
    }

    /* Print refinements */
    @media print {
        .controls, .controls-meta, .skip-link, .kbd-hint,
        .sort-indicator, .lightbox, .toast { display: none !important; }
        details { open: ""; }
        details > summary::before { display: none; }
        .empty-svg circle { stroke: #3fbf7f; }
    }
    """

    html_doc = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Relatório do Telador — {sys_info.get('host', '')}</title>
    <style>{CSS}{extra_css}</style>
</head>
<body>
    <a href="#main-content" class="skip-link">Pular pro conteúdo</a>
    {sidebar_html}
    <main class="main-content" id="main-content" tabindex="-1">
    <header class="page-header">
        <h1>TELADOR BR</h1>
        <div class="sub">Relatório gerado em {sys_info.get('scan_time', '')}</div>
    </header>
    <span id="summary"></span>{summary_html}
    {empty_html}
    <span id="high-confidence"></span>{hc_html}
    <span id="fp-stats"></span>{fp_html}
    <span id="timeline"></span>{timeline_html}
    <span id="pe-analysis"></span>{pe_html}
    {charts_html}
    <span id="sysinfo"></span>{sys_html}
    <span id="screenshots"></span>{screens_html}
    {controls_html}
    {sections}
    {exe_hash}
    <footer class="page-footer">
        Resultado é heurístico (baseado em nomes/locais conhecidos).
        Pode haver falso positivo (ex.: alguém pesquisou sobre o tema) ou falso negativo (cheat com nome trocado).
        Conduza a tela completa e verifique manualmente os pontos suspeitos.
    </footer>
    </main>
    {CONTROLS_JS}
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html_doc)

    return output_path
