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
    for item in finding.get("items", []):
        sev = item.get("severity", "low")
        color = SEVERITY_COLORS.get(sev, "#888")
        conf = item.get("confidence")
        fp_reason = item.get("fp_reason")
        orig_sev = item.get("original_severity")

        # Badge de rebaixamento
        downgrade_badge = ""
        if orig_sev and orig_sev != sev:
            downgrade_badge = (f'<span class="fp-badge" title="{_escape(fp_reason or "")}">'
                                f'↓ era {_escape(orig_sev.upper())}</span>')

        # Confidence bar
        conf_html = ""
        if conf is not None:
            conf_color = "#3fbf7f" if conf >= 70 else ("#ffb020" if conf >= 40 else "#888")
            conf_html = (f'<div class="conf-bar"><div class="conf-fill" '
                          f'style="width:{conf}%; background:{conf_color}"></div>'
                          f'<span class="conf-val">{conf}</span></div>')

        # Detail com fp_reason inline (se houver)
        detail_text = item.get('detail', '')
        if fp_reason:
            detail_text = f"{detail_text}\n[FP-filter: {fp_reason}]"

        rows.append(f"""
        <tr class="row-{sev}">
            <td class="sev"><span class="sev-dot" style="background:{color}"></span>{_escape(sev.upper())}{downgrade_badge}</td>
            <td class="label">{_escape(item.get('label', ''))}</td>
            <td class="detail"><code>{_escape(detail_text)}</code></td>
            <td class="match"><code>{_escape(item.get('matched', ''))}</code></td>
            <td class="conf">{conf_html}</td>
            <td class="ts">{_escape(item.get('timestamp', ''))}</td>
        </tr>""")

    if rows:
        table = f"""
        <table>
            <thead>
                <tr>
                    <th>Severidade</th>
                    <th>Item</th>
                    <th>Detalhe</th>
                    <th>Match</th>
                    <th>Conf.</th>
                    <th>Quando</th>
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
        if n_items > 0:
            badge = f'<span class="nav-badge">{n_items}</span>'
            scanner_links.append(f'<a href="#scan-{slug}" class="nav-link nav-hit">{_escape(f["name"])}{badge}</a>')
        else:
            scanner_links.append(f'<a href="#scan-{slug}" class="nav-link nav-clean">{_escape(f["name"])}</a>')

    score_badge = ""
    if verdict:
        score_badge = f'<div class="nav-score" style="background:{verdict.get("color", "#888")}">' \
                       f'Score {verdict.get("score", 0)}</div>'

    return f"""
    <aside class="sidebar">
        <div class="sidebar-head">
            <h3>TELADOR BR</h3>
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
    """Tela limpa bonita quando 0 hits totais."""
    return """
    <section class="card empty-state">
        <div class="empty-icon">✅</div>
        <h2>Tudo limpo</h2>
        <p>Nenhum hit nas 34 categorias de detecção. Este sistema não apresenta
        indícios de uso de executores Roblox conhecidos, scripts de exploit,
        ou ferramentas de cheating.</p>
        <p class="empty-sub">Lembre-se: detecção heurística pode ter falso-negativo (cheat novo,
        renomeado). Faça SS visual também.</p>
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
    """Barra de search e filtros de severidade."""
    return """
    <section class="card controls">
        <div class="controls-row">
            <input type="text" id="search" placeholder="🔍 Filtrar (ex: krnl, wave, .lua, downloads...)" />
            <div class="filters">
                <button class="filter-btn" data-sev="high"   style="--c:#ff4d4f">High</button>
                <button class="filter-btn" data-sev="medium" style="--c:#ffb020">Medium</button>
                <button class="filter-btn" data-sev="low"    style="--c:#ffe066">Low</button>
                <button id="show-all" class="filter-btn solid">Mostrar tudo</button>
            </div>
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

    // Click pra copiar em code blocks
    document.querySelectorAll('code').forEach(c => {
        c.style.cursor = 'pointer';
        c.title = 'Clique pra copiar';
        c.addEventListener('click', () => {
            navigator.clipboard.writeText(c.textContent).then(() => {
                const orig = c.style.background;
                c.style.background = '#3fbf7f';
                setTimeout(() => { c.style.background = orig; }, 300);
            }).catch(() => {});
        });
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
    """

    html_doc = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Relatório do Telador — {sys_info.get('host', '')}</title>
    <style>{CSS}{extra_css}</style>
</head>
<body>
    {sidebar_html}
    <main class="main-content">
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
