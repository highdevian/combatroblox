"""
Recursos visuais do Telador BR (Aesthetics & UI).
Contém CSS (modo premium glassmorphism), dicionários de cores e SVGs.
Isolado para facilitar manutenção e limpar o report.py.
"""

# Paleta "forensic dark lab" — casa com o site (oklch). Estas cores são
# emitidas em estilos INLINE (gráficos, dots, badges), fora do alcance do
# CSS, então são a fonte única da verdade pra cor de severidade.
INK_CRIT  = "oklch(0.58 0.22 25)"    # crítico — vermelho profundo
INK_HIGH  = "oklch(0.62 0.21 28)"    # high — destructive do site
INK_MED   = "oklch(0.72 0.14 28)"    # medium — evidence do site
INK_LOW   = "oklch(0.78 0.02 240)"   # low — cold (azul dessaturado)
INK_CLEAN = "oklch(0.72 0.14 160)"   # limpo/ok — verde forense
INK_MUTE  = "oklch(0.58 0.012 260)"  # skip/neutro
INK_PAPER = "oklch(0.93 0.012 80)"   # texto papel quente

SEVERITY_COLORS = {
    "critical": INK_CRIT,
    "high":     INK_HIGH,
    "medium":   INK_MED,
    "low":      INK_LOW,
}

STATUS_BADGE = {
    "clean":      ("LIMPO",    INK_CLEAN),
    "suspicious": ("SUSPEITO", INK_HIGH),
    "error":      ("SKIP",     INK_MUTE),
}

SOURCE_LABELS = {
    "prefetch":           "Prefetch",
    "amcache":            "Amcache",
    "bam":                "BAM (Background Activity)",
    "usn_journal":        "USN Journal",
    "shimcache":          "ShimCache",
    "userassist":         "UserAssist",
    "muicache":           "MuiCache",
    "jumplists":          "JumpLists",
    "srum":               "SRUM",
    "kernel_drivers":     "Kernel Drivers",
    "live_processes":     "Processos rodando",
    "removable_media":    "Mídia removível (USB)",
    "user_accounts":      "Contas de Windows",
    "defender_tampering": "Defender adulterado",
    "clock_tampering":    "Relógio mudado",
    "service_state":      "Serviço forense parado",
    "live_dll_injection": "DLL injetadas",
    "yara_signature":     "Assinatura binária (YARA)",
    "dma_hardware":       "Hardware DMA",
    "external_cheat":     "External cheat (aimbot/ESP)",
    "external_corroboration": "Corroboração external+forense",
    # v3.44.0 — detecções técnicas
    "external_reader":    "External (handle no Roblox)",
    "external_footprint": "External (pegada de RAM)",
    "remote_thread":      "Thread remota no Roblox",
    "kernel_only_egress": "Rede: processo do sistema",
    "external_correlation": "External (correlação de sinais)",
    "popup_overlay":      "Overlay D3D/DComp",
    "post_roblox_proc":   "Processo pós-Roblox",
    "suspicious_pipe":    "Named pipe suspeito",
    "random_name_exe":    "Nome aleatório (.exe)",
    "user_path_network":  "Rede (user-path não-assinado)",
    "suspicious_ancestry": "Ancestralidade pós-Roblox",
    # v3.44.0 — forense pós-mortem
    "defender_history":   "Defender (histórico)",
    "dxshader_burst":     "DirectX Shader Cache",
    "wer_crash":          "WER crash (persistente)",
    "reliability_monitor": "Reliability Monitor",
    # v3.46.0 — Tier S state-based
    "dse_state":          "DSE / Test Mode",
    "vbs_disabled":       "VBS / HVCI desativado",
    "roblox_rwx_page":    "Roblox .text RWX (patch)",
    "activities_cache":   "ActivitiesCache Timeline",
    # v3.47.0 — Tier A behavioral
    "dropper_task":       "Task dropper (persistência)",
    "amsi_bypass":        "AMSI Bypass (PowerShell)",
    "apc_injection":      "APC Injection (Roblox)",
    "event_log_exec":     "Event Log (execução)",
    "defender_detection": "Defender (detecção)",
    "roblox_logs":        "Roblox Logs",
    "roblox_bytecode":    "Roblox Bytecode",
    "bloxstrap":          "Bloxstrap",
    "browser_history":    "Browser History",
    "downloads":          "Downloads",
    "dns_cache":          "DNS Cache",
    "discord_cache":      "Discord Cache",
    "anti_forense":       "Anti-forense detectado",
    "anti_evasion":       "Anti-VM / Sandbox",
    "powershell_history": "PowerShell history",
    "command_history":    "Command history",
    "persistence":        "Persistência (Startup/Tasks)",
    "peripherals":        "Macros (mouse/teclado)",
    "network":            "Rede",
    "fresh_install":      "Instalação recente",
    "scripts":            "Scripts (.lua/.luau)",
    "recycle_bin":        "Lixeira",
    "hidden_files":       "Arquivos ocultos",
    "filesystem":         "Filesystem",
}

CLUSTER_VERDICT_STYLE = {
    "CONFIRMED": ("shield-x",       "EXECUTOR CONFIRMADO",  INK_CRIT),
    "DETECTED":  ("alert-octagon",  "EXECUTOR DETECTADO",   INK_HIGH),
    "SUSPECT":   ("alert-triangle", "EVIDÊNCIA SUSPEITA",   INK_MED),
    "WEAK":      ("circle-dashed",  "PISTA FRACA",          INK_LOW),
}

def get_svg_icon(key: str, size: int = 56, color: str = "currentColor", with_pulse: bool = False) -> str:
    paths = {
        "shield-x": (
            '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.5 3.79 17 5 19 5a1 1 0 0 1 1 1z"/>'
            '<path d="m14.5 9-5 5"/><path d="m9.5 9 5 5"/>'
        ),
        "alert-octagon": (
            '<path d="M12.7 2.7a2 2 0 0 0-1.4 0L4.05 6.05a2 2 0 0 0-1.41 1.41L2.7 11.3a2 2 0 0 0 0 1.4l3.4 7.25a2 2 0 0 0 1.41 1.41l3.84 1.34a2 2 0 0 0 1.4 0l7.25-3.4a2 2 0 0 0 1.41-1.41l1.34-3.84a2 2 0 0 0 0-1.4l-3.4-7.25a2 2 0 0 0-1.41-1.41z"/>'
            '<line x1="12" x2="12" y1="8" y2="12"/><line x1="12" x2="12.01" y1="16" y2="16"/>'
        ),
        "alert-triangle": (
            '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>'
            '<path d="M12 9v4"/><path d="M12 17h.01"/>'
        ),
        "circle-dashed": (
            '<path d="M10.1 2.18a9.93 9.93 0 0 1 3.8 0"/><path d="M13.9 21.82a9.94 9.94 0 0 1-3.8 0"/>'
            '<path d="M17.61 3.65a9.96 9.96 0 0 1 2.74 2.74"/><path d="M21.84 10.1a9.93 9.93 0 0 1 0 3.8"/>'
            '<path d="M20.35 17.61a9.96 9.96 0 0 1-2.74 2.74"/><path d="M6.39 20.35a9.96 9.96 0 0 1-2.74-2.74"/>'
            '<path d="M2.16 13.9a9.93 9.93 0 0 1 0-3.8"/><path d="M3.65 6.39a9.96 9.96 0 0 1 2.74-2.74"/>'
        ),
        "shield-check": (
            '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.5 3.79 17 5 19 5a1 1 0 0 1 1 1z"/>'
            '<path d="m9 12 2 2 4-4"/>'
        ),
    }
    body = paths.get(key, paths["circle-dashed"])
    cls = "hv-icon hv-icon-pulse" if with_pulse else "hv-icon"
    return (
        f'<svg class="{cls}" width="{size}" height="{size}" viewBox="0 0 24 24" '
        f'fill="none" stroke="{color}" stroke-width="2" stroke-linecap="round" '
        f'stroke-linejoin="round" aria-hidden="true">{body}</svg>'
    )


# CSS Modernizado (Aesthetics Premium: Cores Ricas, Glassmorphism, Microinterações)
MODERN_CSS = """
:root {
    --bg-dark: #0a0a0c;
    --bg-panel: #141418;
    --border-color: #27272f;
    --text-main: #f0f0f5;
    --text-muted: #9595a6;
    --accent-red: #ff3333;
    --accent-gold: #feca57;
    --accent-green: #1dd1a1;
    --glass-bg: rgba(20, 20, 24, 0.65);
    --glass-border: rgba(255, 255, 255, 0.08);
}
* { box-sizing: border-box; }
body {
    font-family: 'Inter', system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    background: var(--bg-dark); color: var(--text-main); margin: 0; padding: 24px;
    font-size: 14px; line-height: 1.5;
    background-image: 
        radial-gradient(circle at 15% 50%, rgba(255, 51, 51, 0.03), transparent 25%),
        radial-gradient(circle at 85% 30%, rgba(254, 202, 87, 0.03), transparent 25%);
}
header { text-align: center; margin-bottom: 40px; padding-top: 20px; }
header h1 {
    margin: 0; font-size: 42px; font-weight: 900;
    letter-spacing: 2px;
    background: linear-gradient(135deg, #ff6b6b 0%, #feca57 50%, #ff3333 100%);
    -webkit-background-clip: text; background-clip: text; color: transparent;
    filter: drop-shadow(0 2px 8px rgba(255, 107, 107, 0.2));
}
header .sub { color: var(--text-muted); margin-top: 8px; font-weight: 500; letter-spacing: 0.5px; }

/* Cards Genéricos */
.card {
    background: var(--bg-panel); border: 1px solid var(--border-color); border-radius: 12px;
    padding: 24px; margin-bottom: 24px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.2);
    transition: transform 0.2s cubic-bezier(0.16, 1, 0.3, 1), box-shadow 0.2s;
}
.card:hover { transform: translateY(-2px); box-shadow: 0 8px 30px rgba(0,0,0,0.3); }
.card-head { display: flex; justify-content: space-between; align-items: center; gap: 12px; cursor: pointer; outline: none; }
.card-head::-webkit-details-marker { display: none; }
.card h2 { margin: 0; font-size: 20px; color: #fff; font-weight: 700; }
.desc { color: var(--text-muted); margin: 6px 0 12px; font-size: 13.5px; }
.summary { color: #dcdce6; margin: 4px 0 16px; font-weight: 600; }

/* Badges */
.badge {
    padding: 4px 12px; border-radius: 6px; color: #000;
    font-weight: 800; font-size: 11px; letter-spacing: 1.5px;
    text-transform: uppercase; box-shadow: 0 2px 10px rgba(0,0,0,0.2);
}
.status-suspicious { border-color: rgba(255, 107, 107, 0.3); }

/* Tabelas Premium */
table { width: 100%; border-collapse: separate; border-spacing: 0; font-size: 13px; margin-top: 10px; }
th, td { text-align: left; padding: 12px 14px; border-bottom: 1px solid var(--border-color); vertical-align: top; }
th { background: rgba(255,255,255,0.03); color: #aaa; font-weight: 700; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }
th:first-child { border-top-left-radius: 8px; }
th:last-child { border-top-right-radius: 8px; }
tr { transition: background 0.15s; }
tr:hover td { background: rgba(255,255,255,0.02); }
tr.row-high td { background: rgba(255, 51, 51, 0.08); }
tr.row-medium td { background: rgba(254, 202, 87, 0.06); }
tr.row-high:hover td { background: rgba(255, 51, 51, 0.12); }
tr.row-medium:hover td { background: rgba(254, 202, 87, 0.1); }
.sev { white-space: nowrap; font-weight: 800; font-size: 11px; }

code {
    background: rgba(0,0,0,0.5); padding: 4px 8px; border-radius: 4px;
    color: var(--accent-gold); font-family: 'Consolas', 'Courier New', monospace; font-size: 12px;
    word-break: break-all; border: 1px solid rgba(255,255,255,0.05);
}
.empty { color: #666; font-style: italic; margin: 12px 0; background: rgba(0,0,0,0.2); padding: 16px; border-radius: 8px; text-align: center; }
.sys th { width: 160px; color: #aaa; }

/* Stats e Overview */
.stats { display: flex; gap: 16px; justify-content: center; flex-wrap: wrap; margin-top: 20px; }
.stat {
    background: var(--glass-bg); backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px);
    border: 1px solid var(--glass-border); border-radius: 12px;
    padding: 18px 28px; min-width: 110px; text-align: center;
    box-shadow: 0 4px 16px rgba(0,0,0,0.2); transition: transform 0.2s;
}
.stat:hover { transform: translateY(-3px); border-color: rgba(255,255,255,0.15); }
.stat .num { font-size: 28px; font-weight: 800; text-shadow: 0 2px 10px rgba(0,0,0,0.5); margin-bottom: 4px; }
.stat div:last-child { font-size: 12px; color: #888; text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px; }

footer { text-align: center; color: #555; margin-top: 40px; font-size: 12px; padding-bottom: 20px; }
footer code { background: transparent; color: #888; border: none; }

/* ============================ HERO VERDICT ============================ */
.admin-warn {
    background: rgba(254, 202, 87, 0.08); border: 1px solid rgba(254, 202, 87, 0.3); border-left: 4px solid var(--accent-gold);
    border-radius: 10px; padding: 16px 20px; margin: 0 0 24px;
    color: #ffd685; font-size: 14px; line-height: 1.6; font-weight: 500;
}
.admin-warn strong { color: #fff; font-weight: 800; }
.hero-verdict {
    background: var(--glass-bg); backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
    border: 1px solid var(--glass-border);
    border-radius: 16px;
    padding: 48px 32px 32px;
    margin: 0 0 32px;
    text-align: center;
    position: relative;
    overflow: hidden;
    animation: hv-fade-in 0.6s cubic-bezier(0.16, 1, 0.3, 1) both;
    box-shadow: 0 10px 40px rgba(0,0,0,0.3);
}
.hero-verdict::before {
    content: ""; position: absolute; inset: 0;
    background: radial-gradient(circle at 50% 0%, var(--hv-accent, transparent) 0%, transparent 60%);
    opacity: 0.12; pointer-events: none;
}
.hero-verdict::after {
    content: ""; position: absolute; top: 0; left: 0; right: 0; height: 3px;
    background: linear-gradient(90deg, transparent, var(--hv-accent, #888), transparent);
    opacity: 0.8;
}
.hv-state-clean { border-color: rgba(29, 209, 161, 0.3); box-shadow: 0 10px 40px rgba(29, 209, 161, 0.05); }
.hv-state-warn  { border-color: rgba(254, 202, 87, 0.3); box-shadow: 0 10px 40px rgba(254, 202, 87, 0.05); }
.hv-state-bad   { border-color: rgba(255, 51, 51, 0.4); box-shadow: 0 0 60px -10px rgba(255, 51, 51, 0.2); }

.hv-icon-wrap {
    display: inline-flex; align-items: center; justify-content: center;
    width: 104px; height: 104px; margin: 0 auto 24px;
    border-radius: 50%;
    background: radial-gradient(circle, color-mix(in oklch, var(--hv-accent, transparent) 15%, transparent) 0%, transparent 70%);
    position: relative;
    box-shadow: 0 0 30px var(--hv-accent) inset;
}
.hv-icon-wrap::before {
    content: ""; position: absolute; inset: 0; border-radius: 50%;
    border: 2px solid var(--hv-accent, #888); opacity: 0.3;
}
.hv-icon { display: block; filter: drop-shadow(0 0 8px var(--hv-accent)); }
.hv-icon-pulse { animation: hv-pulse 2s ease-in-out infinite; }
.hv-state-bad .hv-icon-wrap::after {
    content: ""; position: absolute; inset: -8px; border-radius: 50%;
    border: 2px solid var(--hv-accent); opacity: 0.5;
    animation: hv-ring 2.2s cubic-bezier(0.2, 0.8, 0.2, 1) infinite;
}

@keyframes hv-fade-in { from { opacity: 0; transform: translateY(-16px); } to { opacity: 1; transform: translateY(0); } }
@keyframes hv-pulse { 0%, 100% { transform: scale(1); opacity: 1; } 50% { transform: scale(1.08); opacity: 0.9; } }
@keyframes hv-ring { 0% { transform: scale(0.85); opacity: 0.6; border-width: 2px; } 100% { transform: scale(1.8); opacity: 0; border-width: 0px; } }

.hv-headline {
    margin: 0 0 8px; font-size: 42px; font-weight: 900;
    letter-spacing: 3px; text-transform: uppercase;
    text-shadow: 0 4px 20px rgba(0,0,0,0.5);
}
.hv-sub { color: #b2b2bf; font-size: 15px; margin-bottom: 20px; letter-spacing: 0.5px; font-weight: 500; }
.hv-conf { font-size: 20px; color: #e0e0e0; margin-bottom: 28px; font-weight: 600; }
.hv-conf strong { font-size: 28px; font-weight: 900; text-shadow: 0 2px 10px rgba(0,0,0,0.4); }

.hv-actions { margin: 8px 0; }
.hv-copy {
    background: rgba(255,255,255,0.05); border: 1px solid var(--glass-border);
    color: #fff; font-size: 14px; font-weight: 600; letter-spacing: 0.5px;
    padding: 10px 24px; border-radius: 8px; cursor: pointer;
    font-family: inherit; transition: all 0.2s; backdrop-filter: blur(4px);
    box-shadow: 0 4px 12px rgba(0,0,0,0.2);
}
.hv-copy:hover { background: rgba(255,255,255,0.1); transform: translateY(-2px); border-color: var(--hv-accent); }
.hv-copy:active { transform: translateY(0); }
.hv-copy.copied { background: rgba(29, 209, 161, 0.2); border-color: #1dd1a1; color: #1dd1a1; }

.hv-cards {
    display: grid; gap: 16px; margin-top: 28px; text-align: left;
    grid-template-columns: repeat(auto-fit, minmax(290px, 1fr));
    max-width: 1200px; margin-left: auto; margin-right: auto;
}
.hv-card {
    background: rgba(0,0,0,0.4); border: 1px solid var(--glass-border);
    border-left: 5px solid #888;
    border-radius: 10px; padding: 20px;
    transition: transform 0.2s, box-shadow 0.2s, border-color 0.2s;
    backdrop-filter: blur(8px);
}
.hv-card:hover { transform: translateY(-4px); box-shadow: 0 8px 24px rgba(0,0,0,0.3); }
.hv-card-head { display: flex; justify-content: space-between; align-items: baseline; gap: 8px; margin-bottom: 14px; }
.hv-target { display: flex; align-items: center; gap: 10px; min-width: 0; flex: 1; }
.hv-card-icon { display: inline-flex; align-items: center; flex-shrink: 0; line-height: 0; }
.hv-card-name { font-size: 18px; font-weight: 800; color: #fff; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; letter-spacing: 0.5px; }
.hv-kind { font-size: 10.5px; color: #888; text-transform: uppercase; letter-spacing: 1.5px; font-weight: 700; flex-shrink: 0; background: rgba(255,255,255,0.05); padding: 2px 6px; border-radius: 4px; }
.hv-card-verdict { font-size: 12px; font-weight: 900; letter-spacing: 1px; flex-shrink: 0; }
.hv-card-meta { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 16px; }
.hv-meta-pill {
    background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.08);
    color: #ddd; padding: 4px 10px; border-radius: 12px;
    font-size: 11px; font-weight: 600;
}
.hv-sources {
    list-style: none; padding: 0; margin: 0;
    display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 8px 12px;
}
.hv-sources li { color: #d0d0d0; font-size: 13.5px; display: flex; align-items: center; gap: 8px; font-weight: 500; }
.hv-check { color: #1dd1a1; font-weight: 800; flex-shrink: 0; text-shadow: 0 0 8px rgba(29, 209, 161, 0.4); }
.hv-time { color: #7a7a8c; font-size: 11.5px; margin-top: 14px; border-top: 1px dashed rgba(255,255,255,0.1); padding-top: 10px; font-weight: 500; }
.hv-time code { background: rgba(0,0,0,0.3); color: #aaa; border: none; }

/* Timeline e outros */
.timeline { position: relative; padding: 30px 0; margin: 20px 0; border-bottom: 1px solid var(--border-color); }
.tl-line { position: absolute; top: 50%; left: 0; right: 0; height: 3px; background: rgba(255,255,255,0.05); border-radius: 2px; }
.tl-dot {
    position: absolute; top: 50%; transform: translate(-50%, -50%);
    width: 14px; height: 14px; border-radius: 50%;
    border: 2px solid var(--bg-panel); cursor: pointer; transition: transform 0.2s, box-shadow 0.2s;
}
.tl-dot:hover { transform: translate(-50%, -50%) scale(1.5); z-index: 10; box-shadow: 0 0 10px rgba(255,255,255,0.5); }
.tl-labels { display: flex; justify-content: space-between; color: #666; font-size: 11.5px; margin-top: 20px; font-weight: 600; letter-spacing: 0.5px; }
"""
