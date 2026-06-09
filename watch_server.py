"""
Dashboard local ao vivo (--watch).

Sobe um servidor HTTP em 127.0.0.1 (porta livre) que mostra os scanners
reportando EM TEMPO REAL e o veredito do Confidence Engine se formando
conforme as evidências chegam.

Diferença filosófica vs. ferramentas comerciais (Abyss etc): aquelas
transmitem os dados do PC do suspeito pra um servidor na nuvem. Aqui é
**100% local** — o servidor roda na própria máquina, em loopback, e nada
sai do PC. O supervisor abre no próprio navegador da sessão.

Sem dependência nova: usa só `http.server` + `json` da stdlib.

Fluxo:
    url = start(total_scanners)         # sobe servidor, devolve URL local
    ...                                  # a cada scanner que termina:
    push_scanner(result, done, total)    # streama o resultado + rebuilda clusters
    ...
    finalize(clusters, verdict)          # trava o veredito final (pós-FP-filter)
    # servidor segue vivo até o processo morrer (daemon thread)
"""

from __future__ import annotations

import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    import evidence as _ev
    _HAS_EVIDENCE = True
except Exception:
    _HAS_EVIDENCE = False


# --------------------------- Estado compartilhado ---------------------------

_lock = threading.Lock()
_state = {
    "status": "scanning",     # "scanning" | "done"
    "total": 0,
    "done": 0,
    "scanners": [],           # [{name, status, n_hits, top_severity}]
    "clusters": [],           # [{label, kind, verdict, confidence, score, n_sources, sources}]
    "verdict": None,          # dict do fp_filter.compute_verdict (final)
    "live_preview": True,     # True enquanto clusters são prévia (pré-FP-filter)
}
# Acumula findings crus pra rebuildar clusters ao vivo.
_findings_accum = []

_SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _top_severity(items):
    worst = "low"
    for it in items:
        s = it.get("severity", "low")
        if _SEV_RANK.get(s, 0) > _SEV_RANK.get(worst, 0):
            worst = s
    return worst


def _clusters_to_dicts(clusters):
    out = []
    for c in clusters:
        # Só mostra clusters que valem alguma coisa no dashboard
        if c.verdict == "WEAK":
            continue
        out.append({
            "label": c.label,
            "kind": c.kind,
            "verdict": c.verdict,
            "confidence": c.confidence_pct,
            "score": round(c.score, 1),
            "n_sources": c.n_sources,
            "sources": sorted(c.sources),
        })
    return out


def _rebuild_clusters_locked():
    """Rebuilda clusters a partir dos findings acumulados. Chamar com _lock."""
    if not _HAS_EVIDENCE:
        return
    try:
        evs = _ev.findings_to_evidences(_findings_accum)
        clusters = _ev.build_clusters(evs)
        _state["clusters"] = _clusters_to_dicts(clusters)
    except Exception:
        # Dashboard nunca pode derrubar o scan — falha silenciosa
        pass


# --------------------------- HTTP handler ---------------------------

class _Handler(BaseHTTPRequestHandler):
    # Silencia o log padrão (spamma o console do scan)
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path.startswith("/state"):
            with _lock:
                body = json.dumps(_state, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # Qualquer outra rota → dashboard HTML
        body = _DASHBOARD_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


_server = None
_server_thread = None


def stop() -> None:
    """Fecha o servidor local e libera o socket. Idempotente."""
    global _server
    if _server is not None:
        try:
            _server.shutdown()
            _server.server_close()
        except Exception:
            pass
        _server = None


def start(total: int, open_browser: bool = True) -> str | None:
    """Sobe o servidor local. Devolve a URL (http://127.0.0.1:PORTA) ou None.

    Idempotente: se já havia um servidor (ex.: chamadas repetidas em teste),
    fecha o anterior antes de subir o novo — evita vazar socket.
    """
    global _server, _server_thread
    stop()  # fecha qualquer servidor anterior
    with _lock:
        _state["total"] = total
        _state["done"] = 0
        _state["status"] = "scanning"
        _state["scanners"] = []
        _state["clusters"] = []
        _state["verdict"] = None
        _state["live_preview"] = True
        _findings_accum.clear()

    try:
        # Porta 0 = SO escolhe uma livre. Só loopback — nada exposto na rede.
        _server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    except OSError:
        return None

    port = _server.server_address[1]
    _server_thread = threading.Thread(target=_server.serve_forever, daemon=True)
    _server_thread.start()

    url = f"http://127.0.0.1:{port}/"
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    return url


def push_scanner(result: dict, done: int, total: int) -> None:
    """Streama um resultado de scanner e rebuilda os clusters ao vivo."""
    items = result.get("items", [])
    entry = {
        "name": result.get("name", "?"),
        "status": result.get("status", "clean"),
        "n_hits": len(items),
        "top_severity": _top_severity(items) if items else None,
    }
    with _lock:
        _state["scanners"].append(entry)
        _state["done"] = done
        _state["total"] = total
        if items:
            _findings_accum.append(result)
            _rebuild_clusters_locked()


def finalize(clusters, verdict: dict) -> None:
    """Trava o veredito final (pós-FP-filter) — clusters autoritativos."""
    with _lock:
        _state["status"] = "done"
        _state["verdict"] = verdict
        _state["live_preview"] = False
        if clusters is not None:
            _state["clusters"] = _clusters_to_dicts(clusters)


# --------------------------- Dashboard HTML ---------------------------
# Self-contained: sem CDN, polling em /state a cada 400ms.

_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Telador — scan ao vivo</title>
<style>
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 24px; background: #0b0b0d; color: #e8e8e8;
    font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px;
  }
  .wrap { max-width: 1080px; margin: 0 auto; }
  header { display: flex; align-items: center; gap: 12px; margin-bottom: 20px; }
  .logo { font-family: 'Consolas', monospace; font-weight: 800; letter-spacing: 2px;
          color: #e8b339; font-size: 18px; }
  .live-dot { width: 9px; height: 9px; border-radius: 50%; background: #27c93f;
              box-shadow: 0 0 0 0 rgba(39,201,63,.6); animation: pulse 1.6s infinite; }
  @keyframes pulse { 0%{box-shadow:0 0 0 0 rgba(39,201,63,.5);} 70%{box-shadow:0 0 0 8px rgba(39,201,63,0);} 100%{box-shadow:0 0 0 0 rgba(39,201,63,0);} }
  .local-badge { margin-left:auto; font-family:'Consolas',monospace; font-size:11px;
                 color:#27c93f; border:1px solid #27c93f44; border-radius:20px; padding:4px 12px; }

  .verdict-card { border:1px solid #2a2a2e; border-radius:12px; padding:24px;
                  background:radial-gradient(ellipse at top,#16161a,#0e0e10 70%);
                  margin-bottom:20px; transition:border-color .4s, box-shadow .4s; }
  .vc-head { display:flex; align-items:center; gap:16px; }
  .vc-icon { width:56px; height:56px; border-radius:50%; display:flex; align-items:center;
             justify-content:center; flex-shrink:0; }
  .vc-title { font-size:26px; font-weight:900; letter-spacing:1px; }
  .vc-sub { color:#999; font-size:13px; margin-top:2px; font-family:'Consolas',monospace; }
  .vc-conf { margin-left:auto; text-align:right; }
  .vc-conf .num { font-size:34px; font-weight:800; font-family:'Consolas',monospace; }
  .vc-conf .lbl { font-size:11px; color:#888; text-transform:uppercase; letter-spacing:1px; }

  .progress { height:6px; border-radius:3px; background:#1a1a1d; overflow:hidden; margin:18px 0 6px; }
  .progress > div { height:100%; background:linear-gradient(90deg,#e8b339,#ff8c42); width:0%;
                    transition:width .3s ease; }
  .progress-txt { font-family:'Consolas',monospace; font-size:11px; color:#888; }

  .grid { display:grid; grid-template-columns:1.4fr 1fr; gap:20px; }
  @media (max-width:820px){ .grid{ grid-template-columns:1fr; } }
  .panel { border:1px solid #2a2a2e; border-radius:10px; background:#121214; overflow:hidden; }
  .panel h2 { margin:0; padding:12px 16px; font-size:12px; text-transform:uppercase;
              letter-spacing:1px; color:#aaa; border-bottom:1px solid #2a2a2e; background:#16161a; }
  .stream { max-height:440px; overflow-y:auto; font-family:'Consolas',monospace; font-size:12.5px; }
  .srow { display:flex; align-items:center; gap:10px; padding:7px 16px; border-bottom:1px solid #1c1c20;
          animation:slidein .25s ease-out; }
  @keyframes slidein { from{opacity:0; transform:translateX(-8px);} to{opacity:1; transform:none;} }
  .srow .nm { flex:1; color:#ccc; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .tag { font-size:10.5px; font-weight:700; padding:1px 8px; border-radius:10px; flex-shrink:0; }
  .tag.ok   { color:#27c93f; border:1px solid #27c93f44; }
  .tag.hit  { color:#ff5f56; border:1px solid #ff5f5644; }
  .tag.skip { color:#666; border:1px solid #333; }

  .clusters { padding:14px; display:flex; flex-direction:column; gap:10px; }
  .cl { border:1px solid #2a2a2e; border-left-width:4px; border-radius:8px; padding:12px 14px;
        background:#0e0e10; animation:slidein .3s ease-out; }
  .cl-top { display:flex; align-items:baseline; gap:8px; }
  .cl-name { font-size:16px; font-weight:700; color:#fff; }
  .cl-kind { font-size:10px; color:#888; text-transform:uppercase; letter-spacing:1px; }
  .cl-verdict { margin-left:auto; font-size:11px; font-weight:800; letter-spacing:1px; }
  .cl-meta { display:flex; gap:6px; flex-wrap:wrap; margin-top:8px; }
  .pill { font-family:'Consolas',monospace; font-size:10px; color:#bbb;
          background:#1a1a1d; border:1px solid #2a2a2e; border-radius:10px; padding:1px 8px; }
  .cl-src { margin-top:10px; display:grid; grid-template-columns:repeat(auto-fit,minmax(110px,1fr)); gap:3px 10px; }
  .cl-src span { font-size:12px; color:#c8c8c8; }
  .cl-src .ck { color:#27c93f; }
  .empty { padding:28px 16px; color:#555; font-style:italic; text-align:center; }
  .preview-note { font-size:11px; color:#888; padding:0 14px 12px; font-style:italic; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <span class="live-dot" id="dot"></span>
    <span class="logo">TELADOR · AO VIVO</span>
    <span class="local-badge">🔒 100% LOCAL · 127.0.0.1 · nada sai do PC</span>
  </header>

  <div class="verdict-card" id="vcard">
    <div class="vc-head">
      <div class="vc-icon" id="vcicon" style="background:#2a2a2e22;border:1px solid #333">
        <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="#888" stroke-width="1.8"
             stroke-linecap="round" stroke-linejoin="round" id="vcsvg">
          <path d="M10.1 2.18a9.93 9.93 0 0 1 3.8 0"/><path d="M21.84 10.1a9.93 9.93 0 0 1 0 3.8"/>
          <path d="M13.9 21.82a9.94 9.94 0 0 1-3.8 0"/><path d="M2.16 13.9a9.93 9.93 0 0 1 0-3.8"/>
        </svg>
      </div>
      <div>
        <div class="vc-title" id="vctitle" style="color:#888">ANALISANDO…</div>
        <div class="vc-sub" id="vcsub">scanners reportando em tempo real</div>
      </div>
      <div class="vc-conf"><div class="num" id="vcconf" style="color:#888">—</div><div class="lbl">confidence</div></div>
    </div>
    <div class="progress"><div id="bar"></div></div>
    <div class="progress-txt" id="ptxt">0 / 0 scanners</div>
  </div>

  <div class="grid">
    <div class="panel">
      <h2>Scanners (ao vivo)</h2>
      <div class="stream" id="stream"></div>
    </div>
    <div class="panel">
      <h2>Targets detectados</h2>
      <div class="preview-note" id="pvnote" style="display:none">Prévia ao vivo — o relatório final aplica filtro de falso-positivo.</div>
      <div class="clusters" id="clusters"><div class="empty">Nenhum target ainda…</div></div>
    </div>
  </div>
</div>

<script>
const VS = {
  CONFIRMED: { c:'#ff2a2a', t:'EXECUTOR CONFIRMADO', svg:'<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.5 3.79 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m14.5 9-5 5"/><path d="m9.5 9 5 5"/>' },
  DETECTED:  { c:'#ff5f56', t:'EXECUTOR DETECTADO', svg:'<path d="M12.7 2.7a2 2 0 0 0-1.4 0L4 6.05a2 2 0 0 0-1.41 1.41L2.7 11.3a2 2 0 0 0 0 1.4l1.34 3.84a2 2 0 0 0 1.41 1.41l3.84 1.34a2 2 0 0 0 1.4 0l7.25-3.4a2 2 0 0 0 1.41-1.41l1.34-3.84a2 2 0 0 0 0-1.4l-3.4-7.25z"/><line x1="12" x2="12" y1="8" y2="12"/><line x1="12" x2="12.01" y1="16" y2="16"/>' },
  SUSPECT:   { c:'#e8b339', t:'EVIDÊNCIA SUSPEITA', svg:'<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/>' },
  CLEAN:     { c:'#3fbf7f', t:'NENHUM EXECUTOR', svg:'<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.5 3.79 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/>' },
};
const SRC_LABELS = {
  prefetch:'Prefetch', amcache:'Amcache', bam:'BAM', usn_journal:'USN Journal', shimcache:'ShimCache',
  userassist:'UserAssist', muicache:'MuiCache', jumplists:'JumpLists', srum:'SRUM',
  kernel_drivers:'Kernel Drivers', live_processes:'Processos', live_dll_injection:'DLL injetadas',
  roblox_logs:'Roblox Logs', roblox_bytecode:'Bytecode', bloxstrap:'Bloxstrap', browser_history:'Browser',
  downloads:'Downloads', dns_cache:'DNS', discord_cache:'Discord', anti_forense:'Anti-forense',
  anti_evasion:'Anti-VM', powershell_history:'PowerShell', command_history:'Histórico',
  persistence:'Persistência', peripherals:'Macros', network:'Rede', fresh_install:'Instalação recente',
  scripts:'Scripts', recycle_bin:'Lixeira', hidden_files:'Ocultos', filesystem:'Filesystem',
};
const srcLbl = s => SRC_LABELS[s] || s;
// Escapa HTML antes de qualquer innerHTML: label/source de cluster derivam de
// nome de arquivo do disco do suspeito (evidence.py), que é controlado por ele.
// Sem isso, um arquivo renomeado pra conter HTML forja o veredito no painel.
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => (
  {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let lastN = 0;

function rank(v){ return {CONFIRMED:3,DETECTED:2,SUSPECT:1}[v]||0; }

function render(st){
  // progresso
  const pct = st.total ? Math.round(st.done/st.total*100) : 0;
  document.getElementById('bar').style.width = pct + '%';
  document.getElementById('ptxt').textContent = `${st.done} / ${st.total} scanners` + (st.status==='done'?' · concluído':'');

  // stream incremental
  const stream = document.getElementById('stream');
  for (let i = lastN; i < st.scanners.length; i++){
    const s = st.scanners[i];
    const row = document.createElement('div'); row.className='srow';
    let tag = '<span class="tag ok">ok</span>';
    if (s.n_hits>0) tag = `<span class="tag hit">${s.n_hits} SUSPEITO</span>`;
    else if (s.status==='error') tag = '<span class="tag skip">skip</span>';
    row.innerHTML = `<span class="nm">${esc(s.name)}</span>${tag}`;
    stream.appendChild(row);
  }
  if (st.scanners.length > lastN) stream.scrollTop = stream.scrollHeight;
  lastN = st.scanners.length;

  // veredito
  let best = null;
  for (const c of st.clusters){ if (!best || rank(c.verdict) > rank(best.verdict)) best = c; }
  const icon = document.getElementById('vcicon'), svg=document.getElementById('vcsvg');
  const title=document.getElementById('vctitle'), sub=document.getElementById('vcsub'), conf=document.getElementById('vcconf');
  const dot=document.getElementById('dot'), card=document.getElementById('vcard');

  if (best){
    const vs = VS[best.verdict] || VS.SUSPECT;
    title.textContent = vs.t; title.style.color = vs.c;
    svg.setAttribute('stroke', vs.c); svg.innerHTML = vs.svg;
    icon.style.background = vs.c+'18'; icon.style.border = '1px solid '+vs.c+'55';
    conf.textContent = best.confidence + '%'; conf.style.color = vs.c;
    sub.textContent = `${st.clusters.length} target(s) · ${best.label}`;
    card.style.borderColor = vs.c+'55';
    card.style.boxShadow = best.verdict==='CONFIRMED' ? '0 0 50px -22px '+vs.c : 'none';
  } else if (st.status==='done'){
    const vs = VS.CLEAN;
    title.textContent = vs.t; title.style.color = vs.c;
    svg.setAttribute('stroke', vs.c); svg.innerHTML = vs.svg;
    icon.style.background = vs.c+'18'; icon.style.border='1px solid '+vs.c+'55';
    conf.textContent='✓'; conf.style.color=vs.c; sub.textContent='nenhum target acima do limite';
    card.style.borderColor = vs.c+'44';
  }
  if (st.status==='done'){ dot.style.background='#888'; dot.style.animation='none'; }

  // clusters
  const wrap = document.getElementById('clusters');
  document.getElementById('pvnote').style.display = (st.live_preview && st.clusters.length) ? 'block':'none';
  if (!st.clusters.length){
    wrap.innerHTML = st.status==='done'
      ? '<div class="empty">PC limpo — nenhum target detectado.</div>'
      : '<div class="empty">Nenhum target ainda…</div>';
  } else {
    const order = {CONFIRMED:0,DETECTED:1,SUSPECT:2};
    const sorted = [...st.clusters].sort((a,b)=> (order[a.verdict]-order[b.verdict]) || (b.score-a.score));
    wrap.innerHTML = sorted.map(c=>{
      const vs = VS[c.verdict] || VS.SUSPECT;
      const srcs = c.sources.map(s=>`<span><span class="ck">✓</span> ${esc(srcLbl(s))}</span>`).join('');
      return `<div class="cl" style="border-left-color:${vs.c}">
        <div class="cl-top"><span class="cl-name">${esc(c.label)}</span><span class="cl-kind">${esc(c.kind)}</span>
          <span class="cl-verdict" style="color:${vs.c}">${esc(c.verdict)}</span></div>
        <div class="cl-meta"><span class="pill" style="color:${vs.c}">Confidence ${c.confidence}%</span>
          <span class="pill">Score ${c.score}</span><span class="pill">${c.n_sources} fonte(s)</span></div>
        <div class="cl-src">${srcs}</div></div>`;
    }).join('');
  }
}

async function poll(){
  try{
    const r = await fetch('/state', {cache:'no-store'});
    const st = await r.json();
    render(st);
    if (st.status !== 'done') setTimeout(poll, 400);
    else setTimeout(poll, 1500); // segue checando devagar caso finalize atrase
  } catch(e){ setTimeout(poll, 800); }
}
poll();
</script>
</body>
</html>
"""
