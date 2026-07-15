# Plano 30 dias — Telador → Echo-tier (Roblox)

**Meta:** o staff BR preferir o Telador na call de SS — não só “ferramenta técnica do dev”.  
**Hoje:** 2026-07-13 · **v3.51.2** · 113 scanners · motor forense forte · UX ainda de terminal.  
**Não-meta:** copiar o Echo multi-game/SaaS em 30 dias.  
**Meta real:** **produto de SS Roblox** com ritual Echo-like + profundidade forense que o Echo não precisa expor.

---

## Norte (definição de “cheguei”)

No fim dos 30 dias, um staff deve conseguir:

1. Baixar **um** link óbvio (site ou release).
2. Rodar **sem terminal** (GUI ou bat “um clique” premium).
3. Em **&lt; 45s** (modo SS-live) ver: **LIMPO / SUSPEITO / CONFIRMADO** + 3 bullets “por quê”.
4. Mandar o resultado no Discord em **1 clique** (MD ou print do painel).
5. Em máquina de **gamer limpo**: score ~0, **zero** MEDIUM/HIGH de FP de baseline Windows.
6. Em máquina com **Winter-class residual**: cluster com ≥2 fontes, não “50 linhas de ruído”.

**KPI de release (todo patch):**

| KPI | Alvo |
|-----|------|
| FP baseline Win (KnownDLLs, cert root, BITS Edge, SCM WMI) | 0 |
| Tempo modo SS-live (admin, SSD médio) | ≤ 45s |
| Passos até o veredito (staff) | ≤ 3 cliques |
| LIMPO vs INCONCLUSIVO contraditório | 0 ocorrências |
| Testes CI | verde em py3.11/12/13 |

---

## Mapa de 4 semanas

```text
Semana 1 (13–19 jul)  DETECÇÃO + ESTABILIDADE     ← você já está no meio
Semana 2 (20–26 jul)  PRODUTO MÍNIMO (UX + ritual)
Semana 3 (27 jul–2 ago) POLIMENTO ECHO-LIKE
Semana 4 (3–9 ago)    LANÇAMENTO + CONFIANÇA
```

Alinha com a ideia de **13–25/07 detecção/bugs/FP/bypass** e **depois** caminho completo (site/UI).

---

## Semana 1 — Detecção & confiança técnica (13–19 jul)

**Objetivo:** motor “não envergonha na call”; FPs de baseline mortos; bypass Winter mais caro.

| Dia | Entrega | Done quando |
|-----|---------|-------------|
| D1–2 | Auditoria FP em 3 perfis: (a) gamer limpo (b) dev (c) com TinyTask/PH | checklist + issues priorizadas |
| D3 | Modo `--ss-live`: subset de scanners (live + forensics fortes + external + streamproof + clipboard + correlation) | flag documentada, &lt; 45s no teu PC |
| D4 | Veredito “staff”: 3 linhas no console/HTML (o que, por quê, o que fazer) | seção fixa no relatório |
| D5 | Assinaturas: `sigupdate` / `signatures.dist` review (Winter, loaders 2026) | changelog de sigs |
| D6–7 | Buffer: bugs de CI/release, `build.bat` alinhado ao `telador.spec` | `build.bat` não apaga o `.spec` |

**Já feito (não reabrir sem regressão):**

- [x] Clipboard history (plano de 10)
- [x] Anti-FP KnownDLLs / cert / BITS / COM / WMI (3.51.1)
- [x] Veredito único + soft PCA (3.51.2)

**Não fazer na S1:** GUI completa, multi-game, cloud.

**Release S1:** `v3.52.0` se tiver `--ss-live` + veredito staff; senão patch `3.51.x` só de FP.

---

## Semana 2 — Produto mínimo (20–26 jul)

**Objetivo:** parar de “parecer script” e parecer **ferramenta de SS**.

### P0 — Shell de produto

| Entrega | Detalhe | Prioridade |
|---------|---------|------------|
| **Launcher GUI** | Janela nativa (CustomTkinter / FreeSimpleGUI / Tauri leve) ou WebView local do `watch_server` full-screen | P0 |
| **Fluxo** | [Iniciar SS] → progresso → veredito grande (verde/amarelo/vermelho) → [Abrir HTML] [Copiar Discord] [Sair] | P0 |
| **Admin** | UAC no clique, sem jargão; se recusar → tela “INCONCLUSIVO, peça admin” | P0 |
| **Modo SS-live default na GUI** | Full scan como “Avançado” | P0 |

### P1 — Ritual Discord

| Entrega | Detalhe |
|---------|---------|
| Botão **Copiar resumo** | Markdown curto: veredito, score, top 5 hits, SHA256 do exe, versão |
| Relatório HTML “staff” | Hero com veredito; detalhes recolhidos; sem parecer log de debug |
| Zip de distribuição | `Telador-vX.zip` = exe + INICIAR + playbook 1 página PDF/MD |

### P1 — Site mínimo (não precisa ser “foda” ainda)

| Página | Conteúdo |
|--------|----------|
| `/` | O que é, download latest, SHA256, 3 screenshots |
| `/playbook` | Roteiro de call SS (5 passos) |
| `/changelog` | link pro CHANGELOG ou últimas 5 tags |

**Release S2:** `v3.53.0` — “Telador com interface”.

**Critério de go/no-go:** staff leigo consegue scan sem você no Discord explicando flags.

---

## Semana 3 — Polimento Echo-like (27 jul – 2 ago)

**Objetivo:** sensação de produto pago, sem ser SaaS.

| Entrega | Por quê Echo ganha aqui |
|---------|-------------------------|
| **Dashboard ao vivo** polido (`TELADOR-AO-VIVO` = default GUI) | Staff vê progresso na call |
| **Perfis de scan** | Rápido / Padrão / Paranóia (`--strict`) com nomes humanos |
| **Histórico local** | Últimos N scans em `%LOCALAPPDATA%\Telador\history\` (JSON + veredito) |
| **Comparar SS** (`--diff` já existe) | Botão “comparar com scan anterior” na GUI |
| **Assinaturas “como update”** | Aviso na UI: “sigs desatualizadas → atualizar” (sem cloud de evidência) |
| **Branding** | Ícone, nome, cores, som opcional no veredito CONFIRMADO |

**Detecção (só se sobrar tempo):** 1–2 scanners Tier A do ROADMAP (ex. swapchain hook **não**; preferir algo &lt; 3s e testável).

**Release S3:** `v3.54.0` — polish + histórico.

---

## Semana 4 — Lançamento & confiança (3–9 ago)

**Objetivo:** virar **padrão** em 1–2 comunidades, não “mais um exe no Drive”.

| Entrega | Ação |
|---------|------|
| **v3.55.0 “Echo-tier Roblox”** | Tag + release notes em PT, video de 60s (opcional) |
| **Playbook de staff** | PDF 1–2 páginas: o que pedir na call, o que é LIMPO, o que é INCONCLUSIVO |
| **Tabela de honestidade** | “O que o Telador pega / o que não pega / quando pedir admin” |
| **Canal de feedback FP** | Issue template `fp-report` no GitHub |
| **Métrica de campo** | 10 scans reais (amigos/staff): anotar tempo, FPs, veredito certo/errado |

**Go-to-market (orgânico):**

1. Post no Discord das communities que já usam SS.  
2. Comparativo honesto: “open source, 100% local, forense Windows profunda”.  
3. Não atacar Echo — **posicionar**: *Telador = forense local Roblox; Echo = plataforma multi-game paga*.

---

## Arquitetura de produto (alvo 30 dias)

```text
┌─────────────────────────────────────────────────┐
│  Telador GUI (default)                          │
│  [SS Rápido] [Completo] [Ao vivo]               │
└─────────────────┬───────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────┐
│  Engine (já existe)                             │
│  scanners → fp_filter → evidence → coverage     │
│  → veredito único                               │
└─────────────────┬───────────────────────────────┘
                  │
        ┌─────────┴─────────┐
        ▼                   ▼
   HTML report         Discord MD
   (local file)        (clipboard)
```

**Regra de ouro:** zero feature de detecção nova se a GUI/veredito staff estiver quebrado.

---

## Backlog explícito “depois dos 30 dias” (não misturar)

- Site “foda” full marketing  
- Conta / cloud / scan link remoto estilo Echo  
- Multi-game  
- Fechar código  
- OCR / screenshot AI  
- Mais famílias no catálogo por nome (Tier C — churn)

---

## Riscos e mitigações

| Risco | Mitigação |
|-------|-----------|
| Open source = bypass mais rápido | Priorizar comportamental/estado; sigs em arquivo atualizável; não documentar OPSEC no README |
| GUI atrasa detecção | S1 só motor; S2 GUI mínima; detecção nova só se P0 de produto ok |
| FP em dev (você) enviesa | Sempre validar perfil “gamer limpo” + “suspeito Winter” |
| Burnout de release diário | Max 2 releases/semana após 3.51.x; quality gate FP |

---

## Checklist semanal (imprimir)

### Semana 1 — ✅ fechada em 14/07 com v3.52.0 → v3.52.4
- [x] `--ss-live` (71 scanners, medido 21.8s no PC dev — target &lt; 45s ✅)
- [x] Veredito staff 3 linhas — HTML + console + Discord md + JSON (`build_staff_verdict_bullets`)
- [x] Anti-FP baseline gamer/dev: 7 scanners endurecidos + 40+ testes em `tests/test_v352_antifp.py`
- [x] `build.bat` usa `telador.spec` (era destrutivo — apagava o `.spec`)
- [x] Release 3.52.x (5 releases: 3.52.0 → 3.52.4)
- [x] Bonus: Winter Bypass/Fishstrap no core (era só opt-in), sigs 2026.07.14 (+62)

### Semana 2 — ✅ fechada em 14/07 com v3.54.0 + v3.54.1
- [x] GUI com 1 botão Iniciar (CustomTkinter, `--gui`, `INICIAR-GUI.bat`)
- [x] Copiar resumo Discord (botão nativo no verdict screen + clipboard tkinter)
- [x] Zip de distribuição (`pack.py` + CI upload de `Telador-vX.X.X.zip`)
- [x] Playbook staff (adiantado da S4 — `PLAYBOOK.md` já vai no zip)
- [x] Release 3.54.x (v3.54.0 GUI + v3.54.1 zip/playbook)
- [ ] Landing download + SHA256 (site — externo/Vercel, não é código)

### Semana 3 — próxima parada
- [ ] Dashboard ao vivo default (integrar `--watch` como default da GUI)
- [ ] Histórico local de scans (`%LOCALAPPDATA%\Telador\history\*.tsr`)
- [ ] Perfis Rápido/Completo/Paranoia (`--profile fast|full|strict`)
- [ ] Release 3.55.0

### Semana 4
- [x] Playbook staff — feito na v3.54.1 (adiantado)
- [ ] 10 field tests documentados  
- [ ] Release "Echo-tier Roblox" (v3.56.0?)
- [ ] Post de lançamento  

---

## Mensagem de posicionamento (usar em tudo)

> **Telador** — SS forense 100% local pra Roblox.  
> Roda no PC do suspeito, cruza dezenas de fontes do Windows e entrega veredito com confiança.  
> Open source. Sem cloud. Sem mandar dado pra fora.  
> Feito pra call de SS — não pra parecer antivírus genérico.

---

## Próximo passo imediato (Semana 2 começa 20/07)

**Semana 1 está fechada** — motor pronto pra call de SS. Foco agora vira UX.

1. **GUI mínima** (P0 da Semana 2): 1 botão Iniciar → progresso → veredito
   grande com semáforo verde/amarelo/vermelho → [Abrir HTML] [Copiar
   Discord] [Sair]. Já tem `--watch` (dashboard local) — vira default da GUI.
2. **UAC no clique** (P0): se usuário negar admin → tela "INCONCLUSIVO,
   peça admin", não roda scan limitado silenciosamente.
3. **Zip de distribuição** (P1): `Telador-v3.53.zip` = `.exe` + `INICIAR.bat`
   + `TELADOR-AO-VIVO.bat` + playbook 1 página (PDF/MD).
4. **Landing mínimo** (P1): página `/` com download latest + SHA256 + 3
   screenshots + link pro `/playbook` de call de SS.

Release-alvo Semana 2: **v3.53.0 — "Telador com interface"**.

Quando começar Semana 2: *"implementa a GUI mínima do PLANO_ECHO_TIER
Semana 2, começando pelo P0 (janela + botão + tela de veredito)."*
