# Roadmap Telador

Priorização de detecções futuras por **custo de evasão para o cheater** (não
por facilidade de implementação). Um bom scanner é aquele que, mesmo com o
source-code aberto na frente do adversário, exige que ele mude arquitetura
ou compre hardware/certificado pra escapar.

Escala:

- **Tier S** — evadir custa **driver kernel assinado, cert real, ou desligar
  proteção do Windows**. Cheater precisa mexer em infra, não em código.
- **Tier A** — evadir custa **recompilar com outra arquitetura de injeção
  ou renderização**. Trabalho de dev de cheat sério.
- **Tier B** — nicho, ou risco de FP alto.
- **Tier C** — **não fazer**: churn, evadível trivialmente por rename/obf,
  ou perf ruim.

---

## v3.46.0 (planejado) — Tier S

Meta: 4 scanners state-based que dependem do estado do Windows, não do nome
do cheat. Cheater lendo o repo não consegue evadir sem custo real.

- [ ] **`scan_dse_state`** — Driver Signature Enforcement OFF ou Test Mode
  ligado. Fonte: `bcdedit /enum` (`testsigning Yes`, `nointegritychecks Yes`)
  e `Registry\Machine\System\CurrentControlSet\Control\CI\State`. Zero FP em
  máquina normal (Windows sempre vem com DSE ON). **HIGH** sozinho, **CRITICAL**
  se combinado com driver não-MS carregado.
- [ ] **`scan_vbs_hvci_disabled`** — Virtualization-Based Security ou
  Hypervisor-Protected Code Integrity desativados. Fonte: `Get-CimInstance
  Win32_DeviceGuard` (`VirtualizationBasedSecurityStatus`,
  `SecurityServicesConfigured`, `SecurityServicesRunning`). **CRITICAL sozinho**
  — nenhum jogador comum desliga VBS/HVCI. É pré-requisito pra rodar driver
  kernel arbitrário em Win10+ moderno.
- [ ] **`scan_roblox_page_protection`** — enumerar regiões de memória do
  `RobloxPlayerBeta` via `VirtualQueryEx` e flaggar páginas de `.text` do
  módulo principal que estão como `PAGE_EXECUTE_READWRITE` (deveriam ser
  `PAGE_EXECUTE_READ`). Sinal de patching in-memory. Pega internal cheat
  sem depender de nome de família. **HIGH**.
- [ ] **`scan_activities_cache_timeline`** — parse do `ActivitiesCache.db`
  SQLite em `%LOCALAPPDATA%\ConnectedDevicesPlatform\<sid>\`. Tem TODA app
  que rodou nos últimos ~30 dias com timestamp preciso. Cleaner popular não
  sabe limpar. Pega cheat que rodou "há uma semana" mas não deixou Prefetch.
  Match contra `EXECUTOR_KEYWORDS`. **MEDIUM/HIGH** dependendo do keyword.

Escopo colateral:

- [ ] Slugs em `SOURCE_WEIGHTS` (evidence.py):
  - `dse_state = 0.95`
  - `vbs_disabled = 0.95`
  - `roblox_rwx_page = 0.90`
  - `activities_cache = 0.85`
- [ ] Labels em `SOURCE_LABELS` (report_assets.py)
- [ ] Registro em `scanner_registry.py` (grupo `system_hardening` novo)
- [ ] Chain em `telador.py` (respeita `--no-forensics` pra os 4)
- [ ] Testes unitários (~15 casos totais)
- [ ] CHANGELOG entry
- [ ] `SCANNER_COUNT: 90 → 94`

Estimativa de esforço: 45-90 min de sessão focada.

---

## Backlog Tier A — Após v3.46.0

Detecções comportamentais que forçam o cheater a mudar arquitetura.

- [ ] **`scan_apc_injection`** — threads do Roblox em estado ALERTABLE +
  histórico de `NtQueueApcThread`. Pega APC injection (não usa
  `CreateRemoteThread`, escapa do `scan_remote_threads_in_roblox`).
- [ ] **`scan_swapchain_hook`** — verificar vtable de
  `IDXGISwapChain::Present` no processo Roblox. Detecta ImGui overlay
  INTERNAL (renderizado pelo próprio Roblox, sem popup separado). Camada
  de detecção que popup_overlay não cobre.
- [ ] **`scan_amsi_bypass`** — primeira instrução de `AmsiScanBuffer` em
  `amsi.dll` do processo `powershell.exe` deveria ser `mov rax, ...`.
  Se foi patcheada (`ret 0` ou `xor rax, rax; ret`), cheater desligou
  AV local. Sinal HIGH.
- [ ] **`scan_etw_provider_disabled`** — GUIDs de providers ETW críticos
  (`Microsoft-Windows-Kernel-Process`, `Microsoft-Windows-Threat-Intelligence`)
  desabilitados via patch de flag na `_ETW_REG_ENTRY`. Cheater silencia
  telemetria antes de rodar.
- [ ] **`scan_scheduled_task_dropper`** — tasks criadas no último dia
  com trigger `AtLogon` + action rodando exe de user path. Persistência
  clássica de cheat loader.

---

## Backlog Tier B — Nicho ou FP-sensível

- [ ] Byte-comparison do `RobloxPlayerBeta.text` com hash conhecida por
  versão. Requer manter tabela de hashes atualizada (Roblox faz release
  semanal — churn de manutenção alto).
- [ ] Deep parse de `Windows.edb` (Search Index) — arquivos indexados
  mesmo após deleção. Perf caro (ESE/JET parsing) e escopo enorme.
- [ ] Handles nested / broker chain — processo A tem handle a processo B
  que tem handle a Roblox. Perf caro (O(N²) na tabela de handles).
- [ ] `CoreScripts` do Roblox hash check — cheat pode patchear. Extremamente
  raro na prática.
- [ ] TLS SNI inspection via ETW `Microsoft-Windows-Schannel-Events` — pega
  handshake pra KeyAuth mesmo sem DNS. Requer captura ETW ao vivo.
- [ ] Frame time / GPU usage anomaly — overlay D3D adiciona ~5-15% GPU. Só
  detecta com baseline (perf caro, difícil calibrar).

---

## Tier C — **Não fazer**

Explícito pra não desperdiçar tempo em ideias que parecem boas mas não
entregam valor.

- ❌ **Mais famílias no `_FAMILY_CATALOG`** — já são 26. Cheater renomeia,
  esse jogo é churn puro. Private cheats (Winter etc.) nunca cairão aqui.
  Correlation faz o trabalho.
- ❌ **Mais domínios em `SUSPICIOUS_DOMAINS`** — cheater usa IP direto ou
  Discord webhook (que é confiável). Marginal.
- ❌ **Mais SCRIPT_RED_FLAGS keywords** — obfuscação Luau
  (`_G["mou".."semoverel"]`) anula match por substring. Corrigir
  aumentando complexidade do matcher tem FP alto.
- ❌ **YARA rules específicas por família** — cheater recompila com
  oxorany/vmprotect anula. Só vale pra cheats "burros" que já são pegos
  pelo catálogo por nome.
- ❌ **Detecção baseada em screenshot / OCR** — perf horrível, cheater
  esconde overlay durante captura.
- ❌ **Análise cross-machine (HWID clustering)** — fora do escopo de
  forense local. Requer infra server-side.

---

## Limites do sistema

Três limites reais a respeitar:

1. **Performance**: um scan atual roda ~90 scanners em 15-30s. Adicionar
   scanners de forense pesado (MFT deep, ESE/JET parsing, ETW real-time
   capture) pode ir pra 5+ min → operator abandona no meio do telão. Regra:
   qualquer scanner novo deve rodar em < 3s no PC de teste. Se não roda,
   ou entra em modo `--slow` opcional, ou não entra.

2. **FP compound**: 90 scanners hoje já geram noise em máquina de dev/gamer
   avançado (`fp_filter` filtrou 16 items na auditoria v3.45.5). Limite
   prático: **~120 scanners** antes de virar unusable mesmo com fp_filter.
   Isso deixa ~30 slots pra próximas releases.

3. **Meia-vida de detecção**: detecção por nome/hash tem meia-vida de dias
   a semanas (cheater rebuild). Detecção comportamental
   (handle + overlay + RAM + estado do Windows) tem meia-vida de meses ou
   anos porque exige o cheater mudar arquitetura, não código. **Prioridade
   sempre pra comportamental**.

---

## Estratégia geral

O jogo é **cluster engine**. Nenhum scanner isolado é bala de prata; o
`scan_external_correlation` já dispara quando 2+ sinais independentes
convergem no mesmo PID. Adicionar detecções em Tier S/A aumenta o teto
de fontes independentes que o cheater precisa evadir simultaneamente.

Cheater privado (Winter-class) precisa hoje evadir:
- Handle no Roblox
- Overlay POPUP+TOPMOST
- RAM footprint
- Egress de sistema
- WNDCLASS masquerade
- Nome de exe

Depois de v3.46.0, também precisará:
- Manter DSE + VBS ligados (então: sem driver custom)
- Manter `.text` do Roblox R-X (então: sem patch in-memory)
- Deixar rastro em ActivitiesCache (então: sem executar de disk raw)

Cada Tier S fecha uma classe inteira de bypass, não uma família específica.
