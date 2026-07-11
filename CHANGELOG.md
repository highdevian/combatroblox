# Changelog

All notable changes to this project will be documented in this file.

## [3.45.5] - 2026-07-11

**+2 famílias externas: LectureExternal e Nocturnal.**

### `_FAMILY_CATALOG` (+2)

- **`lecture_external`** — `github.com/LectureExternal/lectureExternal`.
  README diz "byfron bypass". Repo distribui `lectureExternal.exe` direto
  na raiz (10 MB) — sem source, só binário. Processos: `lectureexternal.exe`,
  `lecture_external.exe`, `lecture.exe`. Basename `lectureexternal` é IOC
  (não é palavra comum).
- **`nocturnal`** — `github.com/matidebugging0/nocturnal`. README menciona
  ".NET" e "dnspy" (decompilador C#) — perfil **C# externo**, distinto dos
  externals C++ das releases anteriores. Releases distribuídas como GUID.zip
  (`ca7af92a-9491-4c23-a5f2-45c1fb009401.zip`) — nome ofuscado, `scan_random_name_executables`
  já cobre. Processos: `nocturnal.exe`, `nocturnalroblox.exe`,
  `nocturnalloader.exe`.

### Anti-FP: `nocturnal` bare

`nocturnal` (sem qualificador) NÃO é IOC — palavra comum em poesia/música/
handles de streamers. `basenames: []` de propósito, mesma doutrina de
`autopsy` bare (v3.45.2). Requer:
- Processo direto (`nocturnal.exe`, `nocturnalroblox.exe`, …), OU
- Token com contexto (`nocturnal roblox`, `nocturnal external`,
  `nocturnal bypass`, `nocturnal byfron`).

### Testes

- `tests/test_external.py` +5: registro das duas famílias, basename match,
  anti-FP de `nocturnal` bare, hit com contexto.
- **637 passed** (era 632).

### Contagem

- Famílias em `_FAMILY_CATALOG`: 24 → **26**.
- SCANNER_COUNT: 90 (só catálogo).

---

## [3.45.4] - 2026-07-11

**Window class names direto do fonte: `autopsy.lol` + masquerade "Task Manager".**

Análise do source de `github.com/pwpo/autopsy` e `github.com/Russtels/Layuh-Roblox`
(via `gh api search/code`) revelou **os nomes exatos das WNDCLASS** que os
externals registram — IoCs muito mais fortes que match por process name.

### `_KNOWN_EXTERNAL_WINDOW_CLASSES` (+1)

- **`autopsy.lol`** — extraído de `autopsy/src/ui/graphic.cpp`:
  ```cpp
  Detail->WindowClass.lpszClassName = "autopsy.lol";
  RegisterClassExA(&Detail->WindowClass);
  Detail->Window = CreateWindowExA(... WS_POPUP, ...);
  ```
  Uma janela POPUP+TOPMOST com class literal `autopsy.lol` = crava. Zero FP.

### `_MASQUERADE_WINDOW_CLASSES` (NOVO — 1 entrada)

Layuh (`Layuh-Roblox/Layuh/cheat/menu/ui/render/overlay.cpp`) registra:
```cpp
WNDCLASSEXW wc = { ..., oxorany(L"Task Manager"), nullptr };
::RegisterClassExW(&wc);
::CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, wc.lpszClassName,
                  oxorany(L"Task Manager"), WS_POPUP, ...);
```

O cheat cria uma janela com **classe e título "Task Manager"** — imita o
Task Manager do Windows pra passar despercebido no SS visual. A obfuscação
com `oxorany` só protege o binário; em runtime a class exposta é a string
plain.

Novo mapa `_MASQUERADE_WINDOW_CLASSES = {"task manager": {"taskmgr.exe"}}`:
se `GetClassNameW` bate `Task Manager` mas o processo dono não é
`taskmgr.exe` → HIGH masquerade. Match: `popup-overlay-masquerade:task manager:<pname>`.

### `SUSPICIOUS_DOMAINS` (+1)

- **`autopsy.lol`** — brand do cheat, aparece como title da `MessageBoxA(...,
  "Open Roblox first.", "autopsy.lol", ...)` no `src/main.cpp`. DNS cache /
  browser history / hosts file com este domínio = cheater tocou o autopsy.

### Testes

- `tests/test_external.py` +3: `test_autopsy_lol_window_class_registered`,
  `test_masquerade_window_class_taskmgr`, `test_autopsy_lol_domain_in_suspicious`.
- **632 passed** (era 629).

### Contagem

- `_KNOWN_EXTERNAL_WINDOW_CLASSES`: 2 → 3.
- `_MASQUERADE_WINDOW_CLASSES`: 0 → 1 (novo mapa).
- `SUSPICIOUS_DOMAINS`: 141 → **142**.

---

## [3.45.3] - 2026-07-11

**Aimbot Luau: 6 IoCs de APIs de executor pra aimbot/ESP.**

Análise do repo `github.com/dev79kz/AimbotScript` (o próprio título diz
"External" mas é Luau in-process, precisa de executor Solara/Xeno-class)
revelou que o Telador cobre `getgenv()`/`getgc()`/`hookfunction` mas
**não cobria** as APIs de executor mais decisivas pra aim/ESP.

### `SCRIPT_RED_FLAGS` (+6)

**HIGH (4)** — zero uso legítimo:
- **`mousemoverel`**: função exposta APENAS por executor pra mover o mouse
  do OS a partir do script Lua (aim-assist "external" saindo do Roblox).
  Roblox client nativo nunca expõe. Um match aqui = executor rodou aim.
- **`drawing.new(`**: Drawing API é exclusiva de executor. Roblox não expõe
  Drawing.new. Primitivas `"Circle"` (FOV), `"Square"` (ESP box), `"Line"`
  (tracer), `"Text"` (name/HP).
- **`fovcircle`**: nome de variável distintivo do combo aimbot + FOV
  visualizer. Se aparece em cache/log/prefetch, é aimbot dropado.
- **`camera.cframe = cframe.new(camera.cframe.position`**: aim-snap
  clássico (rotaciona câmera pra apontar exatamente no alvo). Match
  case-insensitive por substring — sobrevive a whitespace variation.
  Nenhum jogo dev normal escreve isso.

**MEDIUM (2)** — APIs públicas, uso quase-exclusivo em cheat:
- **`worldtoviewportpoint`**: projeção 3D → 2D. Necessária pra desenhar
  ESP mas tem uso raro em UI custom de jogo.
- **`getpartsobscuringtarget`**: raycast entre câmera e alvo. Assinatura
  de wallcheck; uso legítimo em stealth game é raro.

### Testes

- `tests/test_detection.py` +3: `test_aimbot_luau_executor_apis_high`,
  `test_aimbot_luau_borderline_apis_medium`,
  `test_aimbot_script_full_pattern_matches` (roda o script inteiro do
  repo dev79kz/AimbotScript contra as flags e valida 4 matches).
- **629 passed** (era 626).

### Contagem

- `SCRIPT_RED_FLAGS`: 104 → **110**.
- SCANNER_COUNT: 90 (só flags novas, sem scanners).

---

## [3.45.2] - 2026-07-11

**IoCs de repos públicos: KeyAuth, offset feeds, 3 famílias novas, GLFW class.**

Levantamento em 4 repos públicos de external Roblox (`Russtels/Layuh-Roblox`,
`nordlol/nord-external`, `dev79kz/AimbotScript`, `pwpo/autopsy`) revelou
IoCs concretos que o catálogo v3.45.1 ainda não cobria.

### `SUSPICIOUS_DOMAINS` (+9 entradas HIGH)

- **KeyAuth (6)** — SaaS de DRM/licensing embutido em ~todo external pago
  (Layuh depende dele). Handshake HTTPS aparece em DNS cache, browser cache,
  `scan_network_connections`. Um browser que fez DNS pra `keyauth.win` teve
  cheat pago rodando aqui em algum momento.
  - `keyauth.win`, `keyauth.cc`, `keyauth.pro`, `keyauth.gg`,
    `keyauth.to`, `keyauth.us`
- **Offset feeds (3)** — sites que publicam offsets do `RobloxPlayerBeta`
  atualizados para cheaters sincronizarem builds. Ninguém legítimo visita.
  Referenciados em `autopsy` (imtheo.lol/Offsets).
  - `imtheo.lol`, `rbxoffsets.com`, `robloxoffsets.com`

### `_FAMILY_CATALOG` (+3 famílias)

- **`layuh`** — `Russtels/Layuh-Roblox`, C++ com KeyAuth + oxorany (obf
  compile-time) + curl + zlib. Menciona interação "kernel/system-level".
  Processos: `layuh.exe`, `layuhroblox.exe`, `layuhloader.exe`.
- **`nord_external`** — `nordlol/nord-external`, universal ESP em C++ com
  overlay GLFW. Renderer via GLFW = janela `WS_POPUP+TOPMOST` com class
  name `GLFW30`. Processos: `nord.exe`, `nordexternal.exe`, `nord_external.exe`.
- **`autopsy`** — `pwpo/autopsy`, external usermode-only C/C++. Referencia
  `imtheo.lol/Offsets`. Processos: `autopsy.exe`, `autopsyloader.exe`.
  **`autopsy` bare NÃO é IoC** (também é ferramenta forense legítima do
  Sleuth Kit) — `basenames: []`, só entra por processo/token com "roblox".

`dev79kz/AimbotScript` é Lua puro em-processo Roblox (delivery por executor
Luau) — coberto pelas fontes internas existentes (Solara/Xeno-class), não
requer nova família.

### `scan_popup_overlays` — escalador por class name

Janela `WS_POPUP+TOPMOST` fora da whitelist com class name em
`_KNOWN_EXTERNAL_WINDOW_CLASSES = {"glfw30", "glfwwindow"}` sobe pra **HIGH**
em vez de MEDIUM. Match rule: `popup-overlay-framework:<class>:<pname>`.
Rationale: `GLFW30` fora de jogos indie/demos openGL POPUP+TOPMOST é
assinatura de external ESP. `nord-external` cai aqui direto.

### Testes

- `tests/test_external.py` +6 testes: 3 famílias novas, GLFW const,
  KeyAuth domains, offset feed domains.
- **626 passed** (era 620).

### Contagem

- `SUSPICIOUS_DOMAINS`: 132 → 141.
- Famílias em `_FAMILY_CATALOG`: 21 → **24**.
- `SCANNER_COUNT`: mantém 90 (só melhorias de catálogo, sem scanners novos).

---

## [3.45.1] - 2026-07-11

**Anti-FP CRITICAL: System (PID 4) e RobloxCrashHandler no handle scan.**

- Whitelist `system` / PID 0+4 e `robloxcrashhandler.exe` (dump legítimo).
- Auditoria máquina limpa pós-fp_filter: **0 hits visíveis**.

## [3.45.0] - 2026-07-11

**External residual: Roblox FECHADO + SS pós-limpa (Winter-class).**

- **Handles**: fix OpenProcess→re-query (bug que quebrava resolução do
  EPROCESS); SeDebugPrivilege; fallback por frequência; Roblox fechado =
  meta_only (não erro de cobertura).
- **Footprint / post-Roblox / remote-thread**: âncora Prefetch quando o
  client não está vivo; residual ±2h / +6h da última sessão.
- **Novos**: `scan_unsigned_user_network` (user-path + TCP pública),
  `scan_suspicious_process_ancestry` (shell→unsigned perto da sessão).
- **Correlation**: por PID **e** basename (sobrevive a fechar o processo);
  merge pid↔base; inclui artefatos em disco + rede + ancestry.
- **DXCache**: threshold 3/20min, janela 48h.
- SCANNER_COUNT 88 → **90**.

## [3.44.4] - 2026-07-11

**Anti-FP: dual-use do supervisor some no PC de dev.**

- `DEV_SUPPRESS_KEYWORDS`: TinyTask, Process Hacker, System Informer,
  AutoClicker, exclusões Defender de pasta/dev (portfolio, JetBrains).
- Em cheater sem ambiente de dev, esses sinais continuam.

## [3.44.3] - 2026-07-11

**Anti-FP: TinyTask some no PC de dev (supervisor); em cheater continua.**

- `DEV_SUPPRESS_KEYWORDS` no fp_filter: `tinytask` é removido do report
  quando o ambiente é de desenvolvimento (VS/JetBrains/Git/etc).
- Em máquina sem indicadores de dev, TinyTask segue MEDIUM multi-fonte.

## [3.44.2] - 2026-07-11

**Anti-FP: allowlist de domínios quebra com BOM; exclusão Desktop não é HIGH.**

- `load_trusted_domains`: `utf-8-sig` (BOM do PowerShell) + tenta o próximo
  candidato se o JSON estiver quebrado (antes travava nos 2 Discord defaults).
- Exclusão Defender em Desktop/Documents sem marcador de repo: MEDIUM
  (portfolio/projeto). Downloads/Temp/AppData continuam HIGH.

## [3.44.1] - 2026-07-11

**Anti-FP: o próprio Telador e scripts de dev/docs não viram “executor”.**

- Self-whitelist: `telador.exe`, `telador (64).exe`, `telador-*.exe` fora de
  footprint / post-Roblox / correlation / handles.
- Script block 4104 + PS history: wordlists, `match_keyword`, docs/release
  notes e path `combatroblox` não disparam por citar nome de família.
- `trusted_domains.example.json` com domínios de dev/pkg comuns (x.ai,
  opencode, scoop, etc.) — copie pra `%LOCALAPPDATA%\Telador\trusted_domains.json`.

## [3.44.0] - 2026-07-11

**Caça a external PRIVATE (Winter-class): 11 detecções + forense pós-mortem
que sobrevive a cleaner.**

O catálogo de famílias (Matcha/Severe/DX9/Serotonin/…) das v3.43.5-3.43.7
pega external público — o cheater que compra o produto e roda sem trocar
nomes. Externals private (Winter Bypass, forks obfuscados, produtos pagos
que rotacionam o build) escapam do match por nome. **Esta release traz o
que private não consegue esconder**: handle no Roblox, working set, thread
remota, egress de sistema, overlay D3D, correlação de sinais. Mais 4
scanners que pegam **resíduo pós-mortem** — quando o cheater fechou o
cheat + rodou cleaner + só deixou você entrar por AnyDesk depois.

### External hunting técnico (`external_scanner`)

O módulo `external_scanner.py` mantém `_FAMILY_CATALOG` + `scan_external_processes`
+ `scan_external_artifacts` (3.43.7) e **adiciona 9 detecções que não dependem
do nome do cheat**:

- **`scan_external_process_handles`** (HIGH/CRITICAL) — enumera todos os handles
  do Windows via `NtQuerySystemInformation(SystemExtendedHandleInformation)` e
  filtra os com `PROCESS_VM_READ`/`VM_WRITE`/`VM_OPERATION` no
  `RobloxPlayerBeta`. É EXATAMENTE o que external precisa. Handle64.exe é
  usermode e cheat driver-based esconde; NT layer pega mais. **VM_WRITE = CRITICAL**
  (patchar memória do Roblox é único uso: cheat).
- **`scan_external_memory_footprint`** (MEDIUM) — processos com working set
  > 50 MB, exe não-assinado, user path, Roblox ativo. External buferiza
  leituras de memória — RAM inflada é tell involuntário. Whitelist cobre
  Discord/Chrome/Spotify/VS Code.
- **`scan_remote_threads_in_roblox`** (HIGH) — usa
  `NtQueryInformationThread(ThreadQuerySetWin32StartAddress)` pra ler
  `StartAddress` de cada thread do Roblox. Threads cujo start cai fora de
  qualquer módulo carregado = `CreateRemoteThread` (injetor externo).
  Complementa `scan_roblox_manual_map`: shellcode fino não deixa PE header
  mas deixa StartAddress órfão.
- **`scan_kernel_only_egress`** (HIGH, crava sozinho) — conhost/dwm/csrss/
  wininit/fontdrvhost/sihost/spoolsv/audiodg com TCP externa `ESTABLISHED`.
  Esses processos nunca fazem rede em Windows normal — se fazem, é
  masquerading + phone-home. **FP zero** conhecido.
- **`scan_popup_overlays`** (MEDIUM) — janelas `WS_POPUP+TOPMOST` sem
  transparency (D3D/DComp overlay). Complementa `scan_overlay_windows`
  clássico que pegava `LAYERED+TRANSPARENT+TOPMOST`. External private
  moderno prefere D3D em popup.
- **`scan_post_roblox_processes`** (MEDIUM) — não-assinado, user path,
  iniciado APÓS o Roblox. External só existe pra atacar o jogo; roda depois
  pra ter alvo. Sozinho é sinal comportamental; no correlation eleva.
- **`scan_suspicious_named_pipes`** (MEDIUM) — pipes hex/GUID. IPC clássica
  entre reader (memory) e renderer (overlay). Regex apertada não pega
  pipes com palavras (WiFiNetworkManagerTask etc).
- **`scan_random_name_executables`** (MEDIUM) — `.exe` com nome
  hex/base32/GUID em user path. Builds randomizados escapam de blacklist.
- **`scan_external_correlation`** (HIGH/CRITICAL, crava sozinho) — agrega
  os 8 sinais por PID. 2 sinais no mesmo PID = HIGH. 3+ = CRITICAL. Também
  cruza com `scan_external_processes` (catálogo) e `scan_overlay_windows`
  do `live_analysis`. **É esse scanner que pega Winter Bypass**: mesmo sem
  nome no catálogo, handle + overlay + footprint no mesmo PID = quase
  impossível ser app legítimo.

### Forense pós-mortem (`anti_forensic_deep`, novo módulo)

Pega resíduo que sobrevive a "fechei o cheat e rodei cleaner":

- **`scan_defender_detection_history`** (HIGH) — parse binário dos arquivos
  `MpBinaryFormat` em `C:\ProgramData\Microsoft\Windows Defender\Scans\
  History\Service\DetectionHistory`. Extração de path (ASCII + UTF-16 LE),
  threat name (HackTool/Trojan/…), hash SHA. Se o Defender viu o cheat
  algum dia, aparece — **mesmo após clicar "Allowed" ou rodar cleaner**.
- **`scan_dxshader_cache`** (LOW) — burst de shader D3D em `%LOCALAPPDATA%\
  NVIDIA\DXCache`/`AMD\DxCache`/`D3DSCache`. External com ESP renderizado
  via D3D obriga o driver a compilar shader. Sliding window de 15min:
  5+ shaders = burst. Ponteiro pra revisar sessão específica.
- **`scan_wer_reports`** (HIGH) — enumera `Report.wer` em
  `%ProgramData%\Microsoft\Windows\WER\ReportArchive` e `ReportQueue`.
  Parse INI UTF-16 pra extrair `AppPath` e `AppName`. Todo exe que
  crashou (mesmo silenciosamente) fica gravado com **full path** —
  cleaner popular não mexe aí.
- **`scan_reliability_monitor`** (LOW) — RAC (`C:\ProgramData\Microsoft\
  RAC\StateData`) e SUM (`C:\Windows\System32\LogFiles\Sum`). Logs de
  execução/instalação/crash. Ponteiro pra abrir `perfmon /rel` manual.

### Correção de FPs

- **`scan_roblox_launcher_integrity`**: `RobloxPlayerInstaller.exe` e
  `RobloxStudioInstaller.exe` removidos de `_ROBLOX_OFFICIAL_BINARIES`.
  Verificado empiricamente com `Get-AuthenticodeSignature`: o installer
  vem **`NotSigned`** (é um dropper leve — Roblox só assina Beta/Launcher/
  Studio, que são os que rodam no fluxo de jogo). Antes, esse scanner
  cravava HIGH em toda máquina com Roblox — quebrando `test_launcher::
  test_real_clean_machine_zero_hits`. Installers permanecem em
  `_ROBLOX_MASQUERADE_NAMES` (cenário 2 do scanner) via novo set
  `_ROBLOX_INSTALLERS`.
- **`trusted_domains.example.json`**: exemplos mais realistas com domínios
  de dev/pkg-manager comum (x.ai, opencode.ai, get.scoop.sh, python.org,
  rustup.rs, raw.githubusercontent.com).

### Bugs internos (novos módulos)

- **`_find_process_type_index`**: cacheia índice — não muda em runtime, era
  re-scan de 100k+ handles a cada chamada (perf 10×).
- **`_query_object_type_name`**: usa `NtQueryObject` no handle da nossa
  própria tabela pra descobrir o slot "Process".
- **UTF-16 pattern matching**: regex em bytes crus falha em metacaracteres
  (parser via bytes de `(` vira `(\x00` e quebra). Fix: decodifica como
  UTF-16 LE e roda regex string. Isso já cai pra `defender_history`.
- **Severity lógico**: handle com VM_WRITE/VM_OPERATION agora corretamente
  CRITICAL (era `high if X else high` — literal identity, bug).
- **`_module_ranges_via_virtualquery`**: setup de `argtypes` movido pro top
  (não mutava em cada call).

### Fontes/pesos (Confidence Engine)

10 novos slugs em `SOURCE_WEIGHTS`:
- Técnicos: `external_reader=0.92`, `external_footprint=0.72`,
  `remote_thread=0.90`, `kernel_only_egress=0.95`,
  `external_correlation=0.98`, `popup_overlay=0.75`,
  `post_roblox_proc=0.70`, `suspicious_pipe=0.60`, `random_name_exe=0.75`
- Pós-mortem: `defender_history=0.92`, `dxshader_burst=0.55`,
  `wer_crash=0.88`, `reliability_monitor=0.60`

### Testes

- `tests/test_external.py`: catálogo de famílias + detecções técnicas +
  correlation com stubs (11 scanners).
- `tests/test_anti_forensic_deep.py`: extração ASCII/UTF-16, burst de
  shader, WER INI, anti-FP de path benigno/installer.
- **609 testes verdes** na v3.44.0. O
  `test_launcher::test_real_clean_machine_zero_hits` (quebrado pelo
  installer não-assinado) passa de novo.

### Contagem de scanners

- **SCANNER_COUNT**: 75 → **88** (11 external: 2 catálogo + 9 técnicos;
  4 anti-forensic deep; resto do stack 3.43.7).

---

## [3.43.7] - 2026-07-09

**Pesquisa web de externals Roblox → catálogo de famílias + IOCs aplicados.**

### Catálogo public (2024–2026)

Fontes: Reddit r/robloxhackers, UnknownCheats, showcases YouTube (nomes de
produto — **sem** hashes instáveis de crack).

| Família | Notas |
|---|---|
| Matcha | paid, driver/kernel frequente |
| Severe | paid de longa data (ESP/aimbot/script ext.) |
| DX9WARE / DX9 | external kernel-class |
| Matrix / MatrixHub | external (≠ bare "matrix") |
| Celex | Da Hood external (cracks = malware risk) |
| Bauix | moon.sex |
| Sheldon, Vasile, Ronin-ext, Mooze, Oxygen-ext | free/paid showcases |
| timeoutwtf, Santoware, Photon-ext, Clarity-ext | compostos only |
| Serotonin, Spxrkz, Yerba-ext, Polter (.sys) | cena UC/tags |
| genérico | robloxexternal / external aimbot\|esp\|cheat |

### Código

- **`external_scanner._FAMILY_CATALOG`**: fonte única → process/path/basename/alias.
- **`evidence`**: importa `EXTERNAL_ALIAS_MAP` do scanner (cluster unificado).
- **`database`**: keywords + process + folders + domains `moon.sex`, `celex.gg`.
- **Anti-FP**: sem bare `matrix`/`photon`/`dx9`/`sheldon.exe`/`loader.exe`.

## [3.43.6] - 2026-07-09

**Cluster unificado de external + corroboração forense.**

### Confidence Engine

- **`TargetId(scheme="external", family)`**: Matcha/Vasile/… deixam de fragmentar
  em `executor:matcha` vs `raw:external-proc:…` vs path solto.
- **`EXTERNAL_ALIAS_OVERRIDES`**: `matcha.exe`, `matcha external`, `matcha beta`,
  `matchaloader`, etc. → family `matcha` (idem outras famílias).
- **Merge path→external**: pasta `…\Matcha Beta\loader.exe` entra no mesmo cluster.
- **Corroboração**: se cluster external já tem Prefetch/Amcache/BAM/driver + live,
  adiciona fonte `external_corroboration` (low) — sobe diversity sem inventar hit.
- **Anti-FP**: `loader.exe` / `map.exe` sozinhos **não** são IOC (setup Matcha
  só conta via pasta/família).

### Testes

- `test_matcha_variants_unify_to_one_cluster` e aliases de família.

## [3.43.5] - 2026-07-09

**Detecção de external cheat Roblox** (aimbot/ESP fora do cliente — distinto de
executor Luau tipo Xeno/Solara).

### External cheat

- **`external_scanner.py`**: 2 scanners novos
  - processo vivo com nomes de famílias (Matcha, Vasile, Bauix, Sheldon, …)
  - artefatos em disco (Downloads/AppData/Desktop/Temp) via basename + path tokens
- **Confidence Engine**: source `external_cheat` (peso 0.85), kind `external_cheat`,
  label no relatório HTML/MD.
- **Anti-FP**: blocklist de overlays legítimos (Discord, NVIDIA, Medal, Overwolf,
  OBS, SteelSeries, Game Bar, …). Overlay click-through em `live_analysis` ganhou
  Medal/Overwolf/SteelSeries.
- **IOCs embutidos** em `database.py` (keywords + process names + folders) para
  Prefetch/Amcache/BAM também casarem as famílias.
- **`signatures.json`**: seções `external_process_names`, `external_path_tokens`,
  `external_basenames` (severity + family opcional).
- **75 scanners** no registry (`version.SCANNER_COUNT`).
- Testes: `tests/test_external.py`.

> Slot de signatures de propósito: rebuilds diários mudam o .exe — popule com
> Prefetch/path reais do teu SS (Matcha etc.) via `signatures.json`.

## [3.43.4] - 2026-07-09

**Qualidade de produto para SS real**: cobertura, veredito inconclusivo, redação
mais larga, anti-FP de PC de dev, registry de scanners, Markdown Discord-ready.

### Veredito e cobertura

- **`scan_coverage.py`**: agrega scanners ok/erro, flags `--quick`/`--only`/sem admin
  e promove **LIMPO → INCONCLUSIVO** quando a cobertura é incompleta.
- **Relatório HTML**: painel "Cobertura do scan" + "Resumo do operador (30 s)";
  hero trata INCONCLUSIVO de forma explícita.
- **`fp_filter`**: não reescreve mais `status=error` para `clean` após o FP
  filter (cegueira de fonte deixa de parecer "limpo").
- **`--quick`**: aviso no console de que LIMPO é inconclusivo até full scan.
- **Markdown** (`--md` ou com `--codigo`): inclui cobertura, clusters e erros.

### Privacidade / segurança

- **`--no-redact`**: banner vermelho obrigatório; default continua redigindo.
- **Redação**: JWT, Telegram bot token, PEM private key.
- **Screenshot**: lista maior de password managers (Proton, Keeper, VeraCrypt…).
- **SECURITY.md**: escopo in/out e defaults de privacidade.

### Anti-FP

- **DEV_INDICATORS**: Cursor, Windsurf, Python 314, rustup/cargo, pastas
  `dev`/`Projects`/`github`.
- Testes de regressão: `tests/test_coverage.py`, `test_redaction_extra.py`,
  `test_dev_env_fp.py`.

### DX / estrutura

- **`version.py`**: versão canônica `3.43.4` (banner + `version_info.txt`).
- **`scanner_registry.py`**: inventário de **73** scanners (grupos, admin, quick).
- **Watch dashboard**: progresso com contagem de erros, SEM ADMIN e veredito.
- **Ruff**: 6× F541 f-strings sem placeholder corrigidos.

## [3.43.3] - 2026-07-08

**Correções de uma revisão de QA/segurança** do relatório redesenhado (v3.43.2).

### Segurança

- **XSS via `<title>`** (`report.py`): o hostname da máquina
  (`socket.gethostname()`) era interpolado no `<title>` sem escape — o único
  ponto do relatório que não passava por `_escape`. Explorável com um payload
  `</title>...` (provado em navegador). Exploração prática baixa (nome de PC
  no Windows não aceita `<`/`>`), mas depender da validação do SO não é
  controle de segurança. Agora escapado.

### Frontend / robustez

- **Cor legada em JS** (`report.py`): o highlight da navegação por teclado
  (`j`/`k`) ainda usava o vermelho neon antigo; migrado pra oklch do site.
- **Tabelas de detalhe** (`report.py`): 6 colunas rolam na horizontal em telas
  estreitas (`.table-wrap` com `overflow-x` só no mobile — não quebra o sticky
  header no desktop).
- **Copiar código** (`report.py`): `navigator.clipboard.writeText` era chamado
  direto; aberto como `file://` sem a API isso lançava `TypeError`. Agora tem
  `safeCopy` com fallback pra `execCommand`.

## [3.43.2] - 2026-07-08

**Relatório HTML redesenhado** pra bater com o site
(combatroblox-forensics.vercel.app). Antes o report e o site tinham
identidades visuais totalmente diferentes; agora são a mesma família.

### Visual / relatório

- **Nova skin "forensic dark lab"** (`report.py`): paleta oklch exata do site
  (preto frio + texto papel quente, destructive/evidence/cold), Fraunces serif
  nos títulos, Inter Tight no corpo, JetBrains Mono nos números/códigos — com
  fallback de sistema (Georgia/Segoe UI/Consolas) pra manter o relatório
  **100% offline**. Grid-paper de fundo, faixas de perigo, chips de evidência,
  cantos retos de 2px. É um bloco de override no fim do CSS — não reescreve o
  relatório, só sobrepõe a identidade.
- **Cores de severidade na fonte** (`report_assets.py`, `fp_filter.py`): as
  cores emitidas *inline* (gráficos, stats, dots, veredito) migraram do neon
  antigo pra paleta oklch do site, então donut/barras/números casam.

### Fixes

- **Alpha shorthand quebrava com oklch** (`report.py`, `report_assets.py`): o
  código montava `{cor}20`/`{cor}50` e `var(--hv-accent)15` (alpha hex), que é
  inválido com `oklch(...)`. Trocado por `color-mix(in oklch, ...)`.

## [3.43.1] - 2026-07-07

**Fixes de FP e vazamento** achados no smoke test do dono na própria máquina
(um PC de dev limpo dava "ALTAMENTE SUSPEITO" e o relatório expunha um webhook).

### Segurança / redação

- **`redaction.py`**: mascara URLs de webhook do Discord e do Slack
  (`discord.com/api/webhooks/<id>/<token>`, `hooks.slack.com/services/...`).
  Antes, um `Invoke-RestMethod` pra webhook no histórico do PowerShell vazava
  o token INTEIRO no relatório — que é feito justamente pra ser compartilhado.

### Anti-FP

- **`cross_correlate` ciente de severidade** (`telador.py`): um alvo que é LOW
  em TODAS as fontes não vira mais "ALTA CONFIANÇA" só por aparecer em 3+
  lugares. LOW é ambíguo por definição (ferramenta dual-use tipo Process
  Hacker/System Informer num PC de dev) — cross-correlacionar ambíguo não
  fabrica confiança. Alvo com severidade real (>= medium) em 3+ fontes
  continua sinalizado.

## [3.43.0] - 2026-07-07

**Costura de operador (`--seam`)** — nova categoria de detecção pra conta
revezada/pilotada entre partidas: o xitado joga na conta de um membro limpo,
sai, e o dono limpo joga o resto. A tela ao vivo só prova quem controla a
conta AGORA, não o passado — então isso escapa da SS normal. Além disso, o
time-decay do `fp_filter` passou a resistir a corroboração multi-fonte.

### Novo

- **`seam_scanner.py`**: detecta troca de operador numa série de partidas.
  Acha a costura (degrau de skill via z-score + d de Cohen entre dois blocos
  contíguos) e corrobora com `login_ip`/`device` do histórico de login do
  Roblox e `ping_ms`. Costura corroborada por IP/dispositivo = `critical`.
  Consome um JSON de partidas (ver `seam.example.json`); é data-driven, então
  NÃO entra no auto-scan de zero-arg — é ligado por `--seam <arquivo.json>` e
  roda na chain do telador como qualquer scanner (console, veredito,
  HTML/JSON/MD).
- Gate de magnitude absoluta + bloco mínimo de 2 partidas pra costura só-skill
  (corroborado por IP passa com 1) — mata FP de "esquenta" e de jogo isolado.

### Confidence Engine

- **`evidence.py`**: novo kind `operator_swap` e fonte `operator_seam` (peso
  0.90). Toda evidência `seam-*` agrupa num alvo dedicado ("Troca de operador").

### Anti-FP

- **Decay ciente de corroboração** (`fp_filter.py`): o MESMO alvo visto em ≥3
  fontes independentes não decai com a idade (5 fontes num Solara de 4 meses
  ainda é cheater); 2 fontes atenuam um nível; 1 fonte (artefato velho isolado)
  decai cheio, como antes. A contagem de fontes reusa o clustering do
  Confidence Engine (merge path→executor), pra não fragmentar. A costura é
  isenta de decay — ali o timestamp é a hora da partida, não idade de artefato.

### Testes

- `tests/test_seam.py`: 28 testes da costura de operador.
- `tests/test_corpus.py`: corrige um teste time-bomb (o corpus de cheater usava
  timestamps fixos que envelheciam além do limiar do decay e faziam o teste
  falhar sozinho com o tempo — agora relativos a `now()`) e cobre a resistência
  de corroboração ao decay.

## [3.42.1] - 2026-06-30

**Hardening do `scan_windows_events`** — smoke test do dono na própria máquina
pós-v3.42.0 mostrou 2 FPs reais que sobreviviam ao `fp_filter` (ou que o
filtro só rebaixava no resumo final mas o scanner imprimia HIGH ao vivo).
Patch: suprimir na fonte, sem precisar do filtro pós-processamento.

### Anti-FP

- **`LEGIT_DEV_INSTALL_PATHS`** (`extra_forensics.py`): paths de instalação
  OFICIAL de ferramentas dual-use (Process Hacker, System Informer, Cheat
  Engine, dnSpy, IDA, Ghidra, BullZip, Foxit, Wondershare, PDF24). Quando
  o evento 7045 tem ImagePath nesse path, `_classify_service_install`
  retorna `None` — install oficial não é BYOVD-dropper. Outras fontes
  (BAM, Prefetch, MUICache) ainda pegam a presença como LOW. Resolve o
  HIGH falso de `KProcessHacker3` que aparecia em qualquer PC com System
  Informer instalado.
- **`BENIGN_KERNEL_DRIVERS`** (`extra_forensics.py`): nomes específicos de
  drivers kernel-mode de software legítimo de produtividade — PDF virtual
  printers (PDFWKRNL, bzwriter, dopdf, fpdfinst, novapdf, pdf24,
  pdfcreator, primopdf, wppwriter, doc2pdfm) e outros (obs-virtual-cam).
  Esses casavam a heurística `svc-install-userpath-driver` porque
  instaladores rodam de Downloads/Temp; agora o nome é gate de
  suppressão. Resolve o MEDIUM falso de `PDFWKRNL` em qualquer PC com
  PDF virtual printer instalado.
- **Suppression em DOIS gates ANTES das heurísticas positivas** (Gate A:
  path oficial; Gate B: nome benigno). Adversário tentando bypass com
  Process Hacker portable em Downloads (path NÃO oficial) ou com driver
  desconhecido mantém o sinal — Gate A só dispara em Program Files, Gate
  B só em lista explícita.

### Tests

7 testes de regressão em `tests/test_winevent.py`:
`test_process_hacker_official_install_suppressed`,
`test_system_informer_official_install_suppressed`,
`test_process_hacker_portable_in_downloads_still_flagged`,
`test_random_kernel_driver_in_downloads_with_obscure_name_medium`,
`test_pdfwkrnl_benign_driver_suppressed`,
`test_pdf24_benign_driver_suppressed`,
`test_random_userpath_kernel_driver_still_flagged`.

**73 scanners, 500 testes.**

## [3.42.0] - 2026-06-30

Roadmap do curso Purple ScreenShare (anti-bypass FiveM) cruzado com o stack
atual; 3 lacunas reais viraram scanner. Auditoria pré-release pegou 6
problemas de FP/bug — todos corrigidos antes do release.

### Added

- **Round-trip detection no `clock_tampering.py`**
  (`_detect_round_trip_pairs`): pega pares 4616 forward+rollback curtos pelo
  MESMO SID interativo em <60s real, soma ~0. Trick do bypass que altera o
  relógio temporariamente pra forçar o Explorer a recarregar config (sem
  matar/restartar — não gera 6005/6006). Cada perna individual era ignorada
  pelo loop principal (<10min); aqui pegamos o padrão. MEDIUM, matched
  `clock-roundtrip`. Sort e gap calculados por `prev` (wall-clock real antes
  do salto), não por `new` (que está mexido) — sort por `new` invertia a
  sequência quando o segundo evento era rollback.

- **`scan_log_clearance` no `winevent_scanner.py`**: novo scanner cobrindo
  Event Log apagado ALÉM do 1102 (que pega Security limpo, em
  `extra_forensics.scan_anti_forensics`):
  - **EventID 104** (canais System/Application, Provider
    `Microsoft-Windows-Eventlog`): clear-log em log não-Security → HIGH.
  - **EventID 3079** (Application, Provider `Ntfs`) e **501** (canal
    `Microsoft-Windows-Ntfs/Operational` com fallback `System`, Provider
    `Ntfs`): USN journal truncado/apagado → MEDIUM (pode ocorrer em desfrag
    pesada/chkdsk — verifique janela).
  Não duplica com `extra_forensics.scan_event_log_gap`, que pega deleção
  FURTIVA do .evtx sem evento.

- **`service_state_scanner.py`** — novo módulo. Checa STATUS RUNTIME (não
  Start Type) de serviços forenses críticos parados:
  - `eventlog` parado = HIGH sozinho (cega TODO Event Log enquanto parado).
  - 3+ críticos parados juntos (`dps`, `diagtrack`, `pcasvc`, `cdpusersvc_*`)
    = HIGH `multi` (combinação típica de AtlasOS/ReviOS/Ghost Spectre/Lite
    Gamer — Windows modificado).
  - 2 parados = MEDIUM `pair` (debloater de gamer comumente para Diagtrack
    + DPS sem ser cheat).
  - 1 isolado = MEDIUM `service-stopped:<nome>`.
  Slug novo `service_state` (peso 0.85), label `Serviço forense parado`.
  Defender RTP e SysMain *Disabled-via-registry* continuam nos scanners
  separados (`defender_tampering.py`, `extra_forensics.scan_prefetch_sysmain`).

### Anti-FP (auditoria pré-release)

- **`104` SEMPRE filtrado por Provider `Microsoft-Windows-Eventlog`**: sem
  isso, 104 de outros providers (DOTNETRuntime info, Office) gerava FP em PC
  normal. `_query_events` agora aceita parâmetro opcional `provider` que
  insere `Provider[@Name=...]` na query do `wevtutil`.
- **`501` no canal correto** (`Microsoft-Windows-Ntfs/Operational`) com
  fallback `System`; ambos com `Provider=Ntfs`. Sem provider, pegaria 501 de
  outros providers (Service Control Manager etc.).
- **`3079` com `Provider=Ntfs`**: mesmo motivo — Application channel tem
  3079 de várias fontes.
- **`sgrmbroker` fora da lista crítica**: trigger-start em Win11,
  frequentemente Stopped em PC saudável; flaggar gerava FP estrutural.
- **`SysMain` fora da lista crítica**: já coberto por
  `extra_forensics.scan_prefetch_sysmain_disabled` via Start Type=Disabled;
  incluir aqui duplicaria score no Confidence Engine.
- **`cdpusersvc` dedup ordem-independente**: coleta em dois passes
  (running_count + stopped_status). Só vira flag se TODAS as instâncias estão
  paradas. Bug anterior dependia da ordem de iteração do SCM — se running
  vinha antes de stopped, stopped era registrada errado.
- **Combo `pair` rebaixado**: 2 críticos parados (sem eventlog) = MEDIUM
  `pair` em vez de HIGH `multi`. Debloater scripts de gamer comumente param
  Diagtrack+DPS sem ser cheat. HIGH `multi` agora exige 3+.

### Plumbing

`telador.py` (import + assemble_scanners), `evidence.py` (`SOURCE_WEIGHTS`:
`service_state` 0.85; mapper de nome→slug: "serviços forenses" →
`service_state`), `report_assets.py` (`SOURCE_LABELS`), `telador.spec`
(`hiddenimports`: `service_state_scanner`).

### Stats

73 scanners (era 70), 492 testes (era 444). Suite full passa em ~50s.

## [3.41.4] - 2026-06-29

### Fixed

- **Disclosure scanner agora é autodiagnóstico** (`command_history.py`,
  `scan_trusted_domains_notice`): se `trusted_domains.json` EXISTE em algum
  caminho candidato mas `TRUSTED_DOMAINS` ficou vazio (JSON malformado, formato
  errado, erro de leitura), o scanner GRITA com o caminho do arquivo e o
  motivo provável. Sem isso, o dono que dropou o arquivo e não viu efeito
  ficava no escuro — só "ok" silencioso. Quando NÃO há arquivo em lugar
  nenhum (caso normal), continua silencioso pra não poluir o report.

- **USERPROFILE\\AppData\\Local como fallback redundante** (`database.py`):
  caso `LOCALAPPDATA` esteja unset por algum motivo (contexto de exe elevado
  anômalo, env truncado), o caminho derivado de `USERPROFILE` ainda funciona.
  Dedup com set pra não duplicar quando ambas resolvem ao mesmo lugar.

## [3.41.3] - 2026-06-29

### Fixed

- **Allowlist agora carrega de `%LOCALAPPDATA%\Telador\`** (`database.py`,
  `_trusted_domains_candidates`): antes, `trusted_domains.json` só era lido se
  estivesse ao lado do exe ou apontado por env. Quem baixava o `telador.exe` num
  diretório (Downloads/Desktop) e tinha o JSON em outro lugar, NÃO via a
  allowlist carregar — e os `irm | iex` do steamtools voltavam a aparecer como
  HIGH. Agora aceita também o caminho de fallback `%LOCALAPPDATA%\Telador\` —
  drope o JSON ali UMA vez e funciona de qualquer lugar que rode o exe.
  Mesmo padrão que `signatures.json` já usa há tempos. CWD continua de fora
  (evasão drive-by). Ordem: env > sidecar > LOCALAPPDATA.

## [3.41.2] - 2026-06-29

**Segunda passada de auditoria** sobre o stack de allowlist v3.41.0/v3.41.1.

### Fixed

- **UX bug pré-existente no `_result`** (`models.py`): scanners com itens
  `meta_only` (headers como `[PROCESSO]`/`[CONFIG]`) reportavam `summary`
  contando os meta — então um scanner sem achados reais mas com header diziam
  `"1 item(s) suspeito(s)"` apesar do `status='clean'`. Agora status e summary
  computam só itens NÃO-meta (alinha com o que `evidence.py` e `fp_filter.py` já
  faziam na agregação). Afeta o novo `scan_trusted_domains_notice` e o
  `[PROCESSO]` header de `live_analysis.scan_dll_injection`.

- **Disclosure da allowlist explicita 4104** (`command_history.py`,
  `scan_trusted_domains_notice`): texto do item agora menciona que a supressão
  vale tanto pro PowerShell history quanto pro script block 4104 do Event Log
  (winevent_scanner). Sem isso o investigador não sabia que o 4104 também
  estava silenciado.

- **`trusted_domains.example.json` sem domínio real**: removido `ps.lua.tools`
  do template público (era o domínio do dono, vazado por descuido). Substituído
  por placeholders. Um exemplo público não deve "ensinar" outros a confiarem
  num domínio sem auditoria própria.

## [3.41.1] - 2026-06-29

**Hardening da allowlist v3.41.0** — auditoria pós-release pegou três problemas
introduzidos pela feature de domínios confiáveis. Patch, sem mudança de API.

### Security

- **Disclosure obrigatório da allowlist** (`command_history.py`,
  `scan_trusted_domains_notice`): allowlist ativa agora vira item VISÍVEL no
  report (meta_only — não acende veredito, mas o investigador vê os domínios
  isentos). Antes, um `trusted_domains.json` plantado pelo suspeito suprimiria
  download/exec do cradle dele em silêncio. Modelo de ameaça do Telador: o
  suspeito controla o disco — qualquer mecanismo de SUPRESSÃO precisa ser
  transparente. Adicionar regra (yara_rules.json) é seguro; suprimir, não.

- **CWD removido dos candidatos da allowlist** (`database.py`,
  `_trusted_domains_candidates`): `trusted_domains.json` no diretório de onde se
  roda o telador era vetor de evasão drive-by trivial. Só os dois canais
  INTENCIONAIS de config sobreviveram: env `TELADOR_TRUSTED_DOMAINS` e sidecar do
  exe/módulo.

### Fixed

- **FN no `_is_signature_list`** (`command_history.py`): exigia só 1 pipe + 3
  executores, então `solara.exe; krnl.exe; fluxus.exe | tee log` (3 cheats
  rodados de fato, com 1 pipe não-relacionado) era suprimido por engano. Agora
  exige **≥2 pipes** (alternância de verdade) E ≥3 executores distintos.

## [3.41.0] - 2026-06-29

**Redução de falsos positivos**: allowlist de domínios confiáveis (arquivo local)
e fim do auto-flag de listas de assinatura no histórico de comandos.

### Added

- **Allowlist de domínios confiáveis** (`database.py`, `TRUSTED_DOMAINS`): drope um
  `trusted_domains.json` (lista JSON de strings) ao lado do `telador.exe` — ou
  aponte via env `TELADOR_TRUSTED_DOMAINS` — com domínios benignos que você instala
  por one-liner (ex.: ferramenta própria/steamtools). `irm`/`iex`/`iwr`/
  `downloadstring`… vindos desses domínios deixam de acender, tanto no PowerShell
  history quanto no script block 4104. Formato em `trusted_domains.example.json`.
  Vem VAZIO no binário público de propósito — a allowlist é local pra não virar
  ponto cego no Telador de outras pessoas. Semântica estreita: só limpa o par
  download/execução; red flag independente na mesma linha (bypass de Defender,
  anti-forense) ou nome de executor real continuam HIGH.

### Fixed

- **FP de lista de assinatura no PowerShell history** (`command_history.py`): linha
  que enumera vários executores numa alternância (`$cheat = 'solara|xeno|krnl|…'`)
  é a wordlist de um script anti-cheat/screenshare (ou do próprio Telador) caindo
  no histórico — não é cheat rodando. Agora ignorada quando há `|` e ≥3 executores
  distintos. Generaliza a proteção que só existia pra comandos de busca
  (`Where-Object -match`). Comando real que roda UM executor continua detectado.

- **FP de cradle benigno** (`command_history.py`, `winevent_scanner.py`):
  download+execução a partir de domínio na allowlist não é mais flaggado (ver
  `TRUSTED_DOMAINS` acima).

## [3.40.0] - 2026-06-28

**Event Log + YARA extensível**: o Defender como fonte, mais eventos de execução,
e regras YARA que o usuário pluga sem recompilar.

### Added

- **Detecção do Defender (Event Log 1116/1117)** (`winevent_scanner.py`,
  `scan_defender_events`): quando o próprio Windows Defender DETECTOU um hacktool/
  executor e o suspeito manteve/excluiu — prova forte. Complementa o
  `scan_defender_tampering` (que só vê exclusões/RTP no registro). HIGH se casa
  executor conhecido (funde no cluster do executor); MEDIUM se HackTool/exploit
  genérico. Gated por nome de ameaça pra não flaggar PUA/trojan genérico. Parser
  schema-agnóstico pro formato `UserData` do Defender. Fonte `defender_detection`
  (0.90).

- **Evento 4688 (criação de processo)** (`winevent_scanner.py`): pega o executor
  pelo nome/cmdline no Security log mesmo se o `.exe` foi deletado, quando "Audit
  Process Creation" está ligado. Gated por keyword de executor (FP baixo).

- **Regras YARA externas** (`yara_scan.py`): drope um `yara_rules.json` ao lado
  do `telador.exe` (ou aponte via env `TELADOR_YARA_RULES`) pra somar detecções
  sem recompilar — ex.: o pacote-strings do curso. Formato em
  `yara_rules.example.json`. Regra malformada é ignorada sem derrubar o scan.

- **Hook de kmbox** (`dma_scanner.py`, `KMBOX_USB_IDS`): tabela extensível pro
  fuser de input por USB. Vem VAZIA de propósito — os chips comuns (CH340/STM32)
  são usados por milhares de dispositivos legítimos; sem ID de consumidor único
  confiável, flaggar daria FP em massa. Adicione IDs verificados conforme apurar.

## [3.39.0] - 2026-06-28

**Anti-bypass**: 4 detecções novas vindas dos cursos de telagem — process
hollowing, assinatura binária (YARA), hardware DMA e Event Log de execução.
Levou o projeto de 65 → 69 scanners.

### Added

- **Process hollowing / RunPE** (`live_analysis.py`): flagga processo cujo image
  base está em memória PRIVADA (MEM_PRIVATE) em vez de mapeada do `.exe`
  (MEM_IMAGE) — imagem principal trocada em memória, disco limpo. Vai além do
  manual-map (que pega DLL injetada): aqui o miolo inteiro do processo foi
  substituído. HIGH só com executor conhecido. Pula self/sistema/WOW64.

- **Assinatura binária estilo YARA** (`yara_scan.py`): varre `.exe`/`.dll` em
  pastas de usuário casando o CONTEÚDO — símbolos da API de exploit Luau
  (`getrawmetatable`, `hookmetamethod`, `newcclosure`…) = HIGH; toolmarks de
  injeção = MEDIUM. Pega executor renomeado/repackado. Engine própria, sem
  dependência nativa. Anti-FP: só PE, pula o próprio `telador.exe` (que embute
  os símbolos) e descarta binários assinados. Fonte `yara_signature` (0.85).

- **Hardware DMA** (`dma_scanner.py`): enumera `Enum\PCI` e `\USB` e flagga IDs
  de placa DMA conhecidos — FPGA Xilinx (`VEN_10EE`: PCIeScreamer/LeetDMA/
  CaptainDMA) e ponte USB3 FT601 (`0403:601F`). Heurístico: firmware que spoofa
  o ID escapa, ausência **não** inocenta. Fonte `dma_hardware` (0.80).

- **Event Log de execução (estilo Hayabusa)** (`winevent_scanner.py`): lê o
  Event Log via `wevtutil` puxando rastros que sobrevivem à deleção do arquivo —
  **7045** (driver/serviço instalado: pega BYOVD mesmo se o `.sys` foi removido,
  e funde no cluster com `scan_kernel_drivers`) e **4104** (PowerShell script
  block: download cradle e nome de executor). Fonte `event_log_exec` (0.88).

### Changed

- **Hollowing — assinado é MEDIUM** (anti-FP): binário assinado com image base
  privado pode ser anti-tamper/DRM legítimo (Themida), então não crava no HIGH
  sozinho; corrobora no Confidence Engine.
- **7045 user-path restrito a driver kernel** (anti-FP): serviço usermode de
  `%AppData%` (updater legítimo) não flagga mais; só driver kernel-mode de pasta
  gravável (padrão de BYOVD-dropper).
- **4104 exige download + execução** (anti-FP): `Invoke-WebRequest`/`iwr`
  sozinho é uso legítimo comum e não flagga; só o cradle que baixa E executa.

## [3.38.1] - 2026-06-20

**Bugfix FP**: nomes de pasta genéricos colidindo com software legítimo.

### Fixed

- **Codex (e irmãos) em `SUSPICIOUS_FOLDER_NAMES`** (`database.py`): a lista casa
  o nome EXATO da pasta, e tinha bare words genéricos que colidiam com
  software/ferramentas legítimas — visto num PC de dev: a pasta **`Codex`** (da
  OpenAI Codex) flaggava **HIGH** como executor. Removidos `codex`, `argon`
  (Argon, sync tool de Rojo p/ Roblox dev), `electron` (framework), `hydrogen`
  (sequencer de música) e `sentinel` (licensing/HASP), além de `cryptic` (Cryptic
  Studios — Star Trek Online/Neverwinter). Mesma classe de FP que o projeto já
  tratou pra `synapse`/`xeno`/`ronix`. Os executores seguem cobertos por variantes
  específicas (`codex.exe`/`codex.lol`/`codex executor`, `argon executor`,
  `electron exploit`, `hydrogen.exe`, `sentinel exploit`, `cryptic exec`). Teste de
  regressão adicionado.

## [3.38.0] - 2026-06-20

**Anti-bypass**: detecção de anomalias de timestamp (time-stomping).

### Added

- **Anomalia de timestamp** (`timestomp_scanner.py` → `scan_timestomp`):
  time-stomping é adulterar as datas de um arquivo pra ele parecer antigo ou cair
  fora da janela de tempo da SS. O scanner olha arquivos executáveis/script nas
  pastas de usuário e flagga **MEDIUM** em dois sinais **FP-safe**: (1) data de
  criação/modificação **no futuro** (impossível legitimamente; corrobora relógio
  adulterado); (2) arquivo com **nome de executor** conhecido cuja criação está
  **backdated** (antes de 2006). Mapeia pro source `anti_forense`.

### Por quê

Escolha deliberada de sinais FP-safe: o método clássico ($STANDARD_INFORMATION
vs $FILE_NAME no MFT) é confundido por rename legítimo, e atalhos como "sub-segundo
zerado" dão FP em zip/instalador. Data no futuro não tem uso legítimo, e o backdate
é *gated* atrás do match de executor — arquivo limpo nunca casa, então 0 FP.
Validado no PC real: 0 falso positivo (0,8 s) e detecção confirmada (arquivo `.exe`
com data 30 dias no futuro → MEDIUM). Severidade MEDIUM: precisa corroboração no
Confidence Engine, não crava sozinho.

## [3.37.0] - 2026-06-20

**Anti-bypass**: detecção de Alternate Data Streams (ADS) — executável escondido em stream NTFS.

### Added

- **Alternate Data Streams** (`ads_scanner.py` → `scan_alternate_data_streams`):
  o NTFS permite streams nomeados ocultos num arquivo (`notas.txt:cheat.exe`),
  invisíveis pro Explorer e pro `dir`. Um cheater esconde o executor num ADS e
  roda de lá via LOLBin, sem o `.exe` aparecer no disco. O scanner enumera os
  streams (`FindFirstStreamW`) nas pastas de usuário e flagga **HIGH** quando há
  sinal de executável: conteúdo com header `MZ`, nome de executor conhecido, ou
  extensão de executável no nome do stream. Mapeia pro source `anti_forense`.

### Por quê

ADS é ocultação anti-forense clássica e quase nenhuma ferramenta de telagem
olha. FP ~zero: o `Zone.Identifier` (mark-of-the-web que TODO download carrega) e
outros streams legítimos (SmartScreen, Dropbox, WOF…) são whitelistados, e ADS
sem sinal de executável não dispara. Validado no PC real: 0 falso positivo em
Downloads/Desktop/Documents/Temp/AppData (5,4 s), e detecção confirmada com ADS
de teste (`:payload.exe` com MZ → HIGH; `:Zone.Identifier` → ignorado).

## [3.36.3] - 2026-06-15

**Auditoria**: correções nas features anti-cheat da v3.35 (debugger + manual map).

### Fixed

- **Manual Map: FP HIGH não-validado → MEDIUM + validação de PE completo**
  (`live_analysis.py` → `scan_roblox_manual_map`). Antes flaggava como **HIGH**
  qualquer região privada+executável cujos 2 primeiros bytes fossem `MZ` — código
  JIT/bytes coincidentes davam falso positivo, e o anti-cheat do próprio Roblox
  (Hyperion) aloca/mapeia código. Agora: (1) valida a **imagem PE inteira**
  (`MZ` + `e_lfanew` plausível + assinatura `PE\0\0`) via `_region_is_pe`, cortando
  FP de `MZ` solto; (2) severidade **MEDIUM** — sozinho não crava veredito, precisa
  corroboração de outra fonte; (3) guardas contra loop infinito (`region_size == 0`,
  endereço que não avança) e cap de regiões. Nota: mappers que apagam o header PE
  escapam deste check — é sinal complementar, não definitivo.
- **Debugger: bug de buffer no x64** (`live_analysis.py` → `scan_roblox_debuggers`).
  O método `ProcessDebugPort` usava `wintypes.DWORD` (4 bytes), mas no x64 o valor
  é `DWORD_PTR` (8 bytes) → `NtQueryInformationProcess` devolvia
  `STATUS_INFO_LENGTH_MISMATCH` e o método **nunca disparava** em Windows moderno
  (era código morto; o `CheckRemoteDebuggerPresent` cobria o caso). Trocado por
  `ctypes.c_size_t` (pointer-sized).
- **Coerência de versão**: `version_info.txt` tinha `filevers=(3,36,0,0)` mas
  `FileVersion='3.36.2'` (o tuple ficou pra trás nas v3.36.1/.2). Alinhado.

## [3.36.2] - 2026-06-15

**Bugfix**: Ajuste no filtro de falso-positivo para lidar com ferramentas de IA.

### Fixed

- **Falso-positivo**: "codex" adicionado ao `DEV_AMBIGUOUS_KEYWORDS` em `fp_filter.py`. Em ambientes de desenvolvimento detectados, a ocorrência de pastas de ferramentas como "Codex" (IA assistente) será rebaixada adequadamente para `LOW`, impedindo alarmes falsos de nível `HIGH` devido a conflitos de nomenclatura com exploits.

## [3.36.1] - 2026-06-15

**Hardening**: ajustes pequenos de segurança operacional e release hygiene.

### Fixed

- **Versionamento .tsr** (`diff_tool.py`): snapshots agora gravam a versão atual
  do app em vez do valor legado `3.2.0`.
- **Dashboard local** (`watch_server.py`): adicionados headers de segurança
  (`Content-Security-Policy`, `nosniff`, `no-referrer`, `DENY`) e rotas
  desconhecidas agora retornam `404`.
- **Assinaturas externas** (`database.py`, `sigupdate.py`): o update cria a
  pasta de destino e pode usar `%LOCALAPPDATA%\Telador\signatures.json` quando
  não houver `signatures.json` portable ao lado do executável.
- **CLI** (`telador.py`): `--threads` agora valida o intervalo permitido
  (`1..32`) antes de iniciar o scan.

## [3.36.0] - 2026-06-10

**Clean Up & Refactoring Fixes**: Complete refactoring phase to eliminate redundant code and fix architectural bugs.

### Fixed

- **mmap TOCTOU bug** (`extra_forensics.py`): Adicionado tratamento explícito para `ValueError` durante inicialização do mmap para arquivos de 0 bytes, prevenindo crash TOCTOU durante a leitura concorrente do arquivo SRUM.
- **Redundant stats syscalls leak** (`scanners.py`, `removable_media.py`): Os generators iteradores de diretório (`walk_capped`, `_walk_drive`) agora emitem instâncias completas de `os.DirEntry` em vez de apenas o nome em string, permitindo que os consumidores reaproveitem a struct `stat()` pré-cacheadas sem syscalls adicionais de disco.
- **Limpeza arquitetural**: Stripagem bem-sucedida de milhares de linhas redundantes (`_result`, `_item`, `_fmt_ts`) duplicadas em 15 arquivos individuais de scanners. O `models.py` tornou-se a fonte unificada dessas funções, implementado globalmente para todos os componentes.

## [3.35.0] - 2026-06-10

**Anti-cheat**: detecção de debugger ativo e injeção Manual Map no Roblox.

### Added

- **Detecção de debugger** (`live_analysis.py` → `scan_roblox_debuggers`):
  detecta se um debugger (Cheat Engine, x64dbg, etc.) está ativamente atrelado
  a um processo do Roblox usando `CheckRemoteDebuggerPresent` e
  `NtQueryInformationProcess` (`ProcessDebugPort`). Severidade HIGH.
- **Detecção de Manual Map** (`live_analysis.py` → `scan_roblox_manual_map`):
  detecta injeção Manual Map / Reflective DLL procurando por páginas de memória
  executáveis privadas (não mapeadas a arquivos) contendo cabeçalhos PE (`MZ`)
  no processo do Roblox. Pega cheat injetado sem carregar DLL no disco.
  Severidade HIGH.

### Fixed

- **CI: release idempotente** (`.github/workflows/release.yml`): o step de
  publicação agora verifica se a release já existe antes de criar. Se já existir,
  atualiza o asset (`--clobber`) e as notas em vez de falhar com
  `a release with the same tag name already exists`.

## [3.34.0] - 2026-06-09

**Anti-bypass**: detecção de DLL sideloading / proxy DLL no Roblox.

### Added

- **DLL sideloading no Roblox** (`live_analysis.py` → `scan_roblox_dll_sideload`):
  detecta DLL com nome de DLL do sistema (`version.dll`, `dinput8.dll`,
  `d3d9.dll`, `winhttp.dll`, `dwmapi.dll`…) plantada dentro da pasta de
  instalação do Roblox. A ordem de busca de DLL do Windows carrega a do
  diretório do `.exe` ANTES da System32 — então uma proxy DLL ali é carregada
  quando o Roblox abre, reexportando as funções reais e injetando o cheat. NÃO
  precisa patchear o Roblox, então o `scan_roblox_launcher_integrity` (que checa
  a assinatura do `.exe`) não pega. Mapeia pro source `live_dll_injection` (0.90).

### Por quê

É um dos vetores de injeção mais limpos e ensinados — o Roblox roda intacto e
assinado, mas carrega código injetado via search-order hijack. FP ~zero: o
Roblox nunca traz essas DLLs de sistema na pasta de versão (vêm da System32), e
o gate de assinatura deixa passar a única que ele embarca legitimamente
(`d3dcompiler_47.dll`, assinada pela Microsoft). Só flaga DLL de sistema
NÃO-ASSINADA na pasta do Roblox. Validado no PC real: 0 falso positivo.

## [3.33.3] - 2026-06-09

### Fixed
- **Coerência de versão**: o banner do console (`telador.py`) tinha ficado em
  `v3.31.0` enquanto `version_info.txt`, CHANGELOG e a tag já estavam em 3.33.x —
  as releases v3.32/v3.33 esqueceram de bumpar o banner. O binário publicado
  mostrava a versão errada ao lado do SHA256 durante a SS, furando o fluxo de
  confiança "compare o SHA com a release oficial". Agora a versão bate em todo
  lugar (banner, metadados do exe, CHANGELOG, tag, badge e timeline do site).

## [3.33.2] - 2026-06-09

### Fixed
- **USN Journal FP — DELETE órfão**: Entradas de exclusão (DELETE) sem registro de criação (CREATE) correspondente no buffer circular do USN Journal agora são rebaixadas de HIGH para MEDIUM. Sem o par CREATE+DELETE, a evidência é parcial (o CREATE pode ter rotacionado do buffer). A informação continua visível no relatório, mas não infla o veredito — o Confidence Engine exige corroboração de outra fonte (Prefetch, Amcache, BAM…) para confirmar.

## [3.33.1] - 2026-06-09

### Fixed
- **USN Journal False Positive**: Corrigido um bug onde arquivos não-executáveis com sufixos simulando executores (ex: `solara.exe.ps1` ou `krnl.exe.tmp`) tinham o nome truncado pelo regex e geravam Falsos Positivos de remoção de executor.

## [3.33.0] - 2026-06-09

**Performance extrema e Design Premium (Offline Standalone).**

### Added
- **Nova camada Visual Premium**: Extração de lógica CSS massiva e SVGs inline de `report.py` para um novo módulo limpo `report_assets.py`. Implementação de Aesthetics Premium como efeitos de Glassmorphism, texturas de cores vibrantes modernas e stack tipográfico novo, garantindo UI de ponta mantendo operação 100% offline.
- **Mega-Regex Optimization**: Agrupamento lógico de expressões regulares usando chaves de borda (word-boundary) em `matching.py`. Corte maciço na carga do loop de busca do pattern e aceleração de performance em alvos gigantes (como Amcache, Prefetch e logs do roblox).

## [3.32.0] - 2026-06-09

### Fixed
- **Falso positivo do USN Journal corrigido**: Arquivos efêmeros de executor criados e apagados rapidamente (≤120s de intervalo) agora são fundidos e rebaixados para severidade LOW. Isso impede que artefatos de testes, downloads cancelados ou quarentenas do antivírus inflem o veredito, enquanto mantém a detecção real (cheaters que rodam o executor por minutos) com severidade HIGH.

## [3.31.0] - 2026-06-09

**Robustez + hardening + tooling de qualidade.**

### Added

- **`--verbose` / `-v`**: loga no stderr as exceções que os leitores de artefato
  normalmente engolem (`except/pass`). Diagnostica scanner que falha calado.
- **Aviso de cobertura reduzida**: se algum scanner termina com erro, o telador
  avisa no resumo (`N checagem(ns) falharam — cobertura reduzida`). Um "LIMPO"
  com fontes faltando é cobertura reduzida, não inocência.
- **CI com `ruff`** (lint de bug) + **workflow de release** que builda o
  `telador.exe` no `windows-latest` e publica no push de tag (binário
  reprodutível, fim do build manual local).

### Security

- **Anti PATH/cwd-hijack**: `reg`, `fsutil`, `wevtutil`, `powershell`, `ipconfig`
  e `schtasks` agora rodam pelo caminho ABSOLUTO do System32. O `subprocess`
  procura o exe na pasta do `telador.exe` antes do System32 — um suspeito podia
  plantar um `reg.exe` falso ao lado do telador e executá-lo com admin durante a
  perícia. (`win_tools.py`, 12 call-sites)
- **`--update-sigs` só aceita HTTPS** (libera HTTP só pra loopback): a base
  baixada vira regra de detecção; sem TLS daria pra injetar assinatura via MITM.

### Fixed / Chore

- Linguagem do `.tsr`: "assinado HMAC" → "selo HMAC de integridade" (detecta
  adulteração casual, não é prova contra forjador motivado).
- Limpeza de lint: imports mortos, 4 chaves de dict duplicadas (mesmo valor, sem
  perda de dado), loop-vars não usadas.

## [3.30.3] - 2026-06-09

**Fix: PE analysis agora alcança os hits de Amcache (ponto cego de extração de path).**

### Fixed

- **Extração de path no `pe_analysis.enrich_findings_with_pe`**: a detecção do
  caminho do arquivo usava `endswith()` na linha inteira do `detail`. Scanners
  como o **Amcache** reportam `C:\...\cheat.exe SHA1=<hash>` — a linha termina no
  hash, não na extensão, então o `endswith` falhava e o PE analysis
  (packer/entropy/SHA256-match + bump de severidade) **não rodava nos hits de
  Amcache**. Trocado por `_extract_pe_path()`, que casa o path mesmo com sufixo
  depois da extensão (drive-letter ou UNC), preservando o caso antigo. +5 testes.

## [3.30.2] - 2026-06-09

**Segurança: corrige XSS / forja de veredito no dashboard ao vivo.**

### Fixed

- **XSS no painel `--watch`** (`watch_server.py`): `label`, `kind`, `verdict` e
  `sources` de cluster — além do nome do scanner — eram injetados via `innerHTML`
  sem escape. Esses campos derivam do nome de arquivo do disco do suspeito
  (`evidence.py`, `os.path.basename` do path), que é controlado por ele e é
  exatamente o que o scanner de *executor renomeado* coleta. Um arquivo
  renomeado pra conter HTML/JS no nome executava JS no navegador do supervisor
  durante a SS e podia reescrever o painel pra mostrar "PC LIMPO", **forjando o
  veredito**. O relatório estático (`report.py`) já escapava esses campos; só o
  caminho ao vivo estava exposto. Adicionado `esc()` no JS do painel envolvendo
  todos os campos dinâmicos, + teste de regressão (`test_watch.py`).

## [3.30.1] - 2026-06-08

**Auditoria de lógica + hardening do masquerading.**

### Fixed

- **Masquerade do `explorer.exe` agora exige o caminho exato**. O prefixo
  permitido era o diretório `%WINDIR%\` (largo): um `explorer.exe` plantado em
  `c:\windows\temp\` (subdir de %WINDIR%) passava por legítimo. Agora casa o
  arquivo exato `%WINDIR%\explorer.exe`. Os demais processos do SO seguem por
  diretório (System32/SysWOW64/WinSxS), que é o correto — lá moram vários exes.

### Auditado (sem defeito)

- **Confidence Engine** (cluster/veredito): 1 fonte nunca CONFIRMA sem evidência
  critical; diminishing-returns por fonte + bônus de diversidade; agrupamento por
  hash→path→executor com merge path↔executor. Lógica consistente.
- **Ordem de execução**: `post_process_findings` (FP) roda ANTES do clustering —
  downgrades e whitelist chegam ao veredito. Correto.
- Sem mutable default args; `compute_target_id` com cascata correta.

## [3.30.0] - 2026-06-08

**Anti-bypass**: detecção de process masquerading (cheat disfarçado de processo do Windows).

### Added

- **Processo disfarçado de sistema** (`live_analysis.py` → `scan_process_masquerade`):
  detecta cheat renomeado pra nome de processo do Windows (`svchost.exe`,
  `dwm.exe`, `csrss.exe`, `RuntimeBroker.exe`, `explorer.exe`…) rodando de fora
  da pasta do sistema. No Gerenciador de Tarefas / SS manual o cara vê
  "svchost.exe" e passa batido — aqui o path denuncia. Compara o nome contra
  uma lista de processos do SO e exige que rode de `System32`/`SysWOW64`/`WinSxS`
  (ou `%WINDIR%` pro explorer); qualquer outro lugar = HIGH. Mapeia pro source
  `live_processes` (0.95).

### Por quê

Renomear o executor pra nome de processo do sistema é dos disfarces mais
ensinados — engana a inspeção visual de processos. FP ~zero: os binários reais
do Windows nunca rodam fora dessas pastas, e os protegidos (PPL) nem expõem o
path (são pulados). Validado no PC real: 21 processos de nome de sistema, todos
de System32/Windows, 0 falso positivo.

## [3.29.3] - 2026-06-08

**FP-audit dos anti-bypass**: varredura dos 6 scanners anti-bypass caçando o
cenário real onde cada um erraria. Três calibrações, validadas no PC real.

### Fixed

- **Relógio: correção por serviço não é mais ataque**. Salto pra trás feito por
  conta de SERVIÇO (W32Time/NTP, kernel no boot, skew de **dual-boot
  Linux/Windows**) virava MEDIUM/HIGH falso. Agora classifica por **SID de
  serviço** (`S-1-5-18/19/20`) — não pelo nome, que vem **localizado**
  (`SERVIÇO LOCAL` em PT-BR) e quebraria fora do inglês. Serviço → LOW contexto;
  usuário interativo (`S-1-5-21-…`) voltando o relógio continua MEDIUM/HIGH.
  O parser passou a capturar `SubjectUserSid`. Empírico: 14/14 eventos 4616 num
  PC real são NTP (S-1-5-19), todos agora classificados certo.
- **Limpadores: `eraser` por substring pegava editor de foto**. `Photo Eraser`,
  `Background Eraser`, `Magic Eraser` casavam o token `eraser` e viravam HIGH
  (secure-delete falso). Agora o match é ancorado no **início da palavra**
  (`(?<![a-z0-9])`): `PHOTOERASER` não casa, mas `ERASER.EXE`, `MY-ERASER` e
  `SDELETE64` (sufixo de versão) continuam. Freeraser/Secure Eraser seguem
  pegos pelos tokens próprios.
- **Processo suspenso: debugger não é mais FP de dev**. Dev depurando o próprio
  `.exe` não-assinado (recém compilado em pasta de usuário) deixa o processo
  SUSPENSO no breakpoint → MEDIUM falso. Se o **processo-pai** é debugger/IDE
  (PyCharm, VS, x64dbg, WinDbg, VS Code, CLion…), suprime o MEDIUM. Executor
  CONHECIDO suspenso continua HIGH mesmo com pai debugger (rodar 'no debugger'
  não inocenta).

### Auditados sem mudança

- **USB history**: LOW/contexto, janela de 24h — ruído aceitável, não infla veredito.
- **Mídia removível plugada**: exige keyword de executor (word-boundary central) — OK.

## [3.29.2] - 2026-06-08

**Patch FP**: mais dois FPs que sobraram em PC de dev/admin/SS supervisor + um
reforço no Defender.

### Fixed

- **PowerShell history não flagga regex de BUSCA**: linhas tipo
  `Where-Object PathName -match 'winring0|kdmapper|gmer'` (auditoria
  procurando esses tokens) eram tratadas como execução. Detectada presença
  de verbos de busca (`-match`, `-cmatch`, `Select-String`, `findstr`,
  `Where-Object`) + keyword dentro de regex (`|kw|`) ou aspas (`'kw'`) —
  agora ignora. Execução real (`.\kdmapper.exe`, `Start-Process kdmapper`)
  continua detectada.
- **Process Hacker / System Informer rebaixados pra LOW**: ferramentas
  dual-use (sysadmin, dev, SS supervisor usam tanto quanto cheater). De
  baseline MEDIUM em `EXECUTOR_KEYWORDS` e `EXECUTOR_PROCESS_NAMES` viraram
  LOW. Cheater que injeta com elas aparece em outras fontes (DLL não-assinada
  no Roblox, BYOVD, exclusão Defender).
- **`_probe_dev_folder` no Defender**: complementa o `_is_dev_exclusion_path`
  da v3.29.1. Quando a exclusão cai em pasta gravável do usuário mas o nome
  não bate em IDE conhecida (ex.: `Desktop\portfolio`), lê o conteúdo da
  pasta. Se tem marcadores de projeto (`.git`, `package.json`,
  `pyproject.toml`, `node_modules`, `Cargo.toml`, `.sln`…), trata como repo
  de dev (LOW, `exclusao-dev`), não anti-bypass. Cheater não cria `.git` só
  pra disfarçar.

### Por quê

Auditoria FP no PC real (PowerShell com query de auditoria, 5 hits MEDIUM em
Process Hacker/SystemInformer espalhados por userassist/muicache/known_paths/
running_processes/bam, e pasta `portfolio` no Desktop fora da lista hard-coded).
A v3.29.1 já cobre IDEs por path; esta versão fecha os outros vetores sem abrir
brecha pra cheat real.

## [3.29.1] - 2026-06-08

**Bugfix**: falso positivo em exclusões do Defender para IDEs e pastas de projeto em ambiente de dev.

### Fixed

- **`defender_tampering.py`**: `_classify_exclusion` agora reconhece pastas de IDEs
  conhecidas (JetBrains, VS Code, `.vscode`, `.cursor`, Unity, etc.) via
  `DEFENDER_EXCLUSION_DEV_PATHS` e retorna `low` diretamente, sem precisar do
  FP filter downstream.
- **`database.py`**: adicionado `microsoft vs code`, `\.vscode`, `\.cursor` e
  `\.idea` na lista `DEFENDER_EXCLUSION_DEV_PATHS` (entradas faltando).
- **`fp_filter.py`**: `is_whitelisted_path` normalizava barras duplas incorretamente,
  fazendo JetBrains e outros paths escaparem da whitelist quando o valor vinha
  embutido no texto completo do item. `_path_candidates_for_item` extrai o path
  real antes de comparar. `adjust_for_dev_env` passa a rebaixar
  `exclusao-pasta-usuario` de HIGH → MEDIUM em ambiente de dev.
- **`evidence.py`**: exclusões genéricas do Defender (`exclusao-pasta-usuario`,
  `exclusao-processo`) agora viram evidência do tipo `anti_forense` em vez de
  `executor`, eliminando clusters errados como "pycharm2025.3 executor".

### Impacto

PC de dev com pasta da JetBrains/VS Code excluída do Defender não gera mais hit
HIGH nem cluster de executor. Pasta genérica de projeto no Desktop continua
aparecer como MEDIUM (vale revisão), mas não acusa executor.

## [3.29.0] - 2026-06-08

**Anti-bypass**: detecção de ferramentas de limpeza / secure-delete.

### Added

- **Ferramentas de limpeza** (`cleaner_tools.py`): `scan_cleaner_tools` lê o
  Prefetch e flagga limpadores/secure-delete que rodaram — pré-limpeza de
  rastro antes da SS. Secure-delete puro (SDelete, Eraser, BCWipe, shredders) =
  HIGH (sem uso legítimo num PC de jogo); BleachBit/PrivaZer = MEDIUM;
  CCleaner/Wise = LOW (rotineiro, contexto). Mapeia pro source `anti_forense`.

### Por quê

Rodar um apagador seguro pouco antes da SS é destruição de evidência. O .pf
prova que a ferramenta rodou e quando. Validado em dados reais (525 .pf, 0 FP).

## [3.28.0] - 2026-06-08

**Anti-bypass de timeline**: detecção de relógio do sistema voltado pra trás.

### Added

- **Manipulação do relógio** (`clock_tampering.py`): `scan_clock_tampering`
  lê os eventos 4616 (hora do sistema alterada) do log de Security e flagga
  saltos PARA TRÁS de 10+ minutos. Voltar o relógio é anti-bypass: joga os
  artefatos de execução do cheat (Prefetch/Amcache/BAM) pra fora da janela de
  tempo da SS, quebrando a correlação por horário. Salto pra frente (sync de
  NTP / bateria de CMOS) é ignorado — só o rollback interessa. Parser de XML do
  wevtutil validado contra eventos reais. Source próprio (`clock_tampering`).

### Por quê

A correlação por horário é central no veredito. Se o suspeito volta o relógio, o
cheat que rodou às 19h "vira" 16h e some da janela. O salto pra trás é o sinal.

## [3.27.0] - 2026-06-08

**Anti-bypass do Defender**: detecção de exclusões e proteção desligada — o
cheater mandando o próprio Windows ignorar a pasta do executor.

### Added

- **Adulteração do Windows Defender** (`defender_tampering.py`):
  `scan_defender_tampering` lê as exclusões do Defender (via Get-MpPreference,
  a API oficial — o registro é bloqueado pelo Tamper Protection mesmo com
  admin) e a proteção em tempo real. Excluir pasta de usuário, executor ou
  extensão de .exe é o jeito clássico de rodar cheat sem o Defender pegar.
  Exclusão de pasta de usuário/executor/extensão de exe = HIGH; proteção
  desligada = contexto (pode ser AV de terceiro). Sem admin = inconclusivo
  (não vira falso positivo). Source próprio (`defender_tampering`).

### Por quê

Usuário comum nunca mexe em exclusão do antivírus. Uma exclusão apontando pra
Downloads/AppData ou pro nome de um executor é "esconde meu cheat" na cara.
Validado em dados reais, incluindo o placeholder de não-admin do Get-MpPreference.

## [3.26.0] - 2026-06-08

**Multi-conta**: detecção de outras contas de Windows no PC — "cheata na
outra conta".

### Added

- **Detecção de múltiplas contas** (`user_accounts.py`): `scan_user_profiles`
  enumera o ProfileList do Windows, filtra contas de sistema/serviço e avisa
  quando há outra conta humana além da que está sendo telada. O suspeito pode
  jogar limpo numa conta e usar o cheat na outra — conta atual limpa não
  inocenta o PC. Severidade baixa (contexto) ou média (conta com atividade nas
  últimas 48h). Source próprio (`user_accounts`).

### Por quê

O Telador varre só o usuário atual. Sem enumerar as outras contas, dá pra
esconder o cheat numa conta separada e passar na SS. Validado em dados reais
(ProfileList: contas de sistema filtradas, conta atual não flagada).

## [3.25.0] - 2026-06-08

**Mídia removível**: detecção de cheat rodado de pendrive (USB) — o
"trapaças em pen drives" dos cursos de telagem.

### Added

- **Detecção de mídia removível** (`removable_media.py`), dois scanners.
  `scan_usb_history` lista dispositivos USB de armazenamento conectados nas
  últimas 24h (via last-write do USBSTOR) como contexto de SS — pendrive
  plugado perto do horário de jogo é vetor de cheat rodado de USB que
  despluga sem deixar o .exe no disco. `scan_removable_drives` varre o
  conteúdo de unidades removíveis plugadas agora e flagga arquivo de
  executor conhecido (cheat ainda na USB durante a SS). Anti-FP: o histórico
  é severidade baixa (contexto, não infla veredito) e o conteúdo só dispara
  com match de keyword de executor. Source próprio (`removable_media`).

### Por quê

FAT32 de pendrive não tem USN journal — desplugar não deixa rastro NA USB.
Mas o registro do host (USBSTOR) e os artefatos de execução do C: ainda
contam a história. Validado em dados reais (timestamps de USBSTOR + GetDriveType).

## [3.24.0] - 2026-06-08

**Anti-bypass**: detecção de processo suspenso — o truque de pausar o
cheat durante a SS pra ele parecer inativo.

### Added

- **Detecção de processo suspenso** (`scan_suspended_processes`): flagga
  processo em estado SUSPENSO (pausado). Pausar o executor durante a
  screenshare (ex.: Process Hacker → Suspend) o congela e o tira da lista
  de "rodando" sem fechar — método clássico de anti-bypass ensinado nos
  cursos de telagem. Conservador anti-FP: só sinaliza executor conhecido
  (HIGH) ou exe não-assinado em pasta de usuário (MEDIUM); whitelista
  navegador/Discord/shell e apps empacotados (UWP/WindowsApps), que o
  Windows suspende em background. Sozinho vira no máximo SUSPECT no
  Confidence Engine.

### Por quê

Como o processo suspenso continua carregado na memória, o estado é
detectável — e a pausa em si já é o sinal. Validado no Windows real
(suspend → `STATUS_STOPPED`) e 0 falso positivo em máquina limpa.

## [3.23.0] - 2026-06-07

**Lições do primeiro caso real**: o suspeito não rodou como admin e o
scan ficou cego — e pior, o "nada encontrado" parecia inocência.

### Added

- **Auto-elevação (UAC)**: ao abrir, se não estiver como administrador, o
  programa PEDE elevação sozinho (UAC). Não depende mais do supervisor
  saber "botão direito → Executar como administrador". Se o usuário recusar
  o UAC, segue com cobertura limitada (e aviso forte). Opt-out: `--no-elevate`.
- **Aviso de scan inconclusivo**: sem admin, as fontes mais fortes
  (Prefetch/Amcache/BAM/Defender) falham. Um resultado "LIMPO" sem admin
  agora é marcado como **INCONCLUSIVO** — no console (banner vermelho +
  aviso pós-veredito) e no relatório HTML (banner âmbar no topo). Evita o
  erro de ler "nada encontrado" como "inocente" num scan cego.

### Por quê

Sem admin, "nada encontrado" não inocenta — o cheat pode estar lá e o
scan simplesmente não conseguiu ler. Agora isso fica explícito.

## [3.22.3] - 2026-06-07

Auditoria de FP — parte 3. Achado o pior: scanners que bypassavam a
proteção anti-FP central.

### Fixed

- **`command_history` (PowerShell/RunMRU/TypedPaths) e `discord_cache`
  faziam substring de `EXECUTOR_KEYWORDS` e `SUSPICIOUS_DOMAINS`** — ou
  seja, ignoravam TODA a proteção word-boundary/domínio que o resto do
  programa usa. Isso reintroduzia FP (ex.: 'solara' casava 'solarapanel';
  'wave.gg' casava 'soundwave.gg') exatamente nesses dois scanners. Agora
  ambos usam `matching.match_keyword` + `matching.domain_in_text`.
- **`CLEANER_NAMES` com 'wipe'/'shred' (substring)** casava 'swipe.exe' e
  'shredder'. Novo helper `matching.word_in_text()` (fronteira de palavra)
  aplicado — 'wipe' casa 'wipe.exe' mas não 'swipe'.

### Testes

- `test_fp_audit.py` cobre os 3 casos. 170 testes no total.

## [3.22.2] - 2026-06-07

Continuação da auditoria de FP — matching de domínio por fronteira.

### Fixed

- **Domínio suspeito casava como substring de domínio maior**: `wave.gg`
  flagava `soundwave.gg`, `heatwave.cc` flagava... etc. Agora o matching
  exige fronteira de domínio real: `wave.gg` casa `wave.gg` e `sub.wave.gg`
  (subdomínio legítimo), mas NÃO `soundwave.gg` nem `wave.ggames.com`.
- Novo helper `matching.domain_in_text()` aplicado nos 3 pontos que
  comparavam domínio (browser history visitas + downloads, e rede/DNS).

### Testes

- `test_fp_audit.py` ganhou casos de fronteira de domínio. 168 testes.

## [3.22.1] - 2026-06-07

Auditoria de falso positivo — 3 colisões de marca corrigidas.

### Fixed

- **`synapse` (palavra solta) colidia com Razer Synapse** — software de
  mouse em milhões de PCs gamer era flagado como o executor Synapse X, em
  HIGH. FP grave. Removida a palavra solta; mantidas variantes específicas
  (`synapse.exe`, `synapsex`, `synapse x`) que NÃO casam "razersynapse.exe".
- **`ronix` colidia com Ronix** (marca de wakeboard) e **`valex` com Valex**
  (marca de cabos). Removidas; cobertas por `.exe` + "x executor" + domínios.

### Garantido por teste

- `tests/test_fp_audit.py`: trava as 3 colisões (não podem casar) E confirma
  que os executores reais seguem detectados pelas variantes (inclusive em
  formato Prefetch `SYNAPSE.EXE-XXXX.pf`). 166 testes no total.

## [3.22.0] - 2026-06-07

### Added

- **Atribuição no relatório**: rodapé discreto no HTML e no export Markdown
  identificando o Telador + link do site/repo. Quando um supervisor
  compartilha um relatório (o uso natural), quem vê descobre a ferramenta.
  Distribuição passiva — sem propaganda ativa.

## [3.21.0] - 2026-06-07

**Evasão de ban e contas alt** — o arsenal de quem leva ban e volta.

### Added

- **Gerenciadores de alt / multi-instância** (MEDIUM): Roblox Account
  Manager, MultiBloxy, Multi Roblox, rbxmulti, alt manager, account
  generator e variantes. Rodar várias contas não prova cheat, mas é sinal
  forte de botting/alt evasion num SS — o Confidence Engine corrobora.
  (O "roblox account manager" estava sub-avaliado como `low` → agora
  `medium`.)
- **HWID spoofers expandidos** (HIGH): hwid changer, serial/disk/smbios/
  mac spoofer, byfron/hyperion/roblox spoofer, exodus, vanity, cleaner
  spoofer + nomes de processo. Spoofar HWID não tem uso legítimo pra
  jogador normal — é especificamente pra burlar ban de hardware.

### Anti-FP

- Frases específicas + word-boundary protegem: "fps unlocker", "bloxstrap",
  "fishstrap" (legítimos), "alt account" (comum), "steam multi instance"
  (outro jogo), "altair", "multimedia", "smbios info" → NÃO disparam.
- Validado scan LIMPO na máquina. 5 testes novos (164 no total), incl.
  lista de legítimos/comuns que não podem casar.

### Como funciona

- Entram nas listas que os scanners forenses já varrem → pegos
  automaticamente em todas as fontes (Prefetch/Amcache/BAM/Downloads/
  browser/USN/Lixeira/processos), sem código de scanner novo.

## [3.20.0] - 2026-06-07

**Detecção de autoclickers / macros standalone** — pedido pela comunidade.

### Added

- Base de assinaturas de **ferramentas de autoclique/macro** dedicadas:
  OP Autoclicker, Speed Autoclicker, GS Auto Clicker, TinyTask, Mouse
  Recorder, Macro Recorder, Pulover's Macro Creator, MurGee, Mini Mouse
  Macro, Perfect Automation, e variantes (keywords + nomes de processo).
- Como entram nas listas que os scanners forenses já varrem, são pegos
  **automaticamente em todas as fontes** (Prefetch, Amcache, BAM,
  UserAssist, Downloads, browser, USN, Lixeira, processos ao vivo…) —
  sem código de scanner novo.
- Severidade **MEDIUM** (ter um autoclicker não prova cheat — clicker
  game existe — mas é sinal; o Confidence Engine corrobora com atividade
  de Roblox). Variantes Roblox-específicas ("roblox auto clicker", "auto
  farm macro") são **HIGH**.

### Complementa o que já existia

- Software de mouse com motor de macro (G HUB, Razer, Bloody, X-Mouse…)
  e red flags de conteúdo de macro (no recoil, auto click, rapid fire…)
  já eram detectados. Agora cobre também as ferramentas standalone.

### Anti-FP

- Word-boundary matching: "autocad", "clicker heroes" (jogo), "macromedia",
  "macros folder" NÃO disparam. 5 testes novos (159 no total), incl. lista
  de termos inocentes que não podem casar.

## [3.19.0] - 2026-06-07

**Detecção de launcher do Roblox modificado** — pedido pela comunidade de SS.

### Added

- **`scan_roblox_launcher_integrity`**: detecta launcher/player do Roblox
  adulterado. Dois cenários:
  - **Binário oficial adulterado**: `RobloxPlayerBeta.exe` (ou installer/
    studio) no path de instalação com **assinatura digital QUEBRADA**. O
    Roblox sempre assina seus binários — assinatura quebrada = arquivo
    patcheado pra injetar na inicialização. Severidade HIGH.
  - **Launcher falso**: arquivo com nome de launcher do Roblox numa pasta
    de usuário (Downloads/Desktop/Temp) e não-assinado = dropper/executor
    se passando por Roblox. Severidade HIGH.

### Anti-FP

- Validado empiricamente: 0 hits numa máquina com Roblox + Roblox Studio
  legítimos (9 binários oficiais, todos assinados).
- Só flaga assinatura **comprovadamente** quebrada (`False`), nunca
  indeterminada (`None`).
- Bloxstrap/Fishstrap (alternativas legítimas) usam o `RobloxPlayerBeta`
  oficial assinado — não caem aqui.
- Instalador oficial assinado baixado em Downloads é ignorado.
- 7 testes novos (154 no total), incl. trava de regressão zero-FP na
  máquina real.

### Confidence Engine

- Nova fonte `launcher_integrity` (peso 0.90 — binário oficial adulterado
  é sinal forte).

## [3.18.2] - 2026-06-03

Release de consistência — publica correções de produção que já estavam
no `main` mas não no binário (e que não tinham entrada no changelog).

### Fixed

- **`datetime.utcnow()` deprecado** em `scan_event_log_gap` (extra_forensics):
  deprecado no Python 3.12+ e marcado pra remoção — quebraria numa versão
  futura do Python. Trocado por `datetime.now(timezone.utc)`.
- **Leak de socket** no `watch_server.start()`: cada chamada criava um
  servidor novo sem fechar o anterior. Agora `start()` é idempotente
  (fecha o anterior) e há uma função `stop()` pública.

### Tests / infra (já no repo, sem efeito no binário)

- Cobertura de teste: `report.py`, `redaction.py`, `report_signing.py`,
  `diff_tool.py` (eram zero). **147 testes** no total.
- CI: matriz Python 3.11/3.12/3.13, valida `signatures.dist.json`, cobre
  os módulos novos no smoke de imports.

## [3.18.1] - 2026-06-03

Auditoria de bug + melhoria de interface.

### Fixed

- **Bug de robustez no `scan_executor_structure`**: quando a verificação
  de assinatura (WinVerifyTrust) retornava `None` (não deu pra determinar —
  serviço indisponível, arquivo travado, erro), o exe era tratado como
  não-assinado e **flagado**. Se a checagem falhasse sistemicamente num PC,
  isso podia gerar **tempestade de falso positivo**. Agora só flaga quando
  é **comprovadamente** não-assinado (`False`); `None` recebe benefício da
  dúvida. Não perde detecção real (executor é PE válido não-assinado).
  Teste de regressão adicionado.

### Added

- **Botão "Copiar resumo" no hero do relatório**: copia um resumo em texto
  puro (veredito + targets + fontes) pro clipboard, pronto pra colar no
  Discord da staff. Com fallback pra navegadores sem clipboard API.

## [3.18.0] - 2026-06-03

**Detecção comportamental — pega executor mesmo renomeado.**

### Added

- **`scan_executor_structure`**: novo scanner que detecta executor pela
  ESTRUTURA, não pelo nome. Bate no fingerprint dos executores modernos
  (Solara/Wave/Velocity/etc): um `.exe` **não-assinado** na mesma pasta
  de um **runtime web embutido** (EBWebView/CEF), em local gravável pelo
  usuário. Sobrevive a renomear o arquivo E a pasta — onde a detecção
  por nome cega, essa pega.

### Por que não dá falso positivo

- Apps legítimos com WebView2 (Discord, Outlook, WhatsApp, Roblox Studio...)
  deixam só DADOS no AppData e o `.exe` **assinado** em Program Files.
  Executores largam o `.exe` não-assinado junto do runtime. O scanner
  exige as duas coisas JUNTAS.
- Severidade **MEDIUM** — sozinho vira no máximo SUSPECT no Confidence
  Engine; só CONFIRMA se corroborado por outra fonte. Nunca acusa falso.
- Whitelist de pastas Microsoft/Windows/Google/Discord.
- **Validado empiricamente**: 0 hits num PC real com Roblox + Roblox
  Studio + dezenas de apps WebView2. Tem teste que falha se algum dia
  passar a dar FP na máquina.

- 6 testes novos (104 no total): pega renomeado, ignora assinado, ignora
  sem runtime, whitelist, zero-FP na máquina real, e a evidência sozinha
  nunca vira CONFIRMED.

## [3.17.0] - 2026-06-03

**Assinaturas atualizáveis sem rebuildar o `.exe`** — fecha o maior ponto
fraco operacional: a base envelhecer.

### Added

- **`telador.exe --update-sigs`**: baixa a base de assinaturas mais recente
  do GitHub (`signatures.json` do repo) e sai. Comando de manutenção
  **separado** — o scan normal **nunca toca a rede**, preservando o
  "100% local". Adicionar um executor novo agora é **um commit no
  `signatures.json`**, não um rebuild + redistribuição do binário de 10 MB.

- **Versionamento da base**: o `signatures.json` tem campo `version`, e o
  Telador mostra qual versão carregou no console. Permite saber se a base
  local está velha.

- **`signatures.json` publicado no repo**: arquivo-fonte da base
  atualizável (executores estabelecidos, severidades validadas).

### Robustez (zero-estresse por design)

- Atualização **opt-in** — fora do `--update-sigs`, nenhum byte sai do PC.
- Timeout curto; qualquer falha de rede degrada graciosamente (base
  embutida continua valendo).
- Valida que o conteúdo baixado é JSON com estrutura de assinaturas
  **antes** de salvar. Download corrompido/vazio **nunca** substitui a
  base local boa (escrita atômica via arquivo temp + rename).
- Sem dependência nova: `urllib` da stdlib.

- Novo módulo `sigupdate.py`. 6 testes novos (98 no total), incluindo o
  caso crítico "download ruim não apaga a base boa".

## [3.16.0] - 2026-06-03

**Dashboard local ao vivo (`--watch`)** — a vantagem que ferramentas
comerciais tinham, agora 100% local.

### Added

- **`telador.exe --watch`**: sobe um servidor HTTP em `127.0.0.1` (porta
  livre, só loopback) e abre um dashboard no navegador que mostra os
  scanners reportando **em tempo real** e o veredito do Confidence Engine
  **se formando** conforme as evidências chegam.

- **Diferença filosófica vs. concorrentes**: ferramentas como Abyss
  transmitem os dados do PC do suspeito pra um servidor na nuvem. Aqui o
  servidor roda na própria máquina e **nada sai do PC** — o supervisor
  abre no navegador da própria sessão de SS.

- **Zero dependência nova**: usa só `http.server` + `json` da stdlib.
  Mantém o princípio de "só psutil em runtime".

- O dashboard mostra: barra de progresso, stream de scanners (com badge
  de hits ao vivo), e cards de cluster que aparecem/atualizam conforme o
  Confidence Engine recalcula. Marca claramente "prévia ao vivo" enquanto
  os clusters são pré-FP-filter; ao final, `finalize()` substitui pela
  versão autoritativa (pós-filtro).

- Novo módulo `watch_server.py` (~230 linhas, dashboard HTML inline).
- `run_scanners_parallel` ganhou parâmetro opcional `on_result` (callback
  por scanner concluído) — usado pelo streaming do dashboard.

## [3.15.1] - 2026-06-03

Polimento visual do hero verdict no relatório HTML.

### Changed

- Emoji nativo do SO (🔴🟠🟡🟢⚪) renderizado em 56px ficava pixelado/feio.
  Substituído por **SVGs Lucide-style inline** (shield-check, shield-x,
  alert-octagon, alert-triangle, circle-dashed) que escalam como vetor.
- Container circular do ícone com glow ambient da cor do veredito.
- **Pulse animation** sutil no SVG só quando há urgência
  (CONFIRMED/DETECTED) — escala 1.06 + opacity 0.92 num ciclo de 2s.
- **Ring expandindo** ao redor do ícone no estado CONFIRMED — atrai
  atenção sem ser agressivo.
- **Fade-in** suave do hero inteiro ao carregar a página.
- Classes `hv-state-clean/warn/bad` ajustam borda + glow ambient da seção.
- Tudo inline — relatório continua standalone offline. HTML cresceu ~1KB.

## [3.15.0] - 2026-06-03

**Confidence Engine** — o salto arquitetural. Em vez de listar 50+ hits
isolados, o Telador agora **agrupa evidências do mesmo executor em um único
veredito por target**. O supervisor vê em <10s.

### Added — Confidence Engine

- **`evidence.py`**: novo módulo com modelo `Evidence` (observação atômica)
  e `Cluster` (várias evidências sobre o mesmo target). Substitui o
  `cross_correlate` legado baseado em keyword crua.

- **Resolução de `target_id` em cascata**: SHA256 → path normalizado →
  nome canônico do executor → raw. Variantes "solara", "Solara.exe",
  "solara executor", "solara hub" convergem para um único cluster.

- **Merge automático path→executor**: o mesmo Solara visto como
  `path:c:\users\bob\solara\solara.exe` no Prefetch e `executor:solara`
  no BAM vira **um** cluster com 2 fontes — não dois clusters duplicados.

- **Score com diminishing returns por fonte + bônus de diversidade**:
  5 hits da mesma fonte valem menos que 5 fontes diferentes batendo no
  mesmo target. Score = `Σ (severity × source_weight / rank) × (1 + 0.3×(n_sources-1))`.

- **Verdict por cluster** (`CONFIRMED` / `DETECTED` / `SUSPECT` / `WEAK`)
  com **FP protection no DNA**: 1 fonte só nunca chega a CONFIRMED
  (exceto critical). Elimina "Amcache acidentalmente bate 'solara'"
  virar confirmação.

- **`critical` agora pesa no score**: fix preventivo em `SEVERITY_WEIGHT`
  (peso 25) e `SEVERITY_ORDER`. 1 critical + 2 fontes = CONFIRMADO. 2+
  críticos cravam veredito.

### Added — Hero verdict no relatório HTML

- **Topo do relatório totalmente reformado**. Bloco "🔴 EXECUTOR CONFIRMADO
  · Confidence 96%" com cards por cluster mostrando target, score, fontes
  detectadas (✓ Prefetch, ✓ Amcache, ✓ BAM…). O supervisor entende o
  resultado **antes** de rolar a página.

- Cards responsivos com badge de verdict, severity, score numérico e
  timestamp da primeira evidência.

### Added — Assinaturas expandidas (top 5 executores)

- **Ronix** adicionado do zero: keywords, processos, domínios, variantes.
- **Solara**: hub, `.cc`, `.gg`, `.dev`, `solaraexec`, `solaralauncher`.
- **Xeno**: `.cc`, `.dev`, `.lat`, `getxeno`, bootstrappers adicionais.
- **Wave**: hub, `.gg`, `.cc`, `.dev`, `wavelauncher`, `waveexec`.
- **Velocity**: hub, `.cx`, `.gg`, `.cc`, `.lat`, bootstrapper/launcher.

### Changed

- Banner do CLI: "Confidence Engine · 100% local" em vez de "50 scanners".
- Header do relatório HTML: "Análise forense local · veredito por
  correlação de evidências" em vez de contagem de scanners.
- `_render_summary` rebaixado pra "Detalhes técnicos do veredito"
  abaixo do hero (era o protagonista, agora é apoio).

### Tests

- **86 testes passando**, +28 novos cobrindo: canonização de aliases,
  resolução de target_id em cascata, FP protection de single-source,
  merge path→executor, diminishing returns, regressão do `critical`,
  unificação dos top 5 executores.

## [3.14.0] - 2026-06-02

Scanner avançado anti-rootkit + flag de console pra triagem rápida. 50 scanners.

### Added

- `scan_kernel_drivers`: enumera drivers de kernel/filesystem registrados em
  `HKLM\SYSTEM\CurrentControlSet\Services` e flaga os fora do path padrão
  do Windows. Cobre o cenário mais avançado de bypass:

  - Drivers com nome bate base de **BYOVD conhecidos** (winring0, rwdrv,
    gdrv, EneTechIo, iqvw64e, RTCore64, capcom, mhyprot2 e outros usados
    em kdmapper / cheat loader / kernel rootkit): severidade alta.
  - Drivers em **pasta de usuário** (`%TEMP%`, `%APPDATA%`, Desktop,
    Downloads): severidade alta. Drivers legítimos NUNCA carregam de
    pasta de usuário.
  - Drivers fora do path padrão mas em path comum (ex: `C:\ProgramData\`):
    verifica assinatura via WinVerifyTrust; **não-assinado** = alta.
    Assinado ou checagem indisponível = ignora.
  - Driver registrado mas arquivo ausente (entrada órfã): baixa. Comum em
    ferramentas que carregam driver on-demand (CPU-Z, HWInfo).

  Whitelist agressiva por path cobre os ~99% de drivers em
  `System32\drivers`, `DriverStore`, `WinSxS`, `WindowsApps` e
  `WindowsDefender`, mantendo o scanner rápido (0,02 s para 431 drivers
  em PC de teste) e sem ruído.

- Flag `--high-only` no console: filtra a saída pra mostrar apenas itens de
  severidade alta/crítica. Útil pra triagem rápida durante uma SS — quando
  o supervisor quer decisão binária e não precisa do contexto de baixa
  severidade. O relatório HTML e o JSON `.tsr` continuam completos.

### Fixed

- `_normalize_driver_path` usava raw strings com `\\` no final, gerando
  prefixos com dois backslashes que nunca batiam path real. Causava:
  - Whitelist falhando para drivers legítimos em System32 raiz
    (`cdd.dll`, `win32k.sys`).
  - Paths NT (`\??\C:\...`) ficando com `\` extra antes de `C:`, fazendo
    `os.path.isfile` falhar e classificar incorretamente como "órfão".

  Strings agora explicitamente escapadas (`"\\users\\"`, etc.).

### Tests

- 13 testes novos (kernel drivers + `--high-only`): cobre normalização de
  path NT, whitelist de System32 raiz, BYOVD por nome, path de usuário,
  não-assinado, assinado (FP control), órfão, e falha silenciosa do
  verificador de assinatura. Total: 58 testes.

### Changed

- Contagem de scanners: 49 para 50.

## [3.13.1] - 2026-06-02

### Added

- `scan_powershell_history_cleared`: detecta o arquivo `ConsoleHost_history.txt`
  do PSReadLine apagado, zerado ou anormalmente curto. O PowerShell guarda
  toda linha digitada nesse arquivo (append-only, até 4096 linhas) — é o
  que pega "cara rodou comando suspeito no PS antes da SS". Esvaziar o
  arquivo requer ação deliberada (`Clear-History` só limpa a sessão, não
  o arquivo). 0 bytes = alta; < 50 bytes em PC histórico = média; ausente
  em PC histórico = baixa (FP possível: usuário só de CMD/bash).

- 6 testes novos cobrindo zerado, near-empty em PC fresh vs histórico,
  tamanho normal, e ausente em ambos os contextos. Total: 46 testes.

### Changed

- Contagem de scanners: 48 para 49.

## [3.13.0] - 2026-06-02

Três scanners novos focados em bypass que não deixa rastro óbvio. 48 scanners no total.

### Added

- `scan_prefetch_disabled`: detecta `EnablePrefetcher` em 0 ou 2 (só boot)
  e/ou serviço `SysMain` desativado. O padrão do Windows 11 é ambos
  ligados; desativar é a forma "elegante" de impedir que execução nova
  entre no Prefetch. Os dois desativados ao mesmo tempo é severidade
  alta; só um é média (comum em guias antigas de SSD).

- `scan_event_log_gap`: cruza a idade do evento mais antigo dos logs
  `System` e `Application` com a contagem de `.pf` no Prefetch. Log com
  menos de 6 h num PC com Prefetch volumoso (≥ 80 entradas) indica
  `.evtx` deletado com o serviço EventLog parado — bypass furtivo que
  não dispara o evento 1102. Severidade média. Threshold do Prefetch
  evita falso positivo em instalação recente.

- `scan_shadow_copy_wipe`: procura múltiplos eventos `VSS 8224` em janela
  de 60 s (≥ 3). Um evento isolado é a deleção automática do Windows
  quando precisa de espaço — não dispara. Uma rajada curta é compatível
  com `vssadmin delete shadows /all`, que apaga histórico de snapshots
  e destrói a timeline forense de versionamento de arquivos. Severidade
  média.

### Tests

- 10 testes novos cobrindo os 3 scanners: configuração padrão limpa,
  combinação de gatilhos, anti-FP de PC fresh, e distinção entre VSS
  isolado (limpo) e rajada (suspeito). Total: 40 testes.

### Changed

- Contagem de scanners: 45 para 48.

## [3.12.3] - 2026-06-02

### Fixed

- O `build.bat` agora passa `--icon=icon.ico` para o PyInstaller. O ícone
  havia sido adicionado ao repositório em uma versão anterior, mas o script
  de build apagava o `.spec` local (onde o `icon=` estava configurado) e
  invocava o PyInstaller sem o argumento — então o `telador.exe` saía com
  o ícone padrão do PyInstaller. A partir desta versão, o build oficial
  embarca o ícone de terminal corretamente.

## [3.12.2] - 2026-06-02

### Changed

- Otimiza scanning de processos e DLLs no `live_analysis`: reduz overhead na
  varredura de processos ativos e lista de módulos carregados.
- README: adiciona seção "Sobre o Autor".

## [3.12.1] - 2026-06-02

### Changed

- Animação de abertura/fechamento nas seções colapsáveis do relatório HTML
  (suave, com easing spring; 220ms abrir / 180ms fechar).

## [3.12.0] - 2026-06-02

Novo scanner anti-bypass: leitura do USN Journal do NTFS.

### Added

- `scan_usn_journal` (extra_forensics): lê o USN Change Journal do NTFS
  (`fsutil usn readjournal`) e sinaliza arquivos com nome de executor que
  foram **criados, excluídos ou renomeados** no volume — mesmo que o arquivo
  já não exista. Pega o bypass clássico de SS: rodar o executor e apagá-lo
  antes de telar. O journal sobrevive à limpa de Prefetch/Amcache/Recent.
- Também detecta o journal **desativado/recriado** (assinatura de
  `fsutil usn deletejournal`), via `queryjournal` (não exige admin).
- O parser lê o motivo pelos bits do código hex de `USN_REASON_*`, não pelo
  rótulo de texto — funciona em Windows PT-BR (que traduz os rótulos do
  fsutil). `readjournal` exige admin; sem admin o scanner retorna um aviso
  claro em vez de "limpo".
- Severidade: excluído/renomeado = alta; criado = média.
- Testes: bits do motivo independem de idioma, linha de exec excluído vira
  item de alta, e processos legítimos (`chrome.exe`) / extensões fora do
  alvo (`.txt`) não geram falso positivo.

### Changed

- Contagem de scanners: 44 para 45.

## [3.11.5] - 2026-06-01

### Changed

- Animação de digitação do título mais lenta (0,55s para 1,2s), em ritmo
  de digitação mais natural.

## [3.11.4] - 2026-06-01

Animações temáticas de terminal no relatório (sóbrias, de entrada).

### Changed

- O cabeçalho do relatório agora "digita" o título TELADOR ao abrir, com
  um cursor de bloco piscando ao lado, e os três pontos da barra de
  terminal acendem em sequência. As linhas da barra lateral entram em
  cascata curta e as barras do gráfico preenchem da esquerda.
- Todas são animações de entrada (rodam uma vez), exceto o cursor.
  Nada de gradiente, glow ou brilho pulsante — só o que um terminal faz.
- Respeita `prefers-reduced-motion`: quem configurou movimento reduzido
  vê o relatório estático, sem digitação nem cursor.

Sem mudança de funcionalidade.

## [3.11.3] - 2026-06-01

Correção de bug encontrada por auditoria, e teste que a trava.

### Fixed

- **Scanners de subprocess podiam crashar com `OSError`.**
  `scan_scheduled_tasks` (schtasks), `scan_dns_cache` (ipconfig) e
  `scan_amcache` (reg) capturavam apenas `FileNotFoundError` e
  `TimeoutExpired`. Um `OSError` genérico do subprocess (ex.: winerror 50
  em ambientes sem console interativo) não era tratado, e o scanner
  estourava em vez de retornar erro gracioso. Em produção o wrapper de
  execução mascarava, mas qualquer chamada direta quebrava. Agora os três
  capturam `OSError` (que já inclui `FileNotFoundError`).

### Tests

- Novo `test_all_scanners_honor_contract`: executa os 44 scanners e
  garante que nenhum crasha e que todos retornam o contrato completo
  (`name`/`description`/`status`/`items`/`summary`/`error`, com `items`
  lista e `status` válido). Foi esse teste que pegou o bug acima.
  26 testes no total.

## [3.11.2] - 2026-06-01

Reduz falsos positivos de antivírus no executável (empacotamento).

### Changed

- Build agora embute metadados no `.exe` via `--version-file`
  (nome do produto, versão, descrição, autor, link do repo). Um
  executável identificável é menos suspeito para a heurística de
  antivírus do que um binário anônimo, e a informação aparece em
  Propriedades > Detalhes no Windows.
- Build passa a usar `--noupx` para nunca comprimir com UPX (compressão
  que aumenta a taxa de falso positivo).

### Docs

- README ganhou a seção "É seguro? Sobre alertas de antivírus",
  explicando o falso positivo do PyInstaller e mostrando como rodar
  direto do código-fonte para quem preferir não usar o `.exe`.
- Corrigida a contagem de scanners no título da seção (44, 11 categorias).

Sem mudança de funcionalidade ou de detecção.

## [3.11.1] - 2026-06-01

Correção de falsos positivos introduzidos no scan_anti_forensics (v3.11.0).

### Fixed

- **Detecção de Bleachbit/CCleaner por mtime de pasta removida.** O mtime
  da pasta de instalação muda por atualização automática, não só por uso;
  CCleaner é comum demais para ser sinal forte; e o `scan_cleaners` já
  cobre cleaner instalado. Era falso positivo em quem só faz manutenção.
- **"Fontes históricas vazias" agora exige as três juntas** (Prefetch +
  Recent + UserAssist) e severidade MEDIUM, não HIGH. Antes, duas bastavam
  e marcava HIGH — disparava em SSD com SysMain desativado (só Prefetch
  vazia), perfil recém-criado e PC formatado por motivo legítimo. A nota
  do item agora aponta essas alternativas.
- **Log de Security limpo (1102) rebaixado para MEDIUM.** Acontece em
  reinstalação/manutenção, não é exclusivo de cheat.

Sem mudança de funcionalidade. 20 testes passando.

## [3.11.0] - 2026-05-30

Quatro fontes forenses adicionais (extra_forensics.py) para pegar quem
tenta limpar os rastros antes da SS. São fontes que cleaners comuns
raramente tocam. 44 scanners no total.

### Added

- **ShimCache (AppCompatCache):** lê o blob do registry com os
  executáveis vistos pelo subsistema de compatibilidade. Fonte separada
  de Prefetch/Amcache/BAM — sobrevive à limpa dessas. (Precisa admin.)
- **SRUM:** o System Resource Usage Monitor guarda uso de rede/CPU por
  programa nos últimos ~30 dias. Mesmo apagando o executável, o nome
  costuma permanecer. (Arquivo geralmente locado pelo serviço; quando
  acessível, é evidência forte.)
- **Hash de scripts conhecidos:** calcula SHA1 do conteúdo dos
  `.lua`/`.luau`/`.txt` e confronta com `KNOWN_SCRIPT_HASHES`. Pega hub
  público renomeado/comentado cujo conteúdo ainda bate hash. (Base vazia
  por design — popular com amostras reais.)
- **Anti-forense reforçada:** detecta uso de Bleachbit/CCleaner nas
  últimas 24h, a combinação "Prefetch + UserAssist + Recent vazios ao
  mesmo tempo" (assinatura de cleaner pré-SS), e limpeza do log de
  Security (evento 1102).

### Notes

- Todos exigem cobertura total apenas com privilégio de administrador;
  sem ele, degradam para skip sem quebrar.
- ShimCache otimizado para extrair só tokens de executável (de 7s para
  0,2s). 20 testes no total (4 novos).

## [3.10.0] - 2026-05-30

Identidade visual própria: terminal forense.

### Changed

- Relatório HTML repaginado com estética de terminal: tipografia
  monoespaçada em toda a interface, paleta âmbar sobre preto profundo,
  e o cabeçalho como uma janela de terminal (três pontos e título).
- Logo trocado por um wordmark de terminal (`>_ TELADOR`) na barra
  lateral e no relatório.
- Severidades exibidas como tags `[HIGH]` / `[MEDIUM]` / `[LOW]` em vez
  de etiquetas arredondadas.
- Banner do console agora em âmbar, com a linha `>_`.
- README com wordmark ASCII no lugar do SVG anterior (que o GitHub não
  renderizava em Markdown).

Mudança apenas estética; toda a funcionalidade e os dados do relatório
permanecem iguais. 17 testes passando.

## [3.9.0] - 2026-05-30

Permite estender a base de assinaturas sem recompilar.

### Added

- Carregamento de assinaturas externas (`signatures.json`). Se o arquivo
  existir ao lado do executável, suas entradas são mescladas às listas
  embutidas na inicialização. Seções aceitas: `executor_keywords`,
  `executor_process_names`, `suspicious_domains`, `suspicious_folder_names`,
  `script_red_flags`. Permite adicionar um executor novo entre releases
  sem rebuildar.
- `signatures.example.json` documentando o formato.

### Notes

- Degrada graciosamente: arquivo ausente, JSON inválido ou entradas
  malformadas são ignorados sem interromper a execução.
- 17 testes no total (3 novos para o carregamento de assinaturas).

## [3.8.2] - 2026-05-30

Caça a bugs — varredura com pyflakes + revisão manual.

### Fixed

- **Prefetch perdia executores com hífen no nome.** `fname.split("-")[0]`
  truncava `wave-bootstrapper.exe-1A2B.pf` para `"wave"` (que, com o
  matching word-boundary, não casa nada). Trocado por
  `fname[:-3].rsplit("-", 1)[0]`, que remove só o hash final e preserva
  o nome. Agora `wave-bootstrapper`, `xeno-bootstrapper`, etc. são pegos.
- **JumpLists tinha substring match residual.** `scan_jumplists` iterava
  `EXECUTOR_KEYWORDS` com `if kw in text` próprio — escapou da
  centralização word-boundary e reintroduzia FP (`argon`→`argonauts`).
  Agora delega pro `match_keyword` central.

### Removed (limpeza — pyflakes)
- Dead code: `color` (report) e `before_pe` (telador), órfãos após
  refactors anteriores.
- 2 f-strings sem placeholder (cosmético).
- 6 imports não usados (`EXECUTOR_KEYWORDS` ficou órfão nos módulos que
  passaram a delegar pro matching central; `re`, `datetime`, `sys`,
  `json`, `pathlib.Path` soltos).

### Verified
- pyflakes: 0 undefined names, 0 imports unused, 0 f-strings vazias.
- Run completo (40 scanners) sem traceback. 14 testes passando.

## [3.8.1] - 2026-05-30

Frontend — passe de legibilidade (sóbrio, sem efeito gratuito).

### Changed

- **Severidade vira pill sólida** em vez de dot+texto — mais escaneável,
  cores consistentes (high/medium/low).
- **Linhas com faixa lateral colorida** (`box-shadow: inset`) em vez de
  fundo tingido gritante. Mais limpo em tabela longa.
- **Cabeçalho de tabela fixo** (`position: sticky`) — não some o header
  ao rolar uma tabela com muitos hits.
- **Coluna "Detalhe" truncada em 2 linhas**, expande no clique
  (duplo-clique copia). Paths longos + nota de FP-filter não estouram
  mais o layout.
- **Card de resumo (hero) reorganizado** em grid: veredito grande à
  esquerda, stats à direita. Responsivo abaixo de 720px.

## [3.8.0] - 2026-05-30

Foco em CONFIANÇA no resultado — não dá mais pra forjar/reaproveitar a SS,
e detecta cheat visual externo que não injeta DLL.

### Added

#### 🔐 Prova de SS ao vivo (`--codigo`)
- O supervisor dita um código no início da SS; o telado roda
  `telador.exe --codigo XYZ`. O código + um `session_id` aleatório
  (`secrets.token_hex`) + timestamp entram no `sys_info`, que já é
  assinado por HMAC no `.tsr` e exibido em card dedicado no relatório.
- Mata a fraude de "rodar num PC limpo e reapresentar o relatório
  depois": sem o código certo da sessão, o relatório não confere.
- Sem `--codigo`, o card avisa em laranja "sessão NÃO verificada".

#### 🖼️ Detecção de overlay / ESP externo (`scan_overlay_windows`)
- 40º scanner. Enumera janelas com `WS_EX_LAYERED + WS_EX_TRANSPARENT
  + WS_EX_TOPMOST` — janela invisível ao clique desenhada por cima de
  tudo, assinatura de ESP/radar/aimbot visual que roda FORA do processo
  (não injeta DLL, então o scan de DLL não pega).
- Whitelist generosa (Discord, NVIDIA, Steam, OBS, RTSS, Game Bar,
  iCUE, G HUB, PowerToys, etc.) → severity `medium` no resto pra evitar
  FP de overlay legítimo desconhecido.

### Tests
- +5 testes (sessão verificada/não-verificada, sysinfo não polui card,
  overlay scanner roda, whitelist cobre apps comuns). Total: 14.

## [3.7.0] - 2026-05-30

Corrige a RAIZ dos falsos positivos + primeira suíte de testes.

### Changed

- **Matching agora é word-boundary, não substring** (`matching.py`, novo
  módulo central). Antes, `_match_keyword` casava qualquer keyword como
  substring no path/cmdline completo — `argon` casava `argonauts`,
  `trigon` casava `trigonometria`, `scriptware` casava `scriptwarehouse`.
  Agora a keyword só casa quando vem delimitada (ponto, barra, espaço,
  hífen, fim de string): `argon.exe` ✓, `/argon/` ✓, `argonauts` ✗.
  Era o vetor de FP nº 1 sinalizado na auditoria.
- Os 4 `_match_keyword` duplicados (scanners, forensics, live_analysis,
  persistence) agora delegam pro módulo central (DRY).

### Added

- **Primeira suíte de testes** (`tests/test_detection.py`, 9 testes):
  - executores reais continuam casando
  - jogos/apps legítimos (Cryptic Studios, Xenoblade, Nihon Falcom,
    Argonauts, scriptwarehouse) não disparam
  - regressão: keywords soltas removidas não voltam, MACs Hyper-V fora,
    process names genéricos fora, APIs Roblox não-HIGH, verdict ignora
    `meta_only`
- **CI agora roda `pytest`** além do smoke test de imports.

## [3.6.1] - 2026-05-30

Auditoria de falsos positivos — patch sem mudança de funcionalidade,
só precisão de detecção.

### Fixed

- **MACs Hyper-V removidos** (`00:15:5D`, `00:03:FF`). O adaptador
  vEthernet do WSL2/Docker Desktop/Windows Sandbox/VBS usa esses
  prefixos na máquina física — `scan_vm` dava `VM Detection HIGH` em
  Win10/11 legítimo. Era o FP de maior alcance.
- **Keywords substring removidas** (`xeno`, `cryptic`, `empyrean`,
  `calamari`, `nihon`): casavam por substring no path/cmdline completo
  e pegavam jogos legítimos (Cryptic Studios → Star Trek Online/
  Neverwinter; Xenoblade; Nihon Falcom). Variantes específicas
  (`xeno executor`, `cryptic exec`, `nihon.exe`, etc.) preservadas.
- **`compute_verdict` ignora `meta_only`**: o cabeçalho de contexto
  "[PROCESSO] RobloxPlayerBeta.exe" somava +1 LOW no score em todo PC
  com Roblox aberto.
- **Process names genéricos removidos** (exact-match HIGH que pegava
  software legítimo): `electron.exe` (framework dev), `sentinel.exe`
  (Sentinel LDK/HASP licenciamento), `swift.exe`, `ninja.exe` (Ninja
  build system — dev C++/CMake), `apex.exe`, `cosmic.exe`, `coral.exe`,
  `sense.exe`, `omega.exe`, `verbose.exe`, `pylon.exe`, `fenix.exe`,
  `ronin.exe`. Todos cobertos por keyword `<nome> executor`.
- **APIs nativas do Roblox rebaixadas** (`high` → `medium`):
  `firetouchinterest`, `fireclickdetector`, `fireproximityprompt` —
  usadas em jogos legítimos no Studio, não exclusivas de executor.

## [3.6.0] - 2026-05-28

Detecção de PC formatado pra SS — clássica fuga de cheater experiente.

### Added

#### 🚨 Fresh install detector (`fresh_install.py`)

`scan_fresh_install` combina **6 sinais** independentes pra detectar PC
formatado/reinstalado pra apagar rastros antes da SS:

1. **Windows InstallDate** do registry — granularidade de horas/dias:
   - Hoje = HIGH
   - 1-3 dias = HIGH
   - 4-7 dias = MEDIUM
   - 8-21 dias = LOW
2. **Prefetch count** — < 10 = HIGH, < 30 = MEDIUM (normal 100-500)
3. **UserAssist entries** — < 5 = HIGH, < 15 = MEDIUM (normal 50+)
4. **C: volume creation time** via `fsutil fsinfo ntfsinfo` — confirma
   formatação FÍSICA (não só Windows reset)
5. **Gap Roblox → Windows** — Roblox instalado < 6h depois do Windows
   = HIGH (sequência clássica formata→instala→cheata)
6. **Pasta Recent vazia** — < 5 atalhos = formatação recente

Cobertura: mesmo se formatou há 1-2 semanas, vários sinais ficam.
Multi-sinal combinado eleva veredict drasticamente.

## [3.5.0] - 2026-05-28

Network forensics + Discord cache + brand identity.

### Added

#### 🌐 Network scanners (`network_scanners.py`)
- `scan_network_connections` — TCP/UDP ativos com nome de processo,
  flag se processo é executor conhecido (psutil).
- `scan_dns_cache` — `ipconfig /displaydns` parsed, match contra
  domínios suspeitos. Pega site visitado mesmo se browser history
  foi limpo.
- `scan_hosts_file` — detecta bloqueio de telemetria do Roblox
  (`roblox.com`, `rbxcdn.com`, etc.) apontados pra `0.0.0.0`/
  `127.0.0.1`. Red flag forte — cheaters fazem pra não enviar
  telemetria de detecção.

#### 💬 Discord cache (`discord_cache.py`)
- `scan_discord_cache` — parseia cache binário de Discord/Canary/
  PTB/Lightcord procurando URLs de sites de cheat. Pega DM
  apagada com link de download.

#### 🎨 Brand identity
- Logo SVG oficial do Telador (escudo gradient + lupa) no sidebar
  do relatório e no README.
- Filter glow + animação scaleIn no logo.

#### 📛 Badges adicionais no README
- Downloads totais, último commit, CI status — todos `for-the-badge`
  estilo Vercel/Linear.

## [3.4.0] - 2026-05-28

UI redesign do relatório HTML — agora layout dashboard profissional.

### Added

#### 📐 Sidebar sticky com TOC
- Navegação lateral fixa com link pra cada section.
- Badge vermelha com contador de hits ao lado de cada scanner.
- Highlight visual de scanners com hits vs limpos.
- Score do veredito badge no topo da sidebar.

#### 📈 Charts
- **Donut SVG** mostrando distribuição de severidade (high/medium/low)
  com score numérico no centro.
- **Bar chart** dos top 10 scanners por número de hits.
- Tudo SVG/CSS puro, zero dependências.

#### 🔽 Sections colapsáveis
- Cada section vira `<details>`. Limpas começam fechadas, com hits
  abertas. Telador foca no que importa.

#### ✅ Empty state
- Quando 0 hits totais, mostra card verde com checkmark grande,
  explicação clara, e aviso de heurística (não é prova definitiva).

#### 🖨️ Print CSS
- `@media print` esconde sidebar/controls, faz fundo branco,
  expande sections. Telador pode imprimir relatório limpo.

#### 📱 Responsive
- `@media (max-width: 700px)` reorganiza pra mobile (sidebar vira
  topo).
- `@media (max-width: 900px)` colapsa charts em 1 coluna.

## [3.3.0] - 2026-05-28

QoL release — Markdown export + quick mode.

### Added

#### 📋 Markdown export (`report_md.py`)
- Nova flag `--md` salva relatório em `.md` colável **direto no Discord**.
- Inclui veredito, score, stats, cross-correlation, e top hits por
  fonte. Cap em ~6KB pra não estourar limite de mensagem.

#### ⚡ Modo rápido (`--quick`)
- Roda só os 15 scanners base (skip forensics/persistence/live/
  history/peripherals/anti-evasion). ~1s vs ~5s do scan completo.
- Útil pra SS rápida em volume.

## [3.2.2] - 2026-05-28

False-positive precision pass — relatório de PC limpo agora dá LIMPO.

### Fixed

- **`RBXCRASH` removido dos padrões de log do Roblox.** Crash genérico
  do client pode ser driver/OOM/hardware. Só Hyperion/AntiTamper/
  DllInjection/ProcessUntrusted continuam como sinais.
- **Defender exclusion de IDE/dev path não vira flag.** Adicionado
  `DEFENDER_EXCLUSION_DEV_PATHS` cobrindo JetBrains/VS Code/Visual
  Studio/Unity/Unreal/.git/node_modules/.venv/Steam/etc. JetBrains
  literalmente documenta excluir. Não é red flag.
- **`ExecutionPolicy Bypass` sozinho ≠ HIGH.** Agora precisa de
  download keyword (`iex`/`irm`/`iwr`/`Invoke-WebRequest`/etc.) na
  MESMA linha pra continuar HIGH. Sem download = MEDIUM. Devs/admins
  rodam scripts com bypass o tempo todo.

### Changed

Verdict thresholds bumpados pra reduzir falsos suspeitos:

| Verdict | Antes | Agora |
|---|---|---|
| CHEATER CONFIRMADO | score ≥ 40 | **score ≥ 50 E ≥ 3 fontes** |
| ALTAMENTE SUSPEITO | score ≥ 20 | **score ≥ 25 E ≥ 2 fontes** |
| SUSPEITO (REVISAR) | score ≥ 8 | **score ≥ 12 E ≥ 2 fontes** |
| POSSÍVEIS PISTAS | score ≥ 2 | **score ≥ 4** |
| LIMPO | < 2 | < 4 |

Cross-correlation entre fontes agora também conta — 1 fonte só
raramente é evidência de cheat sólida.

## [3.2.1] - 2026-05-27

Security/privacy patch — protege dados sensíveis no relatório.

### Added

#### 🛡️ Redação automática (`redaction.py`)
- Procura padrões de credenciais/tokens/emails em todos os campos
  do relatório e substitui por `[REDACTED]`:
  - Bearer/Basic tokens
  - `password=`, `token=`, `apikey=`, `secret=` inline
  - OpenAI (`sk-`), Anthropic (`sk-ant-`), GitHub (`gh[opsu]_`),
    Slack (`xox*-`), Google (`AIza*`), AWS (`AKIA*`), Discord
  - Emails (mantém domínio)
  - Hex strings de 40+ chars (hashes/tokens)
  - URLs com `user:pass@host`
  - CPF e cartão de crédito

#### 🔒 Screenshot privacy-aware
- Antes de capturar tela, telador detecta se há gerenciador de senha
  rodando (KeePass, 1Password, Bitwarden, LastPass, Dashlane, Authy,
  Enpass, NordPass, etc.) e **pula screenshot** com aviso.
- `--force-screenshot` override pra forçar captura mesmo assim.

### Added — CLI
- `--no-redact` — desliga redação (debug).
- `--force-screenshot` — força captura mesmo com password manager aberto.

## [3.2.0] - 2026-05-27

The "10/10" release. Visual timeline, PE analysis with hash matching,
signed reports, and SS-to-SS comparison.

### Added

#### 🔬 PE analysis (`pe_analysis.py`)
- `compute_sha256` — hash de qualquer arquivo (SHA256).
- `parse_pe_header` — parser nativo (sem deps) que extrai:
  compile timestamp, sections, machine arch, packer detection
  (UPX, Themida, VMProtect, Enigma, ASPack, PECompact, MPRESS, PELock).
- `enrich_findings_with_pe` — pós-processo que pra cada item apontando
  pra um `.exe/.dll` calcula SHA256 + analisa PE header e anexa ao
  item. Faz auto-upgrade de severity:
  - Packed → HIGH (cheat protegido = quase certo)
  - Compilado nos últimos 30 dias → +1 nível
  - Hash match contra `KNOWN_EXECUTOR_HASHES` → HIGH
- Stub `KNOWN_EXECUTOR_HASHES` pronto pra popular com hashes reais.

#### 🕐 Timeline visual (`report.py`)
- Novo card no relatório com todos os hits plotados num eixo horizontal
  por timestamp. Cluster denso = burst suspeito (ex: baixou cheat,
  rodou, deletou em 5 min).

#### 🔏 Report signing (`report_signing.py`)
- `get_self_hash` — SHA256 do próprio `.exe`. Banner mostra primeiros
  e últimos 16 chars pra cara comparar com a release publicada.
- `compute_hmac` / `verify_hmac` — HMAC-SHA256 com chave embedada.
  Tamper-evident: cara teria que recompilar pra burlar.

#### 📊 SS-to-SS diff (`diff_tool.py`)
- `save_tsr` — salva relatório em `.tsr` (JSON + HMAC).
- `load_tsr` — carrega + verifica HMAC, recusa se foi adulterado.
- `diff_reports` — compara 2 .tsr e retorna added/removed/persistent.
- `format_diff_console` — output colorido pra console.
- Nova flag: `--save-tsr PATH` e `--diff OLD.tsr`.

### Changed
- Banner: `v3.2 · 34 scanners · PE analysis · Timeline · Diff entre SS · HMAC`.
- Banner agora mostra SHA256 do próprio exe.
- Report HTML inclui timeline e PE section quando houver dados.
- Footer HTML mostra SHA256 completo do exe (autenticidade).

### Added — CLI
- `--no-pe` — pula PE analysis (mais rápido em PCs com muitos exes).
- `--save-tsr PATH` — salva snapshot assinado pra comparar depois.
- `--diff OLD.tsr` — compara este scan com um .tsr anterior, mostra
  hits novos/removidos.

## [3.1.0] - 2026-05-27

Quality release focused on **reducing false positives** — tool that
flags everyone as cheater is useless for serious SS.

### Added

#### 🛡️ False-positive filter (`fp_filter.py`)
- `detect_dev_environment` — checks for Visual Studio, JetBrains,
  VS Code, Python/Node SDKs, Git, `source\repos` folder. If 2+ indicators
  found, treats user as developer (Cheat Engine / IDA / dnSpy / x32dbg
  get auto-downgraded to LOW — legitimate uses exist).
- `is_whitelisted_path` — paths inside `.git`, `node_modules`, `.venv`,
  `__pycache__`, `.vscode`, `.idea`, Steam library, Microsoft Visual
  Studio, JetBrains, Windows system folders, NVIDIA/AMD/Intel drivers,
  Windows Defender, Windows SDKs — all auto-removed.
- `apply_time_decay` — hits older than 30 days get downgraded one
  severity level. 90+ days = downgraded two levels.
- `adjust_browser_finding` — visits to forum/research domains
  (v3rmillion, unknowncheats, guidedhacking) only get HIGH severity
  if there was an actual DOWNLOAD. Pure visit = MEDIUM at most.
- `compute_confidence` — 0-100 numeric score per item considering
  severity, age, FP downgrades, and freshness boost for recent hits.
- `compute_verdict` — weighted final verdict using `severity × confidence`
  summation. New verdict tiers:
  - `CHEATER CONFIRMADO` (score ≥ 40)
  - `ALTAMENTE SUSPEITO` (score ≥ 20)
  - `SUSPEITO (REVISAR)` (score ≥ 8)
  - `POSSÍVEIS PISTAS` (score ≥ 2)
  - `LIMPO` (score < 2)

#### 📊 New report fields
- Items now carry `original_severity`, `fp_reason`, and `confidence`.
- HTML report shows a `↓ era HIGH` badge with tooltip explaining why
  the item was downgraded.
- Confidence shown as a colored bar per item.
- New "Filtro de Falsos Positivos" card in the report summarizing
  whitelisted/downgraded counts and dev-env evidence.
- Summary card now shows weighted score + most recent hit timestamp.

### Changed
- Verdict logic is now weighted (was: simple HIGH > 0 check).
- Console output shows FP-filter stats inline before the summary.
- Banner: `v3.1 · 34 scanners · FP-filter · Score ponderado · Dev-aware`.

### Added — CLI
- `--strict` flag — disables the entire FP-filter pass for paranoia mode.

## [3.0.0] - 2026-05-27

Major release focused on detection depth — extra coverage layer for
deeper SS analysis. **34 scanners** total (was 25).

### Added

#### 🧬 Live process analysis (`live_analysis.py`)
- `scan_roblox_dll_injection` — lists ALL DLLs loaded into running
  `RobloxPlayerBeta.exe` / `Windows10Universal.exe` processes, flags
  unsigned DLLs (via `WinVerifyTrust`), DLLs in suspicious paths
  (`%TEMP%`, `%APPDATA%`, `Downloads`, `Desktop`), and DLLs whose name
  matches an executor keyword. **Catches injected cheats even if the
  on-disk file was deleted.**
- `scan_process_tree` — verifies that Roblox was spawned by a legit
  parent (`explorer.exe`, `bloxstrap.exe`, `RobloxPlayerLauncher.exe`,
  major browsers). Suspicious parent = possible injector chain.

#### 📜 Command history (`command_history.py`)
- `scan_powershell_history` — reads `ConsoleHost_history.txt`, the
  append-only log of every PowerShell command ever typed. Flags
  `iex (irm krnl.cat/...)`-style one-liner installers, AMSI bypasses,
  Defender exclusion mods, `bitsadmin` / `wget` / `curl` downloads,
  base64-encoded commands, event-log clears, USN journal deletes.
- `scan_runmru` — Win+R history from HKCU Registry.
- `scan_typed_paths` — paths typed into the Explorer address bar.

#### 🖱️ Peripheral macros (`peripherals.py`)
- `scan_mouse_software_installed` — detects G HUB, Logitech Gaming
  Software, Razer Synapse, Bloody (A4Tech), X-Mouse Button Control,
  SteelSeries GG, Corsair iCUE, HyperX NGENUITY, Redragon.
- `scan_logitech_ghub_scripts` — opens G HUB's SQLite `settings.db`,
  reads stored macro Lua scripts, flags keywords: `no recoil`,
  `recoil control`, `auto headshot`, `rapid fire`, `aim assist`,
  `MoveMouseRelative`, etc.
- `scan_xmouse_profiles` and `scan_razer_synapse` — same logic
  against their profile/config files.

#### 🖥️ Multi-monitor screenshot (`capture.py`)
- `capture_all_monitors` enumerates monitors via `EnumDisplayMonitors`
  and captures each one separately. Default `capture_all()` now
  captures **every monitor** + Roblox window. Cheater hiding HUD on
  monitor 2 is now exposed.

### Changed
- Banner: `v3.0 · 34 scanners · DLL live scan · PS history · Multi-monitor · Macros`.
- Added CLI flags: `--no-live`, `--no-history`, `--no-peripherals`.
- Build script: added new hidden imports for the new modules.
- Database additions: `POWERSHELL_RED_FLAGS` (50+ patterns),
  `MACRO_RED_FLAGS` (30+ patterns), `MOUSE_SOFTWARE` registry,
  `ROBLOX_PROCESS_NAMES`, `TRUSTED_DLL_PATHS`, `SUSPICIOUS_DLL_PATHS`.

### Fixed
- Process tree no longer false-flags when parent process can't be
  read due to permission (waits for admin).

## [2.0.0] - 2026-05-27

### Added
- Massive database expansion: **542 detection signatures** (from ~194).
  - `EXECUTOR_KEYWORDS`: 65 → 164 entries
  - `EXECUTOR_PROCESS_NAMES`: 26 → 89 entries
  - `SUSPICIOUS_DOMAINS`: 33 → 104 entries
  - `SUSPICIOUS_FOLDER_NAMES`: 18 → 80 entries
  - `SCRIPT_RED_FLAGS`: 39 → 105 entries
- New executors covered: Xeno, Cryptic, Empyrean, Valyse, Bunni Hub, Cosmic,
  Acrylix, Marin, Coral, Furk Os, Sense, Karambit X, Drumix, Omega X,
  Apex Hardware, Stellar Spoof, Sploitware, CCDownloader, Cellura, Hexus,
  Verbose, Ninja Hub, Valex, Pylon, Fenix, Ronin, Swift X.
- New categories: HWID spoofers (rage/perm/tbhd), kernel mappers
  (kdmapper, drvmap, ezmapper, intelmapper, manualmapper), anti-cheat
  bypass tools (byfron/hyperion killers), debugger/reverser detection
  (IDA, Ghidra, dnSpy, x32/64dbg, OllyDbg, windbg), gray-hat marketplaces
  (elitepvpers, unknowncheats, guidedhacking, mpgh).
- Popular hubs detection: Owl, Dark, Infinite Yield, Hoho, Epix, Vape v4,
  Vape Lite, Fates Admin, Kraken, Rip, Rocky, Fluxus Hub, Thresh.
- Per-game hubs: Blox Fruits, Pet Sim, Arsenal, Phantom Forces, Doors,
  Criminality, Da Hood.
- ~40 new script red flags: `newcclosure`, `checkcaller`, `iscclosure`,
  `getnamecallmethod`, `setnamecallmethod`, `firetouchinterest`,
  `fireclickdetector`, `fireproximityprompt`, `decompile`, `getscripts`,
  `getloadedmodules`, `getinstances`, `getnilinstances`, `getgc`, `getreg`,
  `saveinstance`, `_G.aimbot`, `_G.esp`, `killall`, `btools`, `byfron`,
  `hyperion`, `antitamper`, etc.

### Removed
- **BREAKING:** Discord webhook integration removed. `webhook.py` deleted,
  `--webhook` flag removed, `DISCORD_WEBHOOK_URL` env var no longer read.
  Tool is now 100% local — no network egress anywhere.

### Changed
- Banner updated to `v3.1 · 25 scanners · 542 signatures · Paralelo · 100% local`.
- Build no longer bundles `mimetypes` / `urllib` hidden imports (webhook only).

## [1.0.0] - 2026-05-26

### Added
- Public repository bootstrap with documentation and policy files.
- Initial `.gitignore` for Python and build artifacts.
- Initial `README.md`, `LICENSE`, and `SECURITY.md`.
- GitHub Actions workflow for syntax and import smoke checks.

### Notes
- This release focuses on project publishing readiness and CI baseline.
