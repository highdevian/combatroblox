# Changelog

All notable changes to this project will be documented in this file.

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
