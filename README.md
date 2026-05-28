# Telador BR

Ferramenta forense local para Windows que executa **34 scanners** em paralelo, procurando indícios de executores Roblox, ferramentas de cheating e padrões comportamentais suspeitos. 100% local, zero envio de dados.

[![Latest Release](https://img.shields.io/github/v/release/highdev0/combatroblox)](https://github.com/highdev0/combatroblox/releases/latest)
[![CI](https://github.com/highdev0/combatroblox/actions/workflows/ci.yml/badge.svg)](https://github.com/highdev0/combatroblox/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Comece aqui (mais simples)

1. Baixe `telador.exe` da [última release](https://github.com/highdev0/combatroblox/releases/latest)
2. Clique direito → **Executar como administrador** (pra cobertura completa)
3. Pronto. Relatório HTML abre no navegador automático

Pra distribuir pro usuário final: zipe `telador.exe` + `INICIAR.bat`, manda no Discord, instrui dois cliques.

## O que faz

### 🔍 34 scanners em 7 categorias

| Categoria | Cobertura |
|---|---|
| **Execução** | Prefetch, UserAssist, MUICache, Amcache (SHA1), BAM (timestamp exato) |
| **Persistência** | Startup folder, Run/RunOnce, Scheduled Tasks, WER crash dumps |
| **Filesystem** | Recent files, Lixeira ($I parser), JumpLists, Downloads, hidden files |
| **Browser** | Chrome, Edge, Brave, Opera — URLs + downloads |
| **Roblox** | Logs do client, Bloxstrap, bytecode/autoexec dumps, scripts `.lua/.luau` |
| **Live process** | DLL injection scan em `RobloxPlayerBeta.exe` (com `WinVerifyTrust`), process tree |
| **Comportamento** | PowerShell history, RunMRU, TypedPaths, mouse macros (Logitech G HUB Lua, Razer, X-Mouse) |
| **Anti-evasão** | VM (VMware/VBox/Hyper-V/QEMU), Sandboxie, clock tampering |

### 🛡️ Filtro de falsos positivos
- **Dev-aware**: detecta Visual Studio/JetBrains/VS Code e rebaixa Cheat Engine/IDA/dnSpy automaticamente
- **Time decay**: hits >30d perdem severity, >90d viram LOW
- **Whitelist contextual**: `.git`, `node_modules`, Steam, system folders ignorados
- **Smart browser**: visita a forum ≠ download direto
- **Veredict ponderado**: score numérico, não só HIGH counter

### 🔬 PE Analysis
SHA256 + parser nativo de PE header em todo `.exe`/`.dll` flagado:
- Compile timestamp (compilado <30d = upgrade)
- Detecta packers (UPX/Themida/VMProtect/Enigma/ASPack/PECompact/MPRESS)
- Hash match contra database de executores conhecidos
- Machine arch (x86/x64/ARM64)

### 📊 Relatório HTML
Dashboard com:
- Sidebar sticky + TOC navegável
- Donut SVG + bar chart (severidade e top scanners)
- Timeline visual de hits (cluster denso = burst suspeito)
- Sections colapsáveis + search/filter live
- Multi-monitor screenshots (TODOS os monitores)
- Lightbox modal pra zoom
- Print-friendly + responsive
- Animations sutis, custom scrollbar

### 🔏 Integridade
- `--save-tsr` salva snapshot HMAC-assinado
- `--diff old.tsr` compara com SS anterior, mostra hits novos/sumidos
- Banner mostra SHA256 do próprio `.exe` pra cara verificar autenticidade

### 🛡️ Privacy
- **Zero network egress** — nada sai do PC
- Redação automática de tokens, passwords, emails, CPF, etc.
- Screenshot pulado se gerenciador de senha estiver aberto
- Open-source, código auditável

## Uso

```bash
# Default — roda tudo
telador.exe

# Modo rápido (15 scanners base, ~1s)
telador.exe --quick

# Sem screenshot
telador.exe --no-screenshot

# Salva snapshot pra comparar depois
telador.exe --save-tsr fulano_2026-05-28.tsr

# Compara com SS anterior
telador.exe --save-tsr fulano_2026-06-28.tsr --diff fulano_2026-05-28.tsr

# Markdown export (colável no Discord)
telador.exe --md

# Modo paranoia (desliga FP-filter)
telador.exe --strict

# Skips opcionais
telador.exe --no-forensics --no-persistence --no-live --no-history --no-peripherals
```

## Build do executável

```bat
build.bat
```

Saída: `dist/telador.exe` (~11MB, sem deps externas no runtime).

## Requirements

- Windows 10/11
- Python 3.10+ (apenas pra build/dev)
- `psutil` (única dep runtime)

```bash
pip install -r requirements.txt
```

## Avisos importantes

- **Detecção é heurística** — pode ter falso negativo (cheat renomeado, versão nova). Conduza SS visual também.
- **Use só em ambiente autorizado**. Não é ferramenta de vigilância — é ferramenta de auditoria com consentimento. Respeite leis locais e políticas da sua comunidade.
- **Antivírus pode flagar `.exe`** — PyInstaller é falso-positivo comum. Compare SHA256 do banner com a release oficial pra verificar autenticidade.

## Segurança

Vulnerabilidades: ver `SECURITY.md`.

## Licença

MIT. Ver `LICENSE`.
