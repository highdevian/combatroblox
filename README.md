<div align="center">

# Telador

### Screen-share forense pra Roblox — veredito em segundos, não em horas.

Roda no PC do suspeito, lê os artefatos do Windows (Prefetch, Amcache, BAM, USN, logs do Roblox…)
e entrega um **veredito de cheat com % de confiança**.
**100% local — nada sai do PC.** Open source.

<br>

[![release](https://img.shields.io/github/v/tag/highdevian/combatroblox?sort=semver&label=release&color=ff4d4f)](https://github.com/highdevian/combatroblox/releases/latest)
[![CI](https://img.shields.io/github/actions/workflow/status/highdevian/combatroblox/ci.yml?branch=main&label=CI)](https://github.com/highdevian/combatroblox/actions)
![scanners](https://img.shields.io/badge/scanners-113-8b5cf6)
![tests](https://img.shields.io/badge/tests-846%20passing-3fbf7f)
[![Windows](https://img.shields.io/badge/Windows-10%2F11-0078d6)](https://github.com/highdevian/combatroblox/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-3fbf7f)](LICENSE)

[**Baixar o telador.exe**](https://github.com/highdevian/combatroblox/releases/latest/download/telador.exe) ·
[**Site**](https://combatroblox-forensics.vercel.app/) ·
[**Guia de SS**](https://combatroblox-forensics.vercel.app/playbook) ·
[**Ferramentas**](https://combatroblox-forensics.vercel.app/ferramentas)

</div>

---

```text
  >>> CONFIDENCE ENGINE: TARGETS DETECTADOS <<<
    ● [CONFIRMED] Solara  (executor)    96% confidence    score=52.1 · 4 fontes
        ✓ prefetch   ✓ amcache   ✓ bam   ✓ live_processes
```

> **113 scanners forenses** cruzam evidência de dezenas de fontes do Windows. Uma fonte
> sozinha **nunca** confirma — o **Confidence Engine** agrupa os hits do mesmo alvo num
> veredito único (CONFIRMED / DETECTED / SUSPECT) com % de confiança, em vez de cuspir
> 50 hits soltos pra você interpretar.

## Como usar

Baixa o `telador.exe` e roda. Ele pede admin sozinho (UAC) — **aceita**, senão as fontes
mais fortes (Prefetch, Amcache, BAM) não são lidas e o resultado fica incompleto. Em
alguns segundos o relatório HTML abre no navegador.

Sem terminal? `INICIAR.bat` (scan) e `TELADOR-AO-VIVO.bat` (dashboard ao vivo) rodam com
dois cliques. Pra distribuir, zipa o `.exe` com os `.bat` e manda no Discord.

> **Sem admin, "nada encontrado" não inocenta — é inconclusivo.** O programa avisa isso.

## O que detecta

| | |
|---|---|
| **Executores conhecidos** | 542 assinaturas — Solara, Xeno, Wave, Velocity, Ronix, Krnl, Fluxus, Synapse X e dezenas de menores. Bate em Prefetch, Amcache, BAM, UserAssist, USN, browser, Lixeira, processos. |
| **Executor renomeado** | Por **estrutura**, não por nome: exe não-assinado + runtime web embutido (EBWebView/CEF) em pasta de usuário. Sobrevive a renomear o arquivo. |
| **Executor por assinatura binária (YARA)** | Regras estilo YARA leem o **conteúdo** do `.exe`/`.dll`: se carrega os símbolos da API de exploit Luau (`getrawmetatable`, `hookmetamethod`, `newcclosure`…) ou toolmarks de injeção, casa mesmo renomeado/repackado. Pula assinados e o próprio telador. **Regras externas**: drope um `yara_rules.json` ao lado do exe (ex.: pacote-strings) e vira detecção sem recompilar. |
| **Launcher do Roblox patcheado** | `RobloxPlayerBeta.exe` com assinatura quebrada (modificado pra injetar) — e dropper se passando por launcher. |
| **Autoclickers e macros** | OP Autoclicker, TinyTask, Speed Autoclicker, Pulover, G HUB/Razer com motor de macro, e red flags de conteúdo (no recoil, auto click). |
| **Evasão de ban e alts** | Account managers, multi-instância, HWID spoofers. |
| **Drivers BYOVD / kernel** | winring0, mhyprot2, capcom, gdrv e cia (kdmapper, loader). |
| **Hardware DMA (parcial)** | Enumera PCIe/USB e flagga IDs de placa DMA conhecidos — FPGA Xilinx (`VEN_10EE`: PCIeScreamer/LeetDMA/CaptainDMA) e ponte USB3 FT601. Heurístico: firmware que spoofa o ID escapa, ausência **não** inocenta. |
| **Event Log de execução (estilo Hayabusa)** | Lê o Event Log do Windows: **7045** (driver/serviço instalado — pega BYOVD mesmo se o `.sys` foi deletado, e funde com o detector de drivers), **4104** (PowerShell script block — download cradle e nome de executor) e **4688** (criação de processo — pega o executor pelo nome se o audit estiver ligado). Rastro que sobrevive à deleção do arquivo. |
| **Defender detectou o cheat** | Eventos **1116/1117** do Defender: o próprio antivírus do Windows pegou um hacktool/executor e o suspeito manteve/excluiu. Casa nome de executor (funde no cluster) ou hacktool. Gated pra não flaggar PUA/trojan genérico. |
| **Injeção em runtime** | DLL não-assinada no `RobloxPlayerBeta`, **manual-map / reflective DLL** (imagem PE em memória privada+executável), **process hollowing / RunPE** (image base trocado por memória privada — disco limpo, miolo trocado) e **debugger atrelado** (Cheat Engine, x64dbg). |
| **Anti-forense** | Prefetch/SysMain off, VSS wipe, log de Segurança limpo, PowerShell apagado, USN journal (pega exec que foi deletado). |
| **Windows security enfraquecida (Tier S)** | **DSE / Test Mode** (`bcdedit testsigning`/`nointegritychecks` — pré-requisito pra rodar driver custom kernel), **VBS / HVCI desativados** (nenhum jogador comum desliga), **página RWX dentro do RobloxPlayerBeta** (patch in-memory de internal cheat), **ActivitiesCache Timeline** (SQLite do Windows que registra toda app dos últimos ~30 dias — cleaner popular não limpa). |
| **Comportamental (Tier A)** | **AMSI bypass** (primeira instrução de `AmsiScanBuffer` no PowerShell patcheada pra silenciar Defender), **APC injection** (DLL no Roblox vinda de path suspeito — pega o que `CreateRemoteThread` não pega), **dropper task recente** (scheduled task criada nas últimas 24h com `AtLogon` + exe em `C:\Users\` — persistência clássica de loader). |

### Anti-bypass — os truques que os cursos de telagem ensinam

Processo **suspenso** · processo **disfarçado de sistema** (`svchost.exe`/`dwm.exe` de pasta de
usuário) · **DLL sideloading** (`version.dll`/`dinput8.dll` ao lado do launcher) · executável
escondido em **ADS** (`notas.txt:cheat.exe`) · **time-stomping** (data no futuro / executor
backdated) · cheat em **pendrive** · **outra conta** de Windows · **Defender adulterado** ·
**relógio voltado** pra trás · **limpadores / secure-delete**.

## Flags

```text
telador.exe                       roda tudo, gera o HTML
--ss-live                         modo SS ao vivo — 71 scanners rápidos (< 45 s)
--watch                           dashboard ao vivo em 127.0.0.1 (nada sai do PC)
--update-sigs                     baixa a base de assinaturas mais recente
--quick                           ~1s, só os scanners base
--md                              também exporta Markdown (cola no Discord)
--json                            também exporta JSON completo (verdict + clusters + bullets)
--save-tsr fulano.tsr             snapshot com selo HMAC de integridade
--diff antigo.tsr                 compara com um snapshot anterior
--codigo X7K9                     código do supervisor no relatório (prova de SS ao vivo)
--no-elevate                      não pedir admin (cobertura limitada)
```

## O que não faz

Não é anticheat. O foco é **rastro forense pós-uso**, mas ele também inspeciona o processo
vivo do Roblox (DLL injetada, manual-map, debugger). Sem driver kernel: técnicas só-em-RAM
avançadas, bootkit, e o processo blindado pelo anti-cheat do Roblox (o **Hyperion** pode
bloquear a leitura de memória) ficam fora do alcance direto. Cheat de **DMA** só é pego
parcialmente (ID de placa conhecida no PCIe/USB); placa com firmware que spoofa o ID escapa. PC formatado na hora não tem o
que ler (o Telador sinaliza a formatação, mas não substitui a SS visual). O veredito é
**heurístico** — tem falso positivo e falso negativo. Use como ponto de partida, junto da SS,
não como sentença.

## Antivírus reclama do exe?

Falso positivo conhecido do PyInstaller (empacotador de Python que se descompacta numa pasta
temp ao rodar). **Não é malware — o código é aberto.** Confere no VirusTotal, ou compara o
SHA256 que o programa mostra no banner com o da release. Se preferir, roda do fonte:

```bash
git clone https://github.com/highdevian/combatroblox
cd combatroblox && pip install -r requirements.txt && python telador.py
```

## Build

```bash
build.bat        # gera dist/telador.exe (~11 MB, standalone)
```

Requer Windows 10/11, Python 3.10+, `pip install -r requirements.txt`. As releases saem
reproduzíveis do CI (push de tag → build no `windows-latest` → publica o `.exe` + SHA256).

## Licença

**MIT.** É ferramenta de auditoria **com consentimento** — use onde você tem permissão.
Veja [LICENSE](LICENSE) e [SECURITY.md](SECURITY.md).
