<div align="center">

```
┌─ telador ───────────────────────────────┐
│  >_ TELADOR                              │
│     roblox screenshare                   │
│     análise forense local                │
└──────────────────────────────────────────┘
```

# Telador

**Ferramenta forense local para SS (screen-share) em comunidades Roblox.**
Roda no PC do suspeito, lê artefatos do Windows, e entrega um veredito de cheat — sem nuvem, sem telemetria.

[![Latest Release](https://img.shields.io/github/v/release/highdevian/combatroblox?style=for-the-badge&color=ff4d4f)](https://github.com/highdevian/combatroblox/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/highdevian/combatroblox/total?style=for-the-badge&color=ffb020)](https://github.com/highdevian/combatroblox/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/highdevian/combatroblox/ci.yml?style=for-the-badge&label=CI)](https://github.com/highdevian/combatroblox/actions)
[![License](https://img.shields.io/badge/License-MIT-3fbf7f?style=for-the-badge)](LICENSE)

</div>

---

## Como usar

1. Baixe `telador.exe` da [última release](https://github.com/highdevian/combatroblox/releases/latest)
2. Botão direito → **Executar como administrador** (sem admin, várias fontes falham)
3. Aceita o aviso, espera ~3 segundos. Relatório HTML abre sozinho.

**Sem mexer em terminal:** dois `.bat` de dois-cliques acompanham o projeto —
`INICIAR.bat` (scan normal) e `TELADOR-AO-VIVO.bat` (abre o dashboard ao vivo
do `--watch`). Bom pra supervisor que não quer linha de comando.

Distribuição prática: zipa `telador.exe` + os `.bat`, manda no Discord, supervisor instrui dois cliques.

---

## O que dá certo (na prática)

**Detectar executores conhecidos com confiança alta.**
542 assinaturas cobrindo executores ativos em 2024-2026: Solara, Xeno, Wave, Velocity, Ronix, Krnl, Fluxus, Synapse X, e dezenas de menores. Quando o nome bate em ≥2 fontes forenses (Prefetch + Amcache + BAM + USN + browser…), o veredito vem como **CONFIRMED**, não suposição.

**Pegar quem tentou limpar rastros.**
A maioria das ferramentas de SS olha só Prefetch. O Telador também detecta:
- Prefetch / SysMain **desativado** (pra suprimir o registro do que rodou)
- Limpeza em lote de shadow copies do VSS (`vssadmin delete shadows /all`)
- Histórico do PowerShell apagado ou zerado (PSReadLine)
- Gap suspeito em log de eventos sem o evento 1102 de limpeza
- USN Journal: pega arquivo executado **mesmo depois de deletado** (o registro fica)

**Pegar evasão de ban e contas alt.**
Gerenciadores de alt e multi-instância (Roblox Account Manager, MultiBloxy, Multi Roblox) — sinal de botting/alt evasion. E HWID spoofers (hwid changer, byfron/hyperion spoofer, etc.) que servem só pra burlar ban de hardware do anticheat do Roblox. Ferramentas legítimas como FPS Unlocker e Bloxstrap não disparam.

**Pegar autoclickers e macros.**
Além do software de mouse com motor de macro (G HUB, Razer) e das red flags de conteúdo (no recoil, auto click, rapid fire), o Telador detecta as ferramentas de autoclique/macro standalone — OP Autoclicker, Speed Autoclicker, TinyTask, Macro Recorder, Pulover, MurGee e dezenas de variantes. Pega o rastro delas em Prefetch/Amcache/BAM/Downloads, mesmo que o cara tenha fechado e apagado.

**Pegar launcher do Roblox modificado.**
O `RobloxPlayerBeta.exe` oficial é sempre assinado pela Roblox. Se o binário no path de instalação está com a assinatura **quebrada**, foi patcheado (modificado pra injetar na inicialização) — sinal forte. O Telador também pega arquivo com nome de launcher do Roblox largado em Downloads/Desktop não-assinado (dropper disfarçado). Validado com 0 falso positivo num PC com Roblox + Studio legítimos.

**Pegar executor mesmo renomeado (detecção comportamental).**
Detecção por nome ("solara.exe") morre quando o cheater renomeia o arquivo — e ele sabe renomear, porque o código é aberto. Por isso o Telador também detecta pela **estrutura**: um `.exe` não-assinado largado na mesma pasta de um runtime web embutido (EBWebView/CEF), em local de usuário, é o fingerprint dos executores modernos (Solara/Wave/Velocity). Isso sobrevive a renomear o arquivo *e* a pasta. Validado com 0 falso positivo num PC real cheio de apps WebView2.

**Detectar BYOVD e drivers de kernel suspeitos.**
Enumera drivers carregados em `HKLM\SYSTEM\...\Services` e flaga winring0, rwdrv, gdrv, mhyprot2, capcom e ~20 outros usados em kdmapper / cheat loader / rootkit. Diferencia driver em pasta de usuário (sempre suspeito) de driver em System32 sem assinatura.

**Confidence Engine: evidências do mesmo executor viram 1 veredito.**
"solara.exe" no Prefetch + "Solara Executor" no Amcache + "solara hub" no histórico do navegador convergem para um único cluster Solara com confidence%. Sem isso, o supervisor vê 6 hits soltos e tem que correlacionar mentalmente.

**Dashboard ao vivo — sem mandar nada pra nuvem (`--watch`).**
`telador.exe --watch` abre um painel no navegador que mostra os scanners reportando em tempo real e o veredito se formando. A diferença pras ferramentas comerciais: o servidor roda em `127.0.0.1` (loopback), na própria máquina — **nada sai do PC**. Você tem o "ao vivo" sem entregar os dados do suspeito pra um servidor de terceiro.

**Assinaturas que não envelhecem (`--update-sigs`).**
Executor novo sai toda semana. Em vez de rebuildar e redistribuir o `.exe` de 10 MB a cada um, a base de assinaturas é um arquivo atualizável: `telador.exe --update-sigs` baixa a lista mais recente do GitHub (poucos KB) e pronto. Adicionar um executor é **um commit**, não um release. E continua sendo opt-in — o scan normal nunca toca a rede.

**Não envia nada pra lugar nenhum.**
100% local, sem telemetria, sem cloud, sem update phone-home. Você pode rodar offline. Código aberto, dá pra auditar antes de mandar pro PC do suspeito.

---

## O que NÃO faz (limites honestos)

**Não é anticheat.** O Telador roda **depois** que o cheat já foi usado — analisa rastros forenses no disco e registro. Não tem driver kernel, não faz memory dump do Roblox, não vê injeção em runtime. Pra cheat detectado em tempo real, isso é trabalho do Byfron/Hyperion (anticheat oficial do Roblox).

**Não detecta cheat que nunca foi usado nesse PC.** Se o cheater entrou na call de SS com PC limpo recém-formatado e nunca executou o cheat na máquina, não há rastro forense pra encontrar. O Telador detecta **formatação recente** como sinal indireto, mas não substitui sessão visual.

**Não substitui o supervisor.** O veredito é uma opinião informada baseada em correlação de assinaturas. Falso positivo existe (sempre vai existir em PC real). Falso negativo também — cheater que renomeia o `.exe` e usa só uma vez pode escapar. Use o relatório como ponto de partida da investigação, não como sentença.

**Cobertura tem teto.** Sem driver kernel, há técnicas de evasão que estão **fora do alcance** dessa abordagem: cheat carregado por bootkit, executor que opera só de RAM via tooling em-memory, manual map sem deixar handle no processo Roblox. Pra esses, o Telador depende dos rastros **secundários** (Amcache, USN, BYOVD) — funciona com frequência, mas não é garantia.

---

## Quando usar e quando não usar

**Use quando:**
- Supervisor de comunidade Roblox precisa decidir se um suspeito é cheater
- Você quer auditoria 100% local, sem mandar dados do suspeito pra lugar nenhum
- Cheater já tem histórico de uso e está negando

**Não use quando:**
- Você espera que isso substitua sessão visual de SS — não substitui
- O suspeito formatou o PC hoje (não há rastro pra ler)
- Você não tem consentimento do dono do PC pra rodar a análise

---

## Antivírus reclamando do `.exe`?

**É falso positivo conhecido**, não malware. O `.exe` é gerado com PyInstaller, que empacota o Python e descompacta numa pasta temp ao rodar. Esse "extrair e executar" dispara heurística genérica de alguns AVs.

Como conferir:
- **VirusTotal**: a maioria reporta limpo (incluindo Defender).
- **SHA256 no banner**: o programa mostra o próprio hash ao abrir; compare com o da release oficial.
- **Roda do código-fonte** se preferir não confiar no binário:
  ```bash
  git clone https://github.com/highdevian/combatroblox
  cd combatroblox
  pip install -r requirements.txt
  python telador.py
  ```

---

## Uso por linha de comando

```bash
telador.exe                          # default — roda tudo, gera HTML, abre no browser
telador.exe --watch                  # dashboard local AO VIVO (127.0.0.1) — scanners e veredito em tempo real, nada sai do PC
telador.exe --update-sigs            # baixa a base de assinaturas mais recente (comando de manutenção — o scan normal nunca toca a rede)
telador.exe --quick                  # ~1s, só os 15 scanners base
telador.exe --no-screenshot          # pula captura de tela
telador.exe --high-only              # console mostra só severidade alta/crítica
telador.exe --md                     # também exporta Markdown (cola no Discord)
telador.exe --save-tsr fulano.tsr    # salva snapshot assinado HMAC
telador.exe --diff antigo.tsr        # compara com snapshot anterior
telador.exe --codigo X7K9            # código do supervisor vai no relatório (prova SS ao vivo)
telador.exe --strict                 # desliga FP-filter (modo paranoia)
```

## Build local

```bat
build.bat
```

Saída: `dist/telador.exe` (~11 MB, standalone, zero deps em runtime).

Requisitos: Windows 10/11, Python 3.10+, `pip install -r requirements.txt`.

---

## Tom legal

- **Ferramenta de auditoria com consentimento.** Não é vigilância. Use em PC onde você tem permissão pra investigar (ex: SS combinada na comunidade).
- **Veredito é heurístico.** Mesmo "CONFIRMED" não é prova legal — é evidência forense forte. Falsos positivos e falsos negativos existem.
- **Open source MIT.** Use, modifique, audite. Sem garantia. Veja `LICENSE` e `SECURITY.md`.

---

## Sobre

Desenvolvido por Gabriel ([@highdevian](https://github.com/highdevian)).
Issues e bugs: [github.com/highdevian/combatroblox/issues](https://github.com/highdevian/combatroblox/issues).
