# Telador

Ferramenta forense de screen-share pra Roblox. Roda no PC do suspeito, lê os
artefatos do Windows (Prefetch, Amcache, BAM, USN, logs do Roblox…) e entrega
um veredito de cheat. 100% local — nada sai do PC. Open source.

[![release](https://img.shields.io/github/v/tag/highdevian/combatroblox?sort=semver&label=release&color=ff4d4f)](https://github.com/highdevian/combatroblox/releases/latest)
[![CI](https://img.shields.io/github/actions/workflow/status/highdevian/combatroblox/ci.yml?branch=main&label=CI)](https://github.com/highdevian/combatroblox/actions)
[![Windows](https://img.shields.io/badge/Windows-10%2F11-0078d6)](https://github.com/highdevian/combatroblox/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-3fbf7f)](LICENSE)

Download: [telador.exe](https://github.com/highdevian/combatroblox/releases/latest/download/telador.exe) ·
Site: [combatroblox-forensics.vercel.app](https://combatroblox-forensics.vercel.app/)

## Como usar

Baixa o `telador.exe` e roda. Ele pede permissão de admin sozinho (UAC) — aceita,
senão as fontes mais fortes (Prefetch, Amcache, BAM) não são lidas e o resultado
fica incompleto. Em alguns segundos o relatório HTML abre no navegador.

Quem não quer terminal: tem `INICIAR.bat` (scan) e `TELADOR-AO-VIVO.bat`
(dashboard ao vivo), que rodam com dois cliques. Pra distribuir, zipa o `.exe`
com os `.bat` e manda no Discord.

Sem admin, "nada encontrado" não inocenta — é inconclusivo. O programa avisa isso.

## O que detecta

- Executores conhecidos (542 assinaturas) — Solara, Xeno, Wave, Velocity, Ronix,
  Krnl, Fluxus, Synapse X e dezenas de menores. Bate em Prefetch, Amcache, BAM,
  UserAssist, USN, browser, Lixeira, processos.
- Executor renomeado — por estrutura, não por nome: exe não-assinado + runtime web
  embutido (EBWebView/CEF) em pasta de usuário. Sobrevive a renomear o arquivo.
- Launcher do Roblox modificado — `RobloxPlayerBeta.exe` com assinatura quebrada
  foi patcheado pra injetar. Pega também dropper se passando por launcher.
- Autoclickers e macros — OP Autoclicker, TinyTask, Speed Autoclicker, Pulover,
  G HUB/Razer com motor de macro, e red flags de conteúdo (no recoil, auto click).
- Evasão de ban e alts — account managers, multi-instância, HWID spoofers.
- Drivers BYOVD / kernel — winring0, mhyprot2, capcom, gdrv e cia (kdmapper, loader).
- Anti-forense — Prefetch/SysMain off, VSS wipe, log de Segurança limpo, PowerShell
  apagado, USN journal (pega exec que foi deletado).

As evidências do mesmo executor são agrupadas num veredito por target (Confidence
Engine), com % de confiança, em vez de cuspir 50 hits soltos pra você interpretar.

## Flags

```
telador.exe                       roda tudo, gera o HTML
--watch                           dashboard ao vivo em 127.0.0.1 (nada sai do PC)
--update-sigs                     baixa a base de assinaturas mais recente
--quick                           ~1s, só os scanners base
--md                              também exporta Markdown (cola no Discord)
--save-tsr fulano.tsr             snapshot assinado por HMAC
--diff antigo.tsr                 compara com um snapshot anterior
--codigo X7K9                     código do supervisor no relatório (prova de SS ao vivo)
--no-elevate                      não pedir admin (cobertura limitada)
```

## O que não faz

Não é anticheat. Roda depois do cheat ser usado e lê rastro forense — não tem driver
kernel, não vê injeção em runtime. PC formatado na hora não tem o que ler (o Telador
sinaliza a formatação, mas não substitui a SS visual). O veredito é heurístico: tem
falso positivo e falso negativo. Use como ponto de partida, junto da SS, não como
sentença. Sem driver kernel, há técnicas de evasão (só-em-RAM, bootkit) fora do
alcance direto.

## Antivírus reclama do exe?

Falso positivo conhecido do PyInstaller (empacotador de Python que se descompacta
numa pasta temp ao rodar). Não é malware — o código é aberto. Confere no VirusTotal,
ou compara o SHA256 que o programa mostra no banner com o da release. Se preferir,
roda do fonte:

```
git clone https://github.com/highdevian/combatroblox
cd combatroblox && pip install -r requirements.txt && python telador.py
```

## Build

```
build.bat
```

Gera `dist/telador.exe` (~11 MB, standalone). Requer Windows 10/11, Python 3.10+,
`pip install -r requirements.txt`.

## Licença

MIT. É ferramenta de auditoria com consentimento — use onde você tem permissão.
Veja [LICENSE](LICENSE) e [SECURITY.md](SECURITY.md).
