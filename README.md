<div align="center">

```
████████╗███████╗██╗      █████╗ ██████╗  ██████╗ ██████╗
╚══██╔══╝██╔════╝██║     ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗
   ██║   █████╗  ██║     ███████║██║  ██║██║   ██║██████╔╝
   ██║   ██╔══╝  ██║     ██╔══██║██║  ██║██║   ██║██╔══██╗
   ██║   ███████╗███████╗██║  ██║██████╔╝╚██████╔╝██║  ██║
   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝
```

### Ferramenta forense de screen-share para Roblox

Roda no PC do suspeito, lê os rastros do Windows e entrega **um veredito** — não uma lista de logs pra você interpretar. **100% local, sem nuvem, sem telemetria, open source.**

[![Release](https://img.shields.io/github/v/tag/highdevian/combatroblox?sort=semver&style=for-the-badge&label=release&color=ff4d4f)](https://github.com/highdevian/combatroblox/releases/latest)
[![CI](https://img.shields.io/github/actions/workflow/status/highdevian/combatroblox/ci.yml?branch=main&style=for-the-badge&label=CI)](https://github.com/highdevian/combatroblox/actions)
[![Windows](https://img.shields.io/badge/Windows-10%2F11-0078d6?style=for-the-badge)](https://github.com/highdevian/combatroblox/releases/latest)
[![License](https://img.shields.io/badge/License-MIT-3fbf7f?style=for-the-badge)](LICENSE)

**[⬇️ Baixar telador.exe](https://github.com/highdevian/combatroblox/releases/latest/download/telador.exe)** &nbsp;·&nbsp; [🌐 Site](https://combatroblox-forensics.vercel.app/) &nbsp;·&nbsp; [📋 Releases](https://github.com/highdevian/combatroblox/releases)

</div>

---

## ⚡ Começar em 3 passos

```
1.  Baixe o telador.exe
2.  Execute (ele pede permissão de admin sozinho — clique Sim)
3.  Em segundos o relatório abre no navegador
```

> 💡 **Sem terminal:** os arquivos `INICIAR.bat` (scan) e `TELADOR-AO-VIVO.bat` (dashboard ao vivo) rodam com dois cliques.
> Pra distribuir: zipe o `.exe` + os `.bat` e mande no Discord.

> ⚠️ **Rode como administrador.** Sem admin, as fontes mais fortes (Prefetch, Amcache, BAM) falham — e "nada encontrado" sem admin **não inocenta**, é inconclusivo.

---

## 🎯 O que ele pega

| Categoria | O que detecta |
|---|---|
| 🧩 **Executores** | 542 assinaturas — Solara, Xeno, Wave, Velocity, Ronix, Krnl, Fluxus, Synapse X… |
| 🎭 **Executor renomeado** | Detecção **comportamental**: exe não-assinado + runtime web embutido (sobrevive a renomear) |
| 🔧 **Launcher modificado** | `RobloxPlayerBeta.exe` com assinatura quebrada = patcheado pra injetar |
| 🖱️ **Autoclickers / macros** | OP Autoclicker, TinyTask, Speed Autoclicker, Pulover, MurGee, G HUB/Razer… |
| 🔄 **Evasão de ban / alts** | Account managers, multi-instância, HWID spoofers (byfron/hyperion) |
| ⛓️ **BYOVD / kernel** | winring0, mhyprot2, capcom, gdrv e ~20 drivers de cheat loader |
| 🧹 **Anti-forense** | Prefetch off, VSS wipe, log limpo, PowerShell apagado, USN (pega exec **deletado**) |

---

## ✨ Diferenciais

<table>
<tr>
<td width="50%" valign="top">

**🧠 Confidence Engine**
Junta as evidências do mesmo executor (Prefetch + Amcache + browser…) em **um veredito** com % de confiança. O supervisor entende em 10 segundos.

</td>
<td width="50%" valign="top">

**🔴 Dashboard ao vivo (`--watch`)**
Painel no navegador mostrando os scanners e o veredito **em tempo real** — rodando em `127.0.0.1`. Nada sai do PC.

</td>
</tr>
<tr>
<td width="50%" valign="top">

**🔄 Assinaturas atualizáveis (`--update-sigs`)**
Executor novo? `--update-sigs` baixa a base mais recente. Adicionar um é **um commit**, não um release. O scan normal nunca toca a rede.

</td>
<td width="50%" valign="top">

**🔒 100% local & open source**
Sem servidor, sem telemetria, sem nuvem. Roda offline. Código aberto — dá pra auditar antes de rodar no PC do suspeito.

</td>
</tr>
</table>

<details>
<summary><b>📖 Ver detalhes técnicos de cada detecção</b></summary>

<br>

**Executores conhecidos com confiança alta.**
542 assinaturas de executores ativos em 2024-2026. Quando o nome bate em ≥2 fontes forenses (Prefetch + Amcache + BAM + USN + browser…), o veredito vem como **CONFIRMED**, não suposição.

**Quem tentou limpar rastros.**
A maioria das ferramentas de SS olha só Prefetch. O Telador também pega: Prefetch/SysMain desativado, deleção em lote de shadow copies do VSS (`vssadmin delete shadows /all`), histórico do PowerShell apagado (PSReadLine), gap suspeito em log de eventos sem o evento 1102, e o USN Journal — que registra arquivo executado **mesmo depois de deletado**.

**Evasão de ban e contas alt.**
Account managers / multi-instância (Roblox Account Manager, MultiBloxy) e HWID spoofers que burlam o ban de hardware do anticheat. FPS Unlocker e Bloxstrap legítimos **não** disparam.

**Autoclickers e macros.**
Ferramentas standalone (OP Autoclicker, TinyTask, Pulover…) + software de mouse com macro (G HUB, Razer) + red flags de conteúdo (no recoil, auto click, rapid fire). Pega o rastro mesmo após fechar e apagar.

**Launcher do Roblox modificado.**
O `RobloxPlayerBeta.exe` oficial é sempre assinado pela Roblox. Assinatura quebrada = patcheado pra injetar. Também pega dropper com nome de launcher largado em Downloads não-assinado. Validado com 0 falso positivo.

**Executor renomeado (comportamental).**
Detecção por nome morre quando renomeiam o arquivo. Por isso o Telador bate na **estrutura**: exe não-assinado + runtime web embutido (EBWebView/CEF) em pasta de usuário — fingerprint dos executores modernos. Sobrevive a renomear arquivo *e* pasta.

**BYOVD / drivers de kernel.**
Enumera drivers em `HKLM\SYSTEM\...\Services` e flaga winring0, rwdrv, mhyprot2, capcom e ~20 outros usados em kdmapper / cheat loader / rootkit.

</details>

---

## 🚫 O que **NÃO** faz (limites honestos)

- **Não é anticheat.** Roda *depois* do cheat ser usado — analisa rastros forenses, não runtime. Detecção em tempo real é trabalho do Byfron/Hyperion.
- **Não detecta cheat nunca usado nesse PC.** PC recém-formatado não tem rastro (o Telador sinaliza a formatação recente, mas não substitui a SS visual).
- **Não substitui o supervisor.** O veredito é opinião informada — pode ter falso positivo/negativo. É ponto de partida, não sentença.
- **Cobertura tem teto.** Sem driver kernel, técnicas como execução só-em-RAM ou bootkit ficam fora do alcance direto (dependem de rastros secundários).

---

## 💻 Linha de comando

```bash
telador.exe                       # roda tudo, gera HTML, abre no browser
telador.exe --watch               # dashboard local AO VIVO (127.0.0.1) — tempo real, nada sai do PC
telador.exe --update-sigs         # baixa a base de assinaturas mais recente (manutenção)
telador.exe --quick               # ~1s, só os scanners base
telador.exe --md                  # também exporta Markdown (cola no Discord)
telador.exe --save-tsr fulano.tsr # snapshot assinado HMAC (pra comparar depois)
telador.exe --diff antigo.tsr     # compara com um snapshot anterior
telador.exe --codigo X7K9         # código do supervisor no relatório (prova SS ao vivo)
telador.exe --no-elevate          # não pedir admin (roda com cobertura limitada)
```

---

## 🛡️ Antivírus reclamando do `.exe`?

**É falso positivo conhecido**, não malware. O `.exe` é empacotado com PyInstaller, que se descompacta numa pasta temp ao rodar — esse comportamento dispara heurística de alguns AVs.

Como conferir:
- **VirusTotal** — a maioria reporta limpo, incluindo o Defender.
- **SHA256** — o programa mostra o próprio hash no banner; compare com a release oficial.
- **Rode do código-fonte**, se preferir:
  ```bash
  git clone https://github.com/highdevian/combatroblox
  cd combatroblox && pip install -r requirements.txt && python telador.py
  ```

---

## 🔨 Build local

```bat
build.bat
```

Saída: `dist/telador.exe` (~11 MB, standalone, zero deps em runtime).
Requisitos: Windows 10/11, Python 3.10+, `pip install -r requirements.txt`.

---

## ⚖️ Uso responsável

- **Ferramenta de auditoria com consentimento** — não é vigilância. Use onde você tem permissão (ex: SS combinada na comunidade).
- **Veredito é heurístico** — mesmo "CONFIRMED" é evidência forense forte, não prova legal.
- **Open source MIT** — use, modifique, audite. Sem garantia. Veja [`LICENSE`](LICENSE) e [`SECURITY.md`](SECURITY.md).

---

<div align="center">

Desenvolvido por **Gabriel** · [@highdevian](https://github.com/highdevian)
[Reportar bug](https://github.com/highdevian/combatroblox/issues) · [Site](https://combatroblox-forensics.vercel.app/)

</div>
