# Playbook do Staff — SS forense com Telador

**Objetivo:** conduzir uma SS de Roblox em ~5 minutos, com veredito claro pra
colar no Discord da liga. Este documento é a única página que o staff precisa
ler antes de operar.

---

## 1. Antes de abrir a call

- Combine com o suspeito: **AnyDesk view-only** ou **Discord screen share**.
  Suspeito controla o mouse, você dita passos.
- Peça pra ele baixar o zip `Telador-vX.X.X.zip` do link oficial
  (https://github.com/highdevian/combatroblox/releases/latest).
- Confirme SHA256 se quiser: cole o hash do release ao lado do arquivo.

## 2. Rodar (2 cliques)

**Opção A (recomendada, single-file):** peça pro suspeito baixar SÓ o arquivo
`telador-gui.exe` da página do release, dar **duplo-clique** e aceitar UAC. A
janela abre direto, sem terminal preto. Um arquivo, dois cliques, pronto.

**Opção B (kit completo):** baixar `Telador-vX.X.X.zip`, extrair, duplo-clique
em `telador-gui.exe` (ou `INICIAR-GUI.bat` como fallback). Aceitar UAC.

**SmartScreen** vai reclamar no primeiro run:
> "Windows protegeu seu PC" → clique em "Mais informações" → "Executar assim mesmo"

Isso é porque o exe não tem code-signing pago. Aviso normal, não é vírus.

Se o suspeito recusar UAC:

> Diga: **"Recusa de admin faz o resultado dar INCONCLUSIVO. Isso não
> significa que você é culpado, mas eu não consigo fechar a SS sem admin.
> Roda de novo e aceita o UAC."**

Se ele recusar UAC 2 vezes → **REPORTA COMO SUSPEITO** (recusa de admin
recorrente é anti-forense por si só).

## 3. Aguardar o scan (~30-40 s)

- Barra de progresso vai de `0/71` até `71/71`
- Tempo médio: 20-40s em SSD moderno, até 60s em HDD

**Se travar > 90s:** peça screenshot da tela, cancele com `Sair`, tente rodar
`INICIAR.bat` (versão terminal) — reporta pro dev do Telador
(github.com/highdevian/combatroblox/issues).

## 4. Ler o veredito

Após o scan, aparece o **semáforo**:

| Cor | Veredito | O que fazer |
|---|---|---|
| 🟢 **LIMPO** | Nenhum artefato de executor cruzado. | Libera o suspeito. Ainda vale SS visual rápida do Task Manager antes de fechar. |
| 🟡 **SUSPEITO** | Sinal parcial (1 fonte só). | Não pune. Abra o HTML, cruze com SS visual, verifique pastas Downloads/Temp. |
| 🔴 **CHEATER / CONFIRMADO** | Múltiplas fontes cruzam apontando pro mesmo target. | **NÃO deixa o suspeito reiniciar ou formatar.** Copie o resumo pro Discord agora. Aguarde decisão da liga. |
| ⚫ **INCONCLUSIVO** | Cobertura incompleta (sem admin, formatação recente, log limpo). | Não inocenta. Peça pra rodar de novo como admin OU escale pro moderador da liga. |

Os **3 bullets do staff** aparecem embaixo do semáforo — leia em voz alta na
call:

- **O quê:** [target detectado ou "LIMPO"]
- **Por quê:** [quantas fontes cruzaram]
- **O que fazer:** [ação concreta]

## 5. Enviar pro Discord (1 clique)

- **[Copiar resumo Discord]** → o resumo formatado com veredito + 3 bullets +
  lista de targets vai pro seu clipboard.
- Cola no canal `#tela` (ou equivalente) da liga.
- Anexa o HTML abrindo **[Abrir relatório HTML]** → botão direito no
  arquivo → "Anexar no Discord".

## 6. Red flags que travam a SS

Se qualquer um destes acontecer, marque como **SUSPEITO/INCONCLUSIVO** mesmo
com veredito 🟢:

- Task Manager fecha sozinho quando o suspeito abre (cheat kill-switch)
- Alt-tab está bugado (janela oculta via **streamproof** — Winter Bypass /
  Solara)
- Suspeito diz "formatei ontem" ou "resetei a semana passada"
- Prefetch vazio + Event Log de Segurança limpo (Telador reporta como
  INCONCLUSIVO automaticamente)
- Suspeito recusa admin **2+ vezes** durante a call
- Suspeito reinicia/desliga o PC durante o scan

## 7. O que Telador **não** pega

- **DMA cheat** (placa PCIe FPGA com firmware que spoofa ID) — parcial só.
  Se suspeitar, peça pra abrir o gabinete + SS foto do PCIe.
- **Cheat só-em-RAM** que nunca toca disco (raro em cheat pago comum)
- **Processo blindado pelo Hyperion** (anti-cheat do Roblox pode bloquear
  leitura de memória do próprio Roblox — Telador reporta essa cegueira)
- **PC formatado na hora** — Telador **sinaliza** a formatação (fresh
  install < 24h) mas não consegue reconstruir o que foi apagado

## 8. Discord message template

Copia isso e edita:

```
**SS — Suspeito: @username**
Veredito: 🔴 CHEATER CONFIRMADO (confidence 96%)
Duração: 34s · Modo: --ss-live (11/71 scanners falharam por não-admin)

**O quê:** CONFIRMADO — executor: Solara
**Por quê:** 4 fontes independentes cruzaram — Prefetch + Amcache + BAM + live_processes
**O que fazer:** Não deixa formatar. Aguardando decisão da moderação.

Relatório HTML anexado.
```

---

**Fluxo total: baixar → 2 cliques → aceitar UAC → aguardar 40s → ler veredito
→ 1 clique copiar → colar Discord. ~5 minutos.**

Dúvidas / bug report: github.com/highdevian/combatroblox/issues
