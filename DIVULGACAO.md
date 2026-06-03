# Material de divulgação — Telador

Textos prontos pra colar em Discord / fórum de comunidades de SS de Roblox.
Tom: direto, honesto, sem hype. Não promete "100% detection" (isso é mentira
de marketing e queima credibilidade no primeiro falso positivo).

---

## 1. Post principal (Discord/fórum, PT-BR)

> **Telador — ferramenta forense de SS pra Roblox**
>
> Roda no PC do suspeito, lê os rastros do Windows (Prefetch, Amcache, BAM,
> USN Journal, logs do Roblox…) e entrega **um veredito** — não uma lista de
> 50 logs pra você interpretar sozinho.
>
> **O que diferencia:**
> ➤ **Veredito único por executor.** Junta as evidências de várias fontes
> sobre o mesmo cheat e dá um resultado com % de confiança. Você entende em
> 10 segundos.
> ➤ **Pega executor renomeado.** Não depende só do nome do arquivo — detecta
> pela estrutura. Renomear `solara.exe` pra `roblox.exe` não engana.
> ➤ **Dashboard ao vivo, 100% local.** Roda em `127.0.0.1` na própria
> máquina. Os scanners aparecem em tempo real, mas **nada sai do PC do
> suspeito** — diferente de ferramentas que mandam tudo pra um servidor.
> ➤ **Open source e grátis.** O código está todo no GitHub. Dá pra auditar
> antes de mandar pro suspeito rodar. Sem mensalidade.
>
> **O que NÃO é:** não é anticheat. É forense pós-uso — complementa a SS
> visual, não substitui. Veredito é heurístico (pode ter erro), use como
> ponto de partida da investigação.
>
> 📥 **Baixar:** https://github.com/highdevian/combatroblox/releases/latest
> 🌐 **Site:** https://combatroblox-forensics.vercel.app/
>
> Botão direito no `telador.exe` → Executar como administrador. Pronto.

---

## 2. Versão curta (bio / status / anúncio rápido)

> **Telador · SS forense pra Roblox**
> Veredito de cheat por correlação de evidências. Pega executor renomeado.
> 100% local, open source, grátis.
> github.com/highdevian/combatroblox

---

## 3. Versão inglês (international Roblox SS servers)

> **Telador — forensic screen-share tool for Roblox**
>
> Runs on the suspect's PC, reads Windows artifacts (Prefetch, Amcache, BAM,
> USN Journal, Roblox logs…) and gives **one verdict** — not 50 logs for you
> to interpret.
>
> **What sets it apart:**
> ➤ **One verdict per executor.** Correlates evidence from multiple sources
> about the same cheat into a single result with a confidence %. Understand
> it in 10 seconds.
> ➤ **Catches renamed executors.** Doesn't rely only on the filename —
> detects by structure. Renaming `solara.exe` won't fool it.
> ➤ **Live dashboard, 100% local.** Runs on `127.0.0.1` on the machine
> itself. Scanners stream in real time, but **nothing leaves the suspect's
> PC** — unlike tools that upload everything to a server.
> ➤ **Open source and free.** All code on GitHub. Audit it before you run
> it. No subscription.
>
> **What it's NOT:** not an anticheat. It's post-use forensics — it
> complements visual SS, doesn't replace it. The verdict is heuristic (can
> err), use it as a starting point.
>
> 📥 https://github.com/highdevian/combatroblox/releases/latest
> 🌐 https://combatroblox-forensics.vercel.app/

---

## 4. Respostas a perguntas céticas (comunidade de SS desconfia)

**"É vírus? Por que o antivírus reclama?"**
> Falso positivo conhecido do PyInstaller (empacotador de Python). O código é
> aberto — confere no GitHub. Só LÊ o sistema, não modifica nada, não instala
> nada, não manda nada pela rede. Pode rodar do código-fonte se preferir.

**"Como sei que não tá roubando meus dados?"**
> Não tem servidor, não tem telemetria, não tem nuvem. Roda offline. O
> dashboard ao vivo roda em `127.0.0.1` (a própria máquina). Tudo auditável.

**"E se o cara renomear o cheat?"**
> Detecta por estrutura, não só por nome. Um executor renomeado ainda deixa
> a assinatura estrutural (binário não-assinado + runtime web embutido) que
> o Telador pega.

**"Substitui a SS normal?"**
> Não. É um complemento. A SS visual continua necessária — o Telador acelera
> e embasa a decisão com evidência forense, mas o supervisor decide.

**"Tem como burlar?"**
> Como toda ferramenta forense, sim — formatar o PC antes apaga rastros (mas
> isso o Telador também sinaliza). Por isso o veredito é "evidência forte",
> não "prova absoluta". Use junto da SS visual.

---

## 5. Dicas de abordagem (como divulgar de fato)

- **Não spamme.** Poste em 2-3 comunidades onde você JÁ participa, com
  contexto ("fiz essa ferramenta, código aberto, feedback bem-vindo").
- **Mostre, não conte.** Um print/GIF do dashboard ao vivo achando um
  executor vale mais que qualquer texto.
- **Peça feedback, não adoção.** "Testa e me diz o que achou" abre porta;
  "usem minha ferramenta" fecha.
- **Ofereça pra adicionar executores que eles conhecem.** Comunidade de SS
  conhece os cheats da moda — `--update-sigs` deixa você adicionar rápido.
  Isso transforma membros em colaboradores.
- **O diferencial que mais pega:** "não manda nada dos dados do suspeito pra
  lugar nenhum" + "grátis e open source". Lidera com isso.
