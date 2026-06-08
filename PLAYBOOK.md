# Playbook de SS

Pra quem vai telar. O scan é o começo da SS, não o fim. Este guia cobre o caso
difícil: o Telador rodou, deu `LIMPO`, e você ainda desconfia do cara. Antes de
soltar "inocentado", passe por aqui.

Regra de ouro: `LIMPO` sem admin ou com anti-forense ligado **não é inocência —
é inconclusivo.** O resto do documento é como saber em qual dos dois você está.

## Antes de telar

- Atualize a base **antes** de sair de casa: `telador.exe --update-sigs`. Executor
  novo que saiu ontem não está na base que você empacotou semana passada.
- Leve o kit num zip: `telador.exe` + `INICIAR.bat` + `TELADOR-AO-VIVO.bat`. Pendrive
  ou link direto, do seu jeito.
- Combine as regras e pegue o "ok" do cara antes de começar. SS é auditoria
  combinada, não invasão.
- Dite um **código de 4 dígitos** na hora e use `--codigo XXXX`. Ele entra no
  relatório e prova que a SS foi ao vivo — não um print velho reaproveitado.
- Anote nick, ID e horário de início.

## A ordem importa (não contamine a prova)

A prova é frágil. Cada coisa fechada, apagada ou aberta some do rastro.

1. **Não deixe ele mexer.** Quem dirige o mouse é você, ou ele só com você olhando.
   Fechar um processo na sua frente já é red flag — e mata o rastro ao vivo.
2. **Mantenha o Roblox aberto** se ele estava jogando. O scan ao vivo (árvore de
   processo, injeção de DLL) precisa do jogo de pé. Mandar fechar antes mata essa parte.
3. **Aceite o UAC.** O Telador pede admin sozinho — clica sim. Sem admin, Prefetch,
   Amcache e BAM não são lidos, e "limpo" não vale nada.
4. **Print primeiro.** O Telador já captura a tela no começo; confirme que rodou.

## Lendo o veredito

O topo diz `LIMPO`, `SUSPEITO` ou `CHEATER`. Mas o que decide é o agrupamento por
alvo (Confidence Engine): cada executor vira **um** veredito com % de confiança, em
vez de 50 hits soltos.

- **CONFIRMED** — cravado. Duas ou mais fontes batendo no mesmo alvo, ou hash
  conhecido somado a outra fonte. É o que sustenta uma punição.
- **DETECTED** — forte. Uma fonte crítica isolada, ou duas fontes médias. Investigue,
  está quase lá.
- **SUSPECT** — um indício relevante. Ponto de partida, não condenação.
- **WEAK** — fraco, provável ruído. Sozinho não vale.

A % é heurística. `CONFIRMED 95%` com Prefetch + Amcache + BAM apontando o mesmo
Solara é outra coisa que `SUSPECT 40%` de um nome parecido. Leia de onde veio.

## Deu LIMPO mas você desconfia

Não acabou. Passe por esta lista antes de liberar o cara.

1. **Rodou como admin?** Se você clicou "não" no UAC, ou o banner não mostra admin,
   refaça. Limpo sem admin é inconclusivo — o relatório avisa isso na cara.
2. **Tem anti-forense ligado?** O Telador sinaliza: Prefetch desligado, SysMain
   parado, VSS/Restauração apagado, log de Segurança limpo, histórico do PowerShell
   sumido, buracos no USN journal. Num PC de jogador de Roblox isso não é
   "privacidade" — é alguém que limpou. **O anti-forense em si já é o achado.**
3. **Rode ao vivo, com o jogo aberto:** `TELADOR-AO-VIVO.bat` ou `--watch`. Pega
   injeção de DLL e processo escondido que o scan estático não vê.
4. **Atualize e re-escaneie:** `--update-sigs`. A base que você levou pode não ter
   o executor que ele usa.
5. **Ligue o modo paranoia:** `--strict` (desliga o filtro de falso positivo) e
   `--strict-scripts`. Vai aparecer ruído — mas é pra **você** revisar item a item,
   não pra cravar nada automático.
6. **Abra o HTML e leia item por item.** O veredito de topo é resumo. Vários `WEAK`
   e `SUSPECT` que o filtro rebaixou, somados, podem ser o fio da meada.
7. **Olhe a janela de tempo.** USN, Prefetch e BAM dizem **quando** rodou. Cheat
   usado há 10 minutos deixa rastro quente. Já um Windows formatado/instalado na data
   de hoje (o Telador sinaliza "fresh install") é red flag, não inocência.
8. **Salve um `.tsr` e re-tele depois com `--diff`.** Se ele "limpar" entre uma SS e
   outra, o diff mostra exatamente o que sumiu.

## O olho humano (o que o forense não vê)

O Telador roda depois do cheat. Tem coisa que só a tela ao vivo mostra:

- Alt-tab que trava, "minimizar" que não revela a janela real, barra de tarefas editada.
- Segundo monitor, segundo PC, ou notebook/celular do lado rodando o cheat (executor
  mobile, ESP no telefone espelhando a tela).
- **VM.** Se a SS é dentro de uma máquina virtual, o PC real está fora de alcance. O
  Telador sinaliza VM/sandbox — quando aparecer, desconfie da SS inteira.
- Recusa de abrir uma pasta, processo que ele fecha correndo, "trava" toda vez que
  você pede algo específico.
- **Cheat só em RAM** que nunca tocou o disco: não há rastro forense. Só pega ao vivo
  (jogo aberto) ou no olho.

## Segundo programa (cross-check)

O Telador já parseia Prefetch, Amcache, BAM, USN e ShimCache — o mesmo que as
ferramentas clássicas de forense. Um segundo programa serve pra duas coisas: o cara
não poder dizer que "o teu programa é forjado", e você bater o resultado com fonte
neutra.

Pra isso, use ferramenta **aberta e conhecida**, não "pack de SS" de Discord:

- **Eric Zimmerman tools** (PECmd, AmcacheParser, AppCompatCacheParser, MFTECmd) —
  padrão de DFIR, abertas.
- **Sysinternals** Autoruns + Process Explorer (Microsoft) — persistência e processos
  ao vivo.
- **System Informer** — processos e handles ao vivo.

Aviso sério: a maioria dos "SS tool" / "cheat scanner v3" colados em servidor de
Discord é RAT ou infostealer. Não rode no **seu** PC e pense duas vezes antes de
rodar no do suspeito. Ferramenta de verdade tem código aberto e hash conferível —
como o próprio Telador (confere o SHA256 do banner com o da release).

## O teto forense — quando parar

Aceite o limite. Sem driver kernel, três coisas ficam fora do alcance direto: cheat
só em RAM, bootkit, e PC formatado na hora.

- `LIMPO` **com admin, sem anti-forense, e ao vivo com o jogo aberto** = indício forte
  de inocência. Não é prova absoluta, mas é o melhor que a forense entrega.
- `LIMPO` **sem admin, ou com anti-forense ligado** = inconclusivo. Não escreva
  "inocentado".
- **Não invente prova.** `SUSPECT 40%` não é confissão. O peso da decisão de moderação
  é seu, mas a parte forense tem que ser honesta — a primeira SS errada queima a
  ferramenta e queima você junto.
- Anti-forense ligado + recusa de cooperar é **decisão de regra do servidor**, não
  veredito forense. Trate como tal e seja claro sobre qual dos dois você está aplicando.

## Fechando a SS

- `--codigo XXXX` — o código que você ditou no início, dentro do relatório.
- `--save-tsr nick.tsr` — snapshot assinado por HMAC. É o que vale se questionarem depois.
- `--md` — cola o resumo no Discord da staff.
- Guarda o `.tsr`. Numa re-SS, `--diff nick.tsr` mostra o que mudou desde a última.

## Regras de conduta

- **Só com consentimento.** SS é auditoria combinada (regra do servidor), não invasão.
- **Nunca peça pra ele apagar ou desinstalar nada durante a SS.** Isso destrói prova e
  é literalmente anti-forense. Se for desinstalar cheat, é **depois** do veredito e por
  decisão da staff — não no meio da análise.
- Tenha um segundo da staff junto e registre horário de início e fim.
- Não doxxe e não exponha dado pessoal do relatório. O Telador já reda credenciais e
  e-mails por padrão — não use `--no-redact` sem motivo de verdade.
- O veredito é ponto de partida pra decisão humana. Não é sentença automática.
