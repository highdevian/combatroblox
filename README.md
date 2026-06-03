<div align="center">

```
┌─ telador ───────────────────────────────┐
│  >_ TELADOR                              │
│     roblox screenshare                   │
│     análise forense local                │
└──────────────────────────────────────────┘
```

# Telador

**Ferramenta forense local para SS em comunidades Roblox**

[![Latest Release](https://img.shields.io/github/v/release/highdevian/combatroblox?style=for-the-badge&color=ff4d4f)](https://github.com/highdevian/combatroblox/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/highdevian/combatroblox/total?style=for-the-badge&color=ffb020)](https://github.com/highdevian/combatroblox/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/highdevian/combatroblox/ci.yml?style=for-the-badge&label=CI)](https://github.com/highdevian/combatroblox/actions)
[![License](https://img.shields.io/badge/License-MIT-3fbf7f?style=for-the-badge)](LICENSE)
[![Last Commit](https://img.shields.io/github/last-commit/highdevian/combatroblox?style=for-the-badge&color=888)](https://github.com/highdevian/combatroblox/commits/main)

**Confidence Engine** · correlação de evidências entre múltiplas fontes forenses · veredito único por executor detectado · execução 100% local, sem envio de dados

</div>

---

## Comece aqui (mais simples)

1. Baixe `telador.exe` da [última release](https://github.com/highdevian/combatroblox/releases/latest)
2. Clique direito → **Executar como administrador** (pra cobertura completa)
3. Pronto. Relatório HTML abre no navegador automático

Pra distribuir pro usuário final: zipe `telador.exe` + `INICIAR.bat`, manda no Discord, instrui dois cliques.

## É seguro? Sobre alertas de antivírus

Alguns antivírus podem marcar o `telador.exe` como "dropper" ou suspeito.
**É um falso positivo conhecido**, não malware. Acontece porque o executável
é gerado com PyInstaller, que empacota o Python e se descompacta numa pasta
temporária ao rodar — esse comportamento de "extrair e executar" dispara a
heurística de alguns antivírus. É um problema documentado de qualquer programa
Python distribuído como `.exe`.

Como conferir você mesmo:

- **VirusTotal:** a maioria esmagadora dos antivírus (incluindo o Windows
  Defender) reporta o arquivo como limpo; só alguns motores heurísticos
  reclamam.
- **Código aberto:** todo o código está neste repositório. O programa só
  **lê** informação do sistema — não modifica nada, não instala nada, não
  envia nada pela rede.
- **Rode direto do código-fonte** (sem o `.exe`), se preferir não confiar no
  binário:

  ```bash
  git clone https://github.com/highdevian/combatroblox
  cd combatroblox
  pip install -r requirements.txt
  python telador.py
  ```

- **Confira o SHA256:** o programa mostra o próprio hash no banner ao abrir;
  compare com o da release oficial.

## O que faz

### Scanners (50, em 11 categorias)

| Categoria | Cobertura |
|---|---|
| Execução | Prefetch, UserAssist, MUICache, Amcache (SHA1), BAM (timestamp exato) |
| Persistência | Pasta Startup, Run/RunOnce, Scheduled Tasks, dumps do WER |
| Sistema de arquivos | Arquivos recentes, Lixeira (parser $I), JumpLists, Downloads, arquivos ocultos |
| Navegador | Chrome, Edge, Brave, Opera (URLs e downloads) |
| Roblox | Logs do client, Bloxstrap, dumps de script/autoexec, scripts `.lua`/`.luau` |
| Processo ao vivo | DLLs carregadas no `RobloxPlayerBeta.exe` (WinVerifyTrust), árvore de processo, overlay/ESP externo |
| Comportamento | Histórico do PowerShell, Win+R, barra do Explorer, macros de mouse (G HUB, Razer, X-Mouse) |
| Rede | Conexões TCP/UDP, cache de DNS, arquivo hosts, cache do Discord |
| Anti-evasão | VM (VMware/VBox/Hyper-V/QEMU), Sandboxie, relógio alterado, formatação recente |
| Forense | Amcache, BAM, JumpLists, ShimCache, SRUM, análise PE com comparação de hash, hash de scripts conhecidos |
| Anti-forense | Detecção de formatação recente e de fontes históricas zeradas em conjunto; limpeza do log de Security; USN Journal (exec criado/apagado no disco — sobrevive ao arquivo ser apagado); Prefetch/SysMain desativados; gap suspeito no log de eventos (limpeza furtiva sem evento 1102); deleção em lote de shadow copies do VSS; histórico do PowerShell (PSReadLine) apagado ou zerado; **drivers do kernel suspeitos (anti-rootkit, BYOVD, cheat loader)** |

### Filtro de falsos positivos
- Detecta ambiente de desenvolvimento (Visual Studio, JetBrains, VS Code) e rebaixa ferramentas como Cheat Engine e IDA.
- Decaimento por tempo: itens com mais de 30 dias perdem severidade; acima de 90 dias viram baixa.
- Caminhos ignorados: `.git`, `node_modules`, biblioteca Steam, pastas de sistema.
- Contexto de navegador: visita a fórum não equivale a download.
- Veredito ponderado por severidade e confiança, não apenas contagem.

### Análise PE
SHA256 e leitura nativa do cabeçalho PE de cada executável encontrado:
- Data de compilação (recente eleva a severidade).
- Detecção de empacotadores (UPX, Themida, VMProtect, Enigma, ASPack, PECompact, MPRESS).
- Comparação de hash com uma base de executores conhecidos.
- Arquitetura (x86/x64/ARM64).

### Relatório HTML
- Barra lateral fixa com índice e contador por scanner.
- Gráficos em SVG (severidade e scanners com mais itens).
- Linha do tempo dos itens.
- Seções recolhíveis e busca/filtro em tempo real.
- Capturas de todos os monitores, com visualização ampliada.
- Estilos de impressão e layout responsivo.

### Verificação de sessão e integridade
- `--codigo`: código informado pelo supervisor entra no relatório assinado, evitando reaproveitar relatórios antigos.
- `--save-tsr` salva um instantâneo assinado por HMAC; `--diff` compara com um anterior.
- O programa exibe o próprio SHA256 no banner para conferência.

### Privacidade
- Execução totalmente local, sem envio de dados pela rede.
- Mascara automaticamente tokens, senhas, e-mails e CPF no relatório.
- Não captura a tela se houver gerenciador de senhas aberto.
- Código aberto e auditável.

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

## Sobre o Autor (About Me)

Desenvolvido por Gabriel ([@highdevian](https://github.com/highdevian)).

## Licença

MIT. Ver `LICENSE`.
