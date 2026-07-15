# Tutorial Simples (2 Cliques)

Este guia e para quem nao manja de terminal.

## 1. Baixar o projeto

1. Entre no repositorio no GitHub.
2. Clique em Code.
3. Clique em Download ZIP.
4. Extraia o ZIP em uma pasta facil (exemplo: Desktop).

## 2. Rodar com 2 cliques

1. Entre na pasta extraida.
2. Clique duas vezes em `INICIAR.bat`.

Pronto. O launcher faz sozinho:

1. Se existir `dist\telador.exe`, abre o executavel.
2. Se nao existir, usa Python e instala dependencias automaticamente.

## 3. Ler o resultado

1. `VEREDITO: LIMPO` = nao encontrou vestigio.
2. `SUSPEITO` ou `CHEATER` = abrir o HTML e revisar item por item.

Nota: se um gerenciador de senhas estiver aberto (KeePass, Bitwarden, etc),
o programa pula screenshot para preservar privacidade.

## 4. Quando der erro

### Python nao reconhecido

1. Reinstale o Python 3.10+.
2. Marque `Add Python to PATH` na instalacao.
3. Feche e abra novamente.

### Ainda abriu relatorio velho

No PowerShell, rode:

```powershell
Remove-Item "$env:LOCALAPPDATA\Temp\telador_relatorio_*.html" -ErrorAction SilentlyContinue
Remove-Item "$env:LOCALAPPDATA\Temp\telador_relatorio_*.json" -ErrorAction SilentlyContinue
```

## 5. Modo avancado (opcional)

Se quiser rodar manual no terminal:

```powershell
python telador.py
python telador.py --strict-scripts
python telador.py --no-confirm --no-open --only scripts
python telador.py --no-redact
python telador.py --force-screenshot
```
