# Tutorial Simples (Para Qualquer Pessoa)

Este guia e para quem nao manja de terminal.

## 1. Baixar o projeto

1. Entre no repositorio no GitHub.
2. Clique em Code.
3. Clique em Download ZIP.
4. Extraia o ZIP em uma pasta facil (exemplo: Desktop).

## 2. Abrir no lugar certo

1. Abra a pasta extraida.
2. Clique na barra de endereco da pasta.
3. Digite `powershell` e aperte Enter.
4. Vai abrir o PowerShell ja nessa pasta.

## 3. Instalar dependencias (uma vez so)

Copie e cole este comando:

```powershell
python -m pip install -r requirements.txt
```

## 4. Rodar o scan normal (recomendado)

Copie e cole:

```powershell
python telador.py
```

## 5. Ler o resultado

- Se aparecer `VEREDITO: LIMPO`, nao encontrou vestigio.
- Se aparecer `SUSPEITO` ou `CHEATER`, abra o HTML e veja qual item bateu.

## 6. Modo recomendado para evitar falso positivo

Use o modo padrao (sem flag extra).

## 7. Modo agressivo (somente investigacao)

Este modo e mais pesado e pode aumentar falso positivo:

```powershell
python telador.py --strict-scripts
```

## 8. Teste rapido so do scanner de scripts

```powershell
python telador.py --no-confirm --no-open --only scripts
```

## 9. Erros comuns

### `python` nao reconhecido

1. Reinstale o Python.
2. Marque a opcao `Add Python to PATH` na instalacao.
3. Feche e abra o terminal novamente.

### Ainda aparece relatorio velho

Apague relatorios antigos do Temp:

```powershell
Remove-Item "$env:LOCALAPPDATA\Temp\telador_relatorio_*.html" -ErrorAction SilentlyContinue
Remove-Item "$env:LOCALAPPDATA\Temp\telador_relatorio_*.json" -ErrorAction SilentlyContinue
```

## 10. Build do executavel (opcional)

Se quiser gerar `.exe`:

```powershell
.\build.bat
```

Depois rode:

```powershell
.\dist\telador.exe
```
