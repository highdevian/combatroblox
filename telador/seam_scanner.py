"""
Detecção de COSTURA DE OPERADOR — conta pilotada/revezada entre partidas.

Truque (o buraco lógico que a SS ao vivo não fecha):
    A tela ao vivo só prova QUEM controla a conta AGORA. Ela não prova quem
    controlou nas partidas passadas. No golpe do "revezamento", o xitado
    (external) joga 1-2 partidas na conta de um membro limpo, sai, e o dono
    limpo joga o resto. Quando pedem tela, o dono mostra a máquina dele — que é
    limpa de verdade — e o histórico do external já sumiu do PC dele (que nem é
    a máquina inspecionada). Verificar o disco não pega nada: o cheat nunca
    esteve ali.

Sinal:
    Uma conta = UM humano. Um humano não oscila de sobre-humano pra normal no
    meio de uma série. Se as partidas se separam em DOIS blocos contíguos com
    perfil de skill muito diferente (accuracy/HS/KD/reação), a conta trocou de
    mão. O ponto onde o degrau acontece é a COSTURA (o operador mudou ali).

Método:
    1. Por métrica (kd, accuracy, hs_pct, reaction_ms) calcula z-score ao longo
       da série e monta um "score de skill" por partida (reação invertida: menor
       = melhor). Isso põe métricas de escalas diferentes na mesma régua.
    2. Testa cada fronteira possível k (partidas 0..k | k..n) e mede a separação
       entre os dois blocos com o d de Cohen (diferença de médias em desvios-
       padrão). A fronteira de maior d é a costura candidata. d grande = degrau
       que humano nenhum faz sozinho.
    3. Se as partidas trazem `login_ip`/`device` (exportados de
       Configurações → Segurança do Roblox) OU `ping_ms`, CORROBORA: a máquina/
       conexão muda exatamente na mesma costura? Skill + IP batendo = prova
       dura de pilotagem, não suspeita.

Este módulo NÃO varre a máquina local — ele consome um arquivo de partidas que
o telador monta (stats por partida da liga + histórico de login da conta). Por
isso não entra no auto-scan de zero-arg; é ligado sob demanda com --seam, e aí
roda dentro da chain do telador como qualquer outro scanner (console, veredito,
HTML/JSON/MD):

    python telador.py --seam partidas.json      # integrado ao relatório
    python seam_scanner.py partidas.json         # standalone (só esta análise)

Formato de cada partida (só timestamp é obrigatório; quanto mais métrica,
melhor a costura):

    {
      "match_id": "amistoso-r2",
      "timestamp": "2026-07-07T20:12:00",
      "kd": 3.8, "accuracy": 0.72, "hs_pct": 0.58, "reaction_ms": 135,
      "ping_ms": 21, "login_ip": "189.1.2.3", "device": "Windows-Desktop"
    }
"""

import json
import math
import sys
from datetime import datetime

from .models import _result, _item


# Métricas de SKILL e a direção em que "maior = mais suspeito de external".
# reaction_ms é invertida: reação mais BAIXA (mais rápida) puxa o score pra cima.
_SKILL_METRICS = {
    "kd": +1,
    "accuracy": +1,
    "hs_pct": +1,
    "reaction_ms": -1,
}

_MIN_MATCHES = 3       # com menos de 3 não dá pra ter um split com blocos dos 2 lados

# Limiares do d de Cohen (separação entre os dois blocos, em desvios-padrão).
# Referência clássica: 0.8 já é "efeito grande". Aqui a barra é mais alta porque
# variância de humor/adversário de um mesmo jogador produz d pequeno o tempo todo.
_D_SEAM = 0.8          # abaixo: variância normal de UM operador só
_D_STRONG = 2.0        # degrau enorme (blocos quase sem sobreposição)
_D_PERFECT = 10.0      # sentinela p/ blocos internamente idênticos (separação total)

# Gate de magnitude ABSOLUTA. O d de Cohen é normalizado (invariante a escala),
# então drift trivial estoura o d se for o único sinal — ex: KD subindo de 1.5
# pra 1.65 num "esquenta" do MESMO jogador vira d>2. Pra afirmar troca de
# operador, exige que ALGUMA métrica crua separe os blocos por uma margem real.
_MIN_RAW_DELTA = {
    "kd": 0.8,
    "accuracy": 0.10,     # 10 pontos percentuais
    "hs_pct": 0.10,
    "reaction_ms": 40.0,  # ms
}


# ----------------------------- núcleo estatístico -----------------------------

def _num(v):
    """Converte pra float; None/lixo -> None (métrica ausente na partida)."""
    if isinstance(v, bool):        # bool é subclasse de int; não é métrica
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            return float(v.strip().replace(",", "."))
        except ValueError:
            return None
    return None


def _mean(xs):
    return sum(xs) / len(xs) if xs else 0.0


def _var(xs):
    """Variância amostral (n-1). n<2 -> 0 (sem dispersão definível)."""
    n = len(xs)
    if n < 2:
        return 0.0
    m = _mean(xs)
    return sum((x - m) ** 2 for x in xs) / (n - 1)


def _stdev(xs):
    return math.sqrt(_var(xs))


def _zscores(values):
    """z de cada valor na série. Desvio 0 (todos iguais) -> zeros."""
    m = _mean(values)
    sd = _stdev(values)
    if sd == 0:
        return [0.0 for _ in values]
    return [(v - m) / sd for v in values]


def _cohens_d(a, b):
    """|média(a)-média(b)| em desvios-padrão agrupados (pooled). Guarda casos
    degenerados: sem dispersão interna e médias diferentes = separação total."""
    na, nb = len(a), len(b)
    if na < 1 or nb < 1:
        return 0.0
    ma, mb = _mean(a), _mean(b)
    denom = na + nb - 2
    if denom <= 0:
        pooled = math.sqrt((_var(a) + _var(b)) / 2)
    else:
        pooled = math.sqrt(((na - 1) * _var(a) + (nb - 1) * _var(b)) / denom)
    if pooled == 0:
        return _D_PERFECT if ma != mb else 0.0
    return min(abs(ma - mb) / pooled, _D_PERFECT)


def _skill_scores(matches):
    """Um score de skill por partida = média dos z-scores (com sinal) das
    métricas presentes naquela partida. Partida sem nenhuma métrica -> None."""
    per_metric = {}
    for metric, direction in _SKILL_METRICS.items():
        idx = [i for i, m in enumerate(matches) if _num(m.get(metric)) is not None]
        vals = [_num(matches[i].get(metric)) for i in idx]
        if len(vals) < 2:            # métrica sem variação útil na série
            continue
        zs = _zscores(vals)
        per_metric[metric] = {i: direction * z for i, z in zip(idx, zs, strict=True)}

    scores = []
    for i in range(len(matches)):
        vals = [per_metric[m][i] for m in per_metric if i in per_metric[m]]
        scores.append(_mean(vals) if vals else None)
    return scores


def _best_split(scores):
    """Fronteira k (1..n-1) que MAIS separa os dois blocos contíguos, e o d dela.
    Retorna (k, d). scores não pode ter None (filtre antes)."""
    n = len(scores)
    best_k, best_d = None, -1.0
    for k in range(1, n):
        d = _cohens_d(scores[:k], scores[k:])
        if d > best_d:
            best_k, best_d = k, d
    return best_k, best_d


# ----------------------------- corroboração (IP/rede) -------------------------

def _labels(matches, key):
    """Lista do campo `key` (login_ip/device) por partida; '' vira None."""
    out = []
    for m in matches:
        v = m.get(key)
        out.append(str(v).strip() if v not in (None, "") else None)
    return out


def _disjoint_at(labels, k):
    """Os rótulos ANTES de k não compartilham nenhum valor com os DEPOIS de k?
    (ignora None). Retorna (disjunto?, set_antes, set_depois)."""
    before = {l for l in labels[:k] if l}
    after = {l for l in labels[k:] if l}
    if not before or not after:
        return False, before, after
    return before.isdisjoint(after), before, after


def _two_block_boundary(labels):
    """Se os rótulos (ignorando None) formam EXATAMENTE dois blocos contíguos
    constantes e diferentes (A...A B...B), retorna o índice de partida onde o
    segundo bloco começa; senão None. É o caso do revezamento limpo de máquina."""
    seq = [(i, l) for i, l in enumerate(labels) if l]
    if len(seq) < 2:
        return None
    vals = [l for _, l in seq]
    first = vals[0]
    change = next((j for j in range(1, len(vals)) if vals[j] != first), None)
    if change is None:
        return None
    second = vals[change]
    if first == second:
        return None
    if any(v not in (first, second) for v in vals):
        return None                      # 3+ valores: não é troca limpa
    if any(v != second for v in vals[change:]):
        return None                      # volta pro primeiro valor: não é 2 blocos
    return seq[change][0]


# ----------------------------- perfil de bloco --------------------------------

def _block_profile(matches):
    """Média de cada métrica presente no bloco, pra descrever o perfil."""
    prof = {}
    for metric in list(_SKILL_METRICS) + ["ping_ms"]:
        vals = [_num(m.get(metric)) for m in matches if _num(m.get(metric)) is not None]
        if vals:
            prof[metric] = _mean(vals)
    return prof


def _meaningful_gap(block_a, block_b):
    """Métricas cruas cuja diferença de média entre os blocos passa do limiar de
    magnitude (não é drift trivial). Retorna [(metric, delta), ...] ordenado."""
    pa, pb = _block_profile(block_a), _block_profile(block_b)
    out = []
    for metric, thr in _MIN_RAW_DELTA.items():
        if metric in pa and metric in pb:
            delta = abs(pa[metric] - pb[metric])
            if delta >= thr:
                out.append((metric, delta))
    return sorted(out, key=lambda x: -x[1])


_GAP_NAMES = {"kd": "KD", "accuracy": "accuracy", "hs_pct": "HS%", "reaction_ms": "reação"}


def _fmt_gap(gap_metrics):
    return ", ".join(f"{_GAP_NAMES[m]} dif {d:.2f}" for m, d in gap_metrics)


def _fmt_profile(prof):
    parts = []
    if "kd" in prof:
        parts.append(f"KD {prof['kd']:.2f}")
    if "accuracy" in prof:
        parts.append(f"acc {prof['accuracy'] * 100:.0f}%")
    if "hs_pct" in prof:
        parts.append(f"HS {prof['hs_pct'] * 100:.0f}%")
    if "reaction_ms" in prof:
        parts.append(f"reação {prof['reaction_ms']:.0f}ms")
    if "ping_ms" in prof:
        parts.append(f"ping {prof['ping_ms']:.0f}ms")
    return ", ".join(parts) if parts else "sem métricas"


def _ids(matches):
    return ", ".join(str(m.get("match_id") or f"#{i + 1}") for i, m in enumerate(matches))


# ----------------------------- ordenação / timestamps -------------------------

def _parse_ts(s):
    s = (s or "").strip().rstrip("Z")
    if not s:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def _sorted_matches(matches):
    """Ordena cronologicamente se TODAS têm timestamp parseável; senão mantém a
    ordem dada (a costura assume ordem cronológica)."""
    parsed = [_parse_ts(m.get("timestamp", "")) for m in matches]
    if all(p is not None for p in parsed) and parsed:
        return [m for _, m in sorted(zip(parsed, matches, strict=True), key=lambda x: x[0])]
    return list(matches)


# ----------------------------- scanner ----------------------------------------

_NAME = "Costura de operador (conta revezada/pilotada)"
_DESC = "Degrau de skill entre blocos de partidas + troca de IP/dispositivo na mesma conta"


def scan_operator_seam(matches: list) -> dict:
    """Recebe a lista de partidas de UMA conta numa série e procura a costura
    onde o operador mudou. Não varre máquina — consome dados da liga + login."""
    if not isinstance(matches, list) or len(matches) < _MIN_MATCHES:
        return _result(_NAME, _DESC, [],
                       error=f"precisa de pelo menos {_MIN_MATCHES} partidas da mesma conta")

    # Descarta entradas malformadas (string/número/null soltos no array) antes
    # de qualquer .get() — senão um JSON torto derruba o scanner com AttributeError.
    matches = [m for m in matches if isinstance(m, dict)]
    if len(matches) < _MIN_MATCHES:
        return _result(_NAME, _DESC, [],
                       error=f"precisa de pelo menos {_MIN_MATCHES} partidas válidas (objetos JSON)")

    matches = _sorted_matches(matches)
    scores_all = _skill_scores(matches)

    # partidas com score utilizável, guardando o ÍNDICE original (não o dict) —
    # duas partidas com stats idênticas seriam confundidas por matches.index().
    scored = [(i, m, s)
              for i, (m, s) in enumerate(zip(matches, scores_all, strict=True))
              if s is not None]
    ip_labels = _labels(matches, "login_ip")
    dev_labels = _labels(matches, "device")

    items = []

    # --- caminho A: sem skill suficiente, mas rede/dispositivo pode denunciar ---
    if len(scored) < _MIN_MATCHES:
        for key, human in (("login_ip", "IP"), ("device", "dispositivo")):
            b = _two_block_boundary(_labels(matches, key))
            if b is not None:
                items.append(_item(
                    label=f"Conta jogou de dois(as) {human}s diferentes na série",
                    detail=f"As partidas se partem em dois blocos por {human} (troca em "
                           f"'{matches[b].get('match_id') or f'#{b + 1}'}'), mas faltam métricas "
                           f"de skill pra confirmar troca de operador. Peça as stats por partida "
                           f"(accuracy/HS/KD) e o histórico de login completo.",
                    severity="medium", matched="seam-rede-sem-skill",
                    timestamp=matches[b].get("timestamp", ""),
                ))
        if not items:
            return _result(_NAME, _DESC, [],
                           error="métricas de skill insuficientes e sem IP/dispositivo pra analisar")
        return _result(_NAME, _DESC, items)

    scores = [s for _, _, s in scored]
    k, d = _best_split(scores)

    # fronteira: índice REAL na lista matches (via o índice guardado no scored).
    b_idx = scored[k][0]
    block_a = [m for _, m, _ in scored[:k]]
    block_b = [m for _, m, _ in scored[k:]]
    prev_match = block_a[-1]        # última partida do bloco 1 (real, não a[b_idx-1])
    boundary_match = block_b[0]     # primeira partida do bloco 2
    prof_a, prof_b = _block_profile(block_a), _block_profile(block_b)
    mean_a, mean_b = _mean(scores[:k]), _mean(scores[k:])

    # qual bloco é o suspeito de external = o de MAIOR score de skill
    if mean_a >= mean_b:
        sus_ids, sus_prof, clean_ids = _ids(block_a), prof_a, _ids(block_b)
    else:
        sus_ids, sus_prof, clean_ids = _ids(block_b), prof_b, _ids(block_a)

    # corroboração: a máquina/conexão muda exatamente nessa costura?
    ip_disj, ip_b, ip_a = _disjoint_at(ip_labels, b_idx)
    dev_disj, _, _ = _disjoint_at(dev_labels, b_idx)
    ping_a = [_num(m.get("ping_ms")) for m in block_a if _num(m.get("ping_ms")) is not None]
    ping_b = [_num(m.get("ping_ms")) for m in block_b if _num(m.get("ping_ms")) is not None]
    ping_d = _cohens_d(ping_a, ping_b) if (len(ping_a) >= 2 and len(ping_b) >= 2) else 0.0
    corroborado = ip_disj or dev_disj
    gap_metrics = _meaningful_gap(block_a, block_b)

    # Anti-FP: um bloco de 1 partida só é jogo isolado (dia bom/ruim), não prova
    # de troca. Skill puro exige os dois blocos com >=2 partidas; se o IP/
    # dispositivo corrobora, 1 partida já vale (o login mudou naquele jogo).
    min_block = min(len(block_a), len(block_b))
    enough_block = corroborado or min_block >= 2

    if d >= _D_SEAM and gap_metrics and enough_block:
        # Severidade:
        #   corroborado (skill + IP/dispositivo, dois sinais independentes na
        #     MESMA costura) = critical — prova forense forte, igual hash/BYOVD.
        #   degrau enorme sem login = high; degrau moderado = medium.
        if corroborado:
            sev = "critical"
        elif d >= _D_STRONG:
            sev = "high"
        else:
            sev = "medium"

        corr_txt = ""
        if ip_disj:
            corr_txt = (f" CONFIRMA: login vindo de IPs distintos nos dois blocos "
                        f"({', '.join(sorted(ip_b))} vs {', '.join(sorted(ip_a))}) — máquina "
                        f"diferente na mesma costura.")
        elif dev_disj:
            corr_txt = " CONFIRMA: dispositivo de login muda exatamente na costura."
        elif ping_d >= 1.0:
            corr_txt = (f" Reforço: baseline de ping diferente entre os blocos (d={ping_d:.1f}) "
                        f"— outra conexão/máquina.")
        else:
            corr_txt = (" Sem dado de login pra confirmar — puxe Configurações → Segurança do "
                        "Roblox e cruze IP/dispositivo com os horários das partidas.")

        items.append(_item(
            label=f"Troca de operador na conta — degrau de skill entre "
                  f"'{prev_match.get('match_id') or f'#{b_idx}'}' e "
                  f"'{boundary_match.get('match_id') or f'#{b_idx + 1}'}'",
            detail=f"A série se parte em dois blocos com perfil incompatível de um só jogador "
                   f"(d de Cohen={d:.1f}; separação crua: {_fmt_gap(gap_metrics)}). "
                   f"Bloco suspeito de external [{sus_ids}]: "
                   f"{_fmt_profile(sus_prof)}. Bloco compatível com o dono [{clean_ids}]. "
                   f"Um humano não pula de sobre-humano pra normal no meio da série.{corr_txt}",
            severity=sev, matched="seam-confirmado" if corroborado else "seam-skill",
            timestamp=boundary_match.get("timestamp", ""),
        ))
    else:
        # skill não delatou; mas se IP/dispositivo forma 2 blocos, ainda vale nota
        for key, human in (("login_ip", "IP"), ("device", "dispositivo")):
            bb = _two_block_boundary(_labels(matches, key))
            if bb is not None:
                items.append(_item(
                    label=f"Conta logada de dois(as) {human}s, mas skill estável",
                    detail=f"O {human} troca no meio da série sem degrau de skill (d={d:.1f}). "
                           f"Pode ser troca de rede legítima do MESMO jogador (casa/celular) — "
                           f"não é prova de pilotagem sozinho. Confirme com tela ao vivo + nonce.",
                    severity="low", matched="seam-rede-skill-estavel",
                    timestamp=matches[bb].get("timestamp", ""),
                ))

    # contexto (meta_only): perfil de cada bloco, sempre listado
    items.append(_item(
        label=f"Perfil bloco 1 [{_ids(block_a)}]",
        detail=f"{_fmt_profile(prof_a)} — score médio de skill {mean_a:+.2f}",
        severity="low", matched="perfil-bloco", meta_only=True,
    ))
    items.append(_item(
        label=f"Perfil bloco 2 [{_ids(block_b)}]",
        detail=f"{_fmt_profile(prof_b)} — score médio de skill {mean_b:+.2f}",
        severity="low", matched="perfil-bloco", meta_only=True,
    ))

    return _result(_NAME, _DESC, items)


# ----------------------------- integração telador.py --------------------------
# O telador roda scanners ZERO-ARG numa chain. Este scanner precisa de dados
# externos (arquivo de partidas), então guardamos o caminho num global via
# configure() e expomos um wrapper zero-arg que a chain consegue chamar.

_MATCHES_PATH = None


def configure(path: str) -> None:
    """Registra o arquivo de partidas que o wrapper da chain vai ler (--seam)."""
    global _MATCHES_PATH
    _MATCHES_PATH = path


def scan_costura_de_operador() -> dict:
    """Wrapper zero-arg pro pipeline do telador. Lê o arquivo configurado por
    configure() e roda a análise de costura. Nome vira o label no console/HTML."""
    if not _MATCHES_PATH:
        return _result(_NAME, _DESC, [],
                       error="nenhum arquivo de partidas fornecido (use --seam <arquivo.json>)")
    try:
        matches = _load(_MATCHES_PATH)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        return _result(_NAME, _DESC, [], error=f"erro ao ler {_MATCHES_PATH}: {e}")
    return scan_operator_seam(matches)


# Só é ligado no telador quando --seam é passado (dado externo, não auto-scan).
ALL_SEAM_SCANNERS = [scan_costura_de_operador]


# ----------------------------- CLI --------------------------------------------

def _load(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and "matches" in data:
        data = data["matches"]
    if not isinstance(data, list):
        raise ValueError("JSON deve ser uma lista de partidas ou {\"matches\": [...]}")
    return data


def _print_result(res):
    icon = {"clean": "OK", "suspicious": "!!", "error": "XX"}.get(res["status"], "??")
    print(f"[{icon}] {res['name']}")
    print(f"     {res['summary']}")
    if res.get("error"):
        print(f"     erro: {res['error']}")
    for it in res["items"]:
        tag = "  (contexto)" if it.get("meta_only") else ""
        print(f"  - [{it['severity'].upper()}]{tag} {it['label']}")
        print(f"      {it['detail']}")
        if it.get("timestamp"):
            print(f"      quando: {it['timestamp']}")


def main(argv):
    # console do Windows costuma ser cp1252; evita crash em char fora da tabela
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(errors="replace")
        except (ValueError, OSError):
            pass
    if len(argv) < 2:
        print("uso: python seam_scanner.py <partidas.json>")
        return 2
    try:
        matches = _load(argv[1])
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"erro ao ler {argv[1]}: {e}")
        return 1
    _print_result(scan_operator_seam(matches))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
