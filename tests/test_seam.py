"""
Testes da detecção de costura de operador (seam_scanner.py).

Foco: núcleo estatístico (z, d de Cohen, melhor split), corroboração por
IP/dispositivo, ordenação por timestamp, e os caminhos de decisão do scanner
(costura confirmada, só-rede, skill estável).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import seam_scanner as ss  # noqa: E402


# ----------------------------- núcleo estatístico -----------------------------

def test_num_rejeita_bool_e_lixo():
    assert ss._num(True) is None
    assert ss._num("lixo") is None
    assert ss._num("0,72") == 0.72        # vírgula decimal BR
    assert ss._num(3) == 3.0


def test_zscores_desvio_zero():
    assert ss._zscores([5, 5, 5]) == [0.0, 0.0, 0.0]


def test_cohens_d_separacao_grande():
    d = ss._cohens_d([10, 11, 9], [1, 2, 0])
    assert d > 2.0


def test_cohens_d_blocos_identicos_medias_diferentes():
    # sem dispersão interna e médias diferentes = separação total (sentinela)
    assert ss._cohens_d([5, 5], [1, 1]) == ss._D_PERFECT


def test_cohens_d_sem_diferenca():
    assert ss._cohens_d([5, 5], [5, 5]) == 0.0


def test_best_split_acha_a_fronteira():
    scores = [2.0, 1.8, -1.5, -1.7, -1.6]   # degrau entre idx 1 e 2
    k, d = ss._best_split(scores)
    assert k == 2
    assert d > 2.0


# ----------------------------- corroboração -----------------------------------

def test_disjoint_at_ips_separados():
    labels = ["A", "A", "B", "B"]
    disj, before, after = ss._disjoint_at(labels, 2)
    assert disj is True
    assert before == {"A"} and after == {"B"}


def test_disjoint_at_ip_compartilhado():
    labels = ["A", "A", "A", "B"]
    disj, _, _ = ss._disjoint_at(labels, 2)
    assert disj is False           # "A" aparece dos dois lados de k=2


def test_two_block_boundary_troca_limpa():
    assert ss._two_block_boundary(["x", "x", "y", "y"]) == 2


def test_two_block_boundary_com_none():
    # None (partida sem dado) é ignorado; conta a posição real
    assert ss._two_block_boundary(["x", None, "y", "y"]) == 2


def test_two_block_boundary_tres_valores_nao_e_seam():
    assert ss._two_block_boundary(["x", "y", "z"]) is None


def test_two_block_boundary_volta_pro_primeiro_nao_e_seam():
    assert ss._two_block_boundary(["x", "y", "x"]) is None


# ----------------------------- ordenação --------------------------------------

def test_sorted_matches_ordena_por_timestamp():
    ms = [
        {"match_id": "b", "timestamp": "2026-07-07T21:00:00"},
        {"match_id": "a", "timestamp": "2026-07-07T20:00:00"},
    ]
    out = ss._sorted_matches(ms)
    assert [m["match_id"] for m in out] == ["a", "b"]


def test_sorted_matches_sem_ts_mantem_ordem():
    ms = [{"match_id": "a"}, {"match_id": "b"}]
    assert [m["match_id"] for m in ss._sorted_matches(ms)] == ["a", "b"]


# ----------------------------- scanner: caminhos ------------------------------

def _cheater_block():
    return [
        {"match_id": "r1", "timestamp": "2026-07-07T20:00:00", "kd": 4.1,
         "accuracy": 0.74, "hs_pct": 0.61, "reaction_ms": 128, "ping_ms": 19,
         "login_ip": "201.55.10.7"},
        {"match_id": "r2", "timestamp": "2026-07-07T20:14:00", "kd": 3.6,
         "accuracy": 0.70, "hs_pct": 0.57, "reaction_ms": 141, "ping_ms": 22,
         "login_ip": "201.55.10.7"},
    ]


def _clean_block():
    return [
        {"match_id": "r3", "timestamp": "2026-07-07T20:31:00", "kd": 1.2,
         "accuracy": 0.41, "hs_pct": 0.22, "reaction_ms": 268, "ping_ms": 47,
         "login_ip": "189.40.201.3"},
        {"match_id": "r4", "timestamp": "2026-07-07T20:47:00", "kd": 0.9,
         "accuracy": 0.38, "hs_pct": 0.19, "reaction_ms": 291, "ping_ms": 44,
         "login_ip": "189.40.201.3"},
        {"match_id": "r5", "timestamp": "2026-07-07T21:03:00", "kd": 1.4,
         "accuracy": 0.44, "hs_pct": 0.25, "reaction_ms": 255, "ping_ms": 49,
         "login_ip": "189.40.201.3"},
    ]


def test_scan_costura_confirmada_por_ip():
    res = ss.scan_operator_seam(_cheater_block() + _clean_block())
    assert res["status"] == "suspicious"
    finding = [i for i in res["items"] if not i.get("meta_only")]
    assert finding, "deveria achar a costura"
    top = finding[0]
    assert top["severity"] == "critical"           # corroborado por IP = prova forte
    assert top["matched"] == "seam-confirmado"     # IP corrobora
    assert "201.55.10.7" in top["detail"]


def test_scan_costura_sem_ip_e_medium_ou_high_por_skill():
    # mesmo degrau de skill, mas sem login_ip: cai pra skill puro
    ms = []
    for m in _cheater_block() + _clean_block():
        m = dict(m)
        m.pop("login_ip", None)
        m.pop("ping_ms", None)
        ms.append(m)
    res = ss.scan_operator_seam(ms)
    finding = [i for i in res["items"] if not i.get("meta_only")]
    assert finding
    assert finding[0]["matched"] == "seam-skill"


def test_scan_um_operador_so_e_clean():
    # jogador consistente (variância pequena) + IP fixo = sem costura
    ms = [
        {"match_id": f"r{i}", "timestamp": f"2026-07-07T2{i}:00:00",
         "kd": 1.5 + 0.05 * i, "accuracy": 0.50, "hs_pct": 0.30,
         "reaction_ms": 240, "ping_ms": 30, "login_ip": "10.0.0.1"}
        for i in range(4)
    ]
    res = ss.scan_operator_seam(ms)
    finding = [i for i in res["items"] if not i.get("meta_only")]
    assert finding == []
    assert res["status"] == "clean"


def test_scan_esquenta_nao_e_costura():
    # jogador "esquentando": accuracy sobe suave 0.40->0.47 (drift < gate de 0.10),
    # KD sobe pouco, IP fixo. z-score estoura o d, mas a magnitude crua nao passa
    # -> NAO deve acusar troca de operador.
    ms = [
        {"match_id": f"r{i}", "timestamp": f"2026-07-07T2{i}:00:00",
         "kd": 1.4 + 0.06 * i, "accuracy": 0.40 + 0.02 * i, "hs_pct": 0.28 + 0.01 * i,
         "reaction_ms": 250 - 5 * i, "ping_ms": 30, "login_ip": "10.0.0.1"}
        for i in range(5)
    ]
    res = ss.scan_operator_seam(ms)
    finding = [i for i in res["items"] if not i.get("meta_only")]
    assert finding == []
    assert res["status"] == "clean"


def test_scan_poucas_partidas_erro():
    res = ss.scan_operator_seam([{"match_id": "r1"}, {"match_id": "r2"}])
    assert res["status"] == "error"


def test_scan_entradas_malformadas_nao_crasha():
    # array com lixo (string, número, null) no meio não pode derrubar o scanner
    ms = ["lixo", 42, None] + _cheater_block() + _clean_block()
    res = ss.scan_operator_seam(ms)          # não deve levantar
    assert res["status"] in ("suspicious", "clean")


def test_scan_jogo_isolado_sem_ip_nao_e_costura():
    # 1 partida sobre-humana isolada + 4 normais, SEM login: dia bom, não swap.
    outlier = {"match_id": "lucky", "timestamp": "2026-07-07T20:00:00", "kd": 5.0,
               "accuracy": 0.78, "hs_pct": 0.64, "reaction_ms": 120}
    normais = [
        {"match_id": f"n{i}", "timestamp": f"2026-07-07T2{i + 1}:00:00", "kd": 1.1,
         "accuracy": 0.40, "hs_pct": 0.20, "reaction_ms": 270}
        for i in range(4)
    ]
    res = ss.scan_operator_seam([outlier] + normais)
    finding = [i for i in res["items"] if not i.get("meta_only")]
    assert finding == []          # bloco de 1 partida sem corroboração => não acusa


def test_scan_jogo_isolado_com_ip_distinto_flagga():
    # mesmo jogo isolado, mas logado de outro IP => corrobora, deve acusar
    outlier = {"match_id": "lucky", "timestamp": "2026-07-07T20:00:00", "kd": 5.0,
               "accuracy": 0.78, "hs_pct": 0.64, "reaction_ms": 120,
               "login_ip": "201.55.10.7"}
    normais = [
        {"match_id": f"n{i}", "timestamp": f"2026-07-07T2{i + 1}:00:00", "kd": 1.1,
         "accuracy": 0.40, "hs_pct": 0.20, "reaction_ms": 270, "login_ip": "189.40.201.3"}
        for i in range(4)
    ]
    res = ss.scan_operator_seam([outlier] + normais)
    finding = [i for i in res["items"] if not i.get("meta_only")]
    assert finding and finding[0]["matched"] == "seam-confirmado"


def test_fp_costura_antiga_mantem_critical():
    # série de +90 dias atrás: o time-decay do fp_filter NÃO pode rebaixar a
    # costura (o timestamp é a data da partida, não idade de artefato).
    import fp_filter
    velho_cheater = [
        {"match_id": "r1", "timestamp": "2025-01-05T20:00:00", "kd": 4.1,
         "accuracy": 0.74, "hs_pct": 0.61, "reaction_ms": 128, "login_ip": "201.55.10.7"},
        {"match_id": "r2", "timestamp": "2025-01-05T20:14:00", "kd": 3.6,
         "accuracy": 0.70, "hs_pct": 0.57, "reaction_ms": 141, "login_ip": "201.55.10.7"},
    ]
    velho_clean = [
        {"match_id": "r3", "timestamp": "2025-01-05T20:31:00", "kd": 1.2,
         "accuracy": 0.41, "hs_pct": 0.22, "reaction_ms": 268, "login_ip": "189.40.201.3"},
        {"match_id": "r4", "timestamp": "2025-01-05T20:47:00", "kd": 0.9,
         "accuracy": 0.38, "hs_pct": 0.19, "reaction_ms": 291, "login_ip": "189.40.201.3"},
        {"match_id": "r5", "timestamp": "2025-01-05T21:03:00", "kd": 1.4,
         "accuracy": 0.44, "hs_pct": 0.25, "reaction_ms": 255, "login_ip": "189.40.201.3"},
    ]
    res = ss.scan_operator_seam(velho_cheater + velho_clean)
    findings, _ = fp_filter.post_process_findings([res])
    real = [i for i in findings[0]["items"] if not i.get("meta_only")]
    assert real and real[0]["severity"] == "critical"   # não rebaixado por idade


def test_scan_partidas_identicas_nao_confunde_indice():
    # duas partidas do bloco do xitado com stats IDÊNTICAS: matches.index()
    # retornaria o mesmo índice pras duas — o refactor por índice evita isso.
    dup = {"match_id": "r1", "timestamp": "2026-07-07T20:00:00", "kd": 4.0,
           "accuracy": 0.72, "hs_pct": 0.60, "reaction_ms": 130, "ping_ms": 20,
           "login_ip": "201.55.10.7"}
    dup2 = dict(dup, match_id="r2", timestamp="2026-07-07T20:14:00")
    res = ss.scan_operator_seam([dup, dup2] + _clean_block())
    finding = [i for i in res["items"] if not i.get("meta_only")]
    assert finding and finding[0]["matched"] == "seam-confirmado"


def test_evidence_costura_vira_cluster_operator_swap():
    # integração com o Confidence Engine: a costura tem que virar um cluster
    # de kind 'operator_swap', critical (corroborado) e verdict DETECTED.
    import evidence as ev
    res = ss.scan_operator_seam(_cheater_block() + _clean_block())
    evs = ev.findings_to_evidences([res])
    assert evs, "deveria gerar evidência (item real, não meta_only)"
    assert all(e.target_kind == "operator_swap" for e in evs)
    assert evs[0].source == "operator_seam"
    clusters = ev.build_clusters(evs)
    top = clusters[0]
    assert top.kind == "operator_swap"
    assert top.label == "Troca de operador"
    assert top.has_critical
    assert top.verdict == "DETECTED"        # critical isolado (1 fonte)


def test_wrapper_sem_arquivo_da_erro():
    ss.configure(None)
    res = ss.scan_costura_de_operador()
    assert res["status"] == "error"
    assert "--seam" in res["error"]


def test_wrapper_le_arquivo_e_roda(tmp_path):
    import json
    p = tmp_path / "partidas.json"
    p.write_text(json.dumps({"matches": _cheater_block() + _clean_block()}),
                 encoding="utf-8")
    ss.configure(str(p))
    res = ss.scan_costura_de_operador()
    assert res["status"] == "suspicious"
    finding = [i for i in res["items"] if not i.get("meta_only")]
    assert finding and finding[0]["severity"] == "critical"
    ss.configure(None)   # limpa o global pra não vazar pra outros testes


def test_scan_so_rede_sem_skill():
    # sem métricas de skill, mas IP forma 2 blocos -> nota media pra puxar dados
    ms = [
        {"match_id": "r1", "timestamp": "2026-07-07T20:00:00", "login_ip": "1.1.1.1"},
        {"match_id": "r2", "timestamp": "2026-07-07T20:20:00", "login_ip": "1.1.1.1"},
        {"match_id": "r3", "timestamp": "2026-07-07T20:40:00", "login_ip": "2.2.2.2"},
    ]
    res = ss.scan_operator_seam(ms)
    finding = [i for i in res["items"] if not i.get("meta_only")]
    assert finding
    assert finding[0]["matched"] == "seam-rede-sem-skill"
