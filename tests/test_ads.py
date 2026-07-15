"""
Testes da detecção de Alternate Data Streams (ads_scanner.py).

Cobre o núcleo de classificação (sem Win32), o parse do nome de stream, e uma
integração end-to-end criando ADS NTFS reais num tmp (exercita FindFirstStreamW).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from telador import ads_scanner as ads  # noqa: E402
# ----------------------------- núcleo testável -----------------------------

def test_parse_stream_name():
    assert ads._parse_stream_name(":Zone.Identifier:$DATA") == "Zone.Identifier"
    assert ads._parse_stream_name(":payload.exe:$DATA") == "payload.exe"
    assert ads._parse_stream_name("::$DATA") == ""          # stream default
    assert ads._parse_stream_name("") == ""


def test_classify_zone_identifier_benign():
    """REGRESSÃO FP central: Zone.Identifier (mark-of-the-web de todo download)
    nunca pode flaggar."""
    assert ads._classify_stream("Zone.Identifier", has_mz=False) is None
    assert ads._classify_stream("SmartScreen", has_mz=False) is None
    assert ads._classify_stream("", has_mz=False) is None


def test_classify_mz_content_high():
    sev, m = ads._classify_stream("qualquercoisa", has_mz=True)
    assert sev == "high"
    assert m == "ads-executavel"


def test_classify_executor_name_high():
    sev, m = ads._classify_stream("solara.exe", has_mz=False)
    assert sev == "high"
    assert m.startswith("ads-executor:")


def test_classify_exec_extension_high():
    """Nome de stream com extensão de executável, sem MZ nem keyword conhecida."""
    sev, m = ads._classify_stream("payload.bat", has_mz=False)
    assert sev == "high"
    assert m == "ads-exec-nome"


def test_classify_unknown_non_exec_not_flagged():
    """ADS desconhecido SEM sinal executável = não flagga (evita FP de app)."""
    assert ads._classify_stream("com.example.metadata", has_mz=False) is None
    assert ads._classify_stream("thumbnail", has_mz=False) is None


# ----------------------------- integração (ADS real) -----------------------------

def test_scan_flags_hidden_exe_ignores_zone(tmp_path, monkeypatch):
    """End-to-end: cria ADS NTFS reais — payload com MZ é HIGH, Zone.Identifier
    é ignorado. Exercita FindFirstStreamW de verdade."""
    base = tmp_path / "notas.txt"
    base.write_text("arquivo normal")
    # ADS benigno (mark-of-the-web)
    with open(f"{base}:Zone.Identifier", "w") as fh:
        fh.write("[ZoneTransfer]\nZoneId=3")
    # ADS malicioso: executável escondido
    with open(f"{base}:payload.exe", "wb") as fh:
        fh.write(b"MZ\x90\x00" + b"\x00" * 64)

    monkeypatch.setattr(ads, "_SCAN_DIRS", [str(tmp_path)])
    r = ads.scan_alternate_data_streams()

    assert r["status"] == "suspicious"
    assert len(r["items"]) == 1
    it = r["items"][0]
    assert it["severity"] == "high"
    assert it["matched"] == "ads-executavel"
    assert "payload.exe" in it["label"]
    # o Zone.Identifier NÃO pode aparecer
    assert not any("zone" in i["label"].lower() for i in r["items"])


def test_scan_clean_when_only_benign(tmp_path, monkeypatch):
    base = tmp_path / "baixado.pdf"
    base.write_text("pdf")
    with open(f"{base}:Zone.Identifier", "w") as fh:
        fh.write("[ZoneTransfer]\nZoneId=3")
    monkeypatch.setattr(ads, "_SCAN_DIRS", [str(tmp_path)])
    assert ads.scan_alternate_data_streams()["status"] == "clean"


# ----------------------------- integração com o engine -----------------------------

def test_slug_maps_to_anti_forense():
    from telador import evidence as ev
    slug = ev._source_slug_from_name("Alternate Data Streams (ADS)")
    assert slug == "anti_forense"


def test_feeds_cluster_engine():
    from telador import evidence as ev
    findings = [{
        "name": "Alternate Data Streams (ADS)", "status": "suspicious",
        "items": [{
            "label": "Stream oculto (ADS): notas.txt:payload.exe",
            "detail": "x", "matched": "ads-executavel", "severity": "high",
            "timestamp": "", "confidence": 70,
        }],
    }]
    clusters = ev.build_clusters(ev.findings_to_evidences(findings))
    assert len(clusters) == 1
    assert clusters[0].verdict != "CONFIRMED"  # 1 fonte só não crava


def test_registered_in_scanner_list():
    assert ads.scan_alternate_data_streams in ads.ALL_ADS_SCANNERS
