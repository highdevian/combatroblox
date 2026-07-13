"""
Testes v3.51.0 — clipboard_history_scanner.scan_clipboard_history
"""

import os
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _write_utf16(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    # Prefixo lixo + payload UTF-16 LE (simula blob proprietário)
    blob = b"\x00\x01\x02\x03" + text.encode("utf-16-le") + b"\x00\x00"
    with open(path, "wb") as fh:
        fh.write(blob)


class TestExtractStrings:
    def test_utf16_run(self):
        import clipboard_history_scanner as ch
        blob = b"\xff\xfe" + "iex (irm https://krnl.cat/get)".encode("utf-16-le")
        strs = ch._extract_strings(blob)
        assert any("krnl.cat" in s.lower() for s in strs)

    def test_utf8_run(self):
        import clipboard_history_scanner as ch
        blob = b"xxxx iex (irm https://solara.example/x) yyyy"
        strs = ch._extract_strings(blob)
        assert any("solara" in s.lower() or "iex" in s.lower() for s in strs)


class TestClassify:
    def test_iex_irm_high(self):
        import clipboard_history_scanner as ch
        m, sev = ch._classify("iex (irm https://krnl.cat/get)")
        assert m is not None
        assert sev in ("high", "medium", "critical")

    def test_benign_text_clean(self):
        import clipboard_history_scanner as ch
        m, _ = ch._classify("https://google.com/search?q=roblox")
        assert m is None

    def test_signature_list_ignored(self):
        import clipboard_history_scanner as ch
        # Lista de keywords = wordlist, não invocação
        m, _ = ch._classify("solara|xeno|wave|krnl|fluxus|oxygen")
        assert m is None

    def test_telador_meta_ignored(self):
        import clipboard_history_scanner as ch
        m, _ = ch._classify("telador scan_clipboard changelog combatroblox")
        assert m is None


class TestScanDisk:
    def test_historydata_hit(self):
        import clipboard_history_scanner as ch
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "Clipboard")
            path = os.path.join(
                root, "HistoryData", "{GUID-TEST}", "payload.bin"
            )
            _write_utf16(path, "iex (irm https://krnl.cat/loader)")
            with patch.object(ch, "_clipboard_root", return_value=root), \
                 patch.object(ch, "_read_current_clipboard", return_value=None), \
                 patch.object(ch, "_history_enabled", return_value=True):
                r = ch.scan_clipboard_history()
        assert r["status"] == "suspicious"
        assert any("clipboard:" in (i.get("matched") or "") for i in r["items"])

    def test_pinned_label(self):
        import clipboard_history_scanner as ch
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "Clipboard")
            path = os.path.join(
                root, "Pinned", "{GUID-PIN}", "data.bin"
            )
            _write_utf16(path, "iex (irm https://krnl.cat/pin)")
            with patch.object(ch, "_clipboard_root", return_value=root), \
                 patch.object(ch, "_read_current_clipboard", return_value=None), \
                 patch.object(ch, "_history_enabled", return_value=True):
                r = ch.scan_clipboard_history()
        assert r["status"] == "suspicious"
        assert any("Pinned" in i.get("label", "") for i in r["items"])


class TestScanLive:
    def test_live_clipboard_hit(self):
        import clipboard_history_scanner as ch
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "Clipboard")
            os.makedirs(root, exist_ok=True)
            with patch.object(ch, "_clipboard_root", return_value=root), \
                 patch.object(
                     ch, "_read_current_clipboard",
                     return_value="iex (irm https://krnl.cat/now)",
                 ), \
                 patch.object(ch, "_history_enabled", return_value=True):
                r = ch.scan_clipboard_history()
        assert r["status"] == "suspicious"
        assert any("clipboard-live:" in (i.get("matched") or "") for i in r["items"])

    def test_clean_when_empty(self):
        import clipboard_history_scanner as ch
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "Clipboard")
            os.makedirs(root, exist_ok=True)
            with patch.object(ch, "_clipboard_root", return_value=root), \
                 patch.object(ch, "_read_current_clipboard", return_value=None), \
                 patch.object(ch, "_history_enabled", return_value=True):
                r = ch.scan_clipboard_history()
        assert r["status"] == "clean"
        assert r["items"] == []


class TestHistoryOff:
    def test_meta_when_disabled(self):
        import clipboard_history_scanner as ch
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "Clipboard")
            os.makedirs(root, exist_ok=True)
            with patch.object(ch, "_clipboard_root", return_value=root), \
                 patch.object(ch, "_read_current_clipboard", return_value=None), \
                 patch.object(ch, "_history_enabled", return_value=False):
                r = ch.scan_clipboard_history()
        # meta_only não conta como suspicious
        assert r["status"] == "clean"
        metas = [i for i in r["items"] if i.get("meta_only")]
        assert any("desativ" in i["label"].lower() for i in metas)


class TestChain:
    def test_registry_and_count(self):
        import scanner_registry
        import version
        import telador

        reg = scanner_registry.build_registry()
        names = {m.fn_name for m in reg}
        assert "scan_clipboard_history" in names
        assert version.SCANNER_COUNT == 113
        assert version.VERSION == "3.51.0"
        chain = telador.assemble_scanners(
            skip_forensics=False, skip_antievasion=False,
            skip_persistence=False, skip_live=False,
            skip_history=False, skip_peripherals=False,
        )
        assert len(chain) == version.SCANNER_COUNT
        assert any(fn.__name__ == "scan_clipboard_history" for fn in chain)

    def test_evidence_slug(self):
        from evidence import _source_slug_from_name
        assert _source_slug_from_name("Clipboard History") == "clipboard_history"
        assert _source_slug_from_name("[Clipboard/atual] iex") == "clipboard_history"
