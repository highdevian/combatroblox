"""Testes do canal de debug (--verbose) e da resolução de ferramentas do
Windows por caminho absoluto (anti PATH/cwd-hijack)."""

import io
import os
import sys
import contextlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from telador import database  # noqa: E402
from telador import debug  # noqa: E402
import pytest  # noqa: E402
from telador import cli as telador  # noqa: E402
from telador import win_tools  # noqa: E402
def _reset_debug():
    debug._ENABLED = False


def test_debug_is_noop_when_disabled():
    _reset_debug()
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        debug.dbg("não deveria aparecer", ValueError("x"))
    assert buf.getvalue() == ""
    assert debug.is_enabled() is False


def test_debug_logs_when_enabled():
    _reset_debug()
    debug.enable()
    try:
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            debug.dbg("contexto", ValueError("boom"))
        out = buf.getvalue()
        assert "contexto" in out
        assert "ValueError" in out and "boom" in out
    finally:
        _reset_debug()


def test_win_tools_tool_resolves_or_falls_back():
    # No Windows resolve pro System32 absoluto; fora do Windows cai no nome puro.
    r = win_tools.tool("reg.exe")
    assert r == "reg.exe" or (os.path.isabs(r) and r.lower().endswith("reg.exe"))


def test_win_tools_unknown_falls_back_to_bare_name():
    # Ferramenta inexistente nunca vira caminho absoluto quebrado — volta o nome.
    assert win_tools.tool("ferramenta_que_nao_existe_zzz.exe") == "ferramenta_que_nao_existe_zzz.exe"


def test_win_tools_powershell_path():
    p = win_tools.powershell()
    assert p == "powershell" or p.lower().endswith("powershell.exe")


def test_signatures_path_prefers_appdata_when_no_sidecar(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "_sidecar_signatures_path", lambda: str(tmp_path / "missing.json"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "LocalAppData"))
    expected = tmp_path / "LocalAppData" / "Telador" / "signatures.json"
    assert database.signatures_path() == str(expected)


def test_cli_rejects_invalid_thread_count(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["telador.py", "--threads", "0", "--update-sigs"])
    err = io.StringIO()
    with contextlib.redirect_stderr(err), pytest.raises(SystemExit) as exc:
        telador.main()
    assert exc.value.code == 2
    assert "--threads precisa estar entre 1 e 32" in err.getvalue()
