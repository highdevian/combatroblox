"""
Testes da atualização remota de assinaturas (sigupdate.py).

Sobe um servidor HTTP local servindo conteúdo controlado e aponta o
update pra ele — assim testa o caminho de sucesso E os de falha sem
depender da internet.
"""

import json
import os
import sys
import threading
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from telador import sigupdate  # noqa: E402
# --------------------------- mini servidor de teste ---------------------------

def _serve(body: bytes, content_type="application/json"):
    """Sobe um servidor que devolve `body` em qualquer GET. Retorna (url, stop)."""
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    url = f"http://127.0.0.1:{srv.server_address[1]}/signatures.json"
    return url, srv.shutdown


VALID_SIGS = {
    "version": "2026.test.01",
    "executor_keywords": {"testexec": "high", "another": "medium"},
    "suspicious_domains": {"testexec.gg": "high"},
}


def test_update_success_saves_file():
    body = json.dumps(VALID_SIGS).encode("utf-8")
    url, stop = _serve(body)
    try:
        with tempfile.TemporaryDirectory() as d:
            dest = os.path.join(d, "signatures.json")
            ok, msg = sigupdate.update_signatures(url=url, dest=dest)
            assert ok, msg
            assert os.path.isfile(dest)
            with open(dest, encoding="utf-8") as fh:
                saved = json.load(fh)
            assert saved["version"] == "2026.test.01"
            assert saved["executor_keywords"]["testexec"] == "high"
            assert "2026.test.01" in msg
    finally:
        stop()


def test_update_creates_destination_directory():
    body = json.dumps(VALID_SIGS).encode("utf-8")
    url, stop = _serve(body)
    try:
        with tempfile.TemporaryDirectory() as d:
            dest = os.path.join(d, "Telador", "signatures.json")
            ok, msg = sigupdate.update_signatures(url=url, dest=dest)
            assert ok, msg
            assert os.path.isfile(dest)
    finally:
        stop()


def test_update_rejects_non_json():
    url, stop = _serve(b"<html>not json</html>", content_type="text/html")
    try:
        with tempfile.TemporaryDirectory() as d:
            dest = os.path.join(d, "signatures.json")
            ok, msg = sigupdate.update_signatures(url=url, dest=dest)
            assert not ok
            assert "json" in msg.lower()
            # arquivo bom NÃO deve ter sido criado
            assert not os.path.isfile(dest)
    finally:
        stop()


def test_update_rejects_json_without_signature_sections():
    body = json.dumps({"foo": "bar", "version": "x"}).encode("utf-8")
    url, stop = _serve(body)
    try:
        with tempfile.TemporaryDirectory() as d:
            dest = os.path.join(d, "signatures.json")
            ok, msg = sigupdate.update_signatures(url=url, dest=dest)
            assert not ok
            assert "assinatura" in msg.lower()
            assert not os.path.isfile(dest)
    finally:
        stop()


def test_update_does_not_clobber_on_bad_download():
    """Se o download falha, a base local boa NÃO pode ser apagada."""
    with tempfile.TemporaryDirectory() as d:
        dest = os.path.join(d, "signatures.json")
        # base local boa pré-existente
        good = {"version": "local-good", "executor_keywords": {"keep": "high"}}
        with open(dest, "w", encoding="utf-8") as fh:
            json.dump(good, fh)

        # download que devolve lixo
        url, stop = _serve(b"garbage", content_type="text/plain")
        try:
            ok, _ = sigupdate.update_signatures(url=url, dest=dest)
            assert not ok
            # arquivo local intacto
            with open(dest, encoding="utf-8") as fh:
                still = json.load(fh)
            assert still["version"] == "local-good"
        finally:
            stop()


def test_update_network_failure_graceful():
    # porta provavelmente fechada → erro de conexão, sem exceção
    ok, msg = sigupdate.update_signatures(
        url="http://127.0.0.1:1/signatures.json", dest=None, timeout=2
    )
    assert ok is False
    assert isinstance(msg, str) and msg


def test_validator_accepts_real_repo_file():
    """O signatures.dist.json comitado no repo deve passar no validador."""
    repo_sig = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "signatures.dist.json",
    )
    if not os.path.isfile(repo_sig):
        return  # ok se não existir no ambiente de teste
    with open(repo_sig, encoding="utf-8") as fh:
        data = json.load(fh)
    assert sigupdate._looks_like_valid_signatures(data)
    assert isinstance(data.get("version"), str)
