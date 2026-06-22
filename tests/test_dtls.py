from __future__ import annotations

import datetime as dt
import socket
import threading
import time

import pytest

from trustfall.dtls import HAVE_PYOPENSSL

pytestmark = pytest.mark.skipif(not HAVE_PYOPENSSL, reason="pyOpenSSL not installed")

if HAVE_PYOPENSSL:
    from OpenSSL import SSL, crypto

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from trustfall.certs import CertificateFactory
from trustfall.dtls import DatagramDTLS, DtlsProxy
from trustfall.proxy import State


class FakeLog:
    def __init__(self):
        self.events = []

    def emit(self, kind, **f):
        self.events.append((kind, f))


def _self_signed_pem():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "upstream.local")])
    now = dt.datetime.now(dt.UTC)
    cert = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                              serialization.NoEncryption()))


def _dtls_echo_upstream(ready: threading.Event):
    """Minimal real DTLS server that echoes a client's datagrams, uppercased."""
    certpem, keypem = _self_signed_pem()
    ctx = SSL.Context(SSL.DTLS_METHOD)
    ctx.use_certificate(crypto.load_certificate(crypto.FILETYPE_PEM, certpem))
    ctx.use_privatekey(crypto.load_privatekey(crypto.FILETYPE_PEM, keypem))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    ready.addr = sock.getsockname()  # type: ignore[attr-defined]
    ready.set()
    _peeked, peer = sock.recvfrom(65535, socket.MSG_PEEK)
    sock.connect(peer)
    ep = DatagramDTLS(ctx, sock, server=True)
    if not ep.do_handshake():
        return
    deadline = time.time() + 8
    while time.time() < deadline:
        data = ep.recv(0.5)
        if data is None:
            break
        if data:
            ep.send(data.upper())


def _dtls_client(server_addr, payload: bytes):
    ctx = SSL.Context(SSL.DTLS_METHOD)
    ctx.set_verify(SSL.VERIFY_NONE, lambda *a: True)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect(server_addr)
    ep = DatagramDTLS(ctx, sock, server=False)
    assert ep.do_handshake(), "device could not complete DTLS handshake with the proxy"
    accepted = ep.peer_cert() is not None
    ep.send(payload)
    echoed = b""
    deadline = time.time() + 5
    while time.time() < deadline and not echoed:
        got = ep.recv(0.5)
        if got is None:
            break
        echoed += got
    ep.close()
    return echoed, accepted


def test_dtls_mitm_intercepts_and_captures(tmp_path):
    ready = threading.Event()
    threading.Thread(target=_dtls_echo_upstream, args=(ready,), daemon=True).start()
    assert ready.wait(5)
    upstream_addr = ready.addr  # type: ignore[attr-defined]

    certs = CertificateFactory(str(tmp_path / "certs"))
    state = State(["self_signed_match"], stop_on_success=True)
    log = FakeLog()
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    proxy_port = probe.getsockname()[1]
    probe.close()
    proxy = DtlsProxy(proxy_port, certs, state, log, str(tmp_path / "session"),
                      bind_host="127.0.0.1", default_upstream=upstream_addr, idle_timeout=2.0)
    threading.Thread(target=proxy.serve, daemon=True).start()
    time.sleep(0.5)

    payload = b"\x40\x01\x12\x34\x75status token=secret-jwt"
    echoed, accepted = _dtls_client(("127.0.0.1", proxy_port), payload)
    proxy.stop.set()
    time.sleep(0.3)

    assert accepted, "device should be presented a (forged) cert"
    assert echoed == payload.upper(), f"echo should round-trip through the MITM, got {echoed!r}"
    assert any(k == "TLS" and f.get("result") == "accepted" and f.get("proto") == "dtls"
               for k, f in log.events), "expected an accepted DTLS interception event"
    client_bin = tmp_path / "session" / "d0001" / "client.bin"
    assert client_bin.exists() and payload in client_bin.read_bytes(), "decrypted DTLS payload must be captured"
    key = (upstream_addr[0], upstream_addr[1], None)
    assert state.summary()[key].success_strategy == "self_signed_match"
