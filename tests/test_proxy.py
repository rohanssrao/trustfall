from __future__ import annotations

import datetime as dt
import socket
import threading

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from trustfall.certs import CertificateFactory, describe_cert
from trustfall.logging import _BoundedSet
from trustfall.proxy import PayloadWriter, ProxyServer, State


def _der_for(factory: CertificateFactory, strategy: str, host: str) -> bytes:
    material = factory.material_for(strategy, sni=host, dest_ip="10.0.0.5")
    pems = x509.load_pem_x509_certificates(open(material.certfile, "rb").read())
    return pems[0].public_bytes(serialization.Encoding.DER)


def test_describe_cert_private_ca(tmp_path):
    factory = CertificateFactory(str(tmp_path))
    info = describe_cert(_der_for(factory, "private_ca_match", "cam.lan"))
    assert info["subject_cn"] == "cam.lan"
    assert info["issuer_cn"] == "Trustfall Ephemeral CA"
    assert info["self_signed"] is False
    assert info["expired"] is False
    assert "cam.lan" in info["sans"]


def test_describe_cert_expired(tmp_path):
    factory = CertificateFactory(str(tmp_path))
    info = describe_cert(_der_for(factory, "expired_match", "cam.lan"))
    assert info["expired"] is True
    assert info["self_signed"] is False  # chains to the ephemeral CA


def test_bounded_set_evicts_lru():
    s = _BoundedSet(maxsize=3)
    for k in ("a", "b", "c"):
        s.add(k)
    assert "a" in s  # touch 'a' so it's most-recently-used
    s.add("d")        # evicts least-recently-used, which is now 'b'
    assert "b" not in s
    assert "a" in s and "c" in s and "d" in s


def test_concurrent_cert_generation_is_consistent(tmp_path):
    # Two threads racing on the same (strategy, host) must both return loadable,
    # complete cert/key pairs (no torn reads, no duplicate-write corruption).
    factory = CertificateFactory(str(tmp_path))
    results: list = []
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()
        m = factory.material_for("private_ca_match", sni="race.lan", dest_ip="10.0.0.5")
        # Loading proves both files are complete and mutually valid.
        x509.load_pem_x509_certificates(open(m.certfile, "rb").read())
        serialization.load_pem_private_key(open(m.keyfile, "rb").read(), password=None)
        results.append(m.certfile)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 8
    assert len(set(results)) == 1  # all resolved to the same cached file


class _FakeTLS:
    """Stand-in for an ssl.SSLSocket exposing recv()/pending()/sendall()."""

    def __init__(self, chunks):
        self.chunks = list(chunks)

    def settimeout(self, _t):
        pass

    def recv(self, _n):
        return self.chunks.pop(0) if self.chunks else b""

    def pending(self):
        return sum(len(c) for c in self.chunks)

    def sendall(self, data):
        raise AssertionError("client side should not be written to in this test")


def test_drain_empties_tls_pending_buffer(tmp_path):
    # A single select wake-up must flush *all* buffered TLS records, not just one.
    proxy = ProxyServer(0, str(tmp_path), certs=None, state=State([], stop_on_success=True), log=None)
    received = []

    class Peer:
        def sendall(self, data):
            received.append(data)

    client = _FakeTLS([b"one", b"two", b"three"])
    cont = proxy._drain(client, client=client, upstream=Peer(), payloads=PayloadWriter(tmp_path, "x", {}, enabled=False))
    assert cont is True
    assert b"".join(received) == b"onetwothree"


def test_drain_reports_eof(tmp_path):
    proxy = ProxyServer(0, str(tmp_path), certs=None, state=State([], stop_on_success=True), log=None)
    c1, c2 = socket.socketpair()
    c1.close()  # peer hangs up -> recv returns b"" on c2
    assert proxy._drain(c2, client=c2, upstream=c2, payloads=PayloadWriter(tmp_path, "y", {}, enabled=False)) is False
    c2.close()


def test_state_remaining_counts_down():
    state = State(["self_signed_match", "private_ca_match", "expired_match"], stop_on_success=True)
    key = ("1.1.1.1", 443, "a.test")
    assert state.remaining(key) == 3  # untouched endpoint reports full set
    assert state.total() == 3
    state.next_strategy(key)
    assert state.remaining(key) == 2
    state.next_strategy(key)
    state.next_strategy(key)
    assert state.remaining(key) == 0
