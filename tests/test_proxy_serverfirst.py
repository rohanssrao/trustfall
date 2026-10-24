"""Server-speaks-first TCP relay behavior (TUTK IOTC masters on tcp/443).

The IOTC master protocol has the server speak first: the camera connects and
waits for a binary banner. The proxy's old MSG_PEEK blocked for the full
socket timeout with no upstream connection, black-holing master registration.
These tests pin the contract: silent clients still get a relay (server-first),
client-speaks-first plaintext still relays without delay, and TLS ClientHellos
still route to the TLS interception path.
"""

from __future__ import annotations

import socket
import threading

from trustfall.proxy import ProxyServer, close_quietly
from trustfall.proxy import State


class _Log:
    def __init__(self):
        self.events = []

    def emit(self, kind, **kw):
        self.events.append((kind, kw))


def _pipe_pair():
    """(client, accepted) socket pair over a real loopback TCP connection."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    c = socket.socket()
    c.connect(listener.getsockname())
    s, _ = listener.accept()
    listener.close()
    return c, s


def _start_echo_upstream(first_bytes: bytes):
    """Upstream server that sends first_bytes immediately, then echoes."""
    up = socket.socket()
    up.bind(("127.0.0.1", 0))
    up.listen(1)
    port = up.getsockname()[1]

    def run():
        conn, _ = up.accept()
        try:
            if first_bytes:
                conn.sendall(first_bytes)
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                conn.sendall(b"ECHO:" + data)
        except OSError:
            pass
        finally:
            close_quietly(conn)
            up.close()

    threading.Thread(target=run, daemon=True).start()
    return port


def _make_proxy(tmp_path):
    log = _Log()
    proxy = ProxyServer(0, str(tmp_path), certs=None, state=State([], stop_on_success=True), log=log)
    return proxy, log


def test_server_first_tcp_is_relayed(tmp_path, monkeypatch):
    port = _start_echo_upstream(b"IOTC-BANNER")
    proxy, log = _make_proxy(tmp_path)
    monkeypatch.setattr("trustfall.proxy.original_dst", lambda sock: ("127.0.0.1", port))

    c, s = _pipe_pair()
    t = threading.Thread(target=proxy.handle, args=(s, ("127.0.0.1", 0)), daemon=True)
    t.start()

    # Client stays silent (server-speaks-first): the banner must still arrive
    # once the peek window expires and the upstream relay connects.
    c.settimeout(10)
    assert c.recv(64) == b"IOTC-BANNER"
    # Bidirectional after the banner.
    c.sendall(b"hello-master")
    assert c.recv(64) == b"ECHO:hello-master"
    c.close()
    t.join(timeout=5)
    tcp = [kw for kind, kw in log.events if kind == "TCP"]
    assert tcp and tcp[0]["proto"] == "server-first"


def test_plaintext_client_speaker_relayed_without_peek_wait(tmp_path, monkeypatch):
    port = _start_echo_upstream(b"")
    proxy, log = _make_proxy(tmp_path)
    monkeypatch.setattr("trustfall.proxy.original_dst", lambda sock: ("127.0.0.1", port))

    c, s = _pipe_pair()
    t = threading.Thread(target=proxy.handle, args=(s, ("127.0.0.1", 0)), daemon=True)
    t.start()

    c.settimeout(10)
    c.sendall(b"\x00\x01binary-iotc")  # non-TLS client-speaks-first
    assert c.recv(64) == b"ECHO:\x00\x01binary-iotc"
    c.close()
    t.join(timeout=5)
    tcp = [kw for kind, kw in log.events if kind == "TCP"]
    assert tcp and tcp[0]["proto"] == "plaintext"


def test_tls_client_hello_still_routes_to_tls_handler(tmp_path, monkeypatch):
    port = _start_echo_upstream(b"")
    proxy, log = _make_proxy(tmp_path)
    routed = []
    monkeypatch.setattr("trustfall.proxy.original_dst", lambda sock: ("127.0.0.1", port))

    def fake_handle_tls(client, dst_ip, dst_port, hello):
        routed.append((dst_ip, dst_port))
        close_quietly(client)

    monkeypatch.setattr(proxy, "_handle_tls", fake_handle_tls)

    c, s = _pipe_pair()
    t = threading.Thread(target=proxy.handle, args=(s, ("127.0.0.1", 0)), daemon=True)
    t.start()

    c.settimeout(10)
    # Minimal ClientHello-shaped prefix: record header + handshake type 0x01.
    c.sendall(b"\x16\x03\x01\x00\x05\x01\x00\x00\x00\x00")
    t.join(timeout=5)
    assert not t.is_alive()
    assert routed == [("127.0.0.1", port)]
    c.close()
