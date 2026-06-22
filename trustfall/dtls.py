from __future__ import annotations

import socket
import subprocess
import threading
import time
from pathlib import Path
from queue import Empty, Queue

try:
    from OpenSSL import SSL
    HAVE_PYOPENSSL = True
except ImportError:  # pyOpenSSL is optional; DTLS interception degrades to "detected only"
    HAVE_PYOPENSSL = False

from .certs import CertificateFactory, describe_cert
from .coap import parse_coap
from .proxy import Attempt, PayloadWriter, finding_for
from .scan import scan as scan_secrets

# Original destination of a REDIRECT'd UDP flow is recovered from conntrack:
# unlike TCP there's no SO_ORIGINAL_DST, and IP_RECVORIGDSTADDR reflects the
# post-DNAT local address for plain REDIRECT (only TPROXY preserves the original).
CONNTRACK = "/proc/net/nf_conntrack"
BUF = 65535
HANDSHAKE_TIMEOUT = 8.0


def _conntrack_lines() -> list[str]:
    """Conntrack table as text: prefer procfs, fall back to the `conntrack` CLI."""
    try:
        with open(CONNTRACK) as f:
            return f.read().splitlines()
    except OSError:
        pass
    try:
        out = subprocess.run(["conntrack", "-L", "-p", "udp"], capture_output=True, text=True, timeout=2)
        return out.stdout.splitlines()
    except (FileNotFoundError, subprocess.SubprocessError):
        return []


def origdst_via_conntrack(client_ip: str, client_port: int, dport: int = 5684) -> tuple[str, int] | None:
    """Look up the pre-DNAT destination of a redirected UDP flow in conntrack."""
    for line in _conntrack_lines():
        if "udp" not in line:
            continue
        src = dst = sport = sp = None
        for tok in line.split():
            if tok.startswith("src=") and src is None:
                src = tok[4:]
            elif tok.startswith("dst=") and dst is None:
                dst = tok[4:]
            elif tok.startswith("sport=") and sport is None:
                sport = tok[6:]
            elif tok.startswith("dport=") and sp is None:
                sp = tok[6:]
        if src == client_ip and sport == str(client_port) and sp == str(dport):
            try:
                return dst, int(sp)
            except (TypeError, ValueError):
                return None
    return None


class DatagramDTLS:
    """A DTLS endpoint over a *connected* UDP socket, driven via memory BIOs.

    pyOpenSSL's socket-backed Connection mishandles datagram framing/timeouts, so
    we shuttle records between a memory BIO and the socket ourselves (the approach
    that actually works). Used for the upstream (real-server) leg and in tests.
    """

    def __init__(self, ctx, sock: socket.socket, server: bool):
        self.sock = sock
        self.conn = SSL.Connection(ctx, None)
        (self.conn.set_accept_state if server else self.conn.set_connect_state)()

    def _flush(self):
        while True:
            try:
                out = self.conn.bio_read(BUF)
            except SSL.WantReadError:
                break
            if not out:
                break
            self.sock.send(out)

    def _feed_one(self, timeout: float) -> bool:
        self.sock.settimeout(timeout)
        try:
            dg = self.sock.recv(BUF)
        except (socket.timeout, BlockingIOError):
            return False
        if not dg:
            return False
        self.conn.bio_write(dg)
        return True

    def do_handshake(self, timeout: float = HANDSHAKE_TIMEOUT) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                self.conn.do_handshake()
                self._flush()
                return True
            except SSL.WantReadError:
                self._flush()
                self._feed_one(0.5)
        return False

    def send(self, data: bytes):
        self.conn.send(data)
        self._flush()

    def recv(self, timeout: float = 0.2):
        """bytes if app data ready, b'' if nothing within timeout, None if closed/broken."""
        for attempt in (0, 1):
            try:
                return self.conn.recv(BUF)
            except SSL.WantReadError:
                if attempt == 0 and self._feed_one(timeout):
                    continue
                return b""
            except (SSL.ZeroReturnError, SSL.SysCallError, SSL.Error, OSError):
                return None
        return b""

    def peer_cert(self):
        return self.conn.get_peer_certificate()

    def close(self):
        try:
            self.conn.shutdown()
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass


class _Session:
    __slots__ = ("inq",)

    def __init__(self):
        self.inq: Queue = Queue()


class DtlsProxy:
    """Transparent DTLS MITM for CoAP/DTLS (UDP :5684).

    One shared UDP socket receives all redirected datagrams; conntrack reverses
    the DNAT on our replies (same pattern as the DNS responder). Each client peer
    gets a handler thread: a memory-BIO DTLS *server* presenting a forged cert
    (rotating the same strategies as TCP), and a DTLS *client* to the real server.
    Decrypted CoAP is captured/parsed like the TCP path.

    Only X.509-mode DTLS can be intercepted; PSK/raw-public-key devices can't be
    MITM'd without their key.
    """

    def __init__(self, listen_port: int, certs: CertificateFactory, state, log, session_dir: str,
                 bind_host: str = "0.0.0.0", no_payloads: bool = False,
                 default_upstream: tuple[str, int] | None = None, idle_timeout: float = 30.0):
        self.listen_port = listen_port
        self.certs = certs
        self.state = state
        self.log = log
        self.session_dir = session_dir
        self.bind_host = bind_host
        self.no_payloads = no_payloads
        self.default_upstream = default_upstream  # used when no cmsg origdst (testing/non-redirect)
        self.idle_timeout = idle_timeout
        self.stop = threading.Event()
        self.sock: socket.socket | None = None
        self._sessions: dict = {}
        self._lock = threading.Lock()
        self._counter = 0

    def serve(self):
        if not HAVE_PYOPENSSL:
            self.log.emit("WARN", msg="DTLS interception disabled (pyOpenSSL not installed)")
            return
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.bind_host, self.listen_port))
        s.settimeout(1.0)
        self.sock = s
        self.log.emit("INFO", msg="dtls proxy listening", port=self.listen_port)
        try:
            while not self.stop.is_set():
                try:
                    data, client = s.recvfrom(BUF)
                except socket.timeout:
                    continue
                except OSError:
                    break
                # default_upstream (explicit/non-redirect mode) wins; otherwise recover
                # the pre-DNAT destination from conntrack. Skip if it points back at us.
                orig = self.default_upstream or origdst_via_conntrack(client[0], client[1])
                if not orig or orig[1] == self.listen_port:
                    continue
                with self._lock:
                    sess = self._sessions.get(client)
                    if sess is None:
                        sess = _Session()
                        self._sessions[client] = sess
                        threading.Thread(target=self._handle, args=(client, orig, sess), daemon=True).start()
                sess.inq.put(data)
        finally:
            s.close()

    def _new_session_id(self) -> str:
        with self._lock:
            self._counter += 1
            return f"d{self._counter:04d}"

    def _reply(self, conn, client):
        """Flush pending outbound DTLS records from a memory-BIO conn to the client."""
        while True:
            try:
                out = conn.bio_read(BUF)
            except SSL.WantReadError:
                break
            if not out:
                break
            self.sock.sendto(out, client)

    def _handle(self, client, orig, sess):
        ip, port = orig
        key = (ip, port, None)
        strategy = self.state.next_strategy(key)
        try:
            if not strategy:
                return
            material = self.certs.material_for(strategy, None, ip)
            sctx = SSL.Context(SSL.DTLS_METHOD)
            sctx.use_certificate_chain_file(material.certfile)
            sctx.use_privatekey_file(material.keyfile)
            dc = SSL.Connection(sctx, None)
            dc.set_accept_state()
            if not self._handshake_downstream(dc, sess, client, key, strategy, ip, port):
                return
            self.state.record(key, Attempt(strategy, "accepted"))
            self.log.emit("TLS", proto="dtls", dest=f"{ip}:{port}", sni="none", strategy=strategy,
                          result="accepted", finding=finding_for(strategy))
            self._relay(dc, sess, client, orig)
        except Exception as e:  # noqa: BLE001
            self.log.emit("ERROR", msg="dtls handler failed", dest=f"{ip}:{port}", error=str(e))
        finally:
            with self._lock:
                self._sessions.pop(client, None)

    def _handshake_downstream(self, dc, sess, client, key, strategy, ip, port) -> bool:
        deadline = time.time() + HANDSHAKE_TIMEOUT
        while time.time() < deadline:
            try:
                dg = sess.inq.get(timeout=0.5)
            except Empty:
                continue
            dc.bio_write(dg)
            try:
                dc.do_handshake()
            except SSL.WantReadError:
                self._reply(dc, client)
                continue
            except SSL.Error as e:
                self.state.record(key, Attempt(strategy, "rejected", str(e)))
                self.log.emit("TLS", proto="dtls", dest=f"{ip}:{port}", sni="none", strategy=strategy,
                              result="rejected", error=str(e), remaining=self.state.remaining(key))
                return False
            self._reply(dc, client)
            return True
        return False

    def _connect_upstream(self, orig) -> DatagramDTLS:
        usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        usock.connect(orig)
        uctx = SSL.Context(SSL.DTLS_METHOD)
        uctx.set_verify(SSL.VERIFY_NONE, lambda *a: True)
        uc = DatagramDTLS(uctx, usock, server=False)
        if not uc.do_handshake():
            raise RuntimeError("upstream DTLS handshake timed out")
        return uc

    def _relay(self, dc, sess, client, orig):
        ip, port = orig
        try:
            uc = self._connect_upstream(orig)
        except Exception as e:  # noqa: BLE001
            self.log.emit("ERROR", msg="dtls upstream handshake failed", dest=f"{ip}:{port}", error=str(e))
            return
        self._capture_upstream_cert(uc, ip, port)
        session = self._new_session_id()
        meta = {"session": session, "dest_ip": ip, "dest_port": port, "proto": "dtls",
                "downstream_tls": True, "created": time.time()}
        payloads = PayloadWriter(Path(self.session_dir), session, meta, enabled=not self.no_payloads)
        self.log.emit("PAYLOAD", session=session, dest=f"{ip}:{port}", proto="dtls",
                      path=str(payloads.path) if payloads.enabled else "disabled")
        last = time.time()
        try:
            while not self.stop.is_set():
                moved = False
                # client -> upstream
                try:
                    dg = sess.inq.get_nowait()
                except Empty:
                    dg = None
                if dg is not None:
                    dc.bio_write(dg)
                    app = self._dc_recv(dc)
                    if app is None:
                        return
                    if app:
                        self._on_payload(payloads, "client", app, ip, port)
                        uc.send(app); moved = True
                    self._reply(dc, client)
                # upstream -> client
                app = uc.recv(0.2)
                if app is None:
                    return
                if app:
                    self._on_payload(payloads, "server", app, ip, port)
                    dc.send(app); self._reply(dc, client); moved = True
                if moved:
                    last = time.time()
                elif time.time() - last > self.idle_timeout:
                    return
        finally:
            self._scan_secrets(payloads, session, f"{ip}:{port}")
            payloads.close()
            uc.close()

    @staticmethod
    def _dc_recv(dc):
        """Decrypted bytes from the memory-BIO downstream conn; b'' if none, None if broken."""
        try:
            return dc.recv(BUF)
        except SSL.WantReadError:
            return b""
        except (SSL.ZeroReturnError, SSL.SysCallError, SSL.Error, OSError):
            return None

    def _on_payload(self, payloads: PayloadWriter, direction: str, data: bytes, ip: str, port: int):
        (payloads.write_client if direction == "client" else payloads.write_server)(data)
        msg = parse_coap(data)
        if msg:
            preview = msg.payload[:256].decode("utf-8", "replace") if msg.payload else None
            self.log.emit("COAP", dest=f"{ip}:{port}", summary=msg.summary(), method=msg.method,
                          uri=msg.uri_path or None, query=msg.uri_query or None, payload=preview)

    def _capture_upstream_cert(self, uc: DatagramDTLS, ip: str, port: int):
        try:
            from OpenSSL import crypto
            cert = uc.peer_cert()
            if cert is None:
                return
            info = describe_cert(crypto.dump_certificate(crypto.FILETYPE_ASN1, cert))
        except Exception:
            return
        self.log.emit("UPSTREAM_CERT", dest=f"{ip}:{port}", sni="none", subject=info["subject_cn"],
                      issuer=info["issuer_cn"], self_signed=info["self_signed"], expired=info["expired"],
                      not_after=info["not_after"], sans=",".join(info["sans"]) or None)

    def _scan_secrets(self, payloads: PayloadWriter, session: str, dest: str):
        hits = scan_secrets(bytes(payloads.client_buf), "client") + scan_secrets(bytes(payloads.server_buf), "server")
        for h in hits:
            self.log.emit("SECRET", session=session, dest=dest, proto="dtls", secret=h.kind,
                          direction=h.direction, value=h.masked)
