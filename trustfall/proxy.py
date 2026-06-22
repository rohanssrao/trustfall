from __future__ import annotations

import json
import re
import select
import socket
import ssl
import struct
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from .certs import CertificateFactory, describe_cert
from .netos import original_dst
from .scan import scan as scan_secrets
from .tlshello import looks_tls, parse_client_hello

BUFFER_SIZE = 65536
IDLE_TIMEOUT = 60
FIRST_APP_DATA_TIMEOUT = 3
MAX_SCAN_BYTES = 256 * 1024  # per-direction cap for in-memory secret scanning
STARTTLS_PORTS = {25, 587, 143, 110, 21, 5222}  # opportunistic-TLS protocols

# Equal-length replacements keep byte offsets/length-prefixes intact so we can
# strip an opportunistic-TLS capability without corrupting the protocol framing.
_STARTTLS_TOKENS = [
    (b"STARTTLS", b"XXXXXXXX"),  # SMTP/IMAP
    (b"starttls", b"xxxxxxxx"),  # XMPP <starttls/>
    (b"AUTH TLS", b"XXXXXXXX"),  # FTP
    (b"AUTH SSL", b"XXXXXXXX"),  # FTP
    (b"STLS", b"XXXX"),          # POP3
]


def strip_starttls_caps(data: bytes) -> tuple[bytes, bool]:
    """Blank out STARTTLS capability advertisements so the client stays in cleartext."""
    changed = False
    for token, repl in _STARTTLS_TOKENS:
        if token in data:
            data = data.replace(token, repl)
            changed = True
    return data, changed


class FailOpenTracker:
    """Flags devices that retry in cleartext after their TLS handshake is refused."""

    def __init__(self, window: float = 30.0):
        self.window = window
        self._rejects: dict[str, tuple[float, int, str | None]] = {}
        self._flagged: set[str] = set()
        self._lock = threading.Lock()

    def record_tls_reject(self, ip: str, port: int, sni: str | None):
        with self._lock:
            self._rejects[ip] = (time.time(), port, sni)

    def check_plaintext(self, ip: str, port: int) -> dict | None:
        with self._lock:
            rec = self._rejects.get(ip)
            if not rec or ip in self._flagged:
                return None
            ts, tls_port, sni = rec
            if time.time() - ts > self.window:
                return None
            self._flagged.add(ip)
            return {"tls_port": tls_port, "sni": sni, "cleartext_port": port}

# Maps the TLS alert a client sends when rejecting our forged cert to what that
# rejection implies about the client's validation logic.
_ALERT_MEANING = {
    "unknown_ca": "validates the chain to a trusted CA",
    "bad_certificate": "rejected certificate (generic)",
    "certificate_unknown": "rejected certificate (generic; possible pinning)",
    "certificate_expired": "checks the certificate validity period",
    "certificate_revoked": "performs revocation checking",
    "handshake_failure": "handshake failed (possible pinning or parameter mismatch)",
    "decrypt_error": "signature/handshake verification failed",
    "access_denied": "refused the connection (possible pinning)",
}
# Alerts that suggest the client pins rather than doing ordinary PKI validation.
PINNING_ALERTS = {"bad_certificate", "certificate_unknown", "handshake_failure", "access_denied"}
_ALERT_RE = re.compile(r"ALERT_([A-Z_]+)")

# Maps an accepted strategy to the validation defect it proves.
STRATEGY_FINDING = {
    "self_signed_match": "missing_chain_validation",
    "private_ca_match": "trusts_unknown_ca_or_missing_chain_validation",
    "private_ca_wrong_host": "accepted_unknown_ca_wrong_host",
    "cn_only_match": "accepts_cn_without_san",
    "wildcard_mismatch": "broken_wildcard_hostname_matching",
    "partial_wildcard": "accepts_partial_label_wildcard",
    "weak_key": "accepts_undersized_rsa_key",
    "public_wrong_host": "missing_hostname_validation",
    "expired_match": "missing_validity_period_check",
    "not_yet_valid": "accepts_not_yet_valid_cert",
    "weak_sig_sha1": "accepts_weak_sig_algorithm",
    "weak_sig_md5": "accepts_weak_sig_algorithm",
    "bad_eku": "accepts_cert_without_serverauth_eku",
    "non_ca_issuer": "accepts_non_ca_issuer",
    "null_byte_cn": "accepts_null_byte_in_cn",
    "anon_cipher": "accepts_anonymous_cipher_no_cert",
    "null_cipher": "accepts_null_cipher_cleartext",
}


def finding_for(strategy: str) -> str:
    return STRATEGY_FINDING.get(strategy, "certificate_validation_bypass")


def classify_tls_alert(error: str | None) -> str | None:
    """Extract the TLS alert name (e.g. 'unknown_ca') from an SSLError string."""
    if not error:
        return None
    m = _ALERT_RE.search(error)
    return m.group(1).lower() if m else None


@dataclass
class Attempt:
    strategy: str
    result: str
    error: str | None = None
    session: str | None = None
    alert: str | None = None


@dataclass
class EndpointState:
    strategies: deque[str]
    attempts: list[Attempt] = field(default_factory=list)
    success_strategy: str | None = None


class State:
    def __init__(self, strategies: list[str], stop_on_success: bool):
        self._base = strategies
        self._states: dict[tuple[str, int, str | None], EndpointState] = {}
        self._lock = threading.Lock()
        self.stop_on_success = stop_on_success

    def next_strategy(self, key) -> str | None:
        with self._lock:
            state = self._states.setdefault(key, EndpointState(deque(self._base)))
            if state.success_strategy and self.stop_on_success:
                return state.success_strategy
            if state.strategies:
                return state.strategies.popleft()
            return state.success_strategy

    def record(self, key, attempt: Attempt):
        with self._lock:
            state = self._states.setdefault(key, EndpointState(deque(self._base)))
            state.attempts.append(attempt)
            if attempt.result == "accepted":
                state.success_strategy = attempt.strategy

    def remaining(self, key) -> int:
        """Strategies not yet handed out for this endpoint (await natural reconnects)."""
        with self._lock:
            state = self._states.get(key)
            return len(state.strategies) if state else len(self._base)

    def total(self) -> int:
        return len(self._base)

    def summary(self):
        return self._states


class PayloadWriter:
    def __init__(self, root: Path, session: str, metadata: dict, enabled: bool):
        self.path = root / session
        self.enabled = enabled
        self.metadata = metadata
        self.files = []
        self.client_buf = bytearray()
        self.server_buf = bytearray()
        self.client_bin = self.server_bin = self.client_txt = self.server_txt = None
        if not enabled:
            return
        self.path.mkdir(parents=True, exist_ok=True)
        self._write_metadata()
        self.client_bin = open(self.path / "client.bin", "ab")
        self.server_bin = open(self.path / "server.bin", "ab")
        self.client_txt = open(self.path / "client.txt", "a", encoding="utf-8", errors="replace")
        self.server_txt = open(self.path / "server.txt", "a", encoding="utf-8", errors="replace")
        self.files = [self.client_bin, self.server_bin, self.client_txt, self.server_txt]

    @staticmethod
    def _accumulate(buf: bytearray, data: bytes):
        if len(buf) < MAX_SCAN_BYTES:
            buf.extend(data[: MAX_SCAN_BYTES - len(buf)])

    def _write_metadata(self):
        (self.path / "metadata.json").write_text(json.dumps(self.metadata, indent=2, sort_keys=True) + "\n")

    def update_metadata(self, **extra):
        if not self.enabled:
            return
        self.metadata.update(extra)
        self._write_metadata()

    def write_client(self, data: bytes):
        if not data:
            return
        self._accumulate(self.client_buf, data)
        if not self.enabled:
            return
        self.client_bin.write(data); self.client_bin.flush()
        self.client_txt.write(data.decode("utf-8", "replace")); self.client_txt.flush()

    def write_server(self, data: bytes):
        if not data:
            return
        self._accumulate(self.server_buf, data)
        if not self.enabled:
            return
        self.server_bin.write(data); self.server_bin.flush()
        self.server_txt.write(data.decode("utf-8", "replace")); self.server_txt.flush()

    def close(self):
        for f in self.files:
            try:
                f.close()
            except Exception:
                pass


class ProxyServer:
    def __init__(self, listen_port: int, session_dir: str, certs: CertificateFactory, state: State, log,
                 mode: str = "active", retest: str = "wait", no_payloads: bool = False,
                 on_exhausted: str = "passthrough", strip_starttls: bool = False, bind_host: str = "0.0.0.0",
                 keylog_path: str | None = None):
        self.listen_port = listen_port
        self.bind_host = bind_host
        self.keylog_path = keylog_path
        self.session_dir = Path(session_dir)
        self.certs = certs
        self.state = state
        self.log = log
        self.mode = mode
        self.retest = retest
        self.no_payloads = no_payloads
        self.on_exhausted = on_exhausted
        self.strip_starttls = strip_starttls
        self.failopen = FailOpenTracker()
        self.stop = threading.Event()
        self._counter = 0
        self._counter_lock = threading.Lock()
        self.session_dir.mkdir(parents=True, exist_ok=True)

    def serve(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.bind_host, self.listen_port))
        listener.listen(128)
        listener.settimeout(1)
        self.log.emit("INFO", msg="proxy listening", port=self.listen_port)
        try:
            while not self.stop.is_set():
                try:
                    client, addr = listener.accept()
                    client.settimeout(10)
                    threading.Thread(target=self.handle, args=(client, addr), daemon=True).start()
                except socket.timeout:
                    continue
                except OSError:
                    break
        finally:
            listener.close()

    def handle(self, client: socket.socket, addr):
        try:
            dst_ip, dst_port = original_dst(client)
            peek = client.recv(4096, socket.MSG_PEEK)
            if looks_tls(peek):
                hello = parse_client_hello(peek)
                self.log.emit("TLS_CLIENTHELLO", source="proxy", client=addr[0], dest=f"{dst_ip}:{dst_port}", sni=hello.sni or "none", alpn=",".join(hello.alpn) or None, versions=",".join(hello.offered_versions) or None, ja3=hello.ja3_hash)
                return self._handle_tls(client, dst_ip, dst_port, hello)
            self.log.emit("TCP", client=addr[0], dest=f"{dst_ip}:{dst_port}", proto="plaintext")
            hit = self.failopen.check_plaintext(dst_ip, dst_port)
            if hit:
                self.log.emit("FAIL_OPEN", dest=f"{dst_ip}:{dst_port}", tls_port=hit["tls_port"], sni=hit["sni"] or "none",
                              finding="tls_failure_cleartext_fallback",
                              msg="device retried in cleartext after TLS was refused")
            return self._forward(client, dst_ip, dst_port, downstream_tls=False, proto="tcp")
        except Exception as e:
            self.log.emit("ERROR", msg="proxy handler failed", error=str(e))
            close_quietly(client)

    def _handle_tls(self, client: socket.socket, dst_ip: str, dst_port: int, hello):
        if "bep-relay" in hello.alpn:
            self.log.emit("TLS", dest=f"{dst_ip}:{dst_port}", sni=hello.sni or "none", alpn="bep-relay", result="skipped", action="passthrough")
            return self._forward(client, dst_ip, dst_port, downstream_tls=False, proto="tls-passthrough")
        if self.mode == "passive":
            return self._forward(client, dst_ip, dst_port, downstream_tls=False, proto="tls-passive")
        return self._tls_attempt(client, dst_ip, dst_port, hello.sni)

    def _tls_attempt(self, client: socket.socket, dst_ip: str, dst_port: int, sni: str | None):
        key = (dst_ip, dst_port, sni)
        strategy = self.state.next_strategy(key)
        if not strategy:
            action = self.on_exhausted
            self.log.emit("TLS", dest=f"{dst_ip}:{dst_port}", sni=sni or "none", result="no_strategy_left", action=action)
            if action == "close":
                close_quietly(client)
                return
            return self._forward(client, dst_ip, dst_port, downstream_tls=False, proto="tls-passthrough")

        material = self.certs.material_for(strategy, sni, dst_ip)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if material.min_version:
            context.minimum_version = getattr(ssl.TLSVersion, material.min_version)
        if material.max_version:
            context.maximum_version = getattr(ssl.TLSVersion, material.max_version)
        if material.ciphers:
            context.set_ciphers(material.ciphers)
        if not material.no_cert:
            context.load_cert_chain(material.certfile, material.keyfile)
        self._apply_keylog(context)
        try:
            tls_client = context.wrap_socket(client, server_side=True)
        except Exception as e:
            alert = classify_tls_alert(str(e))
            self.state.record(key, Attempt(strategy, "rejected", str(e), alert=alert))
            self.failopen.record_tls_reject(dst_ip, dst_port, sni)
            self.log.emit("TLS", dest=f"{dst_ip}:{dst_port}", sni=sni or "none", strategy=strategy, result="rejected", error=str(e), alert=alert, alert_meaning=_ALERT_MEANING.get(alert), remaining=self.state.remaining(key))
            if self.retest in ("rst", "auto"):
                set_rst_on_close(client)
            close_quietly(client)
            return

        session = self._new_session_id()
        self.state.record(key, Attempt(strategy, "accepted", session=session))
        self.log.emit("TLS", dest=f"{dst_ip}:{dst_port}", sni=sni or "none", strategy=strategy, result="accepted", finding=self._finding(strategy), tls=tls_client.version(), cipher=(tls_client.cipher() or [None])[0], session=session)
        return self._forward(tls_client, dst_ip, dst_port, downstream_tls=True, sni=sni, proto="tls", session=session)

    def _forward(self, client: socket.socket, dst_ip: str, dst_port: int, downstream_tls: bool,
                 sni: str | None = None, proto: str = "tcp", session: str | None = None):
        first_client_data, upstream_sni = self._read_initial_app_data(client, sni) if downstream_tls else (b"", sni)
        session = session or self._new_session_id()
        metadata = {
            "session": session,
            "dest_ip": dst_ip,
            "dest_port": dst_port,
            "proto": proto,
            "downstream_tls": downstream_tls,
            "sni": sni,
            "upstream_sni": upstream_sni,
            "created": time.time(),
        }
        payloads = PayloadWriter(self.session_dir, session, metadata, enabled=not self.no_payloads)
        payloads.write_client(first_client_data)
        self.log.emit("PAYLOAD", session=session, dest=f"{dst_ip}:{dst_port}", proto=proto, path=str(payloads.path) if payloads.enabled else "disabled")

        upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        upstream.settimeout(10)
        try:
            upstream.connect((dst_ip, dst_port))
            if downstream_tls:
                context = ssl._create_unverified_context()
                self._apply_keylog(context)
                upstream = context.wrap_socket(upstream, server_hostname=upstream_sni or None)
                self.log.emit("UPSTREAM_TLS", dest=f"{dst_ip}:{dst_port}", sni=upstream_sni or "none", tls=upstream.version(), cipher=(upstream.cipher() or [None])[0])
                self._capture_upstream_cert(upstream, dst_ip, dst_port, upstream_sni, payloads)
            if first_client_data:
                upstream.sendall(first_client_data)
            strip = self.strip_starttls and not downstream_tls and dst_port in STARTTLS_PORTS
            self._pump(client, upstream, payloads, strip_starttls=strip)
        except Exception as e:
            self.log.emit("ERROR", msg="upstream connect/proxy failed", dest=f"{dst_ip}:{dst_port}", sni=upstream_sni or "none", error=str(e))
        finally:
            self._scan_secrets(payloads, session, f"{dst_ip}:{dst_port}", proto)
            payloads.close()
            close_quietly(client)
            close_quietly(upstream)

    def _capture_upstream_cert(self, upstream: ssl.SSLSocket, dst_ip: str, dst_port: int, sni: str | None, payloads: PayloadWriter):
        """Record the real server certificate for ground-truth comparison.

        We connect to upstream with verification disabled (we are the MITM), so the
        peer cert is whatever the device's real endpoint actually serves. Logging it
        lets an analyst see, e.g., that a device accepted our forged cert *and* that
        the genuine endpoint uses a public CA / valid hostname / non-expired cert.
        """
        try:
            der = upstream.getpeercert(binary_form=True)
            if not der:
                return
            info = describe_cert(der)
        except Exception as e:
            self.log.emit("WARN", msg="upstream cert describe failed", dest=f"{dst_ip}:{dst_port}", error=str(e))
            return
        payloads.update_metadata(upstream_cert=info)
        self.log.emit(
            "UPSTREAM_CERT",
            dest=f"{dst_ip}:{dst_port}",
            sni=sni or "none",
            subject=info["subject_cn"],
            issuer=info["issuer_cn"],
            self_signed=info["self_signed"],
            expired=info["expired"],
            not_after=info["not_after"],
            sans=",".join(info["sans"]) or None,
        )

    def _apply_keylog(self, context: ssl.SSLContext):
        """Write TLS secrets to an NSS key log so the pcap is decryptable in Wireshark.

        We terminate both TLS legs, so this records CLIENT_RANDOM entries for the
        client<->proxy handshake (captured on the wire) and the proxy<->upstream one.
        """
        if not self.keylog_path:
            return
        try:
            context.keylog_filename = self.keylog_path
        except (AttributeError, OSError):
            pass

    def _read_initial_app_data(self, client: socket.socket, sni: str | None) -> tuple[bytes, str | None]:
        old_timeout = client.gettimeout()
        try:
            client.settimeout(FIRST_APP_DATA_TIMEOUT)
            data = client.recv(BUFFER_SIZE)
            return data, sni or http_host(data)
        except socket.timeout:
            return b"", sni
        finally:
            try:
                client.settimeout(old_timeout)
            except Exception:
                pass

    def _pump(self, client: socket.socket, upstream: socket.socket, payloads: PayloadWriter, strip_starttls: bool = False):
        sockets = [client, upstream]
        stripped = [False]
        while True:
            readable, _, _ = select.select(sockets, [], [], IDLE_TIMEOUT)
            if not readable:
                return
            for sock in readable:
                if not self._drain(sock, client, upstream, payloads, strip_starttls, stripped):
                    return

    def _drain(self, sock: socket.socket, client: socket.socket, upstream: socket.socket, payloads: PayloadWriter,
               strip_starttls: bool = False, stripped: list | None = None) -> bool:
        """Read everything currently available on `sock` and forward it.

        Returns False when the connection should be torn down (EOF or fatal error).
        select() reports readiness on the raw fd, but OpenSSL can buffer additional
        decrypted records internally; we loop while sock.pending() to avoid stalling
        until the next wire packet. Partial/non-app-data records surface as
        SSLWantRead/SSLWantWrite, which just mean "wait for the next select".
        """
        while True:
            try:
                data = sock.recv(BUFFER_SIZE)
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                return True
            except (ssl.SSLError, OSError):
                return False
            if not data:
                return False
            try:
                if sock is client:
                    payloads.write_client(data)
                    upstream.sendall(data)
                else:
                    if strip_starttls:
                        data, changed = strip_starttls_caps(data)
                        if changed and stripped is not None and not stripped[0]:
                            stripped[0] = True
                            if self.log:
                                self.log.emit("STARTTLS_STRIP", finding="opportunistic_tls_strippable",
                                              msg="removed STARTTLS capability; session stays cleartext")
                    payloads.write_server(data)
                    client.sendall(data)
            except OSError:
                return False
            pending = getattr(sock, "pending", None)
            if pending is None or pending() == 0:
                return True

    def _new_session_id(self) -> str:
        with self._counter_lock:
            self._counter += 1
            return f"{self._counter:04d}"

    def _scan_secrets(self, payloads: PayloadWriter, session: str, dest: str, proto: str):
        hits = scan_secrets(bytes(payloads.client_buf), "client") + scan_secrets(bytes(payloads.server_buf), "server")
        if not hits:
            return
        records = [h.as_dict() for h in hits]
        payloads.update_metadata(secrets=records)
        if payloads.enabled:
            (payloads.path / "secrets.json").write_text(json.dumps(records, indent=2) + "\n")
        for h in hits:
            self.log.emit("SECRET", session=session, dest=dest, proto=proto, secret=h.kind, direction=h.direction, value=h.masked)

    def _finding(self, strategy: str) -> str:
        return finding_for(strategy)


def http_host(data: bytes) -> str | None:
    try:
        header = data.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1", "replace")
        for line in header.split("\r\n")[1:]:
            name, _, value = line.partition(":")
            if name.lower() == "host":
                host = value.strip()
                return None if host.startswith("[") else host.rsplit(":", 1)[0]
    except Exception:
        return None
    return None


def close_quietly(sock):
    try:
        sock.close()
    except Exception:
        pass


def set_rst_on_close(sock: socket.socket):
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except Exception:
        pass
