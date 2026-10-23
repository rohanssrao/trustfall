"""Tests for the emudhra_compromised_ca cert strategy.

The October 2026 eMudhra incident left the "EM OV TLS CA - G3C" intermediate's
ECDSA P-384 key publicly known (its private scalar is tiny, so anyone can mint
certificates under it). These tests prove that trustfall's forged leaves

- really chain to the compromised intermediate and are signed by its key,
- validate against the *real* roots that anchored it in public trust stores,
  via both cross-sign paths (emSign ECC Root CA - G3, and the old Comodo
  "AAA Certificate Services" for legacy stores), and
- produce fully working, decryptable TLS and DTLS sessions for exactly the
  devices trustfall targets: stale trust stores, no revocation checking.

The system-store test is conditional: hosts whose bundle already dropped the
emSign root skip it. Any other failure here means the strategy is broken.
"""

from __future__ import annotations

import socket
import ssl
import threading
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from trustfall.certs import CertificateFactory, emudhra_chain

HOST = "device.example.com"
DEST = "10.0.0.5"
REQUEST = (b"POST /telemetry HTTP/1.1\r\nHost: " + HOST.encode() +
           b"\r\nContent-Type: application/json\r\n\r\n"
           b'{"token": "s3cr3t-device-token", "fw": "1.2.3"}')

# The real trust-store anchors of the compromised chain. emSign ECC Root CA - G3
# anchored the modern path; Comodo's AAA Certificate Services (dropped from
# current bundles, still present in legacy/IoT stores) anchors the old one.
EMSIGN_ECC_ROOT_G3_PEM = """-----BEGIN CERTIFICATE-----
MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG
EwJJTjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhyYSBUZWNo
bm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0g
RzMwHhcNMTgwMjE4MTgzMDAwWhcNNDMwMjE4MTgzMDAwWjBrMQswCQYDVQQGEwJJ
TjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhyYSBUZWNobm9s
b2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0gRzMw
djAQBgcqhkjOPQIBBgUrgQQAIgNiAAQjpQy4LRL1KPOxst3iAhKAnjlfSU2fySU0
WXTsuwYc58Byr+iuL+FBVIcUqEqy6HyC5ltqtdyzdc6LBtCGI79G1Y4PPwT01xyS
fvalY8L1X44uT6EYGQIrMgqCZH0Wk9GjQjBAMB0GA1UdDgQWBBR8XQKEE9TMipuB
zhccLikenEhjQjAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAKBggq
hkjOPQQDAwNpADBmAjEAvvNhzwIQHWSVB7gYboiFBS+DCBeQyh+KTOgNG3qxrdWB
CUfvO6wIBHxcmbHtRwfSAjEAnbpV/KlK6O3t5nYBQnvI+GDZjVGLVTv7jHvrZQnD
+JbNR6iC8hZVdyR+EhCVBCyj
-----END CERTIFICATE-----"""

AAA_CERT_SERVICES_PEM = """-----BEGIN CERTIFICATE-----
MIIEMjCCAxqgAwIBAgIBATANBgkqhkiG9w0BAQUFADB7MQswCQYDVQQGEwJHQjEb
MBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHDAdTYWxmb3JkMRow
GAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UEAwwYQUFBIENlcnRpZmlj
YXRlIFNlcnZpY2VzMB4XDTA0MDEwMTAwMDAwMFoXDTI4MTIzMTIzNTk1OVowezEL
MAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UE
BwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNVBAMM
GEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAL5AnfRu4ep2hxxNRUSOvkbIgwadwSr+GB+O5AL686tdUIoWMQua
BtDFcCLNSS1UY8y2bmhGC1Pqy0wkwLxyTurxFa70VJoSCsN6sjNg4tqJVfMiWPPe
3M/vg4aijJRPn2jymJBGhCfHdr/jzDUsi14HZGWCwEiwqJH5YZ92IFCokcdmtet4
YgNW8IoaE+oxox6gmf049vYnMlhvB/VruPsUK6+3qszWY19zjNoFmag4qMsXeDZR
rOme9Hg6jc8P2ULimAyrL58OAd7vn5lJ8S3frHRNG5i1R8XlKdH5kBjHYpy+g8cm
ez6KJcfA3Z3mNWgQIJ2P2N7Sw4ScDV7oL8kCAwEAAaOBwDCBvTAdBgNVHQ4EFgQU
oBEKIz6W8Qfs4q8p74Klf9AwpLQwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQF
MAMBAf8wewYDVR0fBHQwcjA4oDagNIYyaHR0cDovL2NybC5jb21vZG9jYS5jb20v
QUFBQ2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNqA0oDKGMGh0dHA6Ly9jcmwuY29t
b2RvLm5ldC9BQUFDZXJ0aWZpY2F0ZVNlcnZpY2VzLmNybDANBgkqhkiG9w0BAQUF
AAOCAQEACFb8AvCb6P+k+tZ7xkSAzk/ExfYAWMymtrwUSWgEdujm7l3sAg9g1o1Q
GE8mTgHj5rCl7r+8dFRBv/38ErjHT1r0iWAFf2C3BUrz9vHCv8S5dIa2LX1rzNLz
Rt0vxuBqw8M0Ayx9lt1awg6nCpnBBYurDC/zXDrPbDdVCYfeU0BsWO/8tqtlbgT2
G9w84FoVxp7Z8VlIMCFlA2zs6SFz7JsDoeA3raAVGI/6ugLOpyypEBMs1OUIJqsi
l2D4kF501KKaU73yqWjgom7C12yxow+ev+to51byrvLjKzg6CYG1a4XXvi3tPxq3
smPi9WIsgtRqAEFQ8TmDn5XpNpaYbg==
-----END CERTIFICATE-----"""


def _cn(thing) -> str | None:
    """Common name of an x509.Name or a whole Certificate (convenience)."""
    name = getattr(thing, "subject", thing)
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else None


@pytest.fixture(scope="module")
def factory(tmp_path_factory):
    return CertificateFactory(str(tmp_path_factory.mktemp("certs")))


def _material(factory):
    return factory.material_for("emudhra_compromised_ca", sni=HOST, dest_ip=DEST)


def _tls_session(material, client_ctx, server_hostname):
    """Realistic full TLS session: handshake, client sends a request, server ACKs.

    Returns dict with ok/echoed/server_received/peer/cipher, or client_error."""
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(material.certfile, material.keyfile)
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)
    out: dict = {}

    def serve():
        try:
            conn, _ = ls.accept()
            conn.settimeout(5)
            s = sctx.wrap_socket(conn, server_side=True)
            data = b""
            while b"\r\n\r\n" not in data or len(data) < len(REQUEST):
                chunk = s.recv(8192)
                if not chunk:
                    break
                data += chunk
            out["server_received"] = data
            s.sendall(b"ACK")
            s.close()
        except Exception as e:  # noqa: BLE001
            out["server_error"] = str(e)

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        cs = socket.create_connection(ls.getsockname(), timeout=5)
        w = client_ctx.wrap_socket(cs, server_hostname=server_hostname)
        w.sendall(REQUEST)
        echoed = b""
        while len(echoed) < 3:
            chunk = w.recv(8192)
            if not chunk:
                break
            echoed += chunk
        out["peer"] = w.getpeercert()
        out["cipher"] = w.cipher()
        w.close()
        out["ok"] = True
        out["echoed"] = echoed
    except Exception as e:  # noqa: BLE001
        out["client_error"] = str(e)
    finally:
        t.join(timeout=5)
        ls.close()
    return out


def _verifying(cadata: str) -> ssl.SSLContext:
    """A *correct* client that happens to trust an anchor of the compromised chain.

    This is the realistic target device: hostname-checked, chain-validated, but
    with a stale trust store and no revocation/distrust awareness."""
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.load_verify_locations(cadata=cadata)
    c.check_hostname = True
    return c


# --- the embedded material is the genuine compromised chain -------------------


def test_embedded_chain_is_the_genuine_compromised_one():
    key, issuer, cross = emudhra_chain()
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    assert key.curve.name == "secp384r1"
    # The compromise itself: a private scalar so small anyone can find it.
    assert key.private_numbers().private_value < 2**16
    # ...and it really is the key of the intermediate we chain to.
    assert key.public_key().public_numbers() == issuer.public_key().public_numbers()
    assert _cn(issuer) == "EM OV TLS CA - G3C"
    bc = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca and bc.path_length == 0
    # Alternate cross-certs of the same key for different root programs.
    assert {_cn(c.issuer) for c in cross} == {"emSign ECC Root CA - G3", "AAA Certificate Services"}
    for c in cross:
        if _cn(c) == "EM OV TLS CA - G3C":  # the Comodo cross-sign of the same key
            assert c.public_key().public_numbers() == issuer.public_key().public_numbers()


def test_forged_leaf_chains_to_the_compromised_ca(factory):
    m = _material(factory)
    certs = x509.load_pem_x509_certificates(Path(m.certfile).read_bytes())
    leaf, rest = certs[0], certs[1:]
    key, issuer, cross = emudhra_chain()
    assert _cn(leaf) == HOST
    assert _cn(leaf.issuer) == "EM OV TLS CA - G3C"
    # Leaf is signed by the compromised key itself (ECDSA/SHA-384) and carries
    # the SKI/AKI a real leaf under this CA would have.
    assert isinstance(leaf.signature_hash_algorithm, hashes.SHA384)
    issuer.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes,
                               ec.ECDSA(leaf.signature_hash_algorithm))
    ski = leaf.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    aki = leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    assert ski == x509.SubjectKeyIdentifier.from_public_key(leaf.public_key())
    assert aki == x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.public_key())
    # All three CA certs (both cross paths) ride along, emSign path first.
    assert [_cn(c) for c in rest[:2]] == ["EM OV TLS CA - G3C", "emSign Root TLS CA - G3"]
    assert _cn(rest[2]) == "EM OV TLS CA - G3C"  # the Comodo cross-sign, last
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert x509.DNSName(HOST) in san
    # The served key matches the leaf, and is a normal RSA key (realistic leaf).
    lk = serialization.load_pem_private_key(Path(m.keyfile).read_bytes(), password=None)
    assert isinstance(lk, rsa.RSAPrivateKey)
    assert lk.public_key().public_numbers() == leaf.public_key().public_numbers()


def test_legacy_variant_leads_with_the_comodo_cross(factory):
    # OpenSSL never backtracks across same-subject issuer alternates, so the
    # legacy strategy must present the Comodo cross-sign first for old stores.
    m = factory.material_for("emudhra_compromised_ca_legacy", sni=HOST, dest_ip=DEST)
    certs = x509.load_pem_x509_certificates(Path(m.certfile).read_bytes())
    key, issuer, cross = emudhra_chain()
    assert _cn(certs[1]) == "EM OV TLS CA - G3C"
    assert "AAA Certificate Services" in certs[1].issuer.rfc4514_string()


# --- realistic stale-trust-store clients accept and get decrypted --------------


def test_stale_trust_store_client_accepts_and_traffic_flows(factory):
    m = _material(factory)
    out = _tls_session(m, _verifying(EMSIGN_ECC_ROOT_G3_PEM), HOST)
    assert out.get("ok"), out.get("client_error") or out.get("server_error")
    assert out["echoed"] == b"ACK"
    assert out["server_received"] == REQUEST  # full plaintext visible on the wire owner
    assert ("DNS", HOST) in out["peer"]["subjectAltName"]
    assert out["cipher"]


def test_legacy_comodo_path_client_accepts(factory):
    # Old trust stores only carried the Comodo cross-sign of the same key; the
    # legacy variant exists precisely for them.
    m = factory.material_for("emudhra_compromised_ca_legacy", sni=HOST, dest_ip=DEST)
    out = _tls_session(m, _verifying(AAA_CERT_SERVICES_PEM), HOST)
    assert out.get("ok"), out.get("client_error") or out.get("server_error")
    assert out["echoed"] == b"ACK"


def test_rust_path_validator_accepts_both_anchor_paths(factory):
    pytest.importorskip("cryptography.x509.verification")
    from cryptography.x509.verification import PolicyBuilder, Store

    m = _material(factory)
    certs = x509.load_pem_x509_certificates(Path(m.certfile).read_bytes())
    leaf, intermediates = certs[0], list(certs[1:])
    lm = factory.material_for("emudhra_compromised_ca_legacy", sni=HOST, dest_ip=DEST)
    lcerts = x509.load_pem_x509_certificates(Path(lm.certfile).read_bytes())
    for root_pem, (l, ints) in ((EMSIGN_ECC_ROOT_G3_PEM, (leaf, intermediates)),
                                (AAA_CERT_SERVICES_PEM, (lcerts[0], list(lcerts[1:])))):
        store = Store([x509.load_pem_x509_certificate(root_pem.encode())])
        verifier = PolicyBuilder().store(store).build_client_verifier()
        chain = verifier.verify(l, ints)  # raises on any validation defect
        assert any(c.subject == l.subject for c in chain.chain)
        assert x509.DNSName(HOST) in chain.subjects


def test_client_trusting_an_unrelated_ca_rejects(factory):
    # A correct client whose store never contained the anchors must reject.
    m = _material(factory)
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.load_verify_locations(cadata=factory._ca_cert.public_bytes(serialization.Encoding.PEM).decode())
    c.check_hostname = True
    out = _tls_session(m, c, HOST)
    assert not out.get("ok"), "client trusting only the ephemeral CA must reject the emudhra chain"


def test_default_system_store_verdict_is_definitive(factory):
    """Exercise the real host trust store against the forged chain.

    Reality has three populations: root removed (reject: no issuer found),
    root distrust-marked e.g. via Mozilla certdata (reject: cert rejected), and
    genuinely stale stores (accept) — the device class trustfall reports as
    CRITICAL. Whichever host runs this, the verdict must be a clean verification
    decision, and a stale store must map to the CRITICAL finding."""
    paths = ssl.get_default_verify_paths()
    has_store = (paths.cafile and Path(paths.cafile).exists()) or \
                (paths.capath and Path(paths.capath).is_dir())
    if not has_store:
        pytest.skip("no system trust store")
    m = _material(factory)
    out = _tls_session(m, ssl.create_default_context(), HOST)
    if out.get("ok"):
        # Stale store: this host is itself an unpatched device, and trustfall's
        # summary must flag exactly that.
        from trustfall.cli import FINDING_LABELS
        assert "CRITICAL" in FINDING_LABELS["emudhra_compromised_ca"]
    else:
        err = out.get("client_error") or ""
        assert "CERTIFICATE_VERIFY_FAILED" in err, err or out.get("server_error")


# --- wiring: rotation, reporting, CLI ------------------------------------------


def test_strategy_is_wired_into_rotation_and_reporting(factory):
    from trustfall.cli import FINDING_LABELS, parse_args
    from trustfall.proxy import finding_for

    assert "emudhra_compromised_ca" in factory.available_strategies()
    assert factory.available_strategies("emudhra") == ["emudhra_compromised_ca", "emudhra_compromised_ca_legacy"]
    assert finding_for("emudhra_compromised_ca") == "trusts_compromised_public_ca"
    assert finding_for("emudhra_compromised_ca_legacy") == "trusts_compromised_public_ca"
    assert "emudhra_compromised_ca" in FINDING_LABELS
    assert "emudhra_compromised_ca_legacy" in FINDING_LABELS
    args = parse_args(["--strategy", "emudhra", "10.0.0.9"])
    assert args.strategy == "emudhra"


# --- end-to-end over the real DTLS MITM path ------------------------------------


class FakeLog:
    def __init__(self):
        self.events = []

    def emit(self, kind, **f):
        self.events.append((kind, f))


def _self_signed_pem():
    import datetime as dt
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
    from OpenSSL import SSL, crypto
    from trustfall.dtls import DatagramDTLS
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


def _verifying_dtls_client(server_addr, payload: bytes, ca_pem: str):
    """A CoAP/DTLS device that actually validates the server chain (stale store)."""
    import tempfile
    from OpenSSL import SSL
    from trustfall.dtls import DatagramDTLS
    ctx = SSL.Context(SSL.DTLS_METHOD)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem") as f:
        f.write(ca_pem)
        f.flush()
        ctx.load_verify_locations(cafile=f.name)
    seen: list[bool] = []

    def verify_cb(conn, x509_, errnum, errdepth, ok):
        seen.append(bool(ok))
        return ok

    ctx.set_verify(SSL.VERIFY_PEER, verify_cb)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect(server_addr)
    ep = DatagramDTLS(ctx, sock, server=False)
    assert ep.do_handshake(), "verifying DTLS client could not complete the handshake"
    ep.send(payload)
    echoed = b""
    deadline = time.time() + 5
    while time.time() < deadline and not echoed:
        got = ep.recv(0.5)
        if got is None:
            break
        echoed += got
    ep.close()
    return echoed, bool(seen) and all(seen)


def test_dtls_emudhra_mitm_intercepts_verifying_client(tmp_path):
    from trustfall.dtls import HAVE_PYOPENSSL, DtlsProxy
    from trustfall.proxy import State

    if not HAVE_PYOPENSSL:
        pytest.skip("pyOpenSSL not installed")
    ready = threading.Event()
    threading.Thread(target=_dtls_echo_upstream, args=(ready,), daemon=True).start()
    assert ready.wait(5)
    upstream_addr = ready.addr  # type: ignore[attr-defined]

    certs = CertificateFactory(str(tmp_path / "certs"))
    state = State(["emudhra_compromised_ca"], stop_on_success=True)
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
    echoed, verified_ok = _verifying_dtls_client(("127.0.0.1", proxy_port), payload,
                                                 EMSIGN_ECC_ROOT_G3_PEM)
    proxy.stop.set()
    time.sleep(0.3)

    assert verified_ok, "client-side chain verification must have passed (stale store)"
    assert echoed == payload.upper(), f"echo should round-trip through the MITM, got {echoed!r}"
    key = (upstream_addr[0], upstream_addr[1], None)
    assert state.summary()[key].success_strategy == "emudhra_compromised_ca"
    client_bin = tmp_path / "session" / "d0001" / "client.bin"
    assert client_bin.exists() and payload in client_bin.read_bytes(), \
        "decrypted DTLS payload must be captured"
    assert any(k == "TLS" and f.get("result") == "accepted" and f.get("strategy") == "emudhra_compromised_ca"
               for k, f in log.events), "expected an accepted DTLS interception event"
