from __future__ import annotations

import socket
import ssl
import threading

import pytest
from cryptography.hazmat.primitives import serialization

from trustfall.certs import CertificateFactory

HOST = "device.example.com"
DEST = "10.0.0.5"

# A correct client (trusts our CA, checks hostname/validity/EKU/path) must reject
# these — each isolates one defect that real validation catches.
REJECT_BY_CORRECT = [
    "private_ca_wrong_host", "wildcard_mismatch", "partial_wildcard", "null_byte_cn",
    "expired_match", "not_yet_valid", "bad_eku", "non_ca_issuer",
]
# A client using the system trust store (not trusting our CA) must reject these.
REJECT_BY_DEFAULT_TRUST = ["self_signed_match", "private_ca_match"]
# Rejected only when the client enforces a crypto security level.
WEAK_CRYPTO = ["weak_key", "weak_sig_sha1", "weak_sig_md5"]


@pytest.fixture(scope="module")
def factory(tmp_path_factory):
    return CertificateFactory(str(tmp_path_factory.mktemp("certs")))


def _handshake(material, client_ctx, server_hostname):
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if material.min_version:
        sctx.minimum_version = getattr(ssl.TLSVersion, material.min_version)
    if material.max_version:
        sctx.maximum_version = getattr(ssl.TLSVersion, material.max_version)
    if material.ciphers:
        sctx.set_ciphers(material.ciphers)
    if not material.no_cert:
        sctx.load_cert_chain(material.certfile, material.keyfile)
    ls = socket.socket(); ls.bind(("127.0.0.1", 0)); ls.listen(1)
    serr: dict = {}

    def serve():
        try:
            conn, _ = ls.accept()
            s = sctx.wrap_socket(conn, server_side=True); s.close()
        except Exception as e:  # noqa: BLE001
            serr["e"] = e

    t = threading.Thread(target=serve, daemon=True); t.start()
    ok, err, cipher, peer = False, None, None, None
    try:
        cs = socket.create_connection(ls.getsockname(), timeout=5)
        w = client_ctx.wrap_socket(cs, server_hostname=server_hostname)
        ok, cipher, peer = True, w.cipher(), w.getpeercert(binary_form=True)
        w.close()
    except Exception as e:  # noqa: BLE001
        err = str(e)
    finally:
        t.join(timeout=5); ls.close()
    return ok, err, cipher, peer


def _permissive(ciphers=None):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    if ciphers:
        c.set_ciphers(ciphers)
    return c


def _verifying(factory, seclevel=None):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.load_verify_locations(cadata=factory._ca_cert.public_bytes(serialization.Encoding.PEM).decode())
    c.check_hostname = True
    if seclevel is not None:
        c.set_ciphers(f"DEFAULT:@SECLEVEL={seclevel}")
    return c


def test_every_strategy_yields_a_usable_handshake(factory):
    for s in factory.available_strategies():
        if s == "public_wrong_host":
            continue
        m = factory.material_for(s, HOST, DEST)
        ok, err, cipher, peer = _handshake(m, _permissive(m.ciphers), HOST)
        assert ok, f"{s}: permissive handshake failed: {err}"


def test_correct_client_rejects_each_defect(factory):
    avail = set(factory.available_strategies())
    for s in REJECT_BY_CORRECT:
        if s not in avail:
            continue
        m = factory.material_for(s, HOST, DEST)
        ok, err, _, _ = _handshake(m, _verifying(factory), HOST)
        assert not ok, f"{s}: a correct (CA-trusting, hostname-checking) client should reject it"


def test_default_trust_rejects_untrusted_chains(factory):
    for s in REJECT_BY_DEFAULT_TRUST:
        m = factory.material_for(s, HOST, DEST)
        ok, err, _, _ = _handshake(m, ssl.create_default_context(), HOST)
        assert not ok, f"{s}: a default-trust client should reject it"


def test_weak_crypto_rejected_at_seclevel2(factory):
    try:
        client = _verifying(factory, seclevel=2)
    except ssl.SSLError:
        pytest.skip("this TLS build doesn't support @SECLEVEL syntax")
    avail = set(factory.available_strategies())
    for s in WEAK_CRYPTO:
        if s not in avail:
            continue
        m = factory.material_for(s, HOST, DEST)
        ok, err, _, _ = _handshake(m, _verifying(factory, seclevel=2), HOST)
        assert not ok, f"{s}: should be rejected at SECLEVEL=2"


def test_anonymous_cipher_needs_no_certificate(factory):
    if "anon_cipher" not in factory.available_strategies():
        pytest.skip("aNULL not supported by this build")
    m = factory.material_for("anon_cipher", HOST, DEST)
    assert m.no_cert
    ok, err, cipher, peer = _handshake(m, _permissive(m.ciphers), HOST)
    assert ok, f"anon handshake failed: {err}"
    assert not peer, "anonymous cipher must present no certificate"


def test_null_cipher_is_cleartext(factory):
    if "null_cipher" not in factory.available_strategies():
        pytest.skip("eNULL not supported by this build")
    m = factory.material_for("null_cipher", HOST, DEST)
    ok, err, cipher, _ = _handshake(m, _permissive(m.ciphers), HOST)
    assert ok, f"null-cipher handshake failed: {err}"
    assert cipher and "NULL" in cipher[0].upper()
