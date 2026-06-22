from __future__ import annotations

import datetime as dt
import ipaddress
import os
import re
import shutil
import subprocess
import tempfile
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

SAFE = re.compile(r"[^A-Za-z0-9_.-]+")

# Cipher selections for the weak-crypto strategies. aNULL = anonymous key exchange
# (no certificate at all) -> acceptance means we can MITM with no cert. eNULL =
# NULL encryption (still cert-authenticated) -> acceptance means cleartext on the
# wire. @SECLEVEL=0 is required for OpenSSL to even consider these.
ANON_CIPHERS = "aNULL:@SECLEVEL=0"
NULL_CIPHERS = "NULL:@SECLEVEL=0"


def _atomic_write(path: Path, data: bytes):
    """Write data to path atomically so concurrent readers never see a partial file."""
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def describe_cert(der: bytes) -> dict:
    """Summarize a DER-encoded certificate for ground-truth comparison/logging."""
    cert = x509.load_der_x509_certificate(der)

    def cn(name: x509.Name) -> str | None:
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else (name.rfc4514_string() or None)

    sans: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        for g in ext:
            if isinstance(g, x509.DNSName):
                sans.append(g.value)
            elif isinstance(g, x509.IPAddress):
                sans.append(str(g.value))
    except x509.ExtensionNotFound:
        pass

    now = dt.datetime.now(dt.UTC)
    nbf, naf = cert.not_valid_before_utc, cert.not_valid_after_utc
    return {
        "subject_cn": cn(cert.subject),
        "issuer_cn": cn(cert.issuer),
        "self_signed": cert.subject == cert.issuer,
        "not_before": nbf.isoformat(),
        "not_after": naf.isoformat(),
        "expired": now > naf or now < nbf,
        "sans": sans,
        "serial": format(cert.serial_number, "x"),
    }

@dataclass
class CertMaterial:
    strategy: str
    certfile: str
    keyfile: str
    hostname: str | None = None
    no_cert: bool = False                # anonymous (aNULL): present no certificate
    ciphers: str | None = None           # restrict the server cipher list (weak-crypto probes)
    min_version: str | None = None       # ssl.TLSVersion name, e.g. "TLSv1"
    max_version: str | None = None


@dataclass
class LeafSpec:
    """Describes one forged leaf certificate, isolating a single validation defect."""
    host: str
    self_signed: bool = False
    expired: bool = False
    not_yet_valid: bool = False          # notBefore in the future
    include_san: bool = True
    san_host: str | None = None          # SAN dNSName/iPAddress (defaults to host)
    key_size: int = 2048
    sig_hash: object = field(default_factory=lambda: hashes.SHA256())
    eku: list | None = None              # ExtendedKeyUsage OIDs; None = omit the extension
    non_ca_issuer: bool = False          # issue via an intermediate whose BasicConstraints is CA:FALSE
    cn: str | None = None                # override subject CN (e.g. embedded null byte)
    weak_md: str | None = None           # "sha1"/"md5": sign via the openssl CLI (cryptography won't)

class CertificateFactory:
    def __init__(self, workdir: str, operator_cert: str | None = None, operator_key: str | None = None):
        self.workdir = Path(workdir) / "certs"
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.operator_cert = operator_cert
        self.operator_key = operator_key
        self._locks: dict[tuple[str, str], threading.Lock] = defaultdict(threading.Lock)
        self._locks_guard = threading.Lock()
        self._ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Trustfall Ephemeral CA")])
        now = dt.datetime.now(dt.UTC)
        self._ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer).public_key(self._ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=7))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                         key_encipherment=False, content_commitment=False, data_encipherment=False,
                                         key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
            .sign(self._ca_key, hashes.SHA256())
        )
        self._intermediate: tuple | None = None  # lazily-built non-CA intermediate (cert, key)
        self._ca_files_paths: tuple | None = None  # lazily-written CA cert/key PEM for openssl
        # Some defects depend on what this OpenSSL build will emit/negotiate; probe
        # once so we only advertise strategies that actually work here. Modern
        # cryptography refuses SHA-1/MD5 signing, so weak-sig goes through the
        # openssl CLI when available.
        self.caps = {
            "weak_sig_sha1": self._probe(lambda: self._probe_openssl("sha1")),
            "weak_sig_md5": self._probe(lambda: self._probe_openssl("md5")),
            "null_byte_cn": self._probe(lambda: self._probe_build(cn="a\x00.example.com")),
            "anon_cipher": self._probe(lambda: self._probe_handshake(ANON_CIPHERS, with_cert=False)),
            "null_cipher": self._probe(lambda: self._probe_handshake(NULL_CIPHERS, with_cert=True)),
        }

    def available_strategies(self, requested: str = "all") -> list[str]:
        base = [
            "self_signed_match", "private_ca_match", "private_ca_wrong_host",
            "cn_only_match", "wildcard_mismatch", "weak_key", "expired_match",
            "not_yet_valid", "bad_eku", "non_ca_issuer", "partial_wildcard",
        ]
        for cap in ("weak_sig_sha1", "weak_sig_md5", "null_byte_cn", "anon_cipher", "null_cipher"):
            if self.caps.get(cap):
                base.append(cap)
        if self.operator_cert and self.operator_key:
            base.append("public_wrong_host")
        if requested == "all":
            return base
        mapping = {
            "self-signed": ["self_signed_match"],
            "private-ca": ["private_ca_match", "private_ca_wrong_host"],
            "cn-only": ["cn_only_match"],
            "wildcard": ["wildcard_mismatch", "partial_wildcard"],
            "weak-key": ["weak_key"],
            "weak-sig": [s for s in ("weak_sig_sha1", "weak_sig_md5") if s in base],
            "not-yet-valid": ["not_yet_valid"],
            "bad-eku": ["bad_eku"],
            "non-ca-issuer": ["non_ca_issuer"],
            "null-cn": [s for s in ("null_byte_cn",) if s in base],
            "weak-crypto": [s for s in ("anon_cipher", "null_cipher") if s in base],
            "public-wrong-host": ["public_wrong_host"] if self.operator_cert and self.operator_key else [],
            "expired": ["expired_match"],
        }
        return mapping.get(requested, [requested])

    def material_for(self, strategy: str, sni: str | None, dest_ip: str) -> CertMaterial:
        host = sni or dest_ip
        wrong = "wrong-host.trustfall.invalid"
        if strategy == "public_wrong_host":
            if not self.operator_cert or not self.operator_key:
                raise ValueError("public_wrong_host requires --cert and --key")
            return CertMaterial(strategy, self.operator_cert, self.operator_key, hostname=wrong)
        # Weak-crypto probes don't isolate a cert defect; they test whether the
        # device's stack will negotiate dangerous parameters.
        if strategy == "anon_cipher":
            # Anonymous key exchange: present NO certificate. Acceptance => full
            # MITM with no cert needed, independent of cert validation/pinning.
            # aNULL only exists pre-1.3, so pin the version.
            return CertMaterial(strategy, "", "", hostname=host, no_cert=True,
                                ciphers=ANON_CIPHERS, min_version="TLSv1_2", max_version="TLSv1_2")
        if strategy == "null_cipher":
            leaf = self._leaf("null_cipher", LeafSpec(host))
            return CertMaterial(strategy, leaf.certfile, leaf.keyfile, hostname=host,
                                ciphers=NULL_CIPHERS, max_version="TLSv1_2")
        # Each cert strategy isolates one validation defect. Host-validation,
        # validity, signature and extension variants chain to the ephemeral CA so
        # acceptance among CA-trusting devices points squarely at the named defect.
        specs = {
            "self_signed_match": LeafSpec(host, self_signed=True),
            "private_ca_match": LeafSpec(host),
            "private_ca_wrong_host": LeafSpec(wrong),
            "cn_only_match": LeafSpec(host, include_san=False),
            "wildcard_mismatch": LeafSpec(host, san_host="*." + host),
            "partial_wildcard": LeafSpec(host, san_host=self._partial_wildcard(host)),
            "weak_key": LeafSpec(host, key_size=1024),
            "expired_match": LeafSpec(host, expired=True),
            "not_yet_valid": LeafSpec(host, not_yet_valid=True),
            "weak_sig_sha1": LeafSpec(host, weak_md="sha1"),
            "weak_sig_md5": LeafSpec(host, weak_md="md5"),
            "bad_eku": LeafSpec(host, eku=[ExtendedKeyUsageOID.CLIENT_AUTH]),
            "non_ca_issuer": LeafSpec(host, non_ca_issuer=True),
            "null_byte_cn": LeafSpec(host, include_san=False, cn=f"{host}\x00.{wrong}"),
        }
        if strategy not in specs:
            raise ValueError(f"unknown strategy {strategy}")
        material = self._leaf(strategy, specs[strategy])
        if strategy in ("weak_key", "weak_sig_sha1", "weak_sig_md5"):
            # Lower our own server security level so OpenSSL will actually *present*
            # the deliberately-weak cert; whether the device accepts it is the finding.
            material.ciphers = "DEFAULT:@SECLEVEL=0"
        return material

    @staticmethod
    def _partial_wildcard(host: str) -> str:
        """Partial-label wildcard (RFC 6125 violation), e.g. telemetry.x.com -> t*.x.com."""
        try:
            ipaddress.ip_address(host)
            return host  # not applicable to IP literals
        except ValueError:
            pass
        if "." not in host:
            return host
        label, rest = host.split(".", 1)
        return f"{label[:1]}*.{rest}"

    def _lock_for(self, key: tuple[str, str]) -> threading.Lock:
        with self._locks_guard:
            return self._locks[key]

    def _leaf(self, strategy: str, spec: LeafSpec) -> CertMaterial:
        host = spec.host
        safe = SAFE.sub("_", host)[:80]
        certfile = self.workdir / f"{safe}_{strategy}.crt"
        keyfile = self.workdir / f"{safe}_{strategy}.key"
        if certfile.exists() and keyfile.exists():
            return CertMaterial(strategy, str(certfile), str(keyfile), hostname=host)

        with self._lock_for((strategy, safe)):
            # Double-checked: another thread may have generated this pair while we
            # waited for the lock.
            if certfile.exists() and keyfile.exists():
                return CertMaterial(strategy, str(certfile), str(keyfile), hostname=host)
            if spec.weak_md:
                return self._leaf_openssl(strategy, spec, certfile, keyfile)

            key = rsa.generate_private_key(public_exponent=65537, key_size=spec.key_size)
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, spec.cn or host)])
            now = dt.datetime.now(dt.UTC)
            if spec.expired:
                nbf = now - dt.timedelta(days=30); naf = now - dt.timedelta(days=1)
            elif spec.not_yet_valid:
                nbf = now + dt.timedelta(days=30); naf = now + dt.timedelta(days=60)
            else:
                nbf = now - dt.timedelta(hours=1); naf = now + dt.timedelta(days=30)
            # Pick the issuer: self-signed, a deliberately non-CA intermediate, or the CA.
            if spec.self_signed:
                issuer_key, issuer_name, extra_chain = key, subject, []
            elif spec.non_ca_issuer:
                inter_cert, inter_key = self._non_ca_intermediate()
                issuer_key, issuer_name, extra_chain = inter_key, inter_cert.subject, [inter_cert, self._ca_cert]
            else:
                issuer_key, issuer_name, extra_chain = self._ca_key, self._ca_cert.subject, [self._ca_cert]
            builder = (
                x509.CertificateBuilder()
                .subject_name(subject).issuer_name(issuer_name).public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(nbf).not_valid_after(naf)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            )
            if spec.eku is not None:
                builder = builder.add_extension(x509.ExtendedKeyUsage(spec.eku), critical=False)
            if spec.include_san:
                san_host = spec.san_host or host
                try:
                    san = x509.IPAddress(ipaddress.ip_address(san_host))
                except ValueError:
                    san = x509.DNSName(san_host)
                builder = builder.add_extension(x509.SubjectAlternativeName([san]), critical=False)
            cert = builder.sign(issuer_key, spec.sig_hash)
            chain = cert.public_bytes(serialization.Encoding.PEM)
            for extra in extra_chain:
                chain += extra.public_bytes(serialization.Encoding.PEM)
            # Write the key first: callers gate on certfile.exists(), so the cert
            # must only appear once its key is already on disk.
            _atomic_write(keyfile, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
            _atomic_write(certfile, chain)
            return CertMaterial(strategy, str(certfile), str(keyfile), hostname=host)

    def _non_ca_intermediate(self) -> tuple:
        """An intermediate signed by the ephemeral CA but with BasicConstraints CA:FALSE.

        Using it to issue a leaf produces a chain that only a *path-validation*-broken
        client accepts (a correct one rejects: the issuer isn't a CA)."""
        if self._intermediate is None:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Trustfall Non-CA Intermediate")])
            now = dt.datetime.now(dt.UTC)
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject).issuer_name(self._ca_cert.subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=7))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .sign(self._ca_key, hashes.SHA256())
            )
            self._intermediate = (cert, key)
        return self._intermediate

    # --- capability probes (run once at init) --------------------------------

    def _ca_files(self) -> tuple:
        """Write the in-memory ephemeral CA to PEM files (once) for openssl signing."""
        if self._ca_files_paths is None:
            cap = self.workdir / "_ca.crt"
            kap = self.workdir / "_ca.key"
            _atomic_write(cap, self._ca_cert.public_bytes(serialization.Encoding.PEM))
            _atomic_write(kap, self._ca_key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
            self._ca_files_paths = (str(cap), str(kap))
        return self._ca_files_paths

    def _leaf_openssl(self, strategy: str, spec: LeafSpec, certfile: Path, keyfile: Path) -> CertMaterial:
        """Issue a CA-signed leaf whose signature uses a weak digest (SHA-1/MD5),
        which modern `cryptography` refuses to emit \u2014 so we sign via openssl."""
        host = spec.host
        ca_cert, ca_key = self._ca_files()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        _atomic_write(keyfile, key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        try:
            san_host = spec.san_host or host
            try:
                ipaddress.ip_address(san_host); san = f"IP:{san_host}"
            except ValueError:
                san = f"DNS:{san_host}"
            with tempfile.TemporaryDirectory(dir=str(self.workdir)) as td:
                td = Path(td)
                ext = td / "ext.cnf"
                ext.write_text(f"basicConstraints=CA:FALSE\nsubjectAltName={san}\n")
                csr = td / "leaf.csr"
                subprocess.run(["openssl", "req", "-new", "-key", str(keyfile),
                                "-subj", f"/CN={spec.cn or host}", "-out", str(csr)],
                               check=True, capture_output=True)
                leaf = td / "leaf.crt"
                subprocess.run(["openssl", "x509", "-req", "-in", str(csr),
                                "-CA", ca_cert, "-CAkey", ca_key, "-CAcreateserial",
                                "-days", "30", f"-{spec.weak_md}", "-extfile", str(ext), "-out", str(leaf)],
                               check=True, capture_output=True)
                chain = leaf.read_bytes() + self._ca_cert.public_bytes(serialization.Encoding.PEM)
            _atomic_write(certfile, chain)
        except BaseException:
            try: keyfile.unlink()
            except OSError: pass
            raise
        return CertMaterial(strategy, str(certfile), str(keyfile), hostname=host)

    def _probe_openssl(self, md: str):
        """Confirm the openssl CLI exists and can sign a cert with digest `md`. Raises on failure."""
        if not shutil.which("openssl"):
            raise RuntimeError("openssl not found")
        with tempfile.TemporaryDirectory(dir=str(self.workdir)) as td:
            td = Path(td)
            key = td / "k.pem"; crt = td / "c.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:1024", "-nodes",
                            f"-{md}", "-subj", "/CN=probe", "-days", "1",
                            "-keyout", str(key), "-out", str(crt)],
                           check=True, capture_output=True)

    @staticmethod
    def _probe(fn) -> bool:
        try:
            fn()
            return True
        except Exception:
            return False

    @staticmethod
    def _probe_build(sig_hash=None, cn=None):
        """Throwaway self-signed build to check whether this OpenSSL emits a given
        signature hash / a name with an embedded null byte."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn or "probe.local")])
        now = dt.datetime.now(dt.UTC)
        (x509.CertificateBuilder()
         .subject_name(name).issuer_name(name).public_key(key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=1))
         .sign(key, sig_hash or hashes.SHA256()))

    def _probe_handshake(self, ciphers: str, with_cert: bool):
        """Loopback handshake to confirm this build can actually negotiate a cipher
        mode (aNULL needs no cert; eNULL needs one). Raises on failure."""
        import socket as _socket, ssl as _ssl, threading as _threading
        sctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
        sctx.maximum_version = _ssl.TLSVersion.TLSv1_2
        sctx.set_ciphers(ciphers)
        if with_cert:
            m = self._leaf("__probe__", LeafSpec("probe.local"))
            sctx.load_cert_chain(m.certfile, m.keyfile)
        cctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
        cctx.check_hostname = False
        cctx.verify_mode = _ssl.CERT_NONE
        cctx.maximum_version = _ssl.TLSVersion.TLSv1_2
        cctx.set_ciphers(ciphers)
        ls = _socket.socket(); ls.bind(("127.0.0.1", 0)); ls.listen(1)
        out: dict = {}

        def serve():
            try:
                conn, _ = ls.accept()
                sctx.wrap_socket(conn, server_side=True).close()
                out["ok"] = True
            except Exception as e:
                out["err"] = e

        t = _threading.Thread(target=serve, daemon=True); t.start()
        cs = _socket.create_connection(ls.getsockname(), timeout=3)
        try:
            cctx.wrap_socket(cs).close()
        finally:
            t.join(timeout=3); ls.close()
        if not out.get("ok"):
            raise out.get("err", RuntimeError("handshake failed"))
