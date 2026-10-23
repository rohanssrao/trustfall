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

# The October 2026 eMudhra incident: eight intermediate CAs were generated with
# ECDSA P-384 keys whose private scalars were tiny (this one is d=4), making the
# "private" keys effectively public (https://emudhra.we-have-a-problem.com/).
# Below are the compromised "EM OV TLS CA - G3C" intermediate and its
# cross-certificates (via "emSign Root TLS CA - G3" and Comodo's "AAA Certificate
# Services"), identical to what mitmproxy ships for --emudhra (#8500). A device
# that accepts a leaf minted under this chain still trusts the publicly
# compromised CA: a frozen trust store or missing revocation/distrust updating.
# The key is public knowledge - never present this chain outside authorized testing.
EMUDHRA_CHAIN_PEM = b"""

-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAShZANiAAQTglHNUqyS
mMHIqtl3Mh3rl+cJvQtMoKylXcitUdz8nRWJoVl+OlEg4e/WMcY+GDXKyuKYaaYu
FjHoooGBq1ZhbcRdkYq8CfOrDmPPeSqk3O1zh743u6VpVJ8cArJw7Wc=
-----END PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIDaDCCAu6gAwIBAgIPKWkmwiejoVJjkrGUgqUEMAoGCCqGSM49BAMDMFYxCzAJ
BgNVBAYTAklOMSUwIwYDVQQKDBxlTXVkaHJhIFRlY2hub2xvZ2llcyBMaW1pdGVk
MSAwHgYDVQQDDBdlbVNpZ24gUm9vdCBUTFMgQ0EgLSBHMzAeFw0yNTA0MzAxNTM3
NDFaFw00MDA0MjgxODMwMDBaMEAxCzAJBgNVBAYTAlVTMRQwEgYDVQQKDAtlTXVk
aHJhIEluYzEbMBkGA1UEAwwSRU0gT1YgVExTIENBIC0gRzNDMHYwEAYHKoZIzj0C
AQYFK4EEACIDYgAEE4JRzVKskpjByKrZdzId65fnCb0LTKCspV3IrVHc/J0ViaFZ
fjpRIOHv1jHGPhg1ysrimGmmLhYx6KKBgatWYW3EXZGKvAnzqw5jz3kqpNztc4e+
N7ulaVSfHAKycO1no4IBljCCAZIwHwYDVR0jBBgwFoAU4TqrIXzx401UrtRyt/2L
WUIgkFQwHQYDVR0OBBYEFDTq6gzryQra+dDF4u2beMmHnhtsMB0GA1UdJQQWMBQG
CCsGAQUFBwMBBggrBgEFBQcDAjBdBgNVHSAEVjBUMDkGCysGAQQBg44hAQABMCow
KAYIKwYBBQUHAgEWHGh0dHA6Ly9yZXBvc2l0b3J5LmVtc2lnbi5jb20wDQYLKwYB
BAGDjiEBAm4wCAYGZ4EMAQICMHUGCCsGAQUFBwEBBGkwZzAkBggrBgEFBQcwAYYY
aHR0cDovL29jc3AtYy5lbXNpZ24uY29tMD8GCCsGAQUFBzAChjNodHRwOi8vcmVw
b3NpdG9yeS5lbXNpZ24uY29tL2NlcnRzL0VNT1ZUTFNDQUczQy5wN2MwNwYDVR0f
BDAwLjAsoCqgKIYmaHR0cDovL2NybC5lbXNpZ24uY29tLz9yb290dGxzY2FnMy5j
cmwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwCgYIKoZIzj0E
AwMDaAAwZQIxAMSZt2xsPeumRdeSMSQ3CbzIZeQ/q7GDCWfeE1Pq+mhgA6gRM44c
NVF3xJ+wsxJk+wIwFJbaDMokD8Ei6eNOiA8yUMYvfzQyngmrhZQMdPCK1SewrR79
4rSb9vGqxZzelQth
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDdDCCAvmgAwIBAgIQAJYaPvsTWVdu0EAFtGhKWzAKBggqhkjOPQQDAzBrMQsw
CQYDVQQGEwJJTjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhy
YSBUZWNobm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290
IENBIC0gRzMwHhcNMjQwNzExMTU0MzM2WhcNMzkwNzA5MTgzMDAwWjBWMQswCQYD
VQQGEwJJTjElMCMGA1UECgwcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRlZDEg
MB4GA1UEAwwXZW1TaWduIFJvb3QgVExTIENBIC0gRzMwdjAQBgcqhkjOPQIBBgUr
gQQAIgNiAARfD9w/q1cWxL6D9bMGH6CQ4u+gAV6GN9s+PwQx9Bl4hC+0iU8QOk8m
WO/RwXQy10DCSxT8vSIJClHKp+Ao4qJKdYeV0SwZ7LMQziyLfxIUOY6Grja/sQFw
LKYf8EdDXAyjggF1MIIBcTAfBgNVHSMEGDAWgBR8XQKEE9TMipuBzhccLikenEhj
QjAdBgNVHQ4EFgQU4TqrIXzx401UrtRyt/2LWUIgkFQwHQYDVR0lBBYwFAYIKwYB
BQUHAwEGCCsGAQUFBwMCMD0GA1UdIAQ2MDQwMgYEVR0gADAqMCgGCCsGAQUFBwIB
FhxodHRwOi8vcmVwb3NpdG9yeS5lbXNpZ24uY29tMHgGCCsGAQUFBwEBBGwwajAi
BggrBgEFBQcwAYYWaHR0cDovL29jc3AuZW1zaWduLmNvbTBEBggrBgEFBQcwAoY4
aHR0cDovL3JlcG9zaXRvcnkuZW1zaWduLmNvbS9jZXJ0cy9lbVNpZ25FQ0NSb290
Q0FHMy5jcnQwMwYDVR0fBCwwKjAooCagJIYiaHR0cDovL2NybC5lbXNpZ24uY29t
P1Jvb3RDQUczLmNybDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIB
ATAKBggqhkjOPQQDAwNpADBmAjEAt9CIpRGp46QHQYDUBnLKw+vvK0/h9vmilEAg
TroUl/anH4x2rXHqiCtBTBfgKDegAjEA8WpG1LTZdAIL0FSYqxXeREaeTSxEofM0
1jJH3jGvCXC79LU9UPJ2o3TU+UIj2gMV
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDzzCCAregAwIBAgIRAI1aSBGTnvRH13ERzdmEmukwDQYJKoZIhvcNAQELBQAw
ezELMAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
A1UEBwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNV
BAMMGEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczAeFw0yNTA1MTQwMDAwMDBaFw0y
ODEyMzEyMzU5NTlaMEAxCzAJBgNVBAYTAlVTMRQwEgYDVQQKDAtlTXVkaHJhIElu
YzEbMBkGA1UEAwwSRU0gT1YgVExTIENBIC0gRzNDMHYwEAYHKoZIzj0CAQYFK4EE
ACIDYgAEE4JRzVKskpjByKrZdzId65fnCb0LTKCspV3IrVHc/J0ViaFZfjpRIOHv
1jHGPhg1ysrimGmmLhYx6KKBgatWYW3EXZGKvAnzqw5jz3kqpNztc4e+N7ulaVSf
HAKycO1no4IBNTCCATEwHwYDVR0jBBgwFoAUoBEKIz6W8Qfs4q8p74Klf9AwpLQw
HQYDVR0OBBYEFDTq6gzryQra+dDF4u2beMmHnhtsMA4GA1UdDwEB/wQEAwIBBjAS
BgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD
AjAxBgNVHSAEKjAoMAgGBmeBDAECAjANBgsrBgEEAYOOIQEAATANBgsrBgEEAYOO
IQECbjBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsLmNvbW9kb2NhLmNvbS9B
QUFDZXJ0aWZpY2F0ZVNlcnZpY2VzLmNybDA0BggrBgEFBQcBAQQoMCYwJAYIKwYB
BQUHMAGGGGh0dHA6Ly9vY3NwLmNvbW9kb2NhLmNvbTANBgkqhkiG9w0BAQsFAAOC
AQEAHlbhZpjhkPEAQVhPHRtBDaHqiisVD20pQ1TUeSx3l62Qe7NQ0b7vWQy7DN0i
KOu7BGpP5EnIjvXbz9FhpfPJ4FhKEt3tQ51rqXz2oD8vRaryvExWPobDUz3j7HN6
OzBsVMIe3PD7AAkpky0x8zMSi/ep5R9OMzybmNptbtppyuB5ytgq+h7lQdRIP+CQ
TaJX3qTgfMqzntYre5GljmEB5hU2/rSn8zoSU2APkJidlZFpghtgbD4I2VRHZvCw
FFr/SrFM9pwrgbJNZ1MtyTSVgI5NlNb0aMfLR+/r6jJt3ROeY2yh2QQ2dx+Yqgdb
uL5ChFWOQU+ErSDnUq7yr+pjBQ==
-----END CERTIFICATE-----
"""

_emudhra_cache: tuple | None = None
_emudhra_lock = threading.Lock()


def emudhra_chain() -> tuple:
    """(compromised key, issuer cert, [alternate cross-certs]) from EMUDHRA_CHAIN_PEM.

    The first certificate is the compromised intermediate we mint leaves under;
    the rest are alternate cross-signatures of the same key (different root
    programs), presented alongside so each device can build whichever path its
    (stale) trust store still anchors. Parsed once, cached."""
    global _emudhra_cache
    with _emudhra_lock:
        if _emudhra_cache is None:
            key = serialization.load_pem_private_key(EMUDHRA_CHAIN_PEM, password=None)
            certs = x509.load_pem_x509_certificates(EMUDHRA_CHAIN_PEM)
            _emudhra_cache = (key, certs[0], certs[1:])
        return _emudhra_cache


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
    emudhra: bool = False                # issue under the compromised eMudhra intermediate CA
    emudhra_legacy: bool = False         # eMudhra: lead with the Comodo cross-sign (old trust stores)

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
            "emudhra_compromised_ca", "emudhra_compromised_ca_legacy",
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
            "emudhra": ["emudhra_compromised_ca", "emudhra_compromised_ca_legacy"],
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
            "emudhra_compromised_ca": LeafSpec(host, emudhra=True, sig_hash=hashes.SHA384()),
            "emudhra_compromised_ca_legacy": LeafSpec(host, emudhra=True, emudhra_legacy=True, sig_hash=hashes.SHA384()),
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
            elif spec.emudhra:
                # Compromised public CA: chain to the revoked eMudhra intermediate
                # (and its cross-certs) so acceptance means the device still trusts
                # a publicly-known-compromised chain. SHA-384 pairs with the P-384 key.
                # OpenSSL doesn't backtrack across same-subject alternates, so the
                # legacy variant leads with the Comodo cross-sign for old trust stores.
                e_key, e_cert, e_cross = emudhra_chain()
                e_chain = [e_cert, *e_cross]
                if spec.emudhra_legacy:
                    legacy = [c for c in e_cross if c.subject == e_cert.subject]
                    e_chain = legacy + [c for c in e_chain if c not in legacy]
                issuer_key, issuer_name, extra_chain = e_key, e_cert.subject, e_chain
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
            if spec.emudhra:
                # Real leaves under this CA carry SKI/AKI; strict validators (e.g.
                # rustls-webpki) reject certs without them.
                builder = (builder
                           .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                           .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False))
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
