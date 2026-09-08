"""Certificate fixtures, generated in memory.

Everything here uses fictional names (``example.org``). No fixture file is
ever written to disk by the test suite.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12
from cryptography.x509.oid import NameOID


@dataclass(frozen=True)
class GeneratedCert:
    """A generated certificate and the key that signed it (tests only)."""

    certificate: x509.Certificate
    key: rsa.RSAPrivateKey

    @property
    def pem(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.PEM)

    @property
    def der(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.DER)

    @property
    def key_pem(self) -> bytes:
        return self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )


def _name(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "NL"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Organisation"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def make_cert(
    common_name: str = "edi.example.org",
    *,
    days_until_expiry: int = 120,
    issuer: GeneratedCert | None = None,
    is_ca: bool = False,
    sans: list[str] | None = None,
    key_size: int = 2048,
) -> GeneratedCert:
    """Generate a certificate, optionally signed by ``issuer``."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    now = dt.datetime.now(dt.UTC)
    subject = _name(common_name)
    issuer_name = issuer.certificate.subject if issuer else subject
    signing_key = issuer.key if issuer else key

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=days_until_expiry))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    san_names = sans if sans is not None else ([] if is_ca else [common_name])
    if san_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in san_names]),
            critical=False,
        )
    certificate = builder.sign(signing_key, hashes.SHA256())
    return GeneratedCert(certificate=certificate, key=key)


def make_chain(
    leaf_cn: str = "edi.example.org", *, days_until_expiry: int = 120
) -> tuple[GeneratedCert, GeneratedCert]:
    """Return ``(ca, leaf)`` where ``leaf`` is signed by ``ca``."""
    ca = make_cert("Example Issuing CA", days_until_expiry=3650, is_ca=True)
    leaf = make_cert(leaf_cn, days_until_expiry=days_until_expiry, issuer=ca)
    return ca, leaf


def make_pkcs7(certs: list[x509.Certificate], *, pem: bool = False) -> bytes:
    """Build a PKCS#7 certificate-only bundle."""
    encoding = serialization.Encoding.PEM if pem else serialization.Encoding.DER
    return pkcs7.serialize_certificates(certs, encoding)


def make_pkcs12(cert: GeneratedCert, *, password: bytes | None = None) -> bytes:
    """Build a PKCS#12 container. Used only to assert that it is refused."""
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return pkcs12.serialize_key_and_certificates(
        b"example", cert.key, cert.certificate, None, encryption
    )


def make_pkcs12_legacy(cert: GeneratedCert, password: bytes) -> bytes:
    """Build a PKCS#12 container using the legacy SHA-1 and Triple DES scheme.

    This is what Windows' ``Export-PfxCertificate``, Java's ``keytool`` and
    older OpenSSL produce, and it is the shape that the in-browser extraction
    has to cope with — WebCrypto implements neither Triple DES nor RC2.
    """
    builder = (
        serialization.PrivateFormat.PKCS12.encryption_builder()
        .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
        .hmac_hash(hashes.SHA1())  # noqa: S303 — the legacy scheme being reproduced
    )
    return pkcs12.serialize_key_and_certificates(
        b"example", cert.key, cert.certificate, None, builder.build(password)
    )
