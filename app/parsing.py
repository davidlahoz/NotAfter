"""Certificate parsing and — more importantly — refusal.

This module is the only place that looks at uploaded bytes. Its first job is
to *refuse* anything that could carry private key material, before any real
parsing happens. Only then does it hand the bytes to ``cryptography``.

Nothing here writes to disk, and no exception message ever contains bytes
from the upload.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Final

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7

MAX_UPLOAD_BYTES: Final = 256 * 1024

#: PEM labels that may legitimately appear in an upload.
ALLOWED_PEM_LABELS: Final = frozenset(
    {"CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE", "PKCS7"}
)

#: Any PEM label containing one of these is private key material.
PRIVATE_KEY_MARKERS: Final = (
    "PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY",
    "RSA PRIVATE KEY",
    "EC PRIVATE KEY",
    "DSA PRIVATE KEY",
    "OPENSSH PRIVATE KEY",
    "PGP PRIVATE KEY BLOCK",
)

_PEM_LABEL_RE: Final = re.compile(rb"-----BEGIN ([A-Za-z0-9 .#-]{0,64})-----")
_BASE64_ONLY_RE: Final = re.compile(rb"^[A-Za-z0-9+/=\s]+$")

EXTRACT_IN_BROWSER_HINT: Final = (
    "Use the upload page, which reads .pfx/.p12 files inside your browser and "
    "sends only the public certificate, or use the 'Enter the expiry manually' "
    "tab if you do not have the file."
)


class UploadRejected(Exception):
    """An upload was refused. ``message`` is safe to show to the user."""

    code = "rejected"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class PrivateKeyMaterialError(UploadRejected):
    """The upload contained a private key block."""

    code = "private_key_present"


class Pkcs12Rejected(UploadRejected):
    """The upload is a PKCS#12 container, which the server never opens."""

    code = "pkcs12_not_accepted"


class UnsupportedFormat(UploadRejected):
    """The upload is not a certificate format this app accepts."""

    code = "unsupported_format"


class NoCertificateFound(UploadRejected):
    """The upload parsed, but contained no certificate."""

    code = "no_certificate"


class UploadTooLarge(UploadRejected):
    """The upload exceeded the size limit."""

    code = "too_large"


class AmbiguousLeaf(UploadRejected):
    """Several end-entity certificates; the user must pick one."""

    code = "ambiguous_leaf"

    def __init__(self, message: str, choices: list[CertificateFacts]) -> None:
        super().__init__(message)
        self.choices = choices


class DerKind(StrEnum):
    """What a DER blob's outer structure says it is."""

    CERTIFICATE = "certificate"
    PKCS7 = "pkcs7"
    PKCS12 = "pkcs12"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class CertificateFacts:
    """Everything the app keeps about a certificate. All of it is public."""

    subject_cn: str
    subject_rfc4514: str
    issuer_rfc4514: str
    issuer_cn: str
    serial_decimal: str
    not_before: datetime
    not_after: datetime
    fingerprint_sha256: str
    sans: list[str] = field(default_factory=list)
    key_algorithm: str = ""
    key_size: int | None = None
    pem: str = ""


# --------------------------------------------------------------------------
# Refusal gate
# --------------------------------------------------------------------------


def _read_der_header(data: bytes, offset: int) -> tuple[int, int, int] | None:
    """Read one DER tag/length header.

    Returns ``(tag, content_offset, content_length)``, or ``None`` if the
    bytes are not a well-formed definite-length DER header. This reads at most
    a handful of bytes and never interprets the content.
    """
    if len(data) < offset + 2:
        return None
    tag = data[offset]
    length_byte = data[offset + 1]
    if length_byte < 0x80:
        return tag, offset + 2, length_byte
    count = length_byte & 0x7F
    if count == 0 or count > 4 or len(data) < offset + 2 + count:
        # Indefinite length or an implausibly long length: not DER we accept.
        return None
    length = int.from_bytes(data[offset + 2 : offset + 2 + count], "big")
    return tag, offset + 2 + count, length


def sniff_der(data: bytes) -> DerKind:
    """Classify a DER blob by its outer shape, without parsing its content.

    * ``SEQUENCE { SEQUENCE ... }`` — an X.509 certificate (``tbsCertificate``).
    * ``SEQUENCE { OBJECT IDENTIFIER ... }`` — a PKCS#7/CMS ``ContentInfo``.
    * ``SEQUENCE { INTEGER ... }`` — a PKCS#12 ``PFX`` (its ``version`` field).
    """
    outer = _read_der_header(data, 0)
    if outer is None or outer[0] != 0x30:
        return DerKind.UNKNOWN
    inner = _read_der_header(data, outer[1])
    if inner is None:
        return DerKind.UNKNOWN
    match inner[0]:
        case 0x30:
            return DerKind.CERTIFICATE
        case 0x06:
            return DerKind.PKCS7
        case 0x02:
            return DerKind.PKCS12
        case _:
            return DerKind.UNKNOWN


def _looks_like_bare_base64(data: bytes) -> bytes | None:
    """Decode a file that is base64 with no PEM armour, else ``None``.

    Without this, a PKCS#12 file that had been base64-encoded would slip past
    the DER check as "unknown text".
    """
    stripped = data.strip()
    if len(stripped) < 64 or not _BASE64_ONLY_RE.match(stripped):
        return None
    try:
        return base64.b64decode(stripped, validate=False)
    except (binascii.Error, ValueError):
        return None


def reject_private_key_material(data: bytes) -> None:
    """Refuse anything carrying a private key, before parsing anything.

    Raises:
        PrivateKeyMaterialError: if a private key PEM block is present.
        Pkcs12Rejected: if the bytes are a PKCS#12 container.
        UnsupportedFormat: if the bytes are neither PEM nor an accepted DER
            structure.
    """
    labels = [label.decode("ascii", "replace").upper() for label in _PEM_LABEL_RE.findall(data)]
    if labels:
        for label in labels:
            if any(marker in label for marker in PRIVATE_KEY_MARKERS):
                raise PrivateKeyMaterialError(
                    "This file contains a private key. NotAfter only ever stores "
                    "public certificates, so the upload was refused and nothing "
                    "was saved. Remove the private key block and upload only the "
                    "'-----BEGIN CERTIFICATE-----' part, or use manual entry."
                )
        if not any(label in ALLOWED_PEM_LABELS for label in labels):
            joined = ", ".join(sorted(set(labels))) or "unknown"
            raise UnsupportedFormat(
                f"This file contains no certificate — its PEM blocks are: {joined}. "
                "Upload a certificate (.pem, .crt, .cer, .der, .p7b) instead."
            )
        return

    kind = sniff_der(data)
    if kind is DerKind.UNKNOWN:
        decoded = _looks_like_bare_base64(data)
        if decoded is not None:
            kind = sniff_der(decoded)

    match kind:
        case DerKind.PKCS12:
            raise Pkcs12Rejected(
                "This looks like a PKCS#12 file (.pfx/.p12). The server never "
                "opens those, because they usually contain a private key. "
                + EXTRACT_IN_BROWSER_HINT
            )
        case DerKind.CERTIFICATE | DerKind.PKCS7:
            return
        case _:
            raise UnsupportedFormat(
                "This file is not a certificate in a format NotAfter accepts. "
                "Accepted here: PEM, DER (.crt/.cer/.der) and PKCS#7 (.p7b/.p7c). "
                + EXTRACT_IN_BROWSER_HINT
            )


def check_size(data: bytes, limit: int = MAX_UPLOAD_BYTES) -> None:
    """Refuse oversized uploads.

    Raises:
        UploadTooLarge: if ``data`` is larger than ``limit``.
    """
    if len(data) > limit:
        raise UploadTooLarge(
            f"That file is larger than the {limit // 1024} KB limit. A single "
            "certificate is only a few kilobytes; you may have picked a "
            "keystore or an archive by mistake."
        )


# --------------------------------------------------------------------------
# Parsing (only reached once the gate above has passed)
# --------------------------------------------------------------------------


def load_certificates(data: bytes) -> list[x509.Certificate]:
    """Parse every certificate in an accepted upload.

    The refusal gate must already have run.

    Raises:
        NoCertificateFound: if nothing parsed as a certificate.
    """
    certs: list[x509.Certificate] = []
    if b"-----BEGIN" in data:
        if b"-----BEGIN PKCS7-----" in data:
            try:
                certs = list(pkcs7.load_pem_pkcs7_certificates(data))
            except ValueError as exc:
                raise NoCertificateFound(
                    "That PKCS#7 file could not be read. Export it again, or "
                    "upload the certificate on its own as a .pem or .cer file."
                ) from exc
        else:
            try:
                certs = list(x509.load_pem_x509_certificates(data))
            except ValueError as exc:
                raise NoCertificateFound(
                    "That file looks like PEM but no certificate could be read "
                    "from it. Check that it starts with "
                    "'-----BEGIN CERTIFICATE-----'."
                ) from exc
    else:
        kind = sniff_der(data)
        if kind is DerKind.UNKNOWN:
            decoded = _looks_like_bare_base64(data)
            if decoded is not None:
                data, kind = decoded, sniff_der(decoded)
        try:
            if kind is DerKind.PKCS7:
                certs = list(pkcs7.load_der_pkcs7_certificates(data))
            else:
                certs = [x509.load_der_x509_certificate(data)]
        except ValueError as exc:
            raise NoCertificateFound(
                "That file could not be read as a certificate. Accepted here: "
                "PEM, DER (.crt/.cer/.der) and PKCS#7 (.p7b/.p7c)."
            ) from exc

    if not certs:
        raise NoCertificateFound("No certificate was found in that file. Nothing was saved.")
    return certs


def select_leaf(certs: list[x509.Certificate]) -> x509.Certificate:
    """Pick the end-entity certificate from a bundle.

    The leaf is the certificate that is not the issuer of any other
    certificate in the file.

    Raises:
        AmbiguousLeaf: if more than one certificate qualifies.
    """
    if len(certs) == 1:
        return certs[0]

    # A certificate issues another one if its subject is that one's issuer.
    # Self-issued certificates do not count as issuing themselves.
    issues_another = {
        cert.issuer.public_bytes()
        for cert in certs
        if cert.subject.public_bytes() != cert.issuer.public_bytes()
    }
    leaves = [cert for cert in certs if cert.subject.public_bytes() not in issues_another]
    # A self-signed root that nothing chains to is still not the leaf when a
    # genuine end-entity certificate is present.
    non_self_signed = [
        cert for cert in leaves if cert.subject.public_bytes() != cert.issuer.public_bytes()
    ]
    if non_self_signed:
        leaves = non_self_signed

    if len(leaves) == 1:
        return leaves[0]
    if not leaves:
        # Every certificate issues another (a cycle, or a cross-signed pair):
        # fall back to the one expiring soonest, which is the useful one here.
        return min(certs, key=lambda c: c.not_valid_after_utc)
    raise AmbiguousLeaf(
        "That file contains more than one end-entity certificate. Choose the "
        "one you want to track.",
        [facts_from_certificate(cert) for cert in leaves],
    )


def _describe_public_key(cert: x509.Certificate) -> tuple[str, int | None]:
    """Return a human-readable key algorithm and its size in bits."""
    key = cert.public_key()
    match key:
        case rsa.RSAPublicKey():
            return "RSA", key.key_size
        case ec.EllipticCurvePublicKey():
            return f"EC ({key.curve.name})", key.curve.key_size
        case ed25519.Ed25519PublicKey():
            return "Ed25519", 256
        case ed448.Ed448PublicKey():
            return "Ed448", 456
        case dsa.DSAPublicKey():
            return "DSA", key.key_size
        case _:
            return type(key).__name__, None


def _subject_alternative_names(cert: x509.Certificate) -> list[str]:
    """Return SANs as display strings, or an empty list if there are none."""
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    names: list[str] = []
    san = ext.value
    names.extend(f"DNS:{value}" for value in san.get_values_for_type(x509.DNSName))
    names.extend(f"IP:{value}" for value in san.get_values_for_type(x509.IPAddress))
    names.extend(f"EMAIL:{value}" for value in san.get_values_for_type(x509.RFC822Name))
    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    names.extend(f"URI:{value}" for value in uris)
    return names


def _common_name(name: x509.Name) -> str:
    """First CN attribute of a name, or an empty string."""
    attributes = name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    if not attributes:
        return ""
    value = attributes[0].value
    return value if isinstance(value, str) else value.decode("utf-8", "replace")


def facts_from_certificate(cert: x509.Certificate) -> CertificateFacts:
    """Extract the stored fields from a parsed certificate."""
    algorithm, key_size = _describe_public_key(cert)
    return CertificateFacts(
        subject_cn=_common_name(cert.subject),
        subject_rfc4514=cert.subject.rfc4514_string(),
        issuer_rfc4514=cert.issuer.rfc4514_string(),
        issuer_cn=_common_name(cert.issuer),
        serial_decimal=str(cert.serial_number),
        not_before=cert.not_valid_before_utc.replace(tzinfo=None),
        not_after=cert.not_valid_after_utc.replace(tzinfo=None),
        fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(),
        sans=_subject_alternative_names(cert),
        key_algorithm=algorithm,
        key_size=key_size,
        pem=cert.public_bytes(Encoding.PEM).decode("ascii"),
    )


def parse_upload(data: bytes, *, limit: int = MAX_UPLOAD_BYTES) -> CertificateFacts:
    """Refuse, then parse, then describe an uploaded certificate.

    This is the single entry point used by the HTTP layer.

    Raises:
        UploadRejected: any subclass, each carrying a user-facing message.
    """
    check_size(data, limit)
    reject_private_key_material(data)
    certs = load_certificates(data)
    return facts_from_certificate(select_leaf(certs))


def format_fingerprint(fingerprint: str) -> str:
    """Group a hex fingerprint into colon-separated pairs for display."""
    return ":".join(fingerprint[i : i + 2] for i in range(0, len(fingerprint), 2)).upper()
