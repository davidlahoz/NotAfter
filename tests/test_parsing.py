"""The refusal gate: what must never reach the server, and what may."""

from __future__ import annotations

import base64

import pytest

from app.parsing import (
    AmbiguousLeaf,
    DerKind,
    NoCertificateFound,
    Pkcs12Rejected,
    PrivateKeyMaterialError,
    UnsupportedFormat,
    UploadTooLarge,
    parse_upload,
    sniff_der,
)
from tests.fixtures import make_cert, make_chain, make_pkcs7, make_pkcs12


def test_pem_with_private_key_is_refused():
    cert = make_cert()
    with pytest.raises(PrivateKeyMaterialError) as caught:
        parse_upload(cert.pem + cert.key_pem)
    assert "private key" in str(caught.value).lower()


@pytest.mark.parametrize(
    "label",
    [
        b"PRIVATE KEY",
        b"ENCRYPTED PRIVATE KEY",
        b"RSA PRIVATE KEY",
        b"EC PRIVATE KEY",
        b"OPENSSH PRIVATE KEY",
    ],
)
def test_every_private_key_label_is_refused(label: bytes):
    blob = b"-----BEGIN " + label + b"-----\nAAAA\n-----END " + label + b"-----\n"
    with pytest.raises(PrivateKeyMaterialError):
        parse_upload(blob)


def test_key_first_then_certificate_is_still_refused():
    cert = make_cert()
    with pytest.raises(PrivateKeyMaterialError):
        parse_upload(cert.key_pem + cert.pem)


def test_pkcs12_is_refused_without_parsing():
    pfx = make_pkcs12(make_cert(), password=b"hunter2")
    with pytest.raises(Pkcs12Rejected) as caught:
        parse_upload(pfx)
    assert "browser" in str(caught.value)


def test_base64_wrapped_pkcs12_is_also_refused():
    pfx = base64.b64encode(make_pkcs12(make_cert()))
    with pytest.raises(Pkcs12Rejected):
        parse_upload(pfx)


def test_sniff_der_classifies_containers():
    cert = make_cert()
    assert sniff_der(cert.der) is DerKind.CERTIFICATE
    assert sniff_der(make_pkcs7([cert.certificate])) is DerKind.PKCS7
    assert sniff_der(make_pkcs12(cert)) is DerKind.PKCS12
    assert sniff_der(b"not der at all") is DerKind.UNKNOWN


def test_certificate_request_is_refused():
    blob = b"-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n"
    with pytest.raises(UnsupportedFormat):
        parse_upload(blob)


def test_random_bytes_are_refused():
    with pytest.raises(UnsupportedFormat):
        parse_upload(b"\x00\x01\x02 this is not a certificate")


def test_oversized_upload_is_refused():
    with pytest.raises(UploadTooLarge):
        parse_upload(b"x" * (256 * 1024 + 1))


def test_truncated_pem_reports_no_certificate():
    with pytest.raises(NoCertificateFound):
        parse_upload(b"-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n")


def test_pem_certificate_is_parsed():
    cert = make_cert("edi.example.org", days_until_expiry=45)
    facts = parse_upload(cert.pem)
    assert facts.subject_cn == "edi.example.org"
    assert facts.key_algorithm == "RSA"
    assert facts.key_size == 2048
    assert facts.sans == ["DNS:edi.example.org"]
    assert facts.pem.startswith("-----BEGIN CERTIFICATE-----")
    assert "PRIVATE" not in facts.pem


def test_der_and_pem_agree():
    cert = make_cert()
    assert parse_upload(cert.der).fingerprint_sha256 == parse_upload(cert.pem).fingerprint_sha256


def test_leaf_is_chosen_from_a_chain():
    ca, leaf = make_chain("edi.example.org")
    for blob in (ca.pem + leaf.pem, leaf.pem + ca.pem):
        assert parse_upload(blob).subject_cn == "edi.example.org"


def test_leaf_is_chosen_from_pkcs7():
    ca, leaf = make_chain("as2.example.org")
    facts = parse_upload(make_pkcs7([ca.certificate, leaf.certificate]))
    assert facts.subject_cn == "as2.example.org"
    assert facts.issuer_rfc4514.startswith("CN=Example Issuing CA")


def test_two_leaves_ask_the_user_to_choose():
    ca, first = make_chain("one.example.org")
    second = make_cert("two.example.org", issuer=ca)
    with pytest.raises(AmbiguousLeaf) as caught:
        parse_upload(ca.pem + first.pem + second.pem)
    names = {choice.subject_cn for choice in caught.value.choices}
    assert names == {"one.example.org", "two.example.org"}
