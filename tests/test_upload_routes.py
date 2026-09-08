"""HTTP-level acceptance: nothing that carries a key is ever accepted."""

from __future__ import annotations

import base64

from sqlmodel import Session, select

from app.models import AuditLog, Certificate
from tests.conftest import Client
from tests.fixtures import make_cert, make_chain, make_pkcs12


def _upload(client: Client, blob: bytes, name: str, label: str = "Integration PROD"):
    return client.post_files(
        "/certificates/new/upload",
        files={"file": (name, blob, "application/octet-stream")},
        data={"label": label, "environment": "PROD", "owner_email": "owner@example.org"},
        follow_redirects=False,
    )


def test_pem_with_private_key_is_rejected_and_stores_nothing(
    editor: Client, session: Session, caplog
):
    cert = make_cert()
    with caplog.at_level("DEBUG"):
        response = _upload(editor, cert.pem + cert.key_pem, "bundle.pem")

    assert response.status_code == 400
    assert session.exec(select(Certificate)).all() == []
    assert session.exec(select(AuditLog)).all() == []
    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert "PRIVATE KEY" not in logged
    assert "MII" not in logged


def test_pkcs12_upload_is_rejected_with_guidance(editor: Client, session: Session):
    response = _upload(editor, make_pkcs12(make_cert(), password=b"hunter2"), "keystore.pfx")
    assert response.status_code == 400
    assert "browser" in response.text
    assert session.exec(select(Certificate)).all() == []


def test_base64_pkcs12_is_rejected(editor: Client, session: Session):
    blob = base64.b64encode(make_pkcs12(make_cert()))
    assert _upload(editor, blob, "keystore.b64").status_code == 400
    assert session.exec(select(Certificate)).all() == []


def test_valid_pem_creates_a_record(editor: Client, session: Session, outbox):
    cert = make_cert("edi.example.org", days_until_expiry=90)
    response = _upload(editor, cert.pem, "cert.pem")
    assert response.status_code == 303

    stored = session.exec(select(Certificate)).one()
    assert stored.label == "Integration PROD"
    assert stored.subject_cn == "edi.example.org"
    assert stored.not_after.date() == cert.certificate.not_valid_after_utc.date()
    assert (
        stored.fingerprint_sha256
        == cert.certificate.fingerprint(
            __import__("cryptography.hazmat.primitives.hashes", fromlist=["SHA256"]).SHA256()
        ).hex()
    )
    assert stored.verified is True
    assert stored.pem is not None and "PRIVATE" not in stored.pem


def test_uploading_the_same_certificate_twice_links_to_the_first(
    editor: Client, session: Session, outbox
):
    cert = make_cert()
    first = _upload(editor, cert.pem, "cert.pem")
    second = _upload(editor, cert.pem, "cert.pem", label="A different label")

    assert first.status_code == 303
    assert second.status_code == 303
    assert second.headers["location"].endswith("msg=linked")
    assert first.headers["location"].split("?")[0] == second.headers["location"].split("?")[0]
    assert len(session.exec(select(Certificate)).all()) == 1


def test_der_and_pkcs7_are_accepted(editor: Client, session: Session, outbox):
    from tests.fixtures import make_pkcs7

    ca, leaf = make_chain("edi.example.org")
    assert _upload(editor, leaf.der, "cert.der", label="DER").status_code == 303
    other = make_cert("as2.example.org", issuer=ca)
    bundle = make_pkcs7([ca.certificate, other.certificate])
    assert _upload(editor, bundle, "bundle.p7b", label="P7B").status_code == 303
    assert len(session.exec(select(Certificate)).all()) == 2


def test_json_api_accepts_a_browser_extracted_certificate(editor: Client, session: Session, outbox):
    cert = make_cert("edi.example.org")
    response = editor.post_json(
        "/api/certificates",
        {
            "label": "Integration PROD",
            "environment": "PROD",
            "owner_email": "owner@example.org",
            "notes": "",
            "pem": cert.pem.decode(),
        },
    )
    assert response.status_code == 201
    body = response.json()
    assert body["created"] is True
    assert session.get(Certificate, body["id"]) is not None


def test_json_api_refuses_a_pem_carrying_a_key(editor: Client, session: Session):
    cert = make_cert()
    response = editor.post_json(
        "/api/certificates",
        {"label": "Integration PROD", "pem": (cert.pem + cert.key_pem).decode()},
    )
    assert response.status_code == 400
    assert response.json()["code"] == "private_key_present"
    assert session.exec(select(Certificate)).all() == []


def test_oversized_upload_is_rejected(editor: Client, session: Session):
    response = _upload(editor, b"x" * (300 * 1024), "huge.pem")
    assert response.status_code == 400
    assert session.exec(select(Certificate)).all() == []
