"""The in-browser extraction, run against every PKCS#12 encryption scheme.

These run the real TypeScript through Node rather than a browser, so they are
fast enough to be part of the ordinary suite. They exist because pkijs alone
only implements PBES2: a `.pfx` from Windows, `keytool` or older OpenSSL uses
RC2-40 or Triple DES, which WebCrypto does not have, and those files were
being reported to the user as "wrong password".
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes

from tests.fixtures import GeneratedCert, make_cert, make_pkcs12, make_pkcs12_legacy

WEB_DIR = Path(__file__).resolve().parent.parent / "web"
PASSWORD = "hunter2"

pytestmark = pytest.mark.skipif(
    not (WEB_DIR / "node_modules").is_dir() or shutil.which("node") is None,
    reason="needs Node and `npm ci` in web/",
)

RUNNER = """
import { readFileSync } from "node:fs";
import { extractLeaves } from "./bundle.mjs";
const [file, password] = process.argv.slice(2);
try {
  const leaves = await extractLeaves(new Uint8Array(readFileSync(file)), password);
  console.log(JSON.stringify({
    ok: true,
    leaves: leaves.map((l) => ({
      commonName: l.commonName,
      fingerprint: l.fingerprintSha256,
      notAfter: l.notAfter.toISOString(),
      pem: l.pem,
    })),
  }));
} catch (error) {
  console.log(JSON.stringify({ ok: false, name: error.name, message: error.message }));
}
"""


@pytest.fixture(scope="module")
def bundle(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Bundle the extraction module once, and a small runner beside it."""
    workspace = tmp_path_factory.mktemp("extract")
    subprocess.run(  # noqa: S603
        [  # noqa: S607 — npx is resolved from the developer's PATH
            "npx",
            "esbuild",
            "src/extract.ts",
            "--bundle",
            "--format=esm",
            "--target=es2022",
            f"--outfile={workspace / 'bundle.mjs'}",
            "--log-level=warning",
        ],
        cwd=WEB_DIR,
        check=True,
        capture_output=True,
    )
    (workspace / "run.mjs").write_text(RUNNER)
    return workspace


def extract(bundle: Path, tmp_path: Path, blob: bytes, password: str) -> dict[str, Any]:
    """Run the browser extraction over one file and return what it produced."""
    target = tmp_path / "keystore.pfx"
    target.write_bytes(blob)
    result = subprocess.run(  # noqa: S603
        ["node", str(bundle / "run.mjs"), str(target), password],  # noqa: S607
        cwd=bundle,
        check=True,
        capture_output=True,
        text=True,
    )
    parsed: dict[str, Any] = json.loads(result.stdout)
    return parsed


def fingerprint_of(cert: GeneratedCert) -> str:
    return cert.certificate.fingerprint(hashes.SHA256()).hex()


def _variants(cert: GeneratedCert) -> dict[str, bytes]:
    """One PKCS#12 file per encryption scheme worth covering."""
    return {
        "pbes2-aes256": make_pkcs12(cert, password=PASSWORD.encode()),
        "pbesv1-3des": make_pkcs12_legacy(cert, PASSWORD.encode()),
        "unencrypted": make_pkcs12(cert),
    }


@pytest.mark.parametrize("scheme", ["pbes2-aes256", "pbesv1-3des", "unencrypted"])
def test_every_encryption_scheme_yields_the_certificate(bundle: Path, tmp_path: Path, scheme: str):
    cert = make_cert("edi.example.org", days_until_expiry=120)
    result = extract(bundle, tmp_path, _variants(cert)[scheme], PASSWORD)

    assert result["ok"], f"{scheme}: {result.get('name')}: {result.get('message')}"
    leaf = result["leaves"][0]
    assert leaf["commonName"] == "edi.example.org"
    assert leaf["fingerprint"] == fingerprint_of(cert)
    assert leaf["pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert "PRIVATE" not in leaf["pem"]


@pytest.mark.parametrize("scheme", ["pbes2-aes256", "pbesv1-3des"])
def test_a_wrong_password_is_reported_as_a_wrong_password(
    bundle: Path, tmp_path: Path, scheme: str
):
    """Never as anything else — that is what sent people down the wrong path."""
    cert = make_cert()
    result = extract(bundle, tmp_path, _variants(cert)[scheme], "not-the-password")
    assert result["ok"] is False
    assert result["name"] == "PasswordRequiredError"


def test_an_empty_password_attempt_asks_for_one(bundle: Path, tmp_path: Path):
    """The page tries an empty password first; an encrypted file must decline."""
    result = extract(bundle, tmp_path, make_pkcs12(make_cert(), password=b"x"), "")
    assert result["ok"] is False
    assert result["name"] == "PasswordRequiredError"


@pytest.mark.skipif(shutil.which("openssl") is None, reason="needs the openssl command")
def test_windows_style_rc2_40_pfx_is_read(bundle: Path, tmp_path: Path):
    """RC2-40 for certificates is what Windows and keytool commonly emit."""
    cert = make_cert("edi.example.org", days_until_expiry=90)
    (tmp_path / "cert.pem").write_bytes(cert.pem)
    (tmp_path / "key.pem").write_bytes(cert.key_pem)
    built = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "openssl",
            "pkcs12",
            "-export",
            "-legacy",
            "-certpbe",
            "PBE-SHA1-RC2-40",
            "-keypbe",
            "PBE-SHA1-3DES",
            "-macalg",
            "sha1",
            "-in",
            str(tmp_path / "cert.pem"),
            "-inkey",
            str(tmp_path / "key.pem"),
            "-passout",
            f"pass:{PASSWORD}",
            "-out",
            str(tmp_path / "windows.pfx"),
        ],
        capture_output=True,
        check=False,
    )
    if built.returncode != 0:
        pytest.skip("this openssl build cannot write legacy PKCS#12 files")

    result = extract(bundle, tmp_path, (tmp_path / "windows.pfx").read_bytes(), PASSWORD)
    assert result["ok"], f"{result.get('name')}: {result.get('message')}"
    leaf = result["leaves"][0]
    assert leaf["commonName"] == "edi.example.org"
    assert leaf["fingerprint"] == fingerprint_of(cert)
    assert "PRIVATE" not in leaf["pem"]
