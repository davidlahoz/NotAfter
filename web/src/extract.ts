/**
 * Certificate extraction, in the browser.
 *
 * The whole point of this file: a PKCS#12 file and its password are read
 * here, in the page, and never leave it. Only the public certificate — as
 * PEM — is handed back to the caller for sending to the server. Key bags are
 * never touched.
 */

import * as asn1js from "asn1js";
import forge from "node-forge/lib/forge";
import "node-forge/lib/asn1";
import "node-forge/lib/pbe";
import {
  Certificate,
  ContentInfo,
  PFX,
  AuthenticatedSafe,
  SafeContents,
  SignedData,
  PrivateKeyInfo,
  EncryptedData,
} from "pkijs";

export type FileKind = "pkcs12" | "pem" | "der" | "pkcs7" | "unknown";

export interface CertificateSummary {
  readonly commonName: string;
  readonly issuer: string;
  readonly notBefore: Date;
  readonly notAfter: Date;
  readonly fingerprintSha256: string;
  readonly pem: string;
}

export class PasswordRequiredError extends Error {
  constructor(message = "This file needs its password.") {
    super(message);
    this.name = "PasswordRequiredError";
  }
}

export class UnsupportedEncryption extends Error {
  readonly oid: string;

  constructor(oid: string, message: string) {
    super(message);
    this.name = "UnsupportedEncryption";
    this.oid = oid;
  }
}

export class ExtractionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ExtractionError";
  }
}

const PEM_CERT_RE = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
const PRIVATE_KEY_RE = /-----BEGIN (?:[A-Z0-9 ]*)PRIVATE KEY-----/;

/** Guess the format from the bytes, not the file name. */
export function detectKind(bytes: Uint8Array): FileKind {
  const head = new TextDecoder("latin1").decode(bytes.subarray(0, 128));
  if (head.includes("-----BEGIN")) {
    return head.includes("PKCS7") ? "pkcs7" : "pem";
  }
  if (bytes[0] !== 0x30) return "unknown";
  const inner = innerTag(bytes);
  if (inner === 0x30) return "der";
  if (inner === 0x06) return "pkcs7";
  if (inner === 0x02) return "pkcs12";
  return "unknown";
}

/** Tag of the first element inside the outer SEQUENCE. */
function innerTag(bytes: Uint8Array): number | undefined {
  const lengthByte = bytes[1];
  if (lengthByte === undefined) return undefined;
  let offset = 2;
  if (lengthByte >= 0x80) {
    offset = 2 + (lengthByte & 0x7f);
  }
  return bytes[offset];
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function base64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function decodeBase64(value: string): Uint8Array {
  const binary = atob(value.replace(/\s+/g, ""));
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

/** Wrap DER bytes as a PEM certificate block. */
export function toPem(der: Uint8Array): string {
  const body = base64(der).replace(/(.{64})/g, "$1\n").trimEnd();
  return `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----\n`;
}

async function fingerprint(der: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", toArrayBuffer(der));
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function nameToString(name: { typesAndValues: { type: string; value: { valueBlock: { value: string } } }[] }): string {
  const parts = name.typesAndValues.map((entry) => `${shortName(entry.type)}=${entry.value.valueBlock.value}`);
  return parts.join(", ");
}

const NAME_OIDS: Record<string, string> = {
  "2.5.4.3": "CN",
  "2.5.4.6": "C",
  "2.5.4.7": "L",
  "2.5.4.8": "ST",
  "2.5.4.10": "O",
  "2.5.4.11": "OU",
  "1.2.840.113549.1.9.1": "E",
};

function shortName(oid: string): string {
  return NAME_OIDS[oid] ?? oid;
}

function commonNameOf(certificate: Certificate): string {
  for (const entry of certificate.subject.typesAndValues) {
    if (entry.type === "2.5.4.3") return String(entry.value.valueBlock.value);
  }
  return "";
}

async function summarise(certificate: Certificate): Promise<CertificateSummary> {
  const der = new Uint8Array(certificate.toSchema().toBER(false));
  return {
    commonName: commonNameOf(certificate),
    issuer: nameToString(certificate.issuer),
    notBefore: certificate.notBefore.value,
    notAfter: certificate.notAfter.value,
    fingerprintSha256: await fingerprint(der),
    pem: toPem(der),
  };
}

/**
 * Pick the end-entity certificate: the one that is not the issuer of any
 * other certificate in the file.
 */
export function selectLeaves(certificates: Certificate[]): Certificate[] {
  if (certificates.length <= 1) return certificates;
  const issuers = new Set(
    certificates
      .filter((certificate) => subjectKey(certificate) !== issuerKey(certificate))
      .map((certificate) => issuerKey(certificate)),
  );
  const leaves = certificates.filter((certificate) => !issuers.has(subjectKey(certificate)));
  const nonSelfSigned = leaves.filter((certificate) => subjectKey(certificate) !== issuerKey(certificate));
  if (nonSelfSigned.length > 0) return nonSelfSigned;
  return leaves.length > 0 ? leaves : certificates;
}

function subjectKey(certificate: Certificate): string {
  return base64(new Uint8Array(certificate.subject.toSchema().toBER(false)));
}

function issuerKey(certificate: Certificate): string {
  return base64(new Uint8Array(certificate.issuer.toSchema().toBER(false)));
}

function parsePemCertificates(text: string): Certificate[] {
  const blocks = text.match(PEM_CERT_RE) ?? [];
  return blocks.map((block) => {
    const body = block.replace(/-----(BEGIN|END) CERTIFICATE-----/g, "");
    return Certificate.fromBER(toArrayBuffer(decodeBase64(body)));
  });
}

function parsePkcs7(bytes: Uint8Array): Certificate[] {
  const contentInfo = ContentInfo.fromBER(toArrayBuffer(bytes));
  const signedData = new SignedData({ schema: contentInfo.content });
  const certificates = signedData.certificates ?? [];
  return certificates.filter((entry): entry is Certificate => entry instanceof Certificate);
}

/**
 * Read the certificate bags of a PKCS#12 file.
 *
 * Key bags are skipped entirely — they are not decrypted, not read and not
 * returned. The password is used only to open the certificate bags, and only
 * inside this function.
 */
export function readPkcs12(bytes: Uint8Array, password: string): Certificate[] {
  const pfx = PFX.fromBER(toArrayBuffer(bytes));
  const authSafeContent = pfx.authSafe.content;
  if (!(authSafeContent instanceof asn1js.OctetString)) {
    throw new ExtractionError("This .pfx file is not in a shape this app can read.");
  }

  const authenticatedSafe = AuthenticatedSafe.fromBER(authSafeContent.getValue());
  const certificates: Certificate[] = [];
  let refusedPassword = false;
  let unsupported: UnsupportedEncryption | null = null;

  for (const safeContent of authenticatedSafe.safeContents) {
    let contents: SafeContents;
    try {
      contents = openSafeContent(safeContent, password);
    } catch (error) {
      // Keep going: the certificates may be in a blob we can open even if
      // another one defeats us. Remember why, so the message can be honest.
      if (error instanceof UnsupportedEncryption) unsupported = error;
      else refusedPassword = true;
      continue;
    }

    for (const bag of contents.safeBags) {
      const value = bag.bagValue;
      // Key bags are deliberately ignored: nothing here reads them.
      if (value instanceof PrivateKeyInfo) continue;
      const parsed = certificateFromBag(value);
      if (parsed) certificates.push(parsed);
    }
  }

  if (certificates.length === 0) {
    if (unsupported) {
      throw new ExtractionError(
        `This .pfx file is encrypted with a method your browser cannot read ` +
          `(${PKCS12_PBE[unsupported.oid] ?? unsupported.oid}). Export the ` +
          `certificate on its own instead — on a machine with OpenSSL:\n\n` +
          `  openssl pkcs12 -in yourfile.pfx -clcerts -nokeys -out certificate.pem\n\n` +
          `That writes the public certificate only, with no private key, and ` +
          `you can upload it here.`,
      );
    }
    if (refusedPassword) throw new PasswordRequiredError();
    throw new ExtractionError(
      "No certificate was found in that file. It may contain only a private key.",
    );
  }
  return certificates;
}

interface BagValue {
  parsedValue?: { certificate?: Certificate };
  certValue?: unknown;
}

function certificateFromBag(value: unknown): Certificate | null {
  if (value instanceof Certificate) return value;
  const bag = value as BagValue | null;
  if (bag?.parsedValue?.certificate instanceof Certificate) return bag.parsedValue.certificate;
  const certValue = bag?.certValue;
  if (certValue instanceof asn1js.OctetString) {
    try {
      return Certificate.fromBER(certValue.getValue());
    } catch {
      return null;
    }
  }
  if (certValue instanceof Certificate) return certValue;
  return null;
}

/** PKCS#12 encryption schemes, by the OID that names them in the file. */
const PBES2 = "1.2.840.113549.1.5.13";
const PKCS12_PBE: Record<string, string> = {
  "1.2.840.113549.1.12.1.3": "SHA-1 and 3-key Triple DES",
  "1.2.840.113549.1.12.1.4": "SHA-1 and 2-key Triple DES",
  "1.2.840.113549.1.12.1.5": "SHA-1 and 128-bit RC2",
  "1.2.840.113549.1.12.1.6": "SHA-1 and 40-bit RC2",
};

/** node-forge speaks binary strings; these convert to and from bytes. */
function toBinaryString(bytes: Uint8Array): string {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return text;
}

function fromBinaryString(text: string): Uint8Array {
  const bytes = new Uint8Array(text.length);
  for (let index = 0; index < text.length; index += 1) bytes[index] = text.charCodeAt(index);
  return bytes;
}

/**
 * Decrypt one encrypted SafeContents blob.
 *
 * WebCrypto has neither RC2 nor Triple DES, so the legacy PKCS#12 schemes —
 * which is what Windows, `keytool` and older OpenSSL produce — are done by
 * node-forge in pure JavaScript. Only the blob holding certificate bags is
 * ever passed here; a private key bag is encrypted separately and is never
 * given to this function.
 */
function decryptSafeContents(encrypted: EncryptedData, password: string): Uint8Array {
  const info = encrypted.encryptedContentInfo;
  const oid = info.contentEncryptionAlgorithm.algorithmId;
  const isPkcs12Pbe = oid in PKCS12_PBE;
  if (oid !== PBES2 && !isPkcs12Pbe) {
    throw new UnsupportedEncryption(
      oid,
      "This .pfx file is encrypted with a method this app cannot read.",
    );
  }

  const parameters = info.contentEncryptionAlgorithm.algorithmParams;
  if (!parameters) {
    throw new ExtractionError("This .pfx file is missing its encryption settings.");
  }

  // PKCS#12's own schemes derive the key from the password as a BMPString,
  // which forge does itself; PBES2 uses the UTF-8 bytes.
  const secret = isPkcs12Pbe ? password : forge.util.encodeUtf8(password);
  const decipher = forge.pki.pbe.getCipher(
    oid,
    forge.asn1.fromDer(toBinaryString(new Uint8Array(parameters.toBER(false)))),
    secret,
  );
  decipher.update(forge.util.createBuffer(toBinaryString(new Uint8Array(info.getEncryptedContent()))));
  if (!decipher.finish()) {
    throw new PasswordRequiredError();
  }
  return fromBinaryString(decipher.output.getBytes());
}

function openSafeContent(safeContent: ContentInfo, password: string): SafeContents {
  if (safeContent.contentType === "1.2.840.113549.1.7.1") {
    const content = safeContent.content;
    if (content instanceof asn1js.OctetString) {
      return SafeContents.fromBER(content.getValue());
    }
    return new SafeContents({ schema: content });
  }
  if (safeContent.contentType === "1.2.840.113549.1.7.6") {
    const encrypted = new EncryptedData({ schema: safeContent.content });
    return SafeContents.fromBER(toArrayBuffer(decryptSafeContents(encrypted, password)));
  }
  throw new ExtractionError("This .pfx file uses a container this app cannot read.");
}

/** Every certificate found in a file, whatever its format. */
export async function readCertificates(
  bytes: Uint8Array,
  password: string,
): Promise<Certificate[]> {
  const kind = detectKind(bytes);
  switch (kind) {
    case "pkcs12":
      return readPkcs12(bytes, password);
    case "pem": {
      const text = new TextDecoder().decode(bytes);
      if (PRIVATE_KEY_RE.test(text)) {
        throw new ExtractionError(
          "That file contains a private key. Remove the private key block and " +
            "upload only the certificate — NotAfter never stores private keys.",
        );
      }
      const certificates = parsePemCertificates(text);
      if (certificates.length === 0) {
        throw new ExtractionError("No certificate was found in that file.");
      }
      return certificates;
    }
    case "pkcs7":
      return parsePkcs7(bytes);
    case "der":
      return [Certificate.fromBER(toArrayBuffer(bytes))];
    default:
      throw new ExtractionError(
        "That file is not a certificate this app can read. Accepted: .pfx, " +
          ".p12, .pem, .crt, .cer, .der, .p7b, .p7c.",
      );
  }
}

/** Summaries of the end-entity certificates in a file. */
export async function extractLeaves(
  bytes: Uint8Array,
  password: string,
): Promise<CertificateSummary[]> {
  const certificates = await readCertificates(bytes, password);
  const leaves = selectLeaves(certificates);
  return Promise.all(leaves.map(summarise));
}
