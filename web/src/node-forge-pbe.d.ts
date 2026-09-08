/**
 * Types for the parts of node-forge this app uses.
 *
 * Two gaps are filled here. First, `pki.pbe.getCipher` is part of forge's
 * public API but is missing from the community type definitions. Second, the
 * app imports forge's individual modules rather than its index, because
 * pulling in the whole library would add about 140 KB to a bundle the app has
 * to serve itself.
 */

declare module "node-forge/lib/forge" {
  import type { asn1, cipher, util } from "node-forge";

  interface Forge {
    readonly asn1: typeof asn1;
    readonly util: typeof util;
    readonly pki: {
      readonly pbe: {
        /**
         * Return a decipher for a PKCS#5 or PKCS#12 password-based scheme,
         * including the RC2 and Triple DES schemes WebCrypto lacks.
         */
        getCipher(oid: string, params: asn1.Asn1, password: string): cipher.BlockCipher;
      };
    };
  }

  const forge: Forge;
  export default forge;
}

/** Registers ASN.1 support on the forge object. Imported for its side effect. */
declare module "node-forge/lib/asn1";

/** Registers password-based encryption on the forge object. Side effect only. */
declare module "node-forge/lib/pbe";
