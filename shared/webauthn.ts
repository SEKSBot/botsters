// WebAuthn server-side verification using Web Crypto API
// No npm dependencies — works in Cloudflare Workers

import { decodeCBOR } from './cbor';

// ── Base64url helpers ────────────────────────────────────────

export function base64urlEncode(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64urlDecode(s: string): Uint8Array {
  const padded = s.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice(0, (4 - (s.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// ── Challenge generation ─────────────────────────────────────

export function generateChallenge(): string {
  const buf = new Uint8Array(32);
  crypto.getRandomValues(buf);
  return base64urlEncode(buf);
}

// ── RP config ────────────────────────────────────────────────

export function getRpId(hostname: string): string {
  // For local dev, use localhost
  if (hostname === 'localhost' || hostname === '127.0.0.1') return 'localhost';
  return hostname;
}

export function getRpOrigin(url: string): string {
  const u = new URL(url);
  return u.origin;
}

// ── Registration: parse attestation response ─────────────────

export interface ParsedRegistration {
  credentialId: string;       // base64url
  publicKey: string;          // base64url (COSE key bytes)
  algorithm: number;          // COSE algorithm
  counter: number;
}

export async function verifyRegistration(
  clientDataJSON: string,      // base64url from browser
  attestationObject: string,   // base64url from browser
  challenge: string,           // expected challenge (base64url)
  rpOrigin: string,
  rpId: string,
): Promise<ParsedRegistration> {
  // 1. Decode and verify clientDataJSON
  const clientDataBytes = base64urlDecode(clientDataJSON);
  const clientData = JSON.parse(new TextDecoder().decode(clientDataBytes));

  if (clientData.type !== 'webauthn.create') {
    throw new Error('Invalid clientData type');
  }
  if (clientData.challenge !== challenge) {
    throw new Error('Challenge mismatch');
  }
  if (clientData.origin !== rpOrigin) {
    throw new Error(`Origin mismatch: got ${clientData.origin}, expected ${rpOrigin}`);
  }

  // 2. Decode attestation object (CBOR)
  const attObjBytes = base64urlDecode(attestationObject);
  const attObj = decodeCBOR(attObjBytes);

  const authData: Uint8Array = attObj.authData;
  if (!authData || authData.length < 37) {
    throw new Error('Invalid authData');
  }

  // 3. Parse authData
  // rpIdHash (32) + flags (1) + signCount (4) + attestedCredentialData (variable)
  const flags = authData[32];
  const AT = (flags & 0x40) !== 0; // attested credential data present
  if (!AT) throw new Error('No attested credential data in authData');

  const signCount = (authData[33] << 24) | (authData[34] << 16) | (authData[35] << 8) | authData[36];

  // Verify rpIdHash
  const expectedRpIdHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rpId)));
  const actualRpIdHash = authData.slice(0, 32);
  if (!timingSafeEqual(expectedRpIdHash, actualRpIdHash)) {
    throw new Error('RP ID hash mismatch');
  }

  // 4. Parse attested credential data
  // aaguid (16) + credIdLen (2) + credId (credIdLen) + credentialPublicKey (CBOR)
  let pos = 37;
  // skip aaguid
  pos += 16;
  const credIdLen = (authData[pos] << 8) | authData[pos + 1];
  pos += 2;
  const credentialId = authData.slice(pos, pos + credIdLen);
  pos += credIdLen;

  // The rest is the COSE public key
  const publicKeyBytes = authData.slice(pos);
  const coseKey = decodeCBOR(publicKeyBytes);

  // COSE key type 2 = EC2, algorithm -7 = ES256
  const algorithm = coseKey[3]; // alg
  if (algorithm !== -7 && algorithm !== -257) {
    throw new Error(`Unsupported algorithm: ${algorithm}. Only ES256 (-7) and RS256 (-257) supported.`);
  }

  return {
    credentialId: base64urlEncode(credentialId),
    publicKey: base64urlEncode(publicKeyBytes),
    algorithm,
    counter: signCount,
  };
}

// ── Login: verify assertion ──────────────────────────────────

export async function verifyAssertion(
  clientDataJSON: string,       // base64url
  authenticatorData: string,    // base64url
  signature: string,            // base64url
  challenge: string,            // expected challenge
  rpOrigin: string,
  rpId: string,
  storedPublicKey: string,      // base64url (COSE key bytes)
  storedAlgorithm: number,
  storedCounter: number,
): Promise<{ newCounter: number }> {
  // 1. Verify clientDataJSON
  const clientDataBytes = base64urlDecode(clientDataJSON);
  const clientData = JSON.parse(new TextDecoder().decode(clientDataBytes));

  if (clientData.type !== 'webauthn.get') {
    throw new Error('Invalid clientData type');
  }
  if (clientData.challenge !== challenge) {
    throw new Error('Challenge mismatch');
  }
  if (clientData.origin !== rpOrigin) {
    throw new Error(`Origin mismatch: got ${clientData.origin}, expected ${rpOrigin}`);
  }

  // 2. Parse authenticator data
  const authDataBytes = base64urlDecode(authenticatorData);
  if (authDataBytes.length < 37) throw new Error('Invalid authenticator data');

  // Verify rpIdHash
  const expectedRpIdHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rpId)));
  const actualRpIdHash = authDataBytes.slice(0, 32);
  if (!timingSafeEqual(expectedRpIdHash, actualRpIdHash)) {
    throw new Error('RP ID hash mismatch');
  }

  // Check user present flag
  const flags = authDataBytes[32];
  if ((flags & 0x01) === 0) throw new Error('User not present');

  // Check counter
  const newCounter = (authDataBytes[33] << 24) | (authDataBytes[34] << 16) | (authDataBytes[35] << 8) | authDataBytes[36];
  if (storedCounter > 0 && newCounter <= storedCounter) {
    throw new Error('Counter not incremented — possible credential cloning');
  }

  // 3. Verify signature
  // signature is over (authData || SHA-256(clientDataJSON))
  const clientDataHash = new Uint8Array(await crypto.subtle.digest('SHA-256', clientDataBytes));
  const signedData = new Uint8Array(authDataBytes.length + clientDataHash.length);
  signedData.set(authDataBytes);
  signedData.set(clientDataHash, authDataBytes.length);

  const sigBytes = base64urlDecode(signature);

  // Import the stored COSE public key
  const cryptoKey = await importCOSEKey(storedPublicKey, storedAlgorithm);

  let valid: boolean;
  if (storedAlgorithm === -7) {
    // ES256: signature is DER-encoded, need to convert to raw r||s for Web Crypto
    const rawSig = derToRaw(sigBytes);
    valid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      cryptoKey,
      rawSig,
      signedData,
    );
  } else if (storedAlgorithm === -257) {
    valid = await crypto.subtle.verify(
      { name: 'RSASSA-PKCS1-v1_5' },
      cryptoKey,
      sigBytes,
      signedData,
    );
  } else {
    throw new Error(`Unsupported algorithm: ${storedAlgorithm}`);
  }

  if (!valid) throw new Error('Signature verification failed');

  return { newCounter };
}

// ── COSE key import ──────────────────────────────────────────

async function importCOSEKey(publicKeyB64url: string, algorithm: number): Promise<CryptoKey> {
  const keyBytes = base64urlDecode(publicKeyB64url);
  const coseKey = decodeCBOR(keyBytes);

  if (algorithm === -7) {
    // EC2 key: extract x, y coordinates
    const x = coseKey[-2] as Uint8Array; // 32 bytes
    const y = coseKey[-3] as Uint8Array; // 32 bytes
    if (!x || !y || x.length !== 32 || y.length !== 32) {
      throw new Error('Invalid EC2 key: missing or wrong-size x/y');
    }

    // Build uncompressed point: 0x04 || x || y
    const rawKey = new Uint8Array(65);
    rawKey[0] = 0x04;
    rawKey.set(x, 1);
    rawKey.set(y, 33);

    return crypto.subtle.importKey(
      'raw',
      rawKey,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );
  } else if (algorithm === -257) {
    // RSA key: build SPKI from COSE components
    // This is complex; for now just support ES256
    throw new Error('RS256 import not yet implemented — use a passkey with ES256');
  }

  throw new Error(`Cannot import COSE key with algorithm ${algorithm}`);
}

// ── DER to raw signature conversion (for ECDSA) ─────────────

function derToRaw(der: Uint8Array): Uint8Array {
  // DER: 0x30 <len> 0x02 <rlen> <r> 0x02 <slen> <s>
  if (der[0] !== 0x30) throw new Error('Not a DER sequence');

  let offset = 2;
  if (der[1] & 0x80) offset += (der[1] & 0x7f); // long form length

  // Read r
  if (der[offset] !== 0x02) throw new Error('Expected INTEGER tag for r');
  offset++;
  const rLen = der[offset++];
  let r = der.slice(offset, offset + rLen);
  offset += rLen;

  // Read s
  if (der[offset] !== 0x02) throw new Error('Expected INTEGER tag for s');
  offset++;
  const sLen = der[offset++];
  let s = der.slice(offset, offset + sLen);

  // Trim leading zeros (DER integers are signed, may have leading 0x00)
  if (r.length === 33 && r[0] === 0) r = r.slice(1);
  if (s.length === 33 && s[0] === 0) s = s.slice(1);

  // Pad to 32 bytes
  const raw = new Uint8Array(64);
  raw.set(r, 32 - r.length);
  raw.set(s, 64 - s.length);
  return raw;
}

// ── Timing-safe comparison ───────────────────────────────────

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}
