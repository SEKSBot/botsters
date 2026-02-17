// Agent challenge-response authentication using Ed25519 or ECDSA P-256
// Agents register with a public key, login by signing a challenge

import { base64urlEncode, base64urlDecode } from './webauthn';

export interface AgentVerifyResult {
  valid: boolean;
  error?: string;
}

/**
 * Convert DER-encoded ECDSA signature to raw r||s format (64 bytes for P-256).
 * OpenSSL outputs DER; Web Crypto expects raw. We accept both.
 */
function derToRaw(sig: Uint8Array): Uint8Array {
  // DER: 0x30 <len> 0x02 <r_len> <r> 0x02 <s_len> <s>
  if (sig[0] !== 0x30) return sig; // not DER, assume already raw

  let i = 2; // skip SEQUENCE tag + length
  if (sig[i] !== 0x02) return sig;
  const rLen = sig[i + 1];
  const r = sig.slice(i + 2, i + 2 + rLen);
  i = i + 2 + rLen;

  if (sig[i] !== 0x02) return sig;
  const sLen = sig[i + 1];
  const s = sig.slice(i + 2, i + 2 + sLen);

  // Pad/trim to 32 bytes each (P-256)
  const rPad = new Uint8Array(32);
  const sPad = new Uint8Array(32);
  rPad.set(r.length > 32 ? r.slice(r.length - 32) : r, 32 - Math.min(r.length, 32));
  sPad.set(s.length > 32 ? s.slice(s.length - 32) : s, 32 - Math.min(s.length, 32));

  const raw = new Uint8Array(64);
  raw.set(rPad, 0);
  raw.set(sPad, 32);
  return raw;
}

/**
 * Verify an agent's signature over a challenge.
 * Supports ECDSA P-256 (stored as SPKI base64url).
 * Ed25519 support depends on runtime — CF Workers added it recently.
 */
export async function verifyAgentSignature(
  challenge: string,          // the challenge string that was signed
  signatureB64url: string,    // base64url signature
  publicKeyB64url: string,    // base64url SPKI-encoded public key
  algorithm: string,          // 'ES256' or 'Ed25519'
): Promise<AgentVerifyResult> {
  try {
    const sigBytes = base64urlDecode(signatureB64url);
    const pubKeyBytes = base64urlDecode(publicKeyB64url);
    const challengeBytes = new TextEncoder().encode(challenge);

    let cryptoKey: CryptoKey;
    let valid: boolean;

    if (algorithm === 'ES256') {
      // Accept both DER (openssl default) and raw r||s (Web Crypto native)
      const rawSig = derToRaw(sigBytes);

      cryptoKey = await crypto.subtle.importKey(
        'spki',
        pubKeyBytes,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['verify'],
      );
      valid = await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        cryptoKey,
        rawSig,
        challengeBytes,
      );
    } else if (algorithm === 'Ed25519') {
      cryptoKey = await crypto.subtle.importKey(
        'spki',
        pubKeyBytes,
        { name: 'Ed25519' },
        false,
        ['verify'],
      );
      valid = await crypto.subtle.verify(
        'Ed25519',
        cryptoKey,
        sigBytes,
        challengeBytes,
      );
    } else {
      return { valid: false, error: `Unsupported algorithm: ${algorithm}` };
    }

    return { valid };
  } catch (e: any) {
    return { valid: false, error: e.message || 'Verification failed' };
  }
}

/**
 * Validate that a provided public key is well-formed by importing it.
 */
export async function validatePublicKey(
  publicKeyB64url: string,
  algorithm: string,
): Promise<{ valid: boolean; error?: string }> {
  try {
    const pubKeyBytes = base64urlDecode(publicKeyB64url);

    if (algorithm === 'ES256') {
      await crypto.subtle.importKey(
        'spki', pubKeyBytes,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false, ['verify'],
      );
    } else if (algorithm === 'Ed25519') {
      await crypto.subtle.importKey(
        'spki', pubKeyBytes,
        { name: 'Ed25519' },
        false, ['verify'],
      );
    } else {
      return { valid: false, error: `Unsupported algorithm: ${algorithm}` };
    }

    return { valid: true };
  } catch (e: any) {
    return { valid: false, error: e.message || 'Invalid public key' };
  }
}
