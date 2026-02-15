// Agent challenge-response authentication using Ed25519 or ECDSA P-256
// Agents register with a public key, login by signing a challenge

import { base64urlEncode, base64urlDecode } from './webauthn';

export interface AgentVerifyResult {
  valid: boolean;
  error?: string;
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
        sigBytes,
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
