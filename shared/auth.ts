// Simple cookie-based auth — no real crypto yet, just HMAC signing
// Phase 2 will add passwords, proper key derivation, etc.

const SECRET = 'botsters-dev-secret-change-me'; // TODO: move to env

async function hmacSign(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function createSessionCookie(userId: string): Promise<string> {
  const sig = await hmacSign(userId);
  return `session=${userId}.${sig}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000`;
}

export async function parseSession(cookie: string | undefined): Promise<string | null> {
  if (!cookie) return null;
  const match = cookie.match(/session=([^;]+)/);
  if (!match) return null;
  const [userId, sig] = match[1].split('.');
  if (!userId || !sig) return null;
  const expected = await hmacSign(userId);
  return sig === expected ? userId : null;
}

export function clearSessionCookie(): string {
  return 'session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0';
}
