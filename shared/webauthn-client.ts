// Client-side JavaScript strings for WebAuthn ceremonies
// These get inlined into <script> tags on auth pages

export const REGISTER_SCRIPT = `
// Base64url helpers
function b64urlEncode(buf) {
  const bytes = new Uint8Array(buf);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(s) {
  const padded = s.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice(0, (4 - (s.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

const form = document.getElementById('register-form');
const statusEl = document.getElementById('auth-status');
const passkeyBtn = document.getElementById('passkey-btn');

if (window.PublicKeyCredential) {
  // Show passkey option, hide fallback
  document.getElementById('passkey-section').style.display = 'block';
} else {
  statusEl.textContent = 'Your browser does not support passkeys. Registration requires a modern browser.';
}

if (passkeyBtn) {
  passkeyBtn.addEventListener('click', async function(e) {
    e.preventDefault();
    const username = document.getElementById('username').value.trim().toLowerCase();
    if (!username || !/^[a-z0-9_-]+$/.test(username)) {
      statusEl.textContent = 'Invalid username.';
      return;
    }
    statusEl.textContent = 'Starting passkey registration...';
    try {
      // 1. Get challenge from server
      const inviteCode = document.getElementById('invite_code')?.value || '';
      const identityType = document.getElementById('identity_type')?.value || 'human';
      const resp = await fetch('/api/auth/webauthn/register/begin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, invite_code: inviteCode, identity_type: identityType }),
      });
      const opts = await resp.json();
      if (opts.error) { statusEl.textContent = opts.error; return; }

      // 2. Create credential
      const publicKey = {
        challenge: b64urlDecode(opts.challenge),
        rp: opts.rp,
        user: {
          id: b64urlDecode(opts.user.id),
          name: opts.user.name,
          displayName: opts.user.displayName,
        },
        pubKeyCredParams: opts.pubKeyCredParams,
        timeout: 60000,
        authenticatorSelection: {
          residentKey: 'preferred',
          userVerification: 'preferred',
        },
        attestation: 'none',
      };
      const credential = await navigator.credentials.create({ publicKey });

      // 3. Send to server
      const finishResp = await fetch('/api/auth/webauthn/register/finish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username,
          invite_code: inviteCode,
          identity_type: identityType,
          credential: {
            id: credential.id,
            rawId: b64urlEncode(credential.rawId),
            type: credential.type,
            response: {
              clientDataJSON: b64urlEncode(credential.response.clientDataJSON),
              attestationObject: b64urlEncode(credential.response.attestationObject),
            },
          },
        }),
      });
      const result = await finishResp.json();
      if (result.ok) {
        window.location.href = '/';
      } else {
        statusEl.textContent = result.error || 'Registration failed.';
      }
    } catch (err) {
      statusEl.textContent = 'Passkey error: ' + err.message;
    }
  });
}
`;

export const LOGIN_SCRIPT = `
function b64urlEncode(buf) {
  const bytes = new Uint8Array(buf);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(s) {
  const padded = s.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice(0, (4 - (s.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

const statusEl = document.getElementById('auth-status');
const passkeyBtn = document.getElementById('passkey-login-btn');

if (window.PublicKeyCredential && passkeyBtn) {
  document.getElementById('passkey-login-section').style.display = 'block';
}

if (passkeyBtn) {
  passkeyBtn.addEventListener('click', async function(e) {
    e.preventDefault();
    const username = document.getElementById('username').value.trim().toLowerCase();
    if (!username) { statusEl.textContent = 'Enter your username.'; return; }
    statusEl.textContent = 'Starting passkey login...';
    try {
      const resp = await fetch('/api/auth/webauthn/login/begin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username }),
      });
      const opts = await resp.json();
      if (opts.error) { statusEl.textContent = opts.error; return; }

      const publicKey = {
        challenge: b64urlDecode(opts.challenge),
        rpId: opts.rpId,
        allowCredentials: opts.allowCredentials.map(c => ({
          id: b64urlDecode(c.id),
          type: c.type,
          transports: c.transports,
        })),
        timeout: 60000,
        userVerification: 'preferred',
      };
      const assertion = await navigator.credentials.get({ publicKey });

      const finishResp = await fetch('/api/auth/webauthn/login/finish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username,
          credential: {
            id: assertion.id,
            rawId: b64urlEncode(assertion.rawId),
            type: assertion.type,
            response: {
              clientDataJSON: b64urlEncode(assertion.response.clientDataJSON),
              authenticatorData: b64urlEncode(assertion.response.authenticatorData),
              signature: b64urlEncode(assertion.response.signature),
              userHandle: assertion.response.userHandle ? b64urlEncode(assertion.response.userHandle) : null,
            },
          },
        }),
      });
      const result = await finishResp.json();
      if (result.ok) {
        window.location.href = '/';
      } else {
        statusEl.textContent = result.error || 'Login failed.';
      }
    } catch (err) {
      statusEl.textContent = 'Passkey error: ' + err.message;
    }
  });
}
`;

export const UPGRADE_SCRIPT = `
function b64urlEncode(buf) {
  const bytes = new Uint8Array(buf);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(s) {
  const padded = s.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice(0, (4 - (s.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

const statusEl = document.getElementById('auth-status');
const upgradeBtn = document.getElementById('upgrade-btn');

if (upgradeBtn) {
  upgradeBtn.addEventListener('click', async function(e) {
    e.preventDefault();
    statusEl.textContent = 'Starting passkey setup...';
    try {
      const resp = await fetch('/api/auth/webauthn/upgrade/begin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      const opts = await resp.json();
      if (opts.error) { statusEl.textContent = opts.error; return; }

      const publicKey = {
        challenge: b64urlDecode(opts.challenge),
        rp: opts.rp,
        user: {
          id: b64urlDecode(opts.user.id),
          name: opts.user.name,
          displayName: opts.user.displayName,
        },
        pubKeyCredParams: opts.pubKeyCredParams,
        timeout: 60000,
        authenticatorSelection: {
          residentKey: 'preferred',
          userVerification: 'preferred',
        },
        attestation: 'none',
      };
      const credential = await navigator.credentials.create({ publicKey });

      const finishResp = await fetch('/api/auth/webauthn/upgrade/finish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          credential: {
            id: credential.id,
            rawId: b64urlEncode(credential.rawId),
            type: credential.type,
            response: {
              clientDataJSON: b64urlEncode(credential.response.clientDataJSON),
              attestationObject: b64urlEncode(credential.response.attestationObject),
            },
          },
        }),
      });
      const result = await finishResp.json();
      if (result.ok) {
        statusEl.textContent = 'Passkey registered! Your account is now secured.';
        statusEl.style.color = '#0a0';
        if (document.getElementById('upgrade-banner')) {
          document.getElementById('upgrade-banner').style.display = 'none';
        }
      } else {
        statusEl.textContent = result.error || 'Upgrade failed.';
      }
    } catch (err) {
      statusEl.textContent = 'Passkey error: ' + err.message;
    }
  });
}
`;
