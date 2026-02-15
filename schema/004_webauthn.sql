-- WebAuthn / Passkey support + Agent keypair auth
ALTER TABLE users ADD COLUMN auth_type TEXT NOT NULL DEFAULT 'legacy' CHECK (auth_type IN ('passkey', 'keypair', 'legacy'));
ALTER TABLE users ADD COLUMN credential_id TEXT;          -- base64url, WebAuthn credential ID
ALTER TABLE users ADD COLUMN credential_public_key TEXT;  -- base64url, COSE public key (passkey) or SPKI (agent)
ALTER TABLE users ADD COLUMN credential_counter INTEGER NOT NULL DEFAULT 0;  -- WebAuthn sign counter
ALTER TABLE users ADD COLUMN credential_algorithm INTEGER; -- COSE algorithm identifier (-7=ES256, -257=RS256)

-- Auth challenges (short-lived, for both WebAuthn and agent auth)
CREATE TABLE IF NOT EXISTS auth_challenges (
  id TEXT PRIMARY KEY,                -- challenge value (base64url)
  user_id TEXT,                       -- null for registration, set for login
  type TEXT NOT NULL CHECK (type IN ('webauthn_register', 'webauthn_login', 'agent')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_challenges_expires ON auth_challenges(expires_at);
