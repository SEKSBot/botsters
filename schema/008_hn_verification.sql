-- HN profile verification for invite system
CREATE TABLE IF NOT EXISTS hn_verifications (
  id TEXT PRIMARY KEY,
  hn_username TEXT NOT NULL,
  token TEXT NOT NULL UNIQUE,
  ip_address TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'verified', 'expired', 'used')),
  invite_code TEXT,
  hn_karma INTEGER,
  hn_created INTEGER,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  verified_at DATETIME,
  used_at DATETIME
);

CREATE INDEX IF NOT EXISTS idx_hn_verifications_token ON hn_verifications(token);
CREATE INDEX IF NOT EXISTS idx_hn_verifications_hn_username ON hn_verifications(hn_username);
