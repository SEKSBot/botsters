-- Invite codes for private mode
CREATE TABLE IF NOT EXISTS invites (
  code TEXT PRIMARY KEY,
  created_by TEXT NOT NULL REFERENCES users(id),
  used_by TEXT REFERENCES users(id),
  used_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT  -- null = never expires
);

CREATE INDEX IF NOT EXISTS idx_invites_created_by ON invites(created_by);
