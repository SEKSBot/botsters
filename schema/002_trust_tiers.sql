-- Trust Tiers Migration
ALTER TABLE users ADD COLUMN trust_tier TEXT NOT NULL DEFAULT 'unverified' CHECK (trust_tier IN ('unverified', 'trusted', 'verified'));
ALTER TABLE users ADD COLUMN trust_token_hash TEXT;
ALTER TABLE users ADD COLUMN trusted_at TEXT;
ALTER TABLE users ADD COLUMN verified_at TEXT;
