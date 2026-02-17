-- Registration gate: application text + approved flag
ALTER TABLE users ADD COLUMN application_text TEXT;
ALTER TABLE users ADD COLUMN approved INTEGER NOT NULL DEFAULT 1;
-- approved=1 for existing users (default), approved=0 for pending applications
