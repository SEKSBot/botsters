-- Rate limiting table
CREATE TABLE IF NOT EXISTS rate_limits (
  key TEXT NOT NULL,
  window INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (key, window)
);
