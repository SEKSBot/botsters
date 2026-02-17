-- Add Workers AI as detection method for injection scanner

-- Drop the existing check constraint and recreate with workers_ai support
-- SQLite doesn't support ALTER COLUMN, so we'll use a temp table approach

CREATE TABLE injection_log_new (
  id TEXT PRIMARY KEY,
  source_type TEXT NOT NULL CHECK (source_type IN ('submission', 'comment', 'link')),
  raw_pattern TEXT NOT NULL,
  detection_method TEXT NOT NULL CHECK (detection_method IN ('scanner', 'heuristic', 'community', 'manual', 'workers_ai')),
  classifier_score REAL,
  category TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Copy existing data
INSERT INTO injection_log_new SELECT * FROM injection_log;

-- Drop old table and rename new one
DROP TABLE injection_log;
ALTER TABLE injection_log_new RENAME TO injection_log;

-- Recreate indexes
CREATE INDEX idx_injection_log_created ON injection_log(created_at DESC);
CREATE INDEX idx_injection_log_category ON injection_log(category);