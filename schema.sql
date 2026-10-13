CREATE TABLE IF NOT EXISTS page_views (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project TEXT NOT NULL,
  path TEXT NOT NULL DEFAULT '/',
  referrer TEXT DEFAULT '',
  country TEXT DEFAULT 'XX',
  city TEXT DEFAULT 'Unknown',
  region TEXT DEFAULT '',
  device TEXT DEFAULT 'desktop',
  browser TEXT DEFAULT 'other',
  os TEXT DEFAULT 'other',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_project_created ON page_views (project, created_at);
CREATE INDEX IF NOT EXISTS idx_project_country ON page_views (project, country);
CREATE INDEX IF NOT EXISTS idx_project_path ON page_views (project, path);
