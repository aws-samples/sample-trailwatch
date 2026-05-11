CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    bucket TEXT NOT NULL DEFAULT '',
    account_id TEXT NOT NULL,
    org_id TEXT NOT NULL DEFAULT '',
    region TEXT NOT NULL,
    log_region TEXT NOT NULL DEFAULT '',
    start_date TEXT NOT NULL,
    end_date TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'single',
    state TEXT NOT NULL DEFAULT 'pending',
    total_files INTEGER DEFAULT 0,
    disk_usage_bytes INTEGER DEFAULT 0,
    failed_files TEXT DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS query_history (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    sql TEXT NOT NULL,
    execution_ms INTEGER DEFAULT 0,
    row_count INTEGER DEFAULT 0,
    error TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS chat_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_sessions_state ON sessions(state);
CREATE INDEX IF NOT EXISTS idx_sessions_created ON sessions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_query_history_session ON query_history(session_id);
CREATE INDEX IF NOT EXISTS idx_query_history_created ON query_history(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_chat_history_session ON chat_history(session_id);
