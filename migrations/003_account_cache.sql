-- Account-name cache. Populated from AWS Organizations ListAccounts (source='organizations')
-- with user-supplied overrides (source='manual'). When both exist for the same id, the manual
-- entry wins at read time — the resolver does the merge in code so we keep both values around
-- and an Org refresh does not silently overwrite a deliberate override.
CREATE TABLE IF NOT EXISTS account_names (
    account_id TEXT NOT NULL,
    name       TEXT NOT NULL,
    source     TEXT NOT NULL CHECK (source IN ('organizations', 'manual')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (account_id, source)
);

CREATE INDEX IF NOT EXISTS idx_account_names_id ON account_names(account_id);
