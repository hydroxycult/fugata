-- Fugata Database Schema
-- Supports both SQLite and PostgreSQL

-- Secrets table
CREATE TABLE IF NOT EXISTS secrets (
    id TEXT PRIMARY KEY,
    encrypted_dek BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    nonce BLOB NOT NULL,
    tag BLOB NOT NULL,
    metadata BLOB,
    one_time INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    deletion_token_hash TEXT NOT NULL
);

-- Indexes for efficient queries
CREATE INDEX IF NOT EXISTS idx_secrets_expires_at ON secrets(expires_at);
CREATE INDEX IF NOT EXISTS idx_secrets_used ON secrets(used) WHERE one_time = TRUE;

-- Audit log table
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    secret_id TEXT,
    request_id TEXT,
    meta_json TEXT
);

-- Indexes for audit queries
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_secret_id ON audit(secret_id);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit(event_type);
