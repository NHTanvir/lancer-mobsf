-- Initial schema for lancer-mobsf

CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    filename    TEXT NOT NULL,
    file_type   TEXT NOT NULL CHECK (file_type IN ('apk', 'ipa')),
    sha256      TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'done', 'error')),
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT NOT NULL REFERENCES scans(id),
    rule_id     TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    description TEXT NOT NULL,
    file_path   TEXT,
    line_number INTEGER,
    cwe         TEXT,
    owasp       TEXT,
    masvs       TEXT,
    extra       TEXT
);
