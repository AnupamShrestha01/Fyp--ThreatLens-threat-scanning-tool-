CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    scan_type TEXT NOT NULL,
    target TEXT,
    filename TEXT,
    file_size INTEGER,
    verdict TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    threat_score INTEGER DEFAULT 0,
    sha256 TEXT,
    md5 TEXT,
    result_json TEXT,
    scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
