import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DB_PATH = process.env.DB_PATH || path.join(__dirname, '..', 'data', 'forensics.db');

// Ensure data directory exists
const dataDir = path.dirname(DB_PATH);
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const db = new Database(DB_PATH);

// Enable WAL mode for better concurrency
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ── Schema Setup ──────────────────────────────────────────────────────────────

db.exec(`
  CREATE TABLE IF NOT EXISTS analyses (
    id          TEXT PRIMARY KEY,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    verdict     TEXT NOT NULL,
    risk_score  INTEGER NOT NULL,
    confidence  INTEGER NOT NULL,
    severity    TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    subject     TEXT,
    sender      TEXT,
    recipient   TEXT,
    email_date  TEXT,
    analysis_time_ms INTEGER,
    summary     TEXT
  );

  CREATE TABLE IF NOT EXISTS email_headers (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id   TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    spf_status    TEXT,
    dkim_status   TEXT,
    dmarc_status  TEXT,
    sender_reputation INTEGER,
    return_path   TEXT,
    received_from TEXT,
    message_id    TEXT,
    reply_to      TEXT,
    spoofing_indicators TEXT  -- JSON array
  );

  CREATE TABLE IF NOT EXISTS url_results (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id    TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    url            TEXT NOT NULL,
    defanged_url   TEXT,
    status         TEXT NOT NULL,
    reputation     INTEGER,
    category       TEXT,
    vt_detections  INTEGER,
    vt_total       INTEGER,
    urlscan_uuid   TEXT,
    urlscan_verdict TEXT,
    phishing_flags TEXT  -- JSON array of flags
  );

  CREATE TABLE IF NOT EXISTS attachments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id     TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    filename        TEXT,
    content_type    TEXT,
    size_bytes      INTEGER,
    sha256          TEXT,
    status          TEXT,
    sandbox_result  TEXT
  );

  CREATE TABLE IF NOT EXISTS url_cache (
    url_hash    TEXT PRIMARY KEY,
    url         TEXT NOT NULL,
    source      TEXT NOT NULL,
    result      TEXT NOT NULL,  -- JSON blob
    cached_at   TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at  TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS phishing_indicators (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id   TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    type          TEXT NOT NULL,
    description   TEXT NOT NULL,
    severity      TEXT NOT NULL
  );
`);

export default db;
