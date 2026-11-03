-- ============================================================
-- Phishing Forensic Analysis System — Supabase Schema
-- Run this once in your Supabase SQL Editor
-- Project: <your Supabase project URL>
-- ============================================================

-- Enable UUID extension (usually already enabled in Supabase)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ── Main analyses table ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS analyses (
  id                TEXT PRIMARY KEY,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  verdict           TEXT NOT NULL,
  risk_score        INTEGER NOT NULL,
  confidence        INTEGER NOT NULL,
  severity          TEXT NOT NULL,
  sha256            TEXT NOT NULL,
  subject           TEXT,
  sender            TEXT,
  recipient         TEXT,
  email_date        TEXT,
  analysis_time_ms  INTEGER,
  summary           TEXT
);

-- ── Email headers ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS email_headers (
  id                  SERIAL PRIMARY KEY,
  analysis_id         TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
  spf_status          TEXT,
  dkim_status         TEXT,
  dmarc_status        TEXT,
  sender_reputation   INTEGER,
  return_path         TEXT,
  received_from       TEXT,
  message_id          TEXT,
  reply_to            TEXT,
  spoofing_indicators JSONB DEFAULT '[]'
);

-- ── URL scan results ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS url_results (
  id               SERIAL PRIMARY KEY,
  analysis_id      TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
  url              TEXT NOT NULL,
  defanged_url     TEXT,
  status           TEXT NOT NULL,
  reputation       INTEGER,
  category         TEXT,
  vt_detections    INTEGER,
  vt_total         INTEGER,
  urlscan_uuid     TEXT,
  urlscan_verdict  TEXT,
  phishing_flags   JSONB DEFAULT '[]'
);

-- ── Attachments ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS attachments (
  id              SERIAL PRIMARY KEY,
  analysis_id     TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
  filename        TEXT,
  content_type    TEXT,
  size_bytes      INTEGER,
  sha256          TEXT,
  status          TEXT,
  sandbox_result  TEXT
);

-- ── URL scan cache ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS url_cache (
  url_hash    TEXT PRIMARY KEY,
  url         TEXT NOT NULL,
  source      TEXT NOT NULL,
  result      TEXT NOT NULL,
  cached_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at  TIMESTAMPTZ NOT NULL
);

-- ── Phishing indicators ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS phishing_indicators (
  id           SERIAL PRIMARY KEY,
  analysis_id  TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
  type         TEXT NOT NULL,
  description  TEXT NOT NULL,
  severity     TEXT NOT NULL
);

-- ── Indexes for common queries ───────────────────────────────
CREATE INDEX IF NOT EXISTS idx_analyses_created_at       ON analyses(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_email_headers_analysis_id ON email_headers(analysis_id);
CREATE INDEX IF NOT EXISTS idx_url_results_analysis_id   ON url_results(analysis_id);
CREATE INDEX IF NOT EXISTS idx_attachments_analysis_id   ON attachments(analysis_id);
CREATE INDEX IF NOT EXISTS idx_indicators_analysis_id    ON phishing_indicators(analysis_id);
CREATE INDEX IF NOT EXISTS idx_url_cache_expires_at      ON url_cache(expires_at);

-- ── Row Level Security (RLS) — disable for service role ──────
-- The backend uses the service role key which bypasses RLS.
-- Enable RLS only if you plan to expose tables to anon/users.
ALTER TABLE analyses           DISABLE ROW LEVEL SECURITY;
ALTER TABLE email_headers      DISABLE ROW LEVEL SECURITY;
ALTER TABLE url_results        DISABLE ROW LEVEL SECURITY;
ALTER TABLE attachments        DISABLE ROW LEVEL SECURITY;
ALTER TABLE url_cache          DISABLE ROW LEVEL SECURITY;
ALTER TABLE phishing_indicators DISABLE ROW LEVEL SECURITY;
