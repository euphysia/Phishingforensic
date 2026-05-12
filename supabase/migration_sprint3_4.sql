-- ============================================================
-- Sprint 3 & 4 Schema Migration
-- Run this in Supabase SQL Editor to add new tables/columns
-- ============================================================

-- ── Sprint 3: Extend attachments table with deep analysis columns ─────────────
ALTER TABLE attachments ADD COLUMN IF NOT EXISTS md5            TEXT;
ALTER TABLE attachments ADD COLUMN IF NOT EXISTS risks          JSONB DEFAULT '[]';
ALTER TABLE attachments ADD COLUMN IF NOT EXISTS vt_detections  INTEGER DEFAULT 0;
ALTER TABLE attachments ADD COLUMN IF NOT EXISTS vt_total       INTEGER DEFAULT 0;
ALTER TABLE attachments ADD COLUMN IF NOT EXISTS metadata       JSONB DEFAULT '{}';
ALTER TABLE attachments ADD COLUMN IF NOT EXISTS audit_trail    JSONB DEFAULT '[]';

-- ── Sprint 3: Chain-of-Custody table ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS chain_of_custody (
  id            SERIAL PRIMARY KEY,
  analysis_id   TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
  email_sha256  TEXT NOT NULL,
  total_entries INTEGER NOT NULL DEFAULT 0,
  chain_intact  BOOLEAN NOT NULL DEFAULT true,
  entries       JSONB NOT NULL DEFAULT '[]',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_chain_of_custody_analysis_id ON chain_of_custody(analysis_id);

-- ── Sprint 4: IP reputation table (AbuseIPDB results) ────────────────────────
CREATE TABLE IF NOT EXISTS ip_reputations (
  id            SERIAL PRIMARY KEY,
  analysis_id   TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
  ip            TEXT NOT NULL,
  abuse_score   INTEGER NOT NULL DEFAULT 0,
  verdict       TEXT NOT NULL DEFAULT 'unknown',
  total_reports INTEGER DEFAULT 0,
  country_code  TEXT,
  isp           TEXT,
  is_tor        BOOLEAN DEFAULT false,
  categories    JSONB DEFAULT '[]',
  summary       TEXT,
  from_cache    BOOLEAN DEFAULT false,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ip_reputations_analysis_id ON ip_reputations(analysis_id);
CREATE INDEX IF NOT EXISTS idx_ip_reputations_ip          ON ip_reputations(ip);

-- ── Sprint 4: Extend url_results with PhishTank data ─────────────────────────
ALTER TABLE url_results ADD COLUMN IF NOT EXISTS phishtank_verified  BOOLEAN DEFAULT false;
ALTER TABLE url_results ADD COLUMN IF NOT EXISTS phishtank_phish_id  TEXT;
ALTER TABLE url_results ADD COLUMN IF NOT EXISTS phishtank_target     TEXT;

-- ── Disable RLS for new tables (service role handles access) ─────────────────
ALTER TABLE chain_of_custody DISABLE ROW LEVEL SECURITY;
ALTER TABLE ip_reputations   DISABLE ROW LEVEL SECURITY;
