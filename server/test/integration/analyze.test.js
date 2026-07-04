import { describe, it, expect } from 'vitest';
import request from 'supertest';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { buildTestApp } from './testApp.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = buildTestApp();

const PHISHING_EML_PATH = path.join(__dirname, '../samples/paypal-phishing.eml');
const BENIGN_EML        = path.join(__dirname, '../samples/benign-email.eml');
const PHISHING_EML_RAW  = fs.readFileSync(PHISHING_EML_PATH, 'utf8');

// The dedup/cache path keys off the SHA-256 of the raw email, and the Supabase project used
// here is a persistent dev database — so a byte-identical submission of the sample file would
// return a stale, previously-cached analysis instead of exercising a fresh pipeline run.
// Injecting a per-run nonce guarantees this test always drives a brand-new analysis.
function freshPhishingSample() {
  const nonce = `X-Test-Nonce: ${Date.now()}-${Math.random().toString(36).slice(2)}`;
  return PHISHING_EML_RAW.replace('MIME-Version: 1.0', `MIME-Version: 1.0\n${nonce}`);
}

describe('POST /api/analyze — full pipeline, phishing sample', () => {
  it('runs the complete forensic pipeline on a known phishing email end-to-end', async () => {
    const res = await request(app)
      .post('/api/analyze')
      .send({ rawEmail: freshPhishingSample() });

    expect(res.status).toBe(200);
    expect(res.body.cached).toBeFalsy();
    expect(['phishing', 'suspicious']).toContain(res.body.verdict);
    expect(res.body.riskScore).toBeGreaterThanOrEqual(30); // riskScore: 0 = clean, 100 = confirmed phishing

    // Header analysis picked up the forged Return-Path / SPF-DKIM-DMARC failures
    expect(res.body.headerAnalysis.spfStatus).toBe('fail');
    expect(res.body.headerAnalysis.dkimStatus).toBe('fail');
    expect(res.body.headerAnalysis.dmarcStatus).toBe('fail');
    expect(res.body.headerAnalysis.spoofingIndicators.length).toBeGreaterThan(0);

    // URL analysis found the malicious login link (exactly 4 distinct URLs — see the
    // urlExtractor bracket-duplication regression test for why this used to be 8)
    expect(res.body.urlAnalysis.totalUrls).toBe(4);
    expect(res.body.urlAnalysis.maliciousUrls + res.body.urlAnalysis.suspiciousUrls).toBeGreaterThan(0);

    // Chain-of-custody was built and is internally consistent
    expect(res.body.chainOfCustody.chainIntact).toBe(true);
    expect(res.body.chainOfCustody.totalEntries).toBeGreaterThan(0);

    // Evidence hash and IOC-relevant fields are present
    expect(res.body.email.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(Array.isArray(res.body.indicators)).toBe(true);
    expect(res.body.indicators.length).toBeGreaterThan(0);
  });

  it('returns the same analysis (cache hit) for a byte-identical resubmission, with sub-details intact', async () => {
    const sample = freshPhishingSample();
    const first  = await request(app).post('/api/analyze').send({ rawEmail: sample });
    const second = await request(app).post('/api/analyze').send({ rawEmail: sample });

    expect(second.body.cached).toBe(true);
    expect(second.body.verdict).toBe(first.body.verdict);

    // Regression check: the cache-hit clone previously discarded id via `id: undefined`,
    // which supabase-js sends as an explicit SQL NULL against a NOT-NULL id column with no
    // default — so every cloned sub-table insert (urls, headers, indicators, custody...)
    // silently failed and the cached response reported 0 URLs/indicators/custody entries.
    expect(second.body.urlAnalysis.totalUrls).toBe(first.body.urlAnalysis.totalUrls);
    expect(second.body.urlAnalysis.totalUrls).toBeGreaterThan(0);
    expect(second.body.indicators.length).toBe(first.body.indicators.length);
    expect(second.body.chainOfCustody.entries.length).toBeGreaterThan(0);
  });
});

describe('POST /api/analyze — benign email', () => {
  it('scores a legitimate, fully-authenticated personal email as low risk', async () => {
    const res = await request(app)
      .post('/api/analyze')
      .attach('email', BENIGN_EML);

    expect(res.status).toBe(200);
    expect(res.body.headerAnalysis.spfStatus).toBe('pass');
    expect(res.body.headerAnalysis.dkimStatus).toBe('pass');
    expect(res.body.headerAnalysis.dmarcStatus).toBe('pass');
    expect(res.body.urlAnalysis.totalUrls).toBe(0);
    expect(res.body.verdict).not.toBe('phishing');
  });
});

describe('POST /api/analyze — input validation', () => {
  it('rejects a request with no email content with 400', async () => {
    const res = await request(app).post('/api/analyze').send();
    expect(res.status).toBe(400);
  });

  it('rejects an empty/too-short raw email with 400', async () => {
    const res = await request(app).post('/api/analyze').send({ rawEmail: 'hi' });
    expect(res.status).toBe(400);
  });
});

describe('Guest trial limit', () => {
  it('allows exactly 3 free analyses then rejects the 4th with 403 TRIAL_LIMIT', async () => {
    const agent = request.agent(app);

    for (let i = 0; i < 3; i++) {
      const res = await agent.post('/api/analyze').attach('email', BENIGN_EML);
      expect(res.status).toBe(200);
      expect(res.body.trialRemaining).toBe(2 - i);
    }

    const fourth = await agent.post('/api/analyze').attach('email', BENIGN_EML);
    expect(fourth.status).toBe(403);
    expect(fourth.body.code).toBe('TRIAL_LIMIT');
  });
});
