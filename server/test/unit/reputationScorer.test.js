import { describe, it, expect } from 'vitest';
import { scoreUrl, computeEmailRiskScore, scoreIpReputation } from '../../analyzers/reputationScorer.js';

describe('scoreUrl', () => {
  it('scores a clean URL with no signals as 100/safe', () => {
    const result = scoreUrl(null, null, {}, [], null, null);
    expect(result.score).toBe(100);
    expect(result.status).toBe('safe');
  });

  it('applies a proportional VirusTotal penalty based on detection ratio', () => {
    const result = scoreUrl({ detections: 30, total: 60, categories: ['malware'] }, null, {}, [], null, null);
    expect(result.score).toBeLessThan(100);
    expect(result.category).toContain('malware');
  });

  it('applies a flat -35 penalty for a URLScan "malicious" verdict', () => {
    const clean = scoreUrl(null, null, {}, [], null, null).score;
    const malicious = scoreUrl(null, { score: 90, malicious: true }, {}, [], null, null).score;
    expect(clean - malicious).toBe(35);
  });

  it('applies a severe penalty for a PhishTank-verified phishing URL', () => {
    const result = scoreUrl(null, null, {}, [], { available: true, isPhishing: true, verified: true, target: 'PayPal' }, null);
    expect(result.score).toBeLessThanOrEqual(30);
    expect(result.status).toBe('malicious');
    expect(result.category).toContain('Verified Phishing URL');
  });

  it('penalizes unverified PhishTank hits less than verified ones', () => {
    const verified = scoreUrl(null, null, {}, [], { available: true, isPhishing: true, verified: true }, null).score;
    const unverified = scoreUrl(null, null, {}, [], { available: true, isPhishing: true, verified: false }, null).score;
    expect(unverified).toBeGreaterThan(verified);
  });

  it('weighs heuristic indicator severities correctly (high > medium > low)', () => {
    const high = scoreUrl(null, null, {}, [{ type: 'x', severity: 'high' }]).score;
    const medium = scoreUrl(null, null, {}, [{ type: 'y', severity: 'medium' }]).score;
    const low = scoreUrl(null, null, {}, [{ type: 'z', severity: 'low' }]).score;
    expect(high).toBeLessThan(medium);
    expect(medium).toBeLessThan(low);
  });

  it('penalizes newly-registered domains more than recently-registered ones', () => {
    const newDomain = scoreUrl(null, null, {}, [], null, { ageRisk: 'high' }).score;
    const recentDomain = scoreUrl(null, null, {}, [], null, { ageRisk: 'medium' }).score;
    expect(newDomain).toBeLessThan(recentDomain);
  });

  it('applies structural penalties for IP-based and shortened URLs', () => {
    const ipBased = scoreUrl(null, null, { isIpBased: true }, []).score;
    const shortener = scoreUrl(null, null, { isShortener: true }, []).score;
    expect(ipBased).toBe(85);
    expect(shortener).toBe(92);
  });

  it('floors the score at 0 when many penalties stack', () => {
    const result = scoreUrl(
      { detections: 60, total: 60 },
      { score: 100, malicious: true },
      { isIpBased: true, isShortener: true },
      [{ type: 'a', severity: 'high' }, { type: 'b', severity: 'high' }],
      { available: true, isPhishing: true, verified: true },
      { ageRisk: 'high' }
    );
    expect(result.score).toBe(0);
    expect(result.status).toBe('malicious');
  });

  it('classifies scores into safe/suspicious/malicious bands correctly', () => {
    expect(scoreUrl(null, null, {}, [{ type: 'a', severity: 'high' }]).status).toBe('safe'); // 80
    expect(scoreUrl(null, null, {}, [
      { type: 'a', severity: 'high' }, { type: 'b', severity: 'high' }, { type: 'c', severity: 'high' },
    ]).status).toBe('suspicious'); // 40
  });
});

describe('computeEmailRiskScore', () => {
  const cleanHeader = { senderReputation: 100 };

  it('uses only the header signal when no URLs/IPs/attachments/body are present', () => {
    const { riskScore, scoreBreakdown } = computeEmailRiskScore(cleanHeader, [], []);
    expect(Object.keys(scoreBreakdown)).toEqual(['header', 'indicators']);
    expect(riskScore).toBe(0);
  });

  it('re-normalizes weights so an inactive source cannot dilute the score', () => {
    const { riskScore } = computeEmailRiskScore({ senderReputation: 0 }, [], []);
    // header risk = 100, indicators risk = 0 → weighted avg over active (header 0.30, indicators 0.20)
    expect(riskScore).toBe(60);
  });

  it('increases confidence as more independent signal sources become active', () => {
    const headerOnly = computeEmailRiskScore(cleanHeader, [], []).confidence;
    const withUrlAndIp = computeEmailRiskScore(cleanHeader, [{ score: 50 }], [], [{ abuseScore: 10 }]).confidence;
    expect(withUrlAndIp).toBeGreaterThan(headerOnly);
  });

  it('classifies a high risk score as phishing with critical/high severity', () => {
    const { verdict, severity } = computeEmailRiskScore({ senderReputation: 0 }, [{ score: 0 }], [
      { severity: 'high', source: 'x' }, { severity: 'high', source: 'x' },
    ]);
    expect(verdict).toBe('phishing');
    expect(['critical', 'high']).toContain(severity);
  });

  it('classifies a clean, fully-authenticated email as clean/low severity', () => {
    const { verdict, severity, riskScore } = computeEmailRiskScore(cleanHeader, [{ score: 100 }], []);
    expect(verdict).toBe('clean');
    expect(severity).toBe('low');
    expect(riskScore).toBe(0);
  });

  it('excludes body-ai-sourced indicators from the hard-indicator score to avoid double counting', () => {
    const withoutBody = computeEmailRiskScore(cleanHeader, [], [{ severity: 'high', source: 'body-ai' }]);
    const withoutAny = computeEmailRiskScore(cleanHeader, [], []);
    expect(withoutBody.riskScore).toBe(withoutAny.riskScore);
  });

  it('folds in the AI body risk score as its own weighted signal', () => {
    const { scoreBreakdown } = computeEmailRiskScore(cleanHeader, [], [], [], [], { bodyRiskScore: 80 });
    expect(scoreBreakdown.body).toEqual({ risk: 80, weight: 0.25 });
  });
});

describe('scoreIpReputation', () => {
  it('returns risk 0 / unknown when reputation data is unavailable', () => {
    expect(scoreIpReputation(null)).toEqual({ risk: 0, verdict: 'unknown', summary: 'IP reputation data unavailable' });
  });

  it('classifies verdicts using the malicious/suspicious/clean thresholds', () => {
    expect(scoreIpReputation({ available: true, abuseScore: 80 }).verdict).toBe('malicious');
    expect(scoreIpReputation({ available: true, abuseScore: 40 }).verdict).toBe('suspicious');
    expect(scoreIpReputation({ available: true, abuseScore: 5 }).verdict).toBe('clean');
  });

  it('weights recent reports (<=7 days) more heavily than older ones', () => {
    const now = new Date().toISOString();
    const monthAgo = new Date(Date.now() - 20 * 86400000).toISOString();
    const recent = scoreIpReputation({ available: true, abuseScore: 50, lastReportedAt: now }).risk;
    const older = scoreIpReputation({ available: true, abuseScore: 50, lastReportedAt: monthAgo }).risk;
    expect(recent).toBeGreaterThan(older);
  });

  it('caps the adjusted score at 100', () => {
    const now = new Date().toISOString();
    const result = scoreIpReputation({ available: true, abuseScore: 95, lastReportedAt: now });
    expect(result.risk).toBeLessThanOrEqual(100);
  });
});
