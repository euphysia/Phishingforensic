import { describe, it, expect } from 'vitest';
import { analyzeHeaders } from '../../parser/headerAnalyzer.js';

function baseParsed(overrides = {}) {
  return {
    fromAddress: 'alice@example.com',
    fromName: 'Alice',
    returnPath: 'alice@example.com',
    replyTo: 'alice@example.com',
    subject: 'Hello',
    spfStatus: 'pass',
    dkimStatus: 'pass',
    dmarcStatus: 'pass',
    ...overrides,
  };
}

describe('analyzeHeaders', () => {
  it('flags a Return-Path domain mismatch', () => {
    const result = analyzeHeaders(baseParsed({ returnPath: 'bounce@evil.ru' }));
    expect(result.spoofingIndicators.some(d => d.includes('Return-Path'))).toBe(true);
  });

  it('flags display-name brand impersonation on a mismatched domain', () => {
    const result = analyzeHeaders(baseParsed({
      fromName: 'PayPal Security',
      fromAddress: 'noreply@secure-paypa1.ru',
    }));
    const types = result.indicators.map(i => i.type);
    expect(types).toContain('Display Name Spoofing');
  });

  it('flags a homoglyph lookalike domain for a known brand', () => {
    const result = analyzeHeaders(baseParsed({
      fromName: 'PayPal',
      fromAddress: 'service@paypa1.com',
    }));
    const types = result.indicators.map(i => i.type);
    expect(types).toContain('Homoglyph Domain');
  });

  it('flags Reply-To hijacking when Reply-To differs from From', () => {
    const result = analyzeHeaders(baseParsed({ replyTo: 'reply@different.com' }));
    expect(result.indicators.some(i => i.type === 'Reply-To Hijack')).toBe(true);
  });

  it('flags free-mail-provider abuse for sensitive-sounding subjects', () => {
    const result = analyzeHeaders(baseParsed({
      fromAddress: 'security@gmail.com',
      subject: 'Your account billing verify required',
    }));
    expect(result.indicators.some(i => i.type === 'Free Provider Mismatch')).toBe(true);
  });

  it('does not flag free-mail-provider abuse for benign subjects', () => {
    const result = analyzeHeaders(baseParsed({
      fromAddress: 'friend@gmail.com',
      subject: 'Lunch tomorrow?',
    }));
    expect(result.indicators.some(i => i.type === 'Free Provider Mismatch')).toBe(false);
  });

  it('flags suspicious TLDs on the sender domain', () => {
    const result = analyzeHeaders(baseParsed({ fromAddress: 'user@mailer.xyz' }));
    expect(result.indicators.some(i => i.type === 'Suspicious TLD')).toBe(true);
  });

  it('flags SPF/DKIM/DMARC failures independently', () => {
    const result = analyzeHeaders(baseParsed({ spfStatus: 'fail', dkimStatus: 'fail', dmarcStatus: 'fail' }));
    const types = result.indicators.map(i => i.type);
    expect(types).toContain('SPF Failure');
    expect(types).toContain('DKIM Failure');
    expect(types).toContain('DMARC Failure');
  });

  it('flags missing authentication when SPF/DKIM/DMARC are all absent', () => {
    const result = analyzeHeaders(baseParsed({ spfStatus: 'none', dkimStatus: 'none', dmarcStatus: 'none' }));
    expect(result.indicators.some(i => i.type === 'Missing Authentication')).toBe(true);
  });

  it('flags urgency/social-engineering language in the subject', () => {
    const result = analyzeHeaders(baseParsed({ subject: 'URGENT: your account has been suspended' }));
    expect(result.indicators.some(i => i.type === 'Urgency Social Engineering')).toBe(true);
  });

  it('produces a perfect reputation score for a clean, fully-authenticated email', () => {
    const result = analyzeHeaders(baseParsed());
    expect(result.indicators.length).toBe(0);
    expect(result.senderReputation).toBe(100);
  });

  it('clamps the reputation score to the [0, 100] range under many stacked indicators', () => {
    const result = analyzeHeaders(baseParsed({
      returnPath: 'bounce@evil.ru',
      replyTo: 'reply@other.ru',
      fromAddress: 'security@mailer.xyz',
      subject: 'URGENT action required: verify your account now',
      spfStatus: 'fail',
      dkimStatus: 'fail',
      dmarcStatus: 'fail',
    }));
    expect(result.senderReputation).toBeGreaterThanOrEqual(0);
    expect(result.senderReputation).toBeLessThanOrEqual(100);
  });

  it('defaults missing auth fields to "none" rather than throwing', () => {
    const result = analyzeHeaders({ fromAddress: 'a@b.com' });
    expect(result.spfStatus).toBe('none');
    expect(result.dkimStatus).toBe('none');
    expect(result.dmarcStatus).toBe('none');
  });
});
