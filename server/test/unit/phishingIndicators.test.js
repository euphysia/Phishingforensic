import { describe, it, expect } from 'vitest';
import { extractUrls } from '../../analyzers/urlExtractor.js';
import { detectPhishingIndicators } from '../../analyzers/phishingIndicators.js';

function urlsFor(url) {
  return extractUrls(`<a href="${url}">link</a>`, '');
}

function parsedWith(overrides = {}) {
  return { subject: '', textBody: '', htmlBody: '', ...overrides };
}

describe('detectPhishingIndicators', () => {
  it('flags a homoglyph/typosquatted brand domain', () => {
    const urls = urlsFor('https://paypall.com/login');
    const indicators = detectPhishingIndicators(urls, parsedWith());
    expect(indicators.some(i => i.type === 'Homoglyph Attack')).toBe(true);
  });

  it('does not flag the real brand domain itself', () => {
    const urls = urlsFor('https://paypal.com/login');
    const indicators = detectPhishingIndicators(urls, parsedWith());
    expect(indicators.some(i => i.type === 'Homoglyph Attack')).toBe(false);
  });

  it('flags known URL shorteners', () => {
    const urls = urlsFor('https://bit.ly/xyz');
    const indicators = detectPhishingIndicators(urls, parsedWith());
    expect(indicators.some(i => i.type === 'URL Shortener')).toBe(true);
  });

  it('flags IP-based URLs', () => {
    const urls = urlsFor('http://45.33.12.9/verify');
    const indicators = detectPhishingIndicators(urls, parsedWith());
    expect(indicators.some(i => i.type === 'IP-Based URL')).toBe(true);
  });

  it('flags high-risk TLDs', () => {
    const urls = urlsFor('https://freebies.top/claim');
    const indicators = detectPhishingIndicators(urls, parsedWith());
    expect(indicators.some(i => i.type === 'High-Risk TLD')).toBe(true);
  });

  it('flags a URL path containing multiple phishing keywords', () => {
    const urls = urlsFor('https://random-site.com/verify-account-login-confirm');
    const indicators = detectPhishingIndicators(urls, parsedWith());
    expect(indicators.some(i => i.type === 'Phishing URL Pattern')).toBe(true);
  });

  it('does not flag a URL with zero or one phishing keyword', () => {
    const urls = urlsFor('https://random-site.com/login');
    const indicators = detectPhishingIndicators(urls, parsedWith());
    expect(indicators.some(i => i.type === 'Phishing URL Pattern')).toBe(false);
  });

  it('flags a brand name in the subdomain with an unrelated root domain', () => {
    const urls = urlsFor('https://paypal.attacker-domain.com/login');
    const indicators = detectPhishingIndicators(urls, parsedWith());
    expect(indicators.some(i => i.type === 'Brand in Subdomain')).toBe(true);
  });

  it('flags urgency/pressure language in the subject line', () => {
    const indicators = detectPhishingIndicators([], parsedWith({ subject: 'URGENT: Immediate action required' }));
    expect(indicators.some(i => i.type === 'Urgency Manipulation')).toBe(true);
  });

  it('flags credential-harvesting language in the body', () => {
    const indicators = detectPhishingIndicators([], parsedWith({ textBody: 'Please enter your password to continue.' }));
    expect(indicators.some(i => i.type === 'Credential Harvesting Language')).toBe(true);
  });

  it('flags a mismatch between visible link text and the actual href target', () => {
    const html = '<a href="https://evil-attacker.com/x">https://paypal.com/login</a>';
    const indicators = detectPhishingIndicators([], parsedWith({ htmlBody: html }));
    expect(indicators.some(i => i.type === 'Link Text Mismatch')).toBe(true);
  });

  it('returns no indicators for a clean URL and benign content', () => {
    const urls = urlsFor('https://my-personal-blog.com/post/1');
    const indicators = detectPhishingIndicators(urls, parsedWith({ subject: 'Weekly newsletter' }));
    expect(indicators.length).toBe(0);
  });
});
