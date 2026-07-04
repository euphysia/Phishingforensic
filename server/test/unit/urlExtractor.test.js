import { describe, it, expect } from 'vitest';
import { extractUrls, defang } from '../../analyzers/urlExtractor.js';

describe('extractUrls', () => {
  it('extracts URLs from href attributes in the HTML body', () => {
    const html = '<a href="https://example.com/login">click here</a>';
    const urls = extractUrls(html, '');
    expect(urls.map(u => u.url)).toContain('https://example.com/login');
  });

  it('extracts URLs from src attributes (tracking pixels/images)', () => {
    const html = '<img src="https://tracker.example.com/pixel.gif">';
    const urls = extractUrls(html, '');
    expect(urls.map(u => u.url)).toContain('https://tracker.example.com/pixel.gif');
  });

  it('extracts bare URLs from the plaintext body', () => {
    const urls = extractUrls('', 'Visit https://plain-text-link.com/path for details');
    expect(urls.map(u => u.url)).toContain('https://plain-text-link.com/path');
  });

  it('deduplicates the same URL found in both HTML and text bodies', () => {
    const html = '<a href="https://dup.example.com">link</a>';
    const text = 'https://dup.example.com';
    const urls = extractUrls(html, text);
    expect(urls.filter(u => u.url === 'https://dup.example.com').length).toBe(1);
  });

  it('flags known URL shorteners', () => {
    const urls = extractUrls('<a href="https://bit.ly/abc123">link</a>', '');
    expect(urls[0].isShortener).toBe(true);
  });

  it('flags IP-based URLs', () => {
    const urls = extractUrls('<a href="http://192.168.1.5/login">link</a>', '');
    expect(urls[0].isIpBased).toBe(true);
  });

  it('does not flag a normal domain as IP-based or a shortener', () => {
    const urls = extractUrls('<a href="https://legit-bank.com/login">link</a>', '');
    expect(urls[0].isIpBased).toBe(false);
    expect(urls[0].isShortener).toBe(false);
  });

  it('does not capture a trailing "]" when a URL appears bracket-wrapped in derived plaintext (regression)', () => {
    // mailparser's html-to-text conversion renders <a href="URL">text</a> as "text [URL]" —
    // the plaintext URL regex must not swallow the closing bracket into the path.
    const text = 'Verify Your Account Now [http://paypa1-verify.com/secure/login?token=abc123]';
    const urls = extractUrls('', text);
    expect(urls.map(u => u.url)).toEqual(['http://paypa1-verify.com/secure/login?token=abc123']);
  });

  it('rejects data: URIs and non-http(s) schemes', () => {
    const html = '<a href="data:text/html;base64,PHNjcmlwdD4=">x</a><a href="javascript:alert(1)">y</a>';
    const urls = extractUrls(html, '');
    expect(urls.length).toBe(0);
  });

  it('extracts the correct domain for each URL', () => {
    const urls = extractUrls('<a href="https://sub.evil-domain.com/x">link</a>', '');
    expect(urls[0].domain).toBe('sub.evil-domain.com');
  });

  it('returns an empty array for empty bodies', () => {
    expect(extractUrls('', '')).toEqual([]);
    expect(extractUrls(undefined, undefined)).toEqual([]);
  });
});

describe('defang', () => {
  it('replaces http/https and dots for safe display', () => {
    expect(defang('http://evil.com/path')).toBe('hxxp://evil[.]com/path');
    expect(defang('https://evil.co.uk')).toBe('hxxps://evil[.]co[.]uk');
  });
});
