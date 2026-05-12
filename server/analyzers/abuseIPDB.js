/**
 * Sprint 4: AbuseIPDB Connector
 * Checks IP reputation for phishing sender IPs.
 * - Confidence score, abuse categories, last reported date
 * - Rate limiting (1000 checks/day free tier)
 * - Graceful fallback to demo data when API key missing
 */

import axios from 'axios';
import { getCached, setCached } from '../cache/urlCache.js';

const ABUSEIPDB_BASE = 'https://api.abuseipdb.com/api/v2';

// AbuseIPDB category codes relevant to phishing/email threats
const RELEVANT_CATEGORIES = {
  3:  'Fraud Orders',
  4:  'DDoS Attack',
  9:  'Open Proxy',
  10: 'Web Spam',
  11: 'Email Spam',
  14: 'Port Scan',
  15: 'Hacking',
  16: 'SQL Injection',
  18: 'Brute Force',
  19: 'Bad Web Bot',
  20: 'Exploited Host',
  21: 'Web App Attack',
  22: 'SSH',
  23: 'IoT Targeted',
};

/**
 * Check IP reputation using AbuseIPDB.
 * @param {string} ip - IPv4 or IPv6 address
 * @returns {Promise<AbuseIPDBResult>}
 */
export async function checkIpReputation(ip) {
  if (!ip || !isValidIp(ip)) {
    return { ip, available: false, reason: 'Invalid or missing IP address' };
  }

  // Skip private/loopback IPs
  if (isPrivateIp(ip)) {
    return {
      ip,
      available: true,
      isPrivate: true,
      abuseScore: 0,
      totalReports: 0,
      categories: [],
      verdict: 'private',
      summary: `${ip} is a private/loopback address — not publicly routable`,
    };
  }

  // Check cache first (cache by IP, not URL)
  const cacheKey = `ip:${ip}`;
  try {
    const cached = await getCached(cacheKey, 'abuseipdb');
    if (cached) return { ...cached, fromCache: true };
  } catch { /* ignore cache errors */ }

  const apiKey = process.env.ABUSEIPDB_API_KEY;

  if (!apiKey || apiKey === 'YOUR_ABUSEIPDB_API_KEY') {
    return generateDemoAbuseIPDBResult(ip);
  }

  try {
    const response = await withRateLimit('abuseipdb', async () =>
      axios.get(`${ABUSEIPDB_BASE}/check`, {
        headers: {
          'Key':    apiKey,
          'Accept': 'application/json',
        },
        params: {
          ipAddress:      ip,
          maxAgeInDays:   90,
          verbose:        false,
        },
        timeout: 10000,
      })
    );

    const d = response.data?.data;
    if (!d) throw new Error('Empty response from AbuseIPDB');

    const result = {
      ip,
      available:        true,
      isPrivate:        false,
      abuseScore:       d.abuseConfidenceScore || 0,
      totalReports:     d.totalReports || 0,
      distinctUsers:    d.numDistinctUsers || 0,
      lastReportedAt:   d.lastReportedAt || null,
      countryCode:      d.countryCode || null,
      usageType:        d.usageType || null,
      isp:              d.isp || null,
      domain:           d.domain || null,
      isTor:            d.isTor || false,
      categories:       mapCategories(d.reports || []),
      verdict:          scoreToVerdict(d.abuseConfidenceScore || 0),
      summary:          buildSummary(d),
    };

    // Cache for 6 hours (IP reputations change slowly)
    try {
      await setCached(cacheKey, 'abuseipdb', result);
    } catch { /* ignore cache write errors */ }

    return result;

  } catch (err) {
    console.error(`[AbuseIPDB] Error checking ${ip}:`, err.message);

    // Handle rate limiting specifically
    if (err.response?.status === 429) {
      console.warn('[AbuseIPDB] Rate limit hit — using demo data');
      return { ...generateDemoAbuseIPDBResult(ip), rateLimited: true };
    }

    return {
      ip,
      available: false,
      reason:    `API error: ${err.message}`,
      ...generateDemoAbuseIPDBResult(ip),
      isDemo:    true,
    };
  }
}

/**
 * Extract sender IPs from Received headers.
 * @param {string[]} receivedHeaders
 * @returns {string[]} - Array of unique IPs found
 */
export function extractSenderIps(receivedHeaders) {
  const ipSet = new Set();
  const ipRegex = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;
  const ipv6Regex = /\[([0-9a-fA-F:]{3,39})\]/g;

  for (const header of receivedHeaders || []) {
    let match;
    while ((match = ipRegex.exec(header)) !== null) {
      const ip = match[1];
      if (!isPrivateIp(ip)) ipSet.add(ip);
    }
    while ((match = ipv6Regex.exec(header)) !== null) {
      ipSet.add(match[1]);
    }
  }

  return [...ipSet].slice(0, 5); // Max 5 IPs to avoid excessive API calls
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function isValidIp(ip) {
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6  = /^[0-9a-fA-F:]{3,39}$/;
  return ipv4.test(ip) || ipv6.test(ip);
}

function isPrivateIp(ip) {
  return (
    /^127\./.test(ip) ||
    /^10\./.test(ip) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    /^192\.168\./.test(ip) ||
    /^::1$/.test(ip) ||
    /^fe80::/i.test(ip) ||
    ip === '0.0.0.0'
  );
}

function mapCategories(reports) {
  const cats = new Set();
  for (const report of reports) {
    for (const catId of report.categories || []) {
      if (RELEVANT_CATEGORIES[catId]) {
        cats.add(RELEVANT_CATEGORIES[catId]);
      }
    }
  }
  return [...cats];
}

function scoreToVerdict(score) {
  if (score >= 75) return 'malicious';
  if (score >= 25) return 'suspicious';
  return 'clean';
}

function buildSummary(d) {
  const score = d.abuseConfidenceScore || 0;
  if (score === 0) return `${d.ipAddress} has no reported abuse activity`;
  return (
    `${d.ipAddress} has an abuse confidence score of ${score}% ` +
    `based on ${d.totalReports} report(s) from ${d.numDistinctUsers} user(s)` +
    (d.isp ? ` via ${d.isp}` : '') +
    (d.countryCode ? ` (${d.countryCode})` : '')
  );
}

function generateDemoAbuseIPDBResult(ip) {
  // Deterministic "random" based on IP string
  const seed   = ip.split('.').reduce((a, b) => a + parseInt(b || '0'), 0);
  const score  = seed % 100;

  return {
    ip,
    available:      true,
    isPrivate:      false,
    abuseScore:     score,
    totalReports:   Math.floor(score / 5),
    distinctUsers:  Math.floor(score / 15),
    lastReportedAt: score > 20 ? new Date(Date.now() - 86400000 * 7).toISOString() : null,
    countryCode:    'US',
    usageType:      score > 50 ? 'Data Center/Web Hosting/Transit' : 'Fixed Line ISP',
    isp:            'Demo ISP',
    domain:         null,
    isTor:          false,
    categories:     score > 50 ? ['Email Spam', 'Web Spam'] : [],
    verdict:        scoreToVerdict(score),
    summary:        `Demo result for ${ip} — abuse score ${score}%`,
    isDemo:         true,
  };
}

// ── Rate Limiter ──────────────────────────────────────────────────────────────
// Simple in-memory rate limiter (resets on server restart)
const rateLimiters = {};

async function withRateLimit(service, fn) {
  if (!rateLimiters[service]) {
    rateLimiters[service] = { count: 0, resetAt: Date.now() + 86400000 }; // 24h window
  }

  const limiter = rateLimiters[service];

  // Reset window if expired
  if (Date.now() > limiter.resetAt) {
    limiter.count   = 0;
    limiter.resetAt = Date.now() + 86400000;
  }

  const DAILY_LIMIT = service === 'abuseipdb' ? 1000 : 500;

  if (limiter.count >= DAILY_LIMIT) {
    throw new Error(`Rate limit reached for ${service} (${DAILY_LIMIT}/day)`);
  }

  limiter.count++;
  return fn();
}
