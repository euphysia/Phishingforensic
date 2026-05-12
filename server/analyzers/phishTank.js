/**
 * Sprint 4: PhishTank Connector
 * Validates URLs against PhishTank's database of known phishing sites.
 * - Free API (requires registration)
 * - Returns: phish_id, verified, phish_detail_url, submission_time, target
 * - Rate limiting: 50 req/min for basic tier
 * - Caching: 24h TTL (phishing URLs don't become safe quickly)
 */

import axios from 'axios';
import { getCached, setCached } from '../cache/urlCache.js';

const PHISHTANK_BASE    = 'https://checkurl.phishtank.com/checkurl/';
const RATE_LIMIT_MS     = 1200; // 50 req/min = 1 req/1.2s
let   lastRequestTime   = 0;

/**
 * Check a URL against PhishTank database.
 * @param {string} url
 * @returns {Promise<PhishTankResult>}
 */
export async function checkWithPhishTank(url) {
  if (!url || url.length < 10) {
    return { url, available: false, reason: 'Invalid URL' };
  }

  // Check cache first
  try {
    const cached = await getCached(url, 'phishtank');
    if (cached) return { ...cached, fromCache: true };
  } catch { /* ignore */ }

  const apiKey = process.env.PHISHTANK_API_KEY;

  if (!apiKey || apiKey === 'YOUR_PHISHTANK_API_KEY') {
    return generateDemoPhishTankResult(url);
  }

  try {
    // Rate limiting: enforce minimum interval between requests
    await enforceRateLimit();

    const formData = new URLSearchParams({
      url:            url,
      format:         'json',
      app_key:        apiKey,
    });

    const response = await axios.post(PHISHTANK_BASE, formData, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: 15000,
    });

    const d = response.data?.results;
    if (!d) throw new Error('Unexpected PhishTank response structure');

    const result = {
      url,
      available:      true,
      inDatabase:     d.in_database || false,
      isPhishing:     d.valid === true,
      verified:       d.verified === 'yes',
      phishId:        d.phish_id || null,
      phishDetailUrl: d.phish_detail_url || null,
      submittedAt:    d.submission_time || null,
      verifiedAt:     d.verification_time || null,
      target:         d.target || null, // Which brand is being impersonated
      verdict:        d.valid ? 'phishing' : 'clean',
      summary:        buildPhishTankSummary(d, url),
    };

    // Cache result
    try {
      await setCached(url, 'phishtank', result);
    } catch { /* ignore */ }

    return result;

  } catch (err) {
    console.error(`[PhishTank] Error checking ${url}:`, err.message);

    if (err.response?.status === 429) {
      console.warn('[PhishTank] Rate limited — using demo result');
      return { ...generateDemoPhishTankResult(url), rateLimited: true };
    }

    return {
      url,
      available: false,
      reason:    `API error: ${err.message}`,
      ...generateDemoPhishTankResult(url),
      isDemo:    true,
    };
  }
}

/**
 * Check multiple URLs against PhishTank in sequence (to respect rate limits).
 * @param {string[]} urls
 * @returns {Promise<PhishTankResult[]>}
 */
export async function checkUrlsBatchPhishTank(urls) {
  const results = [];
  for (const url of urls) {
    try {
      const result = await checkWithPhishTank(url);
      results.push(result);
    } catch (err) {
      console.warn(`[PhishTank] Batch check failed for ${url}:`, err.message);
      results.push({ url, available: false, reason: err.message });
    }
  }
  return results;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async function enforceRateLimit() {
  const now     = Date.now();
  const elapsed = now - lastRequestTime;
  if (elapsed < RATE_LIMIT_MS) {
    await sleep(RATE_LIMIT_MS - elapsed);
  }
  lastRequestTime = Date.now();
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function buildPhishTankSummary(d, url) {
  if (!d.in_database) return `${url} is not in PhishTank database`;
  if (d.valid) {
    return `${url} is a VERIFIED PHISHING site${d.target ? ` impersonating ${d.target}` : ''} (PhishTank ID: ${d.phish_id})`;
  }
  return `${url} is listed in PhishTank database but not verified as phishing`;
}

function generateDemoPhishTankResult(url) {
  const urlLower   = url.toLowerCase();
  const isPhishing = /paypa1|g00gle|micros0ft|login.*verify|secure.*account|bank.*update/i.test(urlLower);
  const isKnown    = /bit\.ly|tinyurl/i.test(urlLower) ? false : isPhishing;

  return {
    url,
    available:      true,
    inDatabase:     isKnown,
    isPhishing:     isKnown,
    verified:       isKnown,
    phishId:        isKnown ? Math.floor(Math.random() * 9000000) + 1000000 : null,
    phishDetailUrl: null,
    submittedAt:    isKnown ? new Date(Date.now() - 86400000 * 3).toISOString() : null,
    verifiedAt:     isKnown ? new Date(Date.now() - 86400000 * 2).toISOString() : null,
    target:         isKnown ? 'PayPal' : null,
    verdict:        isKnown ? 'phishing' : 'clean',
    summary:        isKnown
      ? `Demo: ${url} flagged as known phishing site`
      : `Demo: ${url} not found in PhishTank database`,
    isDemo:         true,
  };
}
