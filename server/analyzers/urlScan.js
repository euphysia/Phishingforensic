import axios from 'axios';
import { getCached, setCached } from '../cache/urlCache.js';

const URLSCAN_BASE = 'https://urlscan.io/api/v1';

/**
 * Scan a URL with URLScan.io.
 * Falls back to demo data if no API key is configured.
 * @param {string} url
 * @returns {Promise<URLScanResult>}
 */
export async function scanWithURLScan(url) {
  // Check cache first
  const cached = getCached(url, 'urlscan');
  if (cached) return { ...cached, fromCache: true };

  const apiKey = process.env.URLSCAN_API_KEY;

  if (!apiKey || apiKey === 'YOUR_URLSCAN_API_KEY') {
    return generateDemoURLScanResult(url);
  }

  try {
    // Submit scan
    const submitRes = await axios.post(
      `${URLSCAN_BASE}/scan/`,
      { url, visibility: 'private' },
      {
        headers: {
          'API-Key': apiKey,
          'Content-Type': 'application/json',
        },
        timeout: 15000,
      }
    );

    const uuid = submitRes.data?.uuid;
    if (!uuid) throw new Error('No UUID from URLScan submission');

    // Poll for result (max 60s)
    const result = await pollURLScan(uuid);
    setCached(url, 'urlscan', result);
    return result;

  } catch (err) {
    console.error(`[URLScan] Error scanning ${url}:`, err.message);
    return generateDemoURLScanResult(url);
  }
}

async function pollURLScan(uuid, maxAttempts = 10) {
  for (let i = 0; i < maxAttempts; i++) {
    await sleep(6000);
    try {
      const res = await axios.get(`${URLSCAN_BASE}/result/${uuid}/`, {
        timeout: 10000,
      });

      const data = res.data;
      return {
        uuid,
        verdict: data.verdicts?.overall?.score > 50 ? 'malicious' : 'clean',
        score: data.verdicts?.overall?.score || 0,
        malicious: data.verdicts?.overall?.malicious || false,
        brands: data.verdicts?.overall?.brands || [],
        categories: data.verdicts?.overall?.categories || [],
        pageTitle: data.page?.title || '',
        pageUrl: data.page?.url || url,
        tlsIssuer: data.page?.tlsIssuer || null,
        screenshotUrl: `https://urlscan.io/screenshots/${uuid}.png`,
        reportUrl: `https://urlscan.io/result/${uuid}/`,
        redirected: data.page?.url !== url,
      };
    } catch (err) {
      if (err.response?.status === 404) {
        // Still processing
        continue;
      }
      throw err;
    }
  }
  throw new Error('URLScan analysis timed out');
}

function generateDemoURLScanResult(url) {
  const isSuspicious = /verify|secure|login|account|update|confirm/i.test(url) ||
    /paypa1|gooog|micros0ft/i.test(url);

  const score = isSuspicious ? Math.floor(Math.random() * 30) + 65 : Math.floor(Math.random() * 20);

  return {
    uuid: null,
    verdict: isSuspicious ? 'malicious' : 'clean',
    score,
    malicious: score > 60,
    brands: isSuspicious ? ['PayPal', 'Finance'] : [],
    categories: isSuspicious ? ['phishing'] : [],
    pageTitle: isSuspicious ? 'Verify Your Account' : null,
    pageUrl: url,
    tlsIssuer: null,
    screenshotUrl: null,
    reportUrl: null,
    redirected: isSuspicious,
    isDemo: true,
  };
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
