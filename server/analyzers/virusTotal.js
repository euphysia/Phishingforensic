import { hasApiKey } from '../utils/apiKeys.js';
import axios from 'axios';
import { getCached, setCached } from '../cache/urlCache.js';
import { IS_SERVERLESS } from '../runtime.js';

const VT_BASE = 'https://www.virustotal.com/api/v3';

/**
 * Scan a URL with VirusTotal v3 API.
 * Falls back to demo data if no API key is configured.
 * @param {string} url
 * @returns {Promise<VTResult>}
 */
export async function scanWithVirusTotal(url) {
  // Check cache first
  const cached = await getCached(url, 'virustotal');
  if (cached) return { ...cached, fromCache: true };

  const apiKey = process.env.VIRUSTOTAL_API_KEY;

  // Demo mode — no API key
  if (!hasApiKey('VIRUSTOTAL_API_KEY')) {
    return generateDemoVTResult(url);
  }

  try {
    // Step 1: Submit URL for scanning
    const submitRes = await axios.post(
      `${VT_BASE}/urls`,
      new URLSearchParams({ url }),
      {
        headers: {
          'x-apikey': apiKey,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        timeout: 15000,
      }
    );

    const analysisId = submitRes.data?.data?.id;
    if (!analysisId) throw new Error('No analysis ID from VirusTotal submission');

    // Step 2: Poll for result (max 30s)
    const result = await pollVTAnalysis(analysisId, apiKey);
    await setCached(url, 'virustotal', result);
    return result;

  } catch (err) {
    console.error(`[VirusTotal] Error scanning ${url}:`, err.message);
    return generateDemoVTResult(url);
  }
}

async function pollVTAnalysis(analysisId, apiKey, maxAttempts = IS_SERVERLESS ? 3 : 6) {
  for (let i = 0; i < maxAttempts; i++) {
    await sleep(5000);
    try {
      const res = await axios.get(`${VT_BASE}/analyses/${analysisId}`, {
        headers: { 'x-apikey': apiKey },
        timeout: 10000,
      });

      const data = res.data?.data;
      const status = data?.attributes?.status;

      if (status === 'completed') {
        const stats = data.attributes.stats || {};
        const total = Object.values(stats).reduce((a, b) => a + b, 0);
        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;

        return {
          detections: malicious + suspicious,
          total,
          malicious,
          suspicious,
          undetected: stats.undetected || 0,
          harmless: stats.harmless || 0,
          categories: extractCategories(data.attributes.results),
          permalink: `https://www.virustotal.com/gui/url/${analysisId}`,
        };
      }
    } catch (err) {
      console.error(`[VirusTotal] Poll attempt ${i + 1} failed:`, err.message);
    }
  }
  throw new Error('VirusTotal analysis timed out');
}

function extractCategories(results) {
  if (!results) return [];
  const cats = new Set();
  for (const vendor of Object.values(results)) {
    if (vendor.category) cats.add(vendor.category);
    if (vendor.result) cats.add(vendor.result);
  }
  return [...cats].filter(Boolean).slice(0, 5);
}

function generateDemoVTResult(url) {
  const urlLower = url.toLowerCase();
  const isSuspicious =
    /verify|secure|login|account|update|confirm/i.test(urlLower) ||
    /paypa1|gooog|micros0ft/i.test(urlLower);
  const isShortener = /bit\.ly|tinyurl|goo\.gl/i.test(urlLower);

  const detections = isSuspicious ? Math.floor(Math.random() * 30) + 15 :
                     isShortener  ? Math.floor(Math.random() * 10) + 2  : 0;
  const total = 89;

  return {
    detections,
    total,
    malicious: isSuspicious ? Math.floor(detections * 0.7) : 0,
    suspicious: isSuspicious ? Math.ceil(detections * 0.3) : detections,
    undetected: total - detections,
    harmless: 0,
    categories: isSuspicious ? ['phishing', 'credential-theft'] : [],
    permalink: null,
    isDemo: true,
  };
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
