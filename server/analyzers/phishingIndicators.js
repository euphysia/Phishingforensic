/**
 * Phishing heuristics engine.
 * Detects phishing patterns from URL, domain, and email content signals.
 */

// ── Homoglyph map ─────────────────────────────────────────────────────────────
const HOMOGLYPH_MAP = {
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
  '6': 'g', '7': 't', '8': 'b', '@': 'a', '!': 'i',
};

// Well-known brands for lookalike detection
const KNOWN_BRANDS = [
  'paypal', 'google', 'microsoft', 'apple', 'amazon', 'netflix',
  'facebook', 'instagram', 'twitter', 'linkedin', 'dropbox',
  'bankofamerica', 'chase', 'wellsfargo', 'citibank', 'hsbc',
  'dhl', 'fedex', 'ups', 'usps', 'irs', 'gov',
];

// URL shorteners
const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
  'rebrand.ly', 'tiny.cc', 'shorturl.at', 'clck.ru', 'cutt.ly',
];

// Suspicious TLDs
const SUSPICIOUS_TLDS = [
  '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq',
  '.click', '.link', '.work', '.date', '.racing', '.win',
  '.stream', '.download', '.review', '.accountant', '.loan',
];

// Phishing keywords in URL paths/domains
const PHISHING_KEYWORDS = [
  'verify', 'secure', 'login', 'account', 'update', 'confirm',
  'billing', 'payment', 'password', 'credential', 'signin',
  'recover', 'restore', 'unlock', 'suspended', 'validate',
];

// Urgency keywords for body/subject
const URGENCY_KEYWORDS = [
  'urgent', 'immediate', 'action required', 'verify now', 'limited time',
  'suspended', 'locked', 'unusual activity', 'confirm your', 'update your',
  'compromised', 'unauthorized', 'expires today', 'act now', 'final notice',
  'click here immediately', 'your account will be', 'last chance',
];

/**
 * Run phishing heuristics on URLs and email content.
 * @param {Array<ExtractedUrl>} urls
 * @param {object} parsed - ParsedEmail
 * @returns {Array<PhishingIndicator>}
 */
export function detectPhishingIndicators(urls, parsed) {
  const indicators = [];

  // ── URL-level checks ─────────────────────────────────────────────────────
  for (const { url, domain, isShortener, isIpBased } of urls) {
    // 1. Homoglyph domain detection
    for (const brand of KNOWN_BRANDS) {
      const normalized = normalizeDomain(domain);
      if (normalized !== brand && isHomoglyph(normalized, brand) && !domain.includes(brand + '.')) {
        indicators.push({
          type: 'Homoglyph Attack',
          description: `Domain "${domain}" appears to impersonate "${brand}" via character substitution`,
          severity: 'high',
          url,
        });
      }
    }

    // 2. URL shortener
    if (isShortener) {
      indicators.push({
        type: 'URL Shortener',
        description: `URL uses a shortening service that hides the real destination: ${domain}`,
        severity: 'medium',
        url,
      });
    }

    // 3. IP-based URL (no domain name)
    if (isIpBased) {
      indicators.push({
        type: 'IP-Based URL',
        description: `URL uses a raw IP address instead of a domain name — a common phishing tactic`,
        severity: 'high',
        url,
      });
    }

    // 4. Suspicious TLD
    const tld = SUSPICIOUS_TLDS.find(t => domain.endsWith(t));
    if (tld) {
      indicators.push({
        type: 'High-Risk TLD',
        description: `Domain uses high-risk TLD "${tld}": ${domain}`,
        severity: 'medium',
        url,
      });
    }

    // 5. Phishing keywords in URL
    const urlLower = url.toLowerCase();
    const foundKeywords = PHISHING_KEYWORDS.filter(k => urlLower.includes(k));
    if (foundKeywords.length >= 2) {
      indicators.push({
        type: 'Phishing URL Pattern',
        description: `URL contains multiple phishing-related keywords: ${foundKeywords.slice(0, 3).join(', ')}`,
        severity: 'medium',
        url,
      });
    }

    // 6. Misleading brand in subdomain + different root domain
    for (const brand of KNOWN_BRANDS) {
      const parts = domain.split('.');
      const subdomain = parts.slice(0, -2).join('.');
      const rootDomain = parts.slice(-2, -1)[0];
      if (subdomain.includes(brand) && rootDomain !== brand) {
        indicators.push({
          type: 'Brand in Subdomain',
          description: `Domain uses "${brand}" in subdomain to appear legitimate: ${domain}`,
          severity: 'high',
          url,
        });
        break;
      }
    }
  }

  // ── Body/Subject-level checks ────────────────────────────────────────────
  const subjectLower = (parsed.subject || '').toLowerCase();
  const bodyLower = ((parsed.textBody || '') + ' ' + (parsed.htmlBody || '')).toLowerCase();

  // 7. Urgency keywords
  const subjectUrgency = URGENCY_KEYWORDS.filter(k => subjectLower.includes(k));
  if (subjectUrgency.length > 0) {
    indicators.push({
      type: 'Urgency Manipulation',
      description: `Subject/body uses pressure language: "${subjectUrgency.slice(0, 2).join('", "')}"`,
      severity: 'medium',
    });
  }

  // 8. Request for credentials in body
  if (/enter.*password|provide.*credit card|submit.*login|click.*verify.*account/i.test(bodyLower)) {
    indicators.push({
      type: 'Credential Harvesting Language',
      description: 'Email body requests sensitive credentials or personal information',
      severity: 'high',
    });
  }

  // 9. Mismatched link text vs href
  const linkMismatch = detectLinkTextMismatch(parsed.htmlBody || '');
  if (linkMismatch.length > 0) {
    indicators.push({
      type: 'Link Text Mismatch',
      description: `Clickable link text shows a legitimate URL but href points elsewhere (${linkMismatch.length} instance${linkMismatch.length > 1 ? 's' : ''})`,
      severity: 'high',
    });
  }

  return indicators;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function normalizeDomain(domain) {
  let norm = domain.split('.')[0].toLowerCase();
  for (const [glyph, real] of Object.entries(HOMOGLYPH_MAP)) {
    norm = norm.replaceAll(glyph, real);
  }
  return norm;
}

function isHomoglyph(normalized, brand) {
  if (normalized === brand) return false;
  // Levenshtein-like: within 2 char edits
  const dist = levenshtein(normalized, brand);
  return dist > 0 && dist <= 2;
}

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

function detectLinkTextMismatch(html) {
  const mismatches = [];
  const linkRegex = /<a[^>]+href=["']([^"']+)["'][^>]*>([^<]+)<\/a>/gi;
  let match;
  while ((match = linkRegex.exec(html)) !== null) {
    const href = match[1].trim();
    const text = match[2].trim();
    if (text.startsWith('http') || text.startsWith('www')) {
      try {
        const hrefDomain = new URL(href).hostname;
        const textDomain = new URL(text.startsWith('www') ? 'http://' + text : text).hostname;
        if (hrefDomain !== textDomain) {
          mismatches.push({ href, text });
        }
      } catch { /* skip unparseable */ }
    }
  }
  return mismatches;
}
