/**
 * Extracts URLs from email body (HTML and plain text) and defangs them.
 */

const URL_REGEX = /https?:\/\/(?:[-\w]+\.)+[-\w]{2,}(?:\/[^\s<>"'\[\]]*)?/gi;

// URL shorteners to flag
const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
  'buff.ly', 'rebrand.ly', 'tiny.cc', 'shorturl.at', 'clck.ru', 'cutt.ly',
];

// IP-based URL pattern
const IP_URL_REGEX = /https?:\/\/(\d{1,3}\.){3}\d{1,3}/i;

/**
 * Extract and normalize all URLs from email content.
 * @param {string} htmlBody
 * @param {string} textBody
 * @returns {Array<ExtractedUrl>}
 */
export function extractUrls(htmlBody, textBody) {
  const found = new Set();

  // Extract from href attributes in HTML
  const hrefRegex = /href=["']([^"']+)["']/gi;
  let match;
  while ((match = hrefRegex.exec(htmlBody || '')) !== null) {
    const url = cleanUrl(match[1]);
    if (isValidUrl(url)) found.add(url);
  }

  // Extract from src attributes (tracking pixels, images)
  const srcRegex = /src=["']([^"']+)["']/gi;
  while ((match = srcRegex.exec(htmlBody || '')) !== null) {
    const url = cleanUrl(match[1]);
    if (isValidUrl(url)) found.add(url);
  }

  // Extract raw URLs from both bodies
  for (const body of [htmlBody || '', textBody || '']) {
    const stripped = body.replace(/<[^>]+>/g, ' ');
    const urlMatches = stripped.match(URL_REGEX) || [];
    for (const url of urlMatches) {
      const cleaned = cleanUrl(url);
      if (isValidUrl(cleaned)) found.add(cleaned);
    }
  }

  return [...found].map(url => ({
    url,
    defangedUrl: defang(url),
    isShortener: isUrlShortener(url),
    isIpBased: IP_URL_REGEX.test(url),
    domain: extractDomain(url),
  }));
}

function cleanUrl(url) {
  return url.trim().replace(/['">\s]/g, '').replace(/&amp;/g, '&');
}

function isValidUrl(url) {
  if (!url || url.length > 2000) return false;
  if (!url.startsWith('http://') && !url.startsWith('https://')) return false;
  if (url.includes('data:')) return false;
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

/**
 * Defang a URL for safe display — replaces http with hxxp and dots in domain.
 */
export function defang(url) {
  return url
    .replace(/^http:\/\//i, 'hxxp://')
    .replace(/^https:\/\//i, 'hxxps://')
    .replace(/\./g, '[.]');
}

function isUrlShortener(url) {
  try {
    const domain = new URL(url).hostname.toLowerCase();
    return URL_SHORTENERS.some(s => domain === s || domain.endsWith(`.${s}`));
  } catch {
    return false;
  }
}

function extractDomain(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return '';
  }
}
