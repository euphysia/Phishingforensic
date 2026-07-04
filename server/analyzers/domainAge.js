import { createRequire } from 'module';
const { whoisDomain } = createRequire(import.meta.url)('whoiser');

const CACHE = new Map();

/**
 * Look up domain registration date via WHOIS.
 * Returns null if lookup fails or times out.
 * @param {string} domain
 * @returns {Promise<{ registeredAt: Date|null, ageDays: number|null, ageRisk: 'high'|'medium'|null }>}
 */
export async function checkDomainAge(domain) {
  if (!domain) return nullResult();

  // Strip leading wildcard / www
  const cleanDomain = domain.replace(/^\*\./, '').replace(/^www\./, '').toLowerCase();

  if (CACHE.has(cleanDomain)) return CACHE.get(cleanDomain);

  try {
    const result = await Promise.race([
      lookupWhois(cleanDomain),
      new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 10000)),
    ]);
    CACHE.set(cleanDomain, result);
    return result;
  } catch (err) {
    console.warn(`[DomainAge] WHOIS lookup failed for ${cleanDomain}: ${err.message}`);
    const fallback = nullResult();
    CACHE.set(cleanDomain, fallback);
    return fallback;
  }
}

async function lookupWhois(domain) {
  const data = await whoisDomain(domain, { follow: 1 });

  // whoiser returns an object keyed by whois server; find the first with a creation date
  let registeredAt = null;
  for (const entry of Object.values(data)) {
    const raw =
      entry['Created Date'] ||
      entry['Creation Date'] ||
      entry['Registered'] ||
      entry['Registration Date'] ||
      entry['domain_dateregistered'] ||
      entry['created'] ||
      entry['Domain Registration Date'];

    if (raw) {
      const date = new Date(Array.isArray(raw) ? raw[0] : raw);
      if (!isNaN(date.getTime())) {
        registeredAt = date;
        break;
      }
    }
  }

  if (!registeredAt) return nullResult();

  const ageDays = Math.floor((Date.now() - registeredAt.getTime()) / 86400000);
  const ageRisk = ageDays < 30 ? 'high' : ageDays < 90 ? 'medium' : null;

  return { registeredAt, ageDays, ageRisk };
}

function nullResult() {
  return { registeredAt: null, ageDays: null, ageRisk: null };
}
