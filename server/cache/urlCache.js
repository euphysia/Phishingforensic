import crypto from 'crypto';
import supabase from '../db.js';

const CACHE_TTL_HOURS = 24;

/**
 * Get a cached URL scan result.
 * @param {string} url
 * @param {string} source - 'virustotal' or 'urlscan'
 * @returns {object|null}
 */
export async function getCached(url, source) {
  const urlHash = hashUrl(url, source);
  const now = new Date().toISOString();

  const { data, error } = await supabase
    .from('url_cache')
    .select('result')
    .eq('url_hash', urlHash)
    .gt('expires_at', now)
    .single();

  if (error || !data) return null;

  try {
    return typeof data.result === 'string' ? JSON.parse(data.result) : data.result;
  } catch {
    return null;
  }
}

/**
 * Store a URL scan result in cache.
 * @param {string} url
 * @param {string} source
 * @param {object} result
 */
export async function setCached(url, source, result) {
  const urlHash = hashUrl(url, source);
  const expiresAt = new Date(Date.now() + CACHE_TTL_HOURS * 60 * 60 * 1000).toISOString();

  await supabase.from('url_cache').upsert({
    url_hash: urlHash,
    url,
    source,
    result: JSON.stringify(result),
    cached_at: new Date().toISOString(),
    expires_at: expiresAt,
  }, { onConflict: 'url_hash' });
}

function hashUrl(url, source) {
  const key = `${url.trim().toLowerCase()}:${source}`;
  return crypto.createHash('sha256').update(key).digest('hex').substring(0, 32);
}
