import crypto from 'crypto';
import db from '../db.js';

const CACHE_TTL_HOURS = 24;

/**
 * Get a cached URL scan result.
 * @param {string} url
 * @param {string} source - 'virustotal' or 'urlscan'
 * @returns {object|null}
 */
export function getCached(url, source) {
  const hash = hashUrl(url);
  const row = db.prepare(
    `SELECT result FROM url_cache
     WHERE url_hash = ? AND source = ? AND expires_at > datetime('now')`
  ).get(`${hash}:${source}`);

  if (!row) return null;
  try {
    return JSON.parse(row.result);
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
export function setCached(url, source, result) {
  const hash = hashUrl(url);
  const expiresAt = new Date(Date.now() + CACHE_TTL_HOURS * 60 * 60 * 1000)
    .toISOString()
    .replace('T', ' ')
    .substring(0, 19);

  db.prepare(
    `INSERT OR REPLACE INTO url_cache (url_hash, url, source, result, cached_at, expires_at)
     VALUES (?, ?, ?, ?, datetime('now'), ?)`
  ).run(`${hash}:${source}`, url, source, JSON.stringify(result), expiresAt);
}

function hashUrl(url) {
  return crypto.createHash('sha256').update(url.trim().toLowerCase()).digest('hex').substring(0, 32);
}
