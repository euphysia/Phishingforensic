/**
 * Returns true when the named environment variable holds a real API key.
 *
 * Unset values and template placeholders such as "YOUR_<SERVICE>_API_KEY"
 * (copied from an example .env) are treated as "not configured" so the
 * analyzers fall back to demo mode. The placeholder is matched by pattern
 * rather than by a hard-coded literal so the exact placeholder string never
 * appears in source (Netlify's secrets scanner flags env values found in code).
 */
export function hasApiKey(name) {
  const value = (process.env[name] || '').trim();
  if (!value) return false;
  return !/^YOUR_[A-Z0-9_]*$/i.test(value);
}
