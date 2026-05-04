import { simpleParser } from 'mailparser';
import crypto from 'crypto';

/**
 * Parses a raw .eml string or Buffer and returns a structured object.
 * @param {string|Buffer} rawEmail - Raw email content
 * @returns {Promise<ParsedEmail>}
 */
export async function parseEmail(rawEmail) {
  const raw = typeof rawEmail === 'string' ? rawEmail : rawEmail.toString('utf8');

  // SHA-256 of the full raw email
  const sha256 = crypto.createHash('sha256').update(raw).digest('hex');

  const parsed = await simpleParser(raw, {
    skipHtmlToText: false,
    skipTextToHtml: false,
    skipImageLinks: false,
  });

  // ── Extract key fields ───────────────────────────────────────────────────

  const from = parsed.from?.text || '';
  const fromAddress = parsed.from?.value?.[0]?.address || '';
  const fromName = parsed.from?.value?.[0]?.name || '';

  const to = parsed.to?.text || '';
  const subject = parsed.subject || '';
  const date = parsed.date ? parsed.date.toISOString() : null;
  const messageId = parsed.messageId || '';
  const replyTo = parsed.replyTo?.text || '';
  const returnPath = getHeader(parsed, 'return-path') || '';

  // ── Received chain ───────────────────────────────────────────────────────
  const receivedHeaders = getHeaders(parsed, 'received');
  const receivedFrom = receivedHeaders[0] || '';

  // ── Authentication-Results ───────────────────────────────────────────────
  const authResults = getHeader(parsed, 'authentication-results') || '';
  const spfStatus = extractAuthResult(authResults, 'spf');
  const dkimStatus = extractAuthResult(authResults, 'dkim');
  const dmarcStatus = extractAuthResult(authResults, 'dmarc');

  // ── Body content ─────────────────────────────────────────────────────────
  const textBody = parsed.text || '';
  const htmlBody = parsed.html || '';

  // ── Attachments ──────────────────────────────────────────────────────────
  const attachments = (parsed.attachments || []).map(att => ({
    filename: att.filename || 'unknown',
    contentType: att.contentType || 'application/octet-stream',
    sizeBytes: att.size || 0,
    sha256: crypto.createHash('sha256').update(att.content).digest('hex'),
    content: att.content,
  }));

  return {
    sha256,
    from,
    fromAddress,
    fromName,
    to,
    subject,
    date,
    messageId,
    replyTo,
    returnPath,
    receivedFrom,
    receivedHeaders,
    spfStatus,
    dkimStatus,
    dmarcStatus,
    authResults,
    textBody,
    htmlBody,
    attachments,
    rawHeaders: Object.fromEntries(
      [...(parsed.headers?.entries() || [])]
    ),
  };
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function getHeader(parsed, name) {
  const val = parsed.headers?.get(name);
  if (!val) return null;
  if (Array.isArray(val)) return val[0];
  return typeof val === 'object' ? val.text : val;
}

function getHeaders(parsed, name) {
  const val = parsed.headers?.get(name);
  if (!val) return [];
  if (Array.isArray(val)) return val.map(v => (typeof v === 'object' ? v.text || JSON.stringify(v) : v));
  return [typeof val === 'object' ? val.text || JSON.stringify(val) : val];
}

/**
 * Extracts SPF/DKIM/DMARC result from Authentication-Results header.
 * @param {string} authHeader
 * @param {'spf'|'dkim'|'dmarc'} type
 * @returns {'pass'|'fail'|'neutral'|'none'|'unknown'}
 */
function extractAuthResult(authHeader, type) {
  if (!authHeader) return 'none';
  const lower = authHeader.toLowerCase();
  const regex = new RegExp(`${type}=([a-z]+)`);
  const match = lower.match(regex);
  if (!match) return 'none';
  const result = match[1];
  if (['pass', 'fail', 'neutral', 'softfail', 'temperror', 'permerror'].includes(result)) return result;
  return 'unknown';
}
