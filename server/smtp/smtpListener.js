/**
 * SMTP Inbound Listener
 * Receives forwarded phishing emails and automatically triggers analysis.
 *
 * Flow:
 *   User forwards email → SMTP server (port 2525) → extract raw email
 *   → call analysis pipeline → store result in Supabase → emit event
 */

import { SMTPServer } from 'smtp-server';
import { EventEmitter } from 'events';
import { simpleParser } from 'mailparser';

// ── Event bus — frontend polls /api/smtp/status for updates ──────────────────
export const smtpEvents = new EventEmitter();

// Queue of recently auto-analysed emails (in-memory, last 20)
const recentForwards = [];
const MAX_RECENT = 20;

let server = null;
let serverStatus = 'stopped'; // 'stopped' | 'running' | 'error'
let serverError  = null;
let totalReceived = 0;

const SMTP_PORT    = parseInt(process.env.SMTP_PORT    || '2525');
const SMTP_DOMAIN  = process.env.SMTP_DOMAIN  || 'phishing-forensics.local';
const SMTP_ADDRESS = `analyze@${SMTP_DOMAIN}`;

/**
 * Start the SMTP inbound server.
 * @param {Function} analysisPipeline - async fn(rawEmail: string) => result
 */
export function startSmtpListener(analysisPipeline) {
  if (server) return; // Already running

  server = new SMTPServer({
    // ── Server identity ───────────────────────────────────────────────────
    name:    SMTP_DOMAIN,
    banner:  'Phishing Forensic Analysis SMTP Receiver',

    // ── Auth: accept all (internal tool, no public exposure) ─────────────
    authOptional:  true,
    allowInsecureAuth: true,
    disabledCommands: ['STARTTLS'], // No TLS needed for local demo

    // ── Size limit: 25 MB ─────────────────────────────────────────────────
    size: 25 * 1024 * 1024,

    // ── Accept any recipient at our domain ────────────────────────────────
    onRcptTo(address, session, callback) {
      // Accept any email to @phishing-forensics.local (or configured domain)
      if (address.address.endsWith(`@${SMTP_DOMAIN}`) ||
          address.address === 'analyze@localhost') {
        return callback();
      }
      // Also accept wildcard for demo purposes
      return callback();
    },

    // ── Process incoming email ────────────────────────────────────────────
    onData(stream, session, callback) {
      const chunks = [];

      stream.on('data', chunk => chunks.push(chunk));

      stream.on('end', async () => {
        const rawEmail = Buffer.concat(chunks).toString('utf8');
        callback(); // Acknowledge receipt immediately

        // Process asynchronously — don't block SMTP response
        processForwardedEmail(rawEmail, session, analysisPipeline);
      });

      stream.on('error', err => {
        console.error('[SMTP] Stream error:', err.message);
        callback(err);
      });
    },

    onError(err) {
      console.error('[SMTP] Server error:', err.message);
    },
  });

  server.on('error', (err) => {
    serverStatus = 'error';
    serverError  = err.message;
    if (err.code === 'EADDRINUSE') {
      console.warn(`[SMTP] Port ${SMTP_PORT} already in use — SMTP forwarding unavailable. HTTP API is still running.`);
    } else {
      console.error('[SMTP] Fatal error:', err.message);
    }
  });

  server.listen(SMTP_PORT, '0.0.0.0', () => {
    serverStatus = 'running';
    serverError  = null;
    console.log(`\n📧 SMTP inbound server listening on port ${SMTP_PORT}`);
    console.log(`   Forward phishing emails to: ${SMTP_ADDRESS}`);
    console.log(`   Configure your email client: SMTP host=localhost, port=${SMTP_PORT}\n`);
  });
}

/**
 * Stop the SMTP server.
 */
export function stopSmtpListener() {
  if (!server) return;
  server.close(() => {
    serverStatus = 'stopped';
    server = null;
    console.log('[SMTP] Server stopped');
  });
}

/**
 * Get current SMTP server status.
 */
export function getSmtpStatus() {
  return {
    status:       serverStatus,
    port:         SMTP_PORT,
    domain:       SMTP_DOMAIN,
    emailAddress: SMTP_ADDRESS,
    totalReceived,
    error:        serverError,
    recentForwards: recentForwards.slice(0, 10), // Last 10 for UI
  };
}

// ── Internal: process a received email ───────────────────────────────────────

async function processForwardedEmail(rawEmail, session, analysisPipeline) {
  totalReceived++;

  const receivedAt = new Date().toISOString();
  const senderIp   = session.remoteAddress || 'unknown';

  console.log(`[SMTP] Email received from ${senderIp} at ${receivedAt}`);

  // Extract subject/from for logging before analysis
  let subject = '(parsing...)';
  let from    = session.envelope?.mailFrom?.address || 'unknown';

  try {
    // Quick pre-parse for metadata
    const parsed = await simpleParser(rawEmail, { skipHtmlToText: true });
    subject = parsed.subject || '(no subject)';
    from    = parsed.from?.text || from;

    // Check if this is a "forward as attachment" — extract the inner .eml
    const emailToAnalyze = await extractForwardedEmail(parsed, rawEmail);

    console.log(`[SMTP] Analysing email: "${subject}" from ${from}`);

    // Track as pending
    const entry = {
      id:          `smtp-${Date.now()}`,
      receivedAt,
      subject,
      from,
      senderIp,
      status:      'processing',
      analysisId:  null,
      verdict:     null,
      riskScore:   null,
      error:       null,
    };
    recentForwards.unshift(entry);
    if (recentForwards.length > MAX_RECENT) recentForwards.pop();

    smtpEvents.emit('email-received', entry);

    // ── Run full analysis pipeline ────────────────────────────────────────
    const result = await analysisPipeline(emailToAnalyze);

    // Update entry with result
    entry.status     = 'complete';
    entry.analysisId = result.id;
    entry.verdict    = result.verdict;
    entry.riskScore  = result.riskScore;

    console.log(`[SMTP] Analysis complete: ${result.verdict} (score: ${result.riskScore})`);
    smtpEvents.emit('analysis-complete', entry);

  } catch (err) {
    console.error('[SMTP] Analysis error:', err.message);

    // Update the entry with the error
    const entry = recentForwards.find(e => e.receivedAt === receivedAt);
    if (entry) {
      entry.status = 'error';
      entry.error  = err.message;
    }
    smtpEvents.emit('analysis-error', { receivedAt, error: err.message });
  }
}

/**
 * If the forwarded email has an attached .eml file (forward as attachment),
 * extract it. Otherwise analyse the outer email itself.
 */
async function extractForwardedEmail(parsed, rawEmail) {
  // Look for attached .eml file (forward as attachment behaviour)
  const emlAttachment = (parsed.attachments || []).find(att =>
    att.contentType === 'message/rfc822' ||
    att.filename?.toLowerCase().endsWith('.eml') ||
    att.contentType === 'application/octet-stream' && att.filename?.toLowerCase().endsWith('.eml')
  );

  if (emlAttachment?.content) {
    console.log('[SMTP] Found attached .eml — analysing inner email');
    return emlAttachment.content.toString('utf8');
  }

  // No attached .eml — analyse the forwarded email body directly
  // (inline forwards — Gmail/Outlook sometimes include the original headers in body)
  console.log('[SMTP] No attached .eml found — analysing forwarded email as-is');
  return rawEmail;
}
