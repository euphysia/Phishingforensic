import express from 'express';
import { v4 as uuid } from 'uuid';
import db from '../db.js';
import { parseEmail } from '../parser/emailParser.js';
import { analyzeHeaders } from '../parser/headerAnalyzer.js';
import { extractUrls } from '../analyzers/urlExtractor.js';
import { scanWithVirusTotal } from '../analyzers/virusTotal.js';
import { scanWithURLScan } from '../analyzers/urlScan.js';
import { detectPhishingIndicators } from '../analyzers/phishingIndicators.js';
import { scoreUrl, computeEmailRiskScore } from '../analyzers/reputationScorer.js';

const router = express.Router();

/**
 * POST /api/analyze
 * Accepts: multipart/form-data with field "email" (file or text)
 *       OR application/json with body { rawEmail: "..." }
 *       OR text/plain raw email body
 */
router.post('/', async (req, res) => {
  const startTime = Date.now();

  try {
    // ── 1. Get raw email content ────────────────────────────────────────────
    let rawEmail;

    if (req.file) {
      // Uploaded .eml file
      rawEmail = req.file.buffer.toString('utf8');
    } else if (req.body?.rawEmail) {
      rawEmail = typeof req.body.rawEmail === 'string'
        ? req.body.rawEmail
        : String(req.body.rawEmail);
    } else if (typeof req.body === 'string') {
      rawEmail = req.body;
    } else {
      return res.status(400).json({ error: 'No email content provided. Send rawEmail field or upload a .eml file.' });
    }

    if (!rawEmail || rawEmail.trim().length < 10) {
      return res.status(400).json({ error: 'Email content is too short or empty.' });
    }

    // ── 2. Parse email (MIME + SHA-256) ────────────────────────────────────
    const parsed = await parseEmail(rawEmail);

    // ── 3. Header analysis ──────────────────────────────────────────────────
    const headerResult = analyzeHeaders(parsed);

    // ── 4. URL extraction ───────────────────────────────────────────────────
    const extractedUrls = extractUrls(parsed.htmlBody, parsed.textBody);

    // ── 5. URL scanning (VirusTotal + URLScan) ──────────────────────────────
    // Limit to first 5 unique URLs for speed
    const urlsToScan = extractedUrls.slice(0, 5);
    const urlScanResults = await Promise.allSettled(
      urlsToScan.map(async (eu) => {
        const [vtResult, urlScanResult] = await Promise.allSettled([
          scanWithVirusTotal(eu.url),
          scanWithURLScan(eu.url),
        ]);

        const vt = vtResult.status === 'fulfilled' ? vtResult.value : null;
        const us = urlScanResult.status === 'fulfilled' ? urlScanResult.value : null;

        // Phishing flags specific to this URL
        const urlFlags = detectPhishingIndicators([eu], parsed).filter(f => f.url === eu.url);

        const scored = scoreUrl(vt, us, eu, urlFlags);

        return {
          url: eu.url,
          defangedUrl: eu.defangedUrl,
          domain: eu.domain,
          status: scored.status,
          score: scored.score,
          category: scored.category,
          vtDetections: vt?.detections || 0,
          vtTotal: vt?.total || 0,
          urlScanVerdict: us?.verdict || null,
          urlScanUuid: us?.uuid || null,
          phishingFlags: urlFlags,
        };
      })
    );

    const scoredUrls = urlScanResults
      .filter(r => r.status === 'fulfilled')
      .map(r => r.value);

    // ── 6. Phishing indicators (full email scope) ───────────────────────────
    const allIndicators = [
      ...headerResult.indicators,
      ...detectPhishingIndicators(extractedUrls, parsed).filter(f => !f.url), // body-level only
    ];

    // ── 7. Attachment metadata ─────────────────────────────────────────────
    const attachmentResults = (parsed.attachments || []).map(att => ({
      filename: att.filename,
      contentType: att.contentType,
      sizeBytes: att.sizeBytes,
      sha256: att.sha256,
      status: 'safe', // Full sandbox analysis is out of scope for Sprint 1-2
      sandboxResult: 'Static analysis only — dynamic sandbox not configured',
    }));

    // ── 8. Overall risk score ───────────────────────────────────────────────
    const { riskScore, confidence, verdict, severity } = computeEmailRiskScore(
      headerResult,
      scoredUrls.map(u => ({ score: u.score })),
      allIndicators
    );

    // ── 9. Generate summary ─────────────────────────────────────────────────
    const summary = generateSummary(verdict, riskScore, headerResult, scoredUrls, allIndicators, parsed);

    // ── 10. Persist to SQLite ───────────────────────────────────────────────
    const analysisId = uuid();
    const analysisTimeMs = Date.now() - startTime;

    const insertAnalysis = db.prepare(`
      INSERT INTO analyses (id, verdict, risk_score, confidence, severity, sha256, subject, sender, recipient, email_date, analysis_time_ms, summary)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const insertHeader = db.prepare(`
      INSERT INTO email_headers (analysis_id, spf_status, dkim_status, dmarc_status, sender_reputation, return_path, received_from, message_id, reply_to, spoofing_indicators)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const insertUrl = db.prepare(`
      INSERT INTO url_results (analysis_id, url, defanged_url, status, reputation, category, vt_detections, vt_total, urlscan_verdict, urlscan_uuid, phishing_flags)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const insertAttachment = db.prepare(`
      INSERT INTO attachments (analysis_id, filename, content_type, size_bytes, sha256, status, sandbox_result)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    const insertIndicator = db.prepare(`
      INSERT INTO phishing_indicators (analysis_id, type, description, severity)
      VALUES (?, ?, ?, ?)
    `);

    // Run all inserts in a transaction
    const transaction = db.transaction(() => {
      insertAnalysis.run(
        analysisId, verdict, riskScore, confidence, severity,
        parsed.sha256, parsed.subject, parsed.from, parsed.to,
        parsed.date, analysisTimeMs, summary
      );

      insertHeader.run(
        analysisId,
        headerResult.spfStatus, headerResult.dkimStatus, headerResult.dmarcStatus,
        headerResult.senderReputation,
        headerResult.returnPath, headerResult.receivedFrom,
        parsed.messageId, parsed.replyTo,
        JSON.stringify(headerResult.spoofingIndicators)
      );

      for (const url of scoredUrls) {
        insertUrl.run(
          analysisId, url.url, url.defangedUrl, url.status,
          url.score, url.category,
          url.vtDetections, url.vtTotal,
          url.urlScanVerdict, url.urlScanUuid,
          JSON.stringify(url.phishingFlags)
        );
      }

      for (const att of attachmentResults) {
        insertAttachment.run(
          analysisId, att.filename, att.contentType, att.sizeBytes,
          att.sha256, att.status, att.sandboxResult
        );
      }

      for (const ind of allIndicators) {
        insertIndicator.run(analysisId, ind.type, ind.description, ind.severity);
      }
    });

    transaction();

    // ── 11. Build response ──────────────────────────────────────────────────
    const response = {
      id: analysisId,
      createdAt: new Date().toISOString(),
      analysisTimeMs,
      verdict,
      riskScore,
      confidence,
      severity,
      summary,
      email: {
        subject: parsed.subject,
        from: parsed.from,
        to: parsed.to,
        date: parsed.date,
        sha256: parsed.sha256,
        messageId: parsed.messageId,
      },
      headerAnalysis: {
        spfStatus: headerResult.spfStatus,
        dkimStatus: headerResult.dkimStatus,
        dmarcStatus: headerResult.dmarcStatus,
        senderReputation: headerResult.senderReputation,
        returnPath: headerResult.returnPath,
        receivedFrom: headerResult.receivedFrom,
        spoofingIndicators: headerResult.spoofingIndicators,
      },
      urlAnalysis: {
        totalUrls: extractedUrls.length,
        maliciousUrls: scoredUrls.filter(u => u.status === 'malicious').length,
        suspiciousUrls: scoredUrls.filter(u => u.status === 'suspicious').length,
        urls: scoredUrls.map(u => ({
          url: u.defangedUrl || u.url,
          status: u.status,
          reputation: u.score,
          category: u.category,
          vtDetections: u.vtDetections,
          vtTotal: u.vtTotal,
        })),
      },
      attachmentAnalysis: {
        totalAttachments: attachmentResults.length,
        riskyAttachments: attachmentResults.filter(a => a.status !== 'safe').length,
        attachments: attachmentResults.map(a => ({
          name: a.filename,
          type: a.contentType,
          size: formatSize(a.sizeBytes),
          hash: a.sha256,
          status: a.status,
          sandboxResult: a.sandboxResult,
        })),
      },
      indicators: allIndicators.map(({ type, description, severity }) => ({ type, description, severity })),
    };

    return res.json(response);

  } catch (err) {
    console.error('[Analysis] Error:', err);
    return res.status(500).json({
      error: 'Analysis failed',
      message: err.message,
    });
  }
});

// ── Helpers ──────────────────────────────────────────────────────────────────

function generateSummary(verdict, riskScore, headerResult, urls, indicators, parsed) {
  const subject = parsed.subject || '(no subject)';
  const from = parsed.from || '(unknown sender)';
  const highIndicators = indicators.filter(i => i.severity === 'high');
  const malUrls = urls.filter(u => u.status === 'malicious').length;

  if (verdict === 'phishing') {
    return `This email exhibits high-confidence phishing indicators (risk score: ${riskScore}/100). ` +
      `Received from "${from}" with subject "${subject}". ` +
      (headerResult.spfStatus !== 'pass' ? `The sender failed email authentication checks (SPF: ${headerResult.spfStatus}, DKIM: ${headerResult.dkimStatus}, DMARC: ${headerResult.dmarcStatus}). ` : '') +
      (malUrls > 0 ? `${malUrls} malicious URL${malUrls > 1 ? 's' : ''} detected in the email body. ` : '') +
      (highIndicators.length > 0 ? `Key threats: ${highIndicators.slice(0, 2).map(i => i.type).join(', ')}.` : '');
  } else if (verdict === 'suspicious') {
    return `This email contains suspicious elements that warrant further review (risk score: ${riskScore}/100). ` +
      `From "${from}", subject "${subject}". ` +
      `${indicators.length} indicator${indicators.length !== 1 ? 's' : ''} flagged. Treat with caution.`;
  } else {
    return `This email appears clean with no significant phishing indicators detected (risk score: ${riskScore}/100). ` +
      `From "${from}", subject "${subject}". Standard security practices still recommended.`;
  }
}

function formatSize(bytes) {
  if (!bytes) return 'Unknown';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export default router;
