import express from 'express';
import { v4 as uuid } from 'uuid';
import supabase from '../db.js';
import { parseEmail } from '../parser/emailParser.js';
import { analyzeHeaders } from '../parser/headerAnalyzer.js';
import { extractUrls } from '../analyzers/urlExtractor.js';
import { scanWithVirusTotal } from '../analyzers/virusTotal.js';
import { scanWithURLScan } from '../analyzers/urlScan.js';
import { detectPhishingIndicators } from '../analyzers/phishingIndicators.js';
import { scoreUrl, computeEmailRiskScore } from '../analyzers/reputationScorer.js';
import { generateGeminiSummary, isGeminiEnabled } from '../analyzers/geminiSummary.js';

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
    const urlsToScan = extractedUrls.slice(0, 5);
    const urlScanResults = await Promise.allSettled(
      urlsToScan.map(async (eu) => {
        const [vtResult, urlScanResult] = await Promise.allSettled([
          scanWithVirusTotal(eu.url),
          scanWithURLScan(eu.url),
        ]);

        const vt = vtResult.status === 'fulfilled' ? vtResult.value : null;
        const us = urlScanResult.status === 'fulfilled' ? urlScanResult.value : null;

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
      ...detectPhishingIndicators(extractedUrls, parsed).filter(f => !f.url),
    ];

    // ── 7. Attachment metadata ─────────────────────────────────────────────
    const attachmentResults = (parsed.attachments || []).map(att => ({
      filename: att.filename,
      contentType: att.contentType,
      sizeBytes: att.sizeBytes,
      sha256: att.sha256,
      status: 'safe',
      sandboxResult: 'Static analysis only — dynamic sandbox not configured',
    }));

    // ── 8. Overall risk score ───────────────────────────────────────────────
    const { riskScore, confidence, verdict, severity } = computeEmailRiskScore(
      headerResult,
      scoredUrls.map(u => ({ score: u.score })),
      allIndicators
    );

    // ── 9. Generate summary ─────────────────────────────────────────────────
    const fallbackSummary = generateSummary(verdict, riskScore, headerResult, scoredUrls, allIndicators, parsed);
    const summary = await generateGeminiSummary({
      verdict,
      riskScore,
      confidence,
      headerResult,
      scoredUrls,
      indicators: allIndicators,
      parsed,
      fallbackSummary,
    });

    console.log(`[Analysis] Summary via ${isGeminiEnabled() ? 'Gemini AI' : 'rule-based fallback'}`);

    // ── 10. Persist to Supabase ─────────────────────────────────────────────
    const analysisId = uuid();
    const analysisTimeMs = Date.now() - startTime;

    // Insert main analysis row
    const { error: analysisErr } = await supabase.from('analyses').insert({
      id: analysisId,
      verdict,
      risk_score: riskScore,
      confidence,
      severity,
      sha256: parsed.sha256,
      subject: parsed.subject,
      sender: parsed.from,
      recipient: parsed.to,
      email_date: parsed.date,
      analysis_time_ms: analysisTimeMs,
      summary,
    });
    if (analysisErr) throw new Error(`DB insert (analyses): ${analysisErr.message}`);

    // Insert header row
    const { error: headerErr } = await supabase.from('email_headers').insert({
      analysis_id: analysisId,
      spf_status: headerResult.spfStatus,
      dkim_status: headerResult.dkimStatus,
      dmarc_status: headerResult.dmarcStatus,
      sender_reputation: headerResult.senderReputation,
      return_path: headerResult.returnPath,
      received_from: headerResult.receivedFrom,
      message_id: parsed.messageId,
      reply_to: parsed.replyTo,
      spoofing_indicators: headerResult.spoofingIndicators,
    });
    if (headerErr) throw new Error(`DB insert (email_headers): ${headerErr.message}`);

    // Insert URL rows
    if (scoredUrls.length > 0) {
      const { error: urlErr } = await supabase.from('url_results').insert(
        scoredUrls.map(u => ({
          analysis_id: analysisId,
          url: u.url,
          defanged_url: u.defangedUrl,
          status: u.status,
          reputation: u.score,
          category: u.category,
          vt_detections: u.vtDetections,
          vt_total: u.vtTotal,
          urlscan_verdict: u.urlScanVerdict,
          urlscan_uuid: u.urlScanUuid,
          phishing_flags: u.phishingFlags,
        }))
      );
      if (urlErr) throw new Error(`DB insert (url_results): ${urlErr.message}`);
    }

    // Insert attachment rows
    if (attachmentResults.length > 0) {
      const { error: attErr } = await supabase.from('attachments').insert(
        attachmentResults.map(a => ({
          analysis_id: analysisId,
          filename: a.filename,
          content_type: a.contentType,
          size_bytes: a.sizeBytes,
          sha256: a.sha256,
          status: a.status,
          sandbox_result: a.sandboxResult,
        }))
      );
      if (attErr) throw new Error(`DB insert (attachments): ${attErr.message}`);
    }

    // Insert phishing indicator rows
    if (allIndicators.length > 0) {
      const { error: indErr } = await supabase.from('phishing_indicators').insert(
        allIndicators.map(ind => ({
          analysis_id: analysisId,
          type: ind.type,
          description: ind.description,
          severity: ind.severity,
        }))
      );
      if (indErr) throw new Error(`DB insert (phishing_indicators): ${indErr.message}`);
    }

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
