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
import { analyzeEmailBody } from '../analyzers/bodyAnalyzer.js';

// ── Sprint 3: Attachment Analysis + Chain-of-Custody ─────────────────────────
import { analyzeAttachments } from '../analyzers/attachmentAnalyzer.js';
import { createChainOfCustody, mergeAttachmentAuditTrails } from '../analyzers/chainOfCustody.js';

// ── Sprint 4: Threat Intelligence (AbuseIPDB + PhishTank) ────────────────────
import { checkIpReputation, extractSenderIps } from '../analyzers/abuseIPDB.js';
import { checkWithPhishTank } from '../analyzers/phishTank.js';

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

    // ── 3. Chain-of-Custody: initialise forensic audit trail ───────────────
    const analysisId  = uuid();
    const custody     = createChainOfCustody(
      analysisId,
      parsed.sha256,
      parsed.subject || '(no subject)',
      parsed.from    || '(unknown)'
    );

    // ── 4. Header analysis ──────────────────────────────────────────────────
    const headerResult = analyzeHeaders(parsed);
    custody.addEntry('HEADER_ANALYSIS', 'HeaderAnalyzer',
      `SPF: ${headerResult.spfStatus}, DKIM: ${headerResult.dkimStatus}, DMARC: ${headerResult.dmarcStatus}`);

    // ── 5. URL extraction ───────────────────────────────────────────────────
    const extractedUrls = extractUrls(parsed.htmlBody, parsed.textBody);
    custody.addEntry('URL_EXTRACTION', 'URLExtractor',
      `Extracted ${extractedUrls.length} URL(s) from email body`);

    // ── 5b. AI Body Analysis ─────────────────────────────────────────────────
    const bodyAnalysis = await analyzeEmailBody({
      textBody: parsed.textBody,
      htmlBody:  parsed.htmlBody,
      subject:   parsed.subject,
      from:      parsed.from,
    });
    custody.addEntry('BODY_ANALYSIS', 'BodyAnalyzer',
      `Body risk: ${bodyAnalysis.bodyRiskScore}/100, threat: ${bodyAnalysis.overallThreatLevel}, tactics: ${bodyAnalysis.tactics.length} (source: ${bodyAnalysis.source})`);

    // ── 6. Sprint 4: AbuseIPDB — Sender IP reputation ──────────────────────
    const senderIps     = extractSenderIps(parsed.receivedHeaders);
    const ipRepResults  = await Promise.allSettled(
      senderIps.map(ip => checkIpReputation(ip))
    );
    const ipReputations = ipRepResults
      .filter(r => r.status === 'fulfilled')
      .map(r => r.value);

    for (const ipResult of ipReputations) {
      custody.addEntry('IP_REPUTATION_CHECK', 'AbuseIPDB',
        ipResult.summary || `IP ${ipResult.ip} checked`,
        null);
      if (ipResult.verdict === 'malicious' || ipResult.verdict === 'suspicious') {
        headerResult.indicators = headerResult.indicators || [];
        headerResult.indicators.push({
          type:        'MALICIOUS_SENDER_IP',
          severity:    ipResult.verdict === 'malicious' ? 'high' : 'medium',
          description: `Sender IP ${ipResult.ip} has abuse score ${ipResult.abuseScore}% — ${ipResult.summary}`,
        });
      }
    }

    // ── 7. URL scanning (VirusTotal + URLScan + PhishTank) ──────────────────
    const urlsToScan = extractedUrls.slice(0, 5);
    const urlScanResults = await Promise.allSettled(
      urlsToScan.map(async (eu) => {
        const [vtResult, urlScanResult, phishTankResult] = await Promise.allSettled([
          scanWithVirusTotal(eu.url),
          scanWithURLScan(eu.url),
          checkWithPhishTank(eu.url),   // Sprint 4: PhishTank
        ]);

        const vt = vtResult.status      === 'fulfilled' ? vtResult.value      : null;
        const us = urlScanResult.status === 'fulfilled' ? urlScanResult.value : null;
        const pt = phishTankResult.status === 'fulfilled' ? phishTankResult.value : null;

        const urlFlags = detectPhishingIndicators([eu], parsed).filter(f => f.url === eu.url);
        const scored   = scoreUrl(vt, us, eu, urlFlags, pt);  // Sprint 4: pass PhishTank

        custody.addEntry('URL_SCAN', 'URLScanner',
          `${eu.defangedUrl || eu.url} — score: ${scored.score}, status: ${scored.status}`);

        return {
          url:              eu.url,
          defangedUrl:      eu.defangedUrl,
          domain:           eu.domain,
          status:           scored.status,
          score:            scored.score,
          category:         scored.category,
          vtDetections:     vt?.detections || 0,
          vtTotal:          vt?.total || 0,
          urlScanVerdict:   us?.verdict || null,
          urlScanUuid:      us?.uuid || null,
          phishTankResult:  pt,                    // Sprint 4
          phishingFlags:    urlFlags,
        };
      })
    );

    const scoredUrls = urlScanResults
      .filter(r => r.status === 'fulfilled')
      .map(r => r.value);

    // ── 8. Phishing indicators (full email scope, including AI body tactics) ─
    const bodyTacticIndicators = bodyAnalysis.tactics.map(t => ({
      type:        t.type,
      description: t.description || t.evidence || t.type,
      severity:    t.severity,
      source:      'body-ai',
    }));

    const allIndicators = [
      ...headerResult.indicators,
      ...detectPhishingIndicators(extractedUrls, parsed).filter(f => !f.url),
      ...bodyTacticIndicators,
    ];

    // ── 9. Sprint 3: Attachment deep analysis + audit trail ────────────────
    const attachmentResults = await analyzeAttachments(
      parsed.attachments || [],
      analysisId
    );
    mergeAttachmentAuditTrails(custody, attachmentResults);

    custody.addEntry('ATTACHMENT_ANALYSIS', 'AttachmentAnalyzer',
      `${attachmentResults.length} attachment(s) analysed. ` +
      `Malicious: ${attachmentResults.filter(a => a.status === 'malicious').length}, ` +
      `Suspicious: ${attachmentResults.filter(a => a.status === 'suspicious').length}`);

    // ── 10. Sprint 4: Unified risk score (all 5 signal sources) ────────────
    const { riskScore, confidence, verdict, severity, scoreBreakdown } = computeEmailRiskScore(
      headerResult,
      scoredUrls.map(u => ({ score: u.score })),
      allIndicators,
      ipReputations,        // Sprint 4: AbuseIPDB
      attachmentResults     // Sprint 3: Attachment risks
    );

    custody.addEntry('RISK_SCORE_COMPUTED', 'ReputationScorer',
      `Final risk score: ${riskScore}/100, verdict: ${verdict}, severity: ${severity}`);
    custody.addEntry('ANALYSIS_FINALISED', 'AnalysisEngine',
      `Forensic analysis complete. Chain-of-custody entries: ${custody.entries.length}`);

    // ── 11. Generate AI summary ─────────────────────────────────────────────
    const fallbackSummary = generateSummary(verdict, riskScore, headerResult, scoredUrls, allIndicators, parsed, attachmentResults, ipReputations);
    const summary = await generateGeminiSummary({
      verdict,
      riskScore,
      confidence,
      headerResult,
      scoredUrls,
      indicators: allIndicators,
      parsed,
      fallbackSummary,
      attachmentResults,  // Sprint 3
      ipReputations,      // Sprint 4
      bodyAnalysis,       // AI body analysis
    });

    console.log(`[Analysis] Summary via ${isGeminiEnabled() ? 'Gemini AI' : 'rule-based fallback'}`);

    // ── 12. Persist to Supabase ─────────────────────────────────────────────
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

    // Insert attachment rows (Sprint 3: extended schema)
    if (attachmentResults.length > 0) {
      const { error: attErr } = await supabase.from('attachments').insert(
        attachmentResults.map(a => ({
          analysis_id:    analysisId,
          filename:       a.filename,
          content_type:   a.contentType,
          size_bytes:     a.sizeBytes,
          sha256:         a.sha256,
          md5:            a.md5,
          status:         a.status,
          risks:          a.risks || [],
          vt_detections:  a.vtResult?.detections || 0,
          vt_total:       a.vtResult?.total || 0,
          metadata:       a.metadata || {},
          audit_trail:    a.auditTrail || [],
          sandbox_result: a.vtResult
            ? `VirusTotal: ${a.vtResult.detections}/${a.vtResult.total} detections${a.vtResult.malwareFamily ? ` — ${a.vtResult.malwareFamily}` : ''}`
            : 'Static analysis only',
        }))
      );
      if (attErr) {
        // Gracefully degrade if new columns don't exist yet (schema migration pending)
        console.warn(`[Analysis] Attachment insert warning: ${attErr.message}`);
        // Retry with minimal columns for backwards compatibility
        const { error: attErrFallback } = await supabase.from('attachments').insert(
          attachmentResults.map(a => ({
            analysis_id:   analysisId,
            filename:      a.filename,
            content_type:  a.contentType,
            size_bytes:    a.sizeBytes,
            sha256:        a.sha256,
            status:        a.status,
            sandbox_result: `Static analysis — ${a.risks?.length || 0} risk(s) found`,
          }))
        );
        if (attErrFallback) throw new Error(`DB insert (attachments): ${attErrFallback.message}`);
      }
    }

    // Insert IP reputation rows (Sprint 4)
    if (ipReputations.length > 0) {
      try {
        await supabase.from('ip_reputations').insert(
          ipReputations.map(r => ({
            analysis_id:    analysisId,
            ip:             r.ip,
            abuse_score:    r.abuseScore || 0,
            verdict:        r.verdict || 'unknown',
            total_reports:  r.totalReports || 0,
            country_code:   r.countryCode || null,
            isp:            r.isp || null,
            is_tor:         r.isTor || false,
            categories:     r.categories || [],
            summary:        r.summary || null,
            from_cache:     r.fromCache || false,
          }))
        );
      } catch (ipInsertErr) {
        console.warn('[Analysis] ip_reputations table may not exist yet:', ipInsertErr.message);
      }
    }

    // Persist chain-of-custody (Sprint 3)
    const custodySummary = custody.getSummary();
    await supabase.from('chain_of_custody').insert({
      analysis_id:   analysisId,
      email_sha256:  parsed.sha256,
      total_entries: custodySummary.totalEntries,
      chain_intact:  custodySummary.chainIntact,
      entries:       custodySummary.entries,
      created_at:    custodySummary.startTime,
    }).then(({ error }) => {
      if (error) console.warn('[Analysis] chain_of_custody table may not exist yet:', error.message);
    });

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
        totalAttachments:  attachmentResults.length,
        riskyAttachments:  attachmentResults.filter(a => a.status !== 'safe').length,
        maliciousAttachments: attachmentResults.filter(a => a.status === 'malicious').length,
        attachments: attachmentResults.map(a => ({
          name:          a.filename,
          type:          a.contentType,
          size:          formatSize(a.sizeBytes),
          hash:          a.sha256,
          md5:           a.md5,
          status:        a.status,
          risks:         a.risks || [],
          vtDetections:  a.vtResult?.detections || 0,
          vtTotal:       a.vtResult?.total || 0,
          metadata:      a.metadata || {},
        })),
      },
      // Sprint 4: IP reputation data
      ipReputation: {
        totalIpsChecked: ipReputations.length,
        maliciousIps:    ipReputations.filter(r => r.verdict === 'malicious').length,
        suspiciousIps:   ipReputations.filter(r => r.verdict === 'suspicious').length,
        ips: ipReputations.map(r => ({
          ip:           r.ip,
          abuseScore:   r.abuseScore,
          verdict:      r.verdict,
          totalReports: r.totalReports,
          countryCode:  r.countryCode,
          isp:          r.isp,
          isTor:        r.isTor,
          categories:   r.categories,
          summary:      r.summary,
        })),
      },
      // Sprint 4: Score breakdown per source
      scoreBreakdown,
      // AI body analysis
      bodyAnalysis: {
        bodyRiskScore:     bodyAnalysis.bodyRiskScore,
        overallThreatLevel: bodyAnalysis.overallThreatLevel,
        confidence:        bodyAnalysis.confidence,
        tactics:           bodyAnalysis.tactics,
        summary:           bodyAnalysis.summary,
        source:            bodyAnalysis.source,
      },
      // Sprint 3: Chain-of-custody summary
      chainOfCustody: {
        totalEntries: custody.entries.length,
        chainIntact:  custody.verifyChain(),
        startTime:    custody.entries[0]?.timestamp,
        endTime:      custody.entries[custody.entries.length - 1]?.timestamp,
        entries:      custody.entries,
      },
      indicators: allIndicators.map(({ type, description, severity }) => ({ type, description, severity })),
    };

    return res.json(response);

  } catch (err) {
    console.error('[Analysis] FATAL ERROR:', err.message);
    console.error(err.stack);
    return res.status(500).json({
      error: err.message || 'Analysis failed',
      message: err.message || 'An unexpected error occurred during analysis.',
    });
  }
});

// ── Helpers ──────────────────────────────────────────────────────────────────

function generateSummary(verdict, riskScore, headerResult, urls, indicators, parsed, attachmentResults = [], ipReputations = []) {
  const subject      = parsed.subject || '(no subject)';
  const from         = parsed.from    || '(unknown sender)';
  const highIndicators  = indicators.filter(i => i.severity === 'high');
  const malUrls         = urls.filter(u => u.status === 'malicious').length;
  const malAttachments  = attachmentResults.filter(a => a.status === 'malicious').length;
  const malIps          = ipReputations.filter(r => r.verdict === 'malicious').length;

  if (verdict === 'phishing') {
    return `This email exhibits high-confidence phishing indicators (risk score: ${riskScore}/100). ` +
      `Received from "${from}" with subject "${subject}". ` +
      (headerResult.spfStatus !== 'pass' ? `Sender failed authentication (SPF: ${headerResult.spfStatus}, DKIM: ${headerResult.dkimStatus}, DMARC: ${headerResult.dmarcStatus}). ` : '') +
      (malUrls > 0 ? `${malUrls} malicious URL${malUrls > 1 ? 's' : ''} detected. ` : '') +
      (malAttachments > 0 ? `${malAttachments} malicious attachment${malAttachments > 1 ? 's' : ''} found. ` : '') +
      (malIps > 0 ? `${malIps} sender IP${malIps > 1 ? 's' : ''} flagged by AbuseIPDB. ` : '') +
      (highIndicators.length > 0 ? `Key threats: ${highIndicators.slice(0, 2).map(i => i.type).join(', ')}.` : '');
  } else if (verdict === 'suspicious') {
    return `This email contains suspicious elements warranting further review (risk score: ${riskScore}/100). ` +
      `From "${from}", subject "${subject}". ` +
      `${indicators.length} indicator${indicators.length !== 1 ? 's' : ''} flagged.` +
      (attachmentResults.filter(a => a.status !== 'safe').length > 0 ? ' Suspicious attachments detected.' : '') +
      ' Treat with caution.';
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
