import 'dotenv/config';
import express      from 'express';
import cors         from 'cors';
import multer       from 'multer';
import cookieParser from 'cookie-parser';
import analysisRouter from './routes/analysis.js';
import historyRouter  from './routes/history.js';
import smtpRouter     from './routes/smtp.js';
import authRouter     from './routes/auth.js';
import auditRouter    from './routes/audit.js';
import { startSmtpListener } from './smtp/smtpListener.js';
import { COOKIE_SECRET } from './middleware/auth.js';

// ── Import analysis pipeline for SMTP-triggered runs ─────────────────────────
import { parseEmail }                    from './parser/emailParser.js';
import { analyzeHeaders }                from './parser/headerAnalyzer.js';
import { extractUrls }                   from './analyzers/urlExtractor.js';
import { scanWithVirusTotal }            from './analyzers/virusTotal.js';
import { scanWithURLScan }               from './analyzers/urlScan.js';
import { detectPhishingIndicators }      from './analyzers/phishingIndicators.js';
import { scoreUrl, computeEmailRiskScore } from './analyzers/reputationScorer.js';
import { generateAISummary }             from './analyzers/aiSummary.js';
import { analyzeAttachments }            from './analyzers/attachmentAnalyzer.js';
import { createChainOfCustody, mergeAttachmentAuditTrails } from './analyzers/chainOfCustody.js';
import { checkIpReputation, extractSenderIps } from './analyzers/abuseIPDB.js';
import { checkWithPhishTank }            from './analyzers/phishTank.js';
import { v4 as uuid }                    from 'uuid';
import supabase                          from './db.js';

const app  = express();
const PORT = process.env.PORT || 3001;

// ── Middleware ────────────────────────────────────────────────────────────────

app.use(cors({ origin: ['http://localhost:5173', 'http://localhost:4173'], credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.text({ type: 'message/rfc822', limit: '10mb' }));
app.use(cookieParser(COOKIE_SECRET));

// Multer for .eml file uploads (memory storage)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    const allowed = ['.eml', '.txt', '.msg'];
    const ext = file.originalname.toLowerCase().slice(file.originalname.lastIndexOf('.'));
    if (allowed.includes(ext) || file.mimetype.includes('text')) {
      cb(null, true);
    } else {
      cb(new Error('Only .eml, .txt, or .msg files are allowed'));
    }
  },
});

// ── Routes ────────────────────────────────────────────────────────────────────

app.use('/api/auth',    authRouter);
app.use('/api/analyze', upload.single('email'), analysisRouter);
app.use('/api/history', historyRouter);
app.use('/api/audit',   auditRouter);
app.use('/api/smtp',    smtpRouter);

// Health check
app.get('/api/health', (req, res) => {
  const smtpPort = process.env.SMTP_PORT || 2525;
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    demoMode: {
      virusTotal:  !process.env.VIRUSTOTAL_API_KEY || process.env.VIRUSTOTAL_API_KEY === 'YOUR_VIRUSTOTAL_API_KEY',
      urlScan:     !process.env.URLSCAN_API_KEY    || process.env.URLSCAN_API_KEY    === 'YOUR_URLSCAN_API_KEY',
      gemini:      !process.env.GEMINI_API_KEY     || process.env.GEMINI_API_KEY     === 'your-gemini-api-key-here',
      abuseIpDb:   !process.env.ABUSEIPDB_API_KEY  || process.env.ABUSEIPDB_API_KEY  === 'YOUR_ABUSEIPDB_API_KEY',
      phishTank:   !process.env.PHISHTANK_API_KEY  || process.env.PHISHTANK_API_KEY  === 'YOUR_PHISHTANK_API_KEY',
    },
    smtp: { port: smtpPort },
  });
});

// ── Error handler ─────────────────────────────────────────────────────────────

app.use((err, req, res, next) => {
  console.error('[Server Error]', err.message);
  res.status(err.status || 500).json({
    error: err.message || 'Internal server error',
  });
});

// ── Start HTTP server then SMTP listener ──────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n🔬 Phishing Forensic API running at http://localhost:${PORT}`);
  console.log(`   Health:      http://localhost:${PORT}/api/health`);
  console.log(`   VirusTotal:  ${process.env.VIRUSTOTAL_API_KEY ? '✅ API key set' : '⚠️  Demo mode'}`);
  console.log(`   URLScan:     ${process.env.URLSCAN_API_KEY    ? '✅ API key set' : '⚠️  Demo mode'}`);
  console.log(`   Gemini AI:   ${process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'your-gemini-api-key-here' ? '✅ API key set' : '⚠️  Fallback summaries'}`);
  console.log(`   AbuseIPDB:   ${process.env.ABUSEIPDB_API_KEY && process.env.ABUSEIPDB_API_KEY !== 'YOUR_ABUSEIPDB_API_KEY' ? '✅ API key set' : '⚠️  Demo mode'}`);
  console.log(`   PhishTank:   ${process.env.PHISHTANK_API_KEY && process.env.PHISHTANK_API_KEY !== 'YOUR_PHISHTANK_API_KEY' ? '✅ API key set' : '⚠️  Demo mode'}\n`);

  // Start SMTP inbound listener
  startSmtpListener(runAnalysisPipeline);
});

// ── Shared analysis pipeline (used by both HTTP route and SMTP listener) ──────

async function runAnalysisPipeline(rawEmail) {
  const analysisId = uuid();
  const startTime  = Date.now();

  const parsed       = await parseEmail(rawEmail);
  const custody      = createChainOfCustody(analysisId, parsed.sha256, parsed.subject || '(no subject)', parsed.from || '(unknown)');
  const headerResult = analyzeHeaders(parsed);

  custody.addEntry('HEADER_ANALYSIS', 'HeaderAnalyzer',
    `SPF: ${headerResult.spfStatus}, DKIM: ${headerResult.dkimStatus}, DMARC: ${headerResult.dmarcStatus}`);

  const extractedUrls = extractUrls(parsed.htmlBody, parsed.textBody);
  custody.addEntry('URL_EXTRACTION', 'URLExtractor', `Extracted ${extractedUrls.length} URL(s)`);

  // IP reputation
  const senderIps    = extractSenderIps(parsed.receivedHeaders);
  const ipRepResults = await Promise.allSettled(senderIps.map(ip => checkIpReputation(ip)));
  const ipReputations = ipRepResults.filter(r => r.status === 'fulfilled').map(r => r.value);

  for (const ipResult of ipReputations) {
    if (ipResult.verdict === 'malicious' || ipResult.verdict === 'suspicious') {
      headerResult.indicators = headerResult.indicators || [];
      headerResult.indicators.push({
        type:        'MALICIOUS_SENDER_IP',
        severity:    ipResult.verdict === 'malicious' ? 'high' : 'medium',
        description: `Sender IP ${ipResult.ip} has abuse score ${ipResult.abuseScore}% — ${ipResult.summary}`,
      });
    }
  }

  // URL scanning
  const urlsToScan    = extractedUrls.slice(0, 5);
  const urlScanResults = await Promise.allSettled(
    urlsToScan.map(async (eu) => {
      const [vtResult, urlScanResult, phishTankResult] = await Promise.allSettled([
        scanWithVirusTotal(eu.url),
        scanWithURLScan(eu.url),
        checkWithPhishTank(eu.url),
      ]);
      const vt = vtResult.status      === 'fulfilled' ? vtResult.value      : null;
      const us = urlScanResult.status === 'fulfilled' ? urlScanResult.value : null;
      const pt = phishTankResult.status === 'fulfilled' ? phishTankResult.value : null;
      const urlFlags = detectPhishingIndicators([eu], parsed).filter(f => f.url === eu.url);
      const scored   = scoreUrl(vt, us, eu, urlFlags, pt);
      return { url: eu.url, defangedUrl: eu.defangedUrl, domain: eu.domain, status: scored.status, score: scored.score, category: scored.category, vtDetections: vt?.detections || 0, vtTotal: vt?.total || 0, urlScanVerdict: us?.verdict || null, urlScanUuid: us?.uuid || null, phishTankResult: pt, phishingFlags: urlFlags };
    })
  );
  const scoredUrls = urlScanResults.filter(r => r.status === 'fulfilled').map(r => r.value);

  const allIndicators = [
    ...headerResult.indicators,
    ...detectPhishingIndicators(extractedUrls, parsed).filter(f => !f.url),
  ];

  const attachmentResults = await analyzeAttachments(parsed.attachments || [], analysisId);
  mergeAttachmentAuditTrails(custody, attachmentResults);

  const { riskScore, confidence, verdict, severity, scoreBreakdown } = computeEmailRiskScore(
    headerResult, scoredUrls.map(u => ({ score: u.score })), allIndicators, ipReputations, attachmentResults
  );

  custody.addEntry('ANALYSIS_FINALISED', 'AnalysisEngine', `Risk: ${riskScore}/100, Verdict: ${verdict}`);

  const summary = await generateAISummary({ verdict, riskScore, confidence, headerResult, scoredUrls, indicators: allIndicators, parsed, fallbackSummary: `Email "${parsed.subject}" — Risk score: ${riskScore}/100 (${verdict})`, attachmentResults, ipReputations });

  const analysisTimeMs = Date.now() - startTime;

  // Persist to Supabase
  await supabase.from('analyses').insert({ id: analysisId, verdict, risk_score: riskScore, confidence, severity, sha256: parsed.sha256, subject: parsed.subject, sender: parsed.from, recipient: parsed.to, email_date: parsed.date, analysis_time_ms: analysisTimeMs, summary });
  await supabase.from('email_headers').insert({ analysis_id: analysisId, spf_status: headerResult.spfStatus, dkim_status: headerResult.dkimStatus, dmarc_status: headerResult.dmarcStatus, sender_reputation: headerResult.senderReputation, return_path: headerResult.returnPath, received_from: headerResult.receivedFrom, message_id: parsed.messageId, reply_to: parsed.replyTo, spoofing_indicators: headerResult.spoofingIndicators });
  if (scoredUrls.length > 0) await supabase.from('url_results').insert(scoredUrls.map(u => ({ analysis_id: analysisId, url: u.url, defanged_url: u.defangedUrl, status: u.status, reputation: u.score, category: u.category, vt_detections: u.vtDetections, vt_total: u.vtTotal, urlscan_verdict: u.urlScanVerdict, urlscan_uuid: u.urlScanUuid, phishing_flags: u.phishingFlags })));
  if (attachmentResults.length > 0) {
    const { error: attErr } = await supabase.from('attachments').insert(attachmentResults.map(a => ({ analysis_id: analysisId, filename: a.filename, content_type: a.contentType, size_bytes: a.sizeBytes, sha256: a.sha256, status: a.status, sandbox_result: `Static analysis — ${a.risks?.length || 0} risk(s) found` })));
    if (attErr) console.warn('[SMTP Pipeline] Attachment insert warning:', attErr.message);
  }
  if (allIndicators.length > 0) await supabase.from('phishing_indicators').insert(allIndicators.map(ind => ({ analysis_id: analysisId, type: ind.type, description: ind.description, severity: ind.severity })));

  return { id: analysisId, verdict, riskScore, confidence, severity, summary, scoreBreakdown };
}

