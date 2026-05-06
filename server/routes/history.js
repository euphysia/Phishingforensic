import express from 'express';
import supabase from '../db.js';

const router = express.Router();

/**
 * GET /api/history
 * Returns paginated list of past analyses, newest first.
 * Query params: ?page=1&limit=20
 */
router.get('/', async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20));
    const from = (page - 1) * limit;
    const to = from + limit - 1;

    const { data: rows, error, count } = await supabase
      .from('analyses')
      .select('id, created_at, verdict, risk_score, confidence, severity, sha256, subject, sender, recipient, email_date, analysis_time_ms, summary', { count: 'exact' })
      .order('created_at', { ascending: false })
      .range(from, to);

    if (error) throw new Error(error.message);

    const analyses = (rows || []).map(row => ({
      id: row.id,
      createdAt: row.created_at,
      verdict: row.verdict,
      riskScore: row.risk_score,
      confidence: row.confidence,
      severity: row.severity,
      sha256: row.sha256,
      subject: row.subject || '(no subject)',
      sender: row.sender || '(unknown)',
      recipient: row.recipient || '',
      emailDate: row.email_date,
      analysisTimeMs: row.analysis_time_ms,
      summary: row.summary,
    }));

    const total = count ?? 0;

    return res.json({
      analyses,
      pagination: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
      },
    });
  } catch (err) {
    console.error('[History] Error:', err);
    return res.status(500).json({ error: 'Failed to retrieve history', message: err.message });
  }
});

/**
 * GET /api/history/:id
 * Returns full details for a single analysis.
 */
router.get('/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const { data: analysis, error: aErr } = await supabase
      .from('analyses')
      .select('*')
      .eq('id', id)
      .single();

    if (aErr || !analysis) return res.status(404).json({ error: 'Analysis not found' });

    const { data: headersRow } = await supabase
      .from('email_headers')
      .select('*')
      .eq('analysis_id', id)
      .single();

    const { data: urls } = await supabase
      .from('url_results')
      .select('*')
      .eq('analysis_id', id);

    const { data: attachments } = await supabase
      .from('attachments')
      .select('*')
      .eq('analysis_id', id);

    const { data: indicators } = await supabase
      .from('phishing_indicators')
      .select('*')
      .eq('analysis_id', id);

    const urlList = urls || [];
    const attList = attachments || [];
    const indList = indicators || [];

    // spoofing_indicators is stored as a jsonb array in Supabase
    const spoofingIndicators = Array.isArray(headersRow?.spoofing_indicators)
      ? headersRow.spoofing_indicators
      : [];

    return res.json({
      id: analysis.id,
      createdAt: analysis.created_at,
      verdict: analysis.verdict,
      riskScore: analysis.risk_score,
      confidence: analysis.confidence,
      severity: analysis.severity,
      summary: analysis.summary,
      email: {
        subject: analysis.subject,
        from: analysis.sender,
        to: analysis.recipient,
        date: analysis.email_date,
        sha256: analysis.sha256,
      },
      headerAnalysis: headersRow ? {
        spfStatus: headersRow.spf_status,
        dkimStatus: headersRow.dkim_status,
        dmarcStatus: headersRow.dmarc_status,
        senderReputation: headersRow.sender_reputation,
        returnPath: headersRow.return_path,
        receivedFrom: headersRow.received_from,
        spoofingIndicators,
      } : null,
      urlAnalysis: {
        totalUrls: urlList.length,
        maliciousUrls: urlList.filter(u => u.status === 'malicious').length,
        suspiciousUrls: urlList.filter(u => u.status === 'suspicious').length,
        urls: urlList.map(u => ({
          url: u.defanged_url || u.url,
          status: u.status,
          reputation: u.reputation,
          category: u.category,
          vtDetections: u.vt_detections,
          vtTotal: u.vt_total,
        })),
      },
      attachmentAnalysis: {
        totalAttachments: attList.length,
        riskyAttachments: attList.filter(a => a.status !== 'safe').length,
        attachments: attList.map(a => ({
          name: a.filename,
          type: a.content_type,
          size: formatSize(a.size_bytes),
          hash: a.sha256,
          status: a.status,
          sandboxResult: a.sandbox_result,
        })),
      },
      indicators: indList.map(i => ({
        type: i.type,
        description: i.description,
        severity: i.severity,
      })),
    });
  } catch (err) {
    console.error('[History/:id] Error:', err);
    return res.status(500).json({ error: 'Failed to retrieve analysis', message: err.message });
  }
});

function formatSize(bytes) {
  if (!bytes) return 'Unknown';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export default router;
