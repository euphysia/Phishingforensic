import express from 'express';
import db from '../db.js';

const router = express.Router();

/**
 * GET /api/history
 * Returns paginated list of past analyses, newest first.
 * Query params: ?page=1&limit=20
 */
router.get('/', (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20));
    const offset = (page - 1) * limit;

    const total = db.prepare('SELECT COUNT(*) as count FROM analyses').get().count;

    const rows = db.prepare(`
      SELECT
        a.id,
        a.created_at,
        a.verdict,
        a.risk_score,
        a.confidence,
        a.severity,
        a.sha256,
        a.subject,
        a.sender,
        a.recipient,
        a.email_date,
        a.analysis_time_ms,
        a.summary
      FROM analyses a
      ORDER BY a.created_at DESC
      LIMIT ? OFFSET ?
    `).all(limit, offset);

    const analyses = rows.map(row => ({
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
router.get('/:id', (req, res) => {
  try {
    const { id } = req.params;

    const analysis = db.prepare('SELECT * FROM analyses WHERE id = ?').get(id);
    if (!analysis) return res.status(404).json({ error: 'Analysis not found' });

    const headers = db.prepare('SELECT * FROM email_headers WHERE analysis_id = ?').get(id);
    const urls = db.prepare('SELECT * FROM url_results WHERE analysis_id = ?').all(id);
    const attachments = db.prepare('SELECT * FROM attachments WHERE analysis_id = ?').all(id);
    const indicators = db.prepare('SELECT * FROM phishing_indicators WHERE analysis_id = ?').all(id);

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
      headerAnalysis: headers ? {
        spfStatus: headers.spf_status,
        dkimStatus: headers.dkim_status,
        dmarcStatus: headers.dmarc_status,
        senderReputation: headers.sender_reputation,
        returnPath: headers.return_path,
        receivedFrom: headers.received_from,
        spoofingIndicators: JSON.parse(headers.spoofing_indicators || '[]'),
      } : null,
      urlAnalysis: {
        totalUrls: urls.length,
        maliciousUrls: urls.filter(u => u.status === 'malicious').length,
        suspiciousUrls: urls.filter(u => u.status === 'suspicious').length,
        urls: urls.map(u => ({
          url: u.defanged_url || u.url,
          status: u.status,
          reputation: u.reputation,
          category: u.category,
          vtDetections: u.vt_detections,
          vtTotal: u.vt_total,
        })),
      },
      attachmentAnalysis: {
        totalAttachments: attachments.length,
        riskyAttachments: attachments.filter(a => a.status !== 'safe').length,
        attachments: attachments.map(a => ({
          name: a.filename,
          type: a.content_type,
          size: formatSize(a.size_bytes),
          hash: a.sha256,
          status: a.status,
          sandboxResult: a.sandbox_result,
        })),
      },
      indicators: indicators.map(i => ({
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
