import express from 'express';
import supabase from '../db.js';
import { requireAuth } from '../middleware/auth.js';

const router = express.Router();

// GET /api/audit/logs — auditor + admin only
router.get('/logs', requireAuth('auditor', 'admin'), async (req, res) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20));
    const from  = (page - 1) * limit;
    const to    = from + limit - 1;

    const { data: rows, error, count } = await supabase
      .from('chain_of_custody')
      .select('*, analyses(id, subject, sender, verdict, risk_score, created_at, submitted_by)', { count: 'exact' })
      .order('created_at', { ascending: false })
      .range(from, to);

    if (error) throw new Error(error.message);

    return res.json({
      logs: (rows ?? []).map(r => ({
        id:         r.id,
        analysisId: r.analysis_id,
        entries:    r.entries ?? [],
        createdAt:  r.created_at,
        analysis:   r.analyses ?? null,
      })),
      pagination: {
        total:      count ?? 0,
        page,
        limit,
        totalPages: Math.ceil((count ?? 0) / limit),
      },
    });
  } catch (err) {
    console.error('[Audit] Error:', err);
    return res.status(500).json({ error: 'Failed to retrieve audit logs' });
  }
});

export default router;
