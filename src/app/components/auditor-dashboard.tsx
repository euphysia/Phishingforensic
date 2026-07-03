import { useState, useEffect } from 'react';
import { Shield, ChevronDown, ChevronUp, RefreshCw, Clock, AlertTriangle } from 'lucide-react';
import { Card }   from './ui/card';
import { Button } from './ui/button';

interface AuditEntry {
  timestamp: string;
  action:    string;
  module:    string;
  description: string;
}

interface AuditLog {
  id:         string;
  analysisId: string;
  entries:    AuditEntry[];
  createdAt:  string;
  analysis: {
    subject:    string;
    sender:     string;
    verdict:    string;
    risk_score: number;
    created_at: string;
  } | null;
}

const VERDICT_COLORS: Record<string, string> = {
  phishing:   'text-red-400 bg-red-950/40 border-red-700/50',
  suspicious: 'text-amber-400 bg-amber-950/40 border-amber-700/50',
  clean:      'text-emerald-400 bg-emerald-950/40 border-emerald-700/50',
};

export function AuditorDashboard() {
  const [logs,     setLogs]     = useState<AuditLog[]>([]);
  const [loading,  setLoading]  = useState(true);
  const [error,    setError]    = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  const fetchLogs = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/audit/logs?limit=50', { credentials: 'include' });
      if (res.status === 401 || res.status === 403) {
        setError('Access denied — Auditor or Admin role required.');
        return;
      }
      if (!res.ok) throw new Error(`Server error ${res.status}`);
      const data = await res.json();
      setLogs(data.logs ?? []);
    } catch (err: any) {
      setError(err.message || 'Failed to load audit logs');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchLogs(); }, []);

  const toggleExpand = (id: string) =>
    setExpanded(prev => ({ ...prev, [id]: !prev[id] }));

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Shield className="w-5 h-5 text-amber-400" />
            Audit Log / Chain of Custody
          </h2>
          <p className="text-sm text-slate-400 mt-1">
            Forensic audit trail for all email analyses
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={fetchLogs}
          disabled={loading}
          className="border-slate-700 text-slate-300 hover:text-white"
        >
          <RefreshCw className={`w-4 h-4 mr-1.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {error && (
        <div className="flex items-center gap-2 p-4 rounded-lg bg-red-950/30 border border-red-700/50 text-red-400">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          {error}
        </div>
      )}

      {loading && !error && (
        <div className="space-y-3">
          {[1, 2, 3].map(i => (
            <div key={i} className="h-20 rounded-lg bg-slate-800/40 animate-pulse" />
          ))}
        </div>
      )}

      {!loading && !error && logs.length === 0 && (
        <Card className="bg-slate-900 border-slate-800 p-12 text-center">
          <Clock className="w-10 h-10 text-slate-600 mx-auto mb-3" />
          <p className="text-slate-400">No audit logs yet.</p>
        </Card>
      )}

      <div className="space-y-3">
        {logs.map(log => {
          const isOpen = expanded[log.id] ?? false;
          const analysis = log.analysis;
          const verdict = analysis?.verdict ?? 'unknown';

          return (
            <Card key={log.id} className="bg-slate-900 border-slate-800 overflow-hidden">
              {/* Summary row */}
              <button
                className="w-full flex items-center gap-4 px-5 py-4 hover:bg-slate-800/40 transition-colors text-left"
                onClick={() => toggleExpand(log.id)}
              >
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-3 mb-1">
                    <p className="text-sm font-medium text-white truncate">
                      {analysis?.subject || '(no subject)'}
                    </p>
                    {verdict !== 'unknown' && (
                      <span className={`shrink-0 text-[10px] px-2 py-0.5 rounded-full border font-semibold uppercase ${VERDICT_COLORS[verdict] ?? ''}`}>
                        {verdict}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-4 text-xs text-slate-500">
                    <span className="font-mono">{log.analysisId.slice(0, 8).toUpperCase()}</span>
                    <span>{analysis?.sender ?? '—'}</span>
                    <span>{new Date(log.createdAt).toLocaleString('en-GB')}</span>
                    <span>{log.entries.length} audit entries</span>
                  </div>
                </div>
                {isOpen
                  ? <ChevronUp className="w-4 h-4 text-slate-500 shrink-0" />
                  : <ChevronDown className="w-4 h-4 text-slate-500 shrink-0" />
                }
              </button>

              {/* Expanded chain of custody */}
              {isOpen && (
                <div className="border-t border-slate-800 px-5 pb-5 pt-4">
                  <p className="text-[10px] text-slate-500 uppercase tracking-widest font-semibold mb-3">
                    Chain of Custody
                  </p>
                  <table className="w-full text-xs border-collapse">
                    <thead>
                      <tr className="bg-slate-800">
                        {['Timestamp', 'Event', 'Module', 'Details'].map(h => (
                          <th key={h} className="text-left px-3 py-2 text-slate-400 font-semibold uppercase tracking-wide text-[10px] border border-slate-700">
                            {h}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {log.entries.map((e, i) => (
                        <tr key={i} className={i % 2 === 0 ? 'bg-slate-900' : 'bg-slate-950'}>
                          <td className="px-3 py-2 border border-slate-800 font-mono text-slate-500 whitespace-nowrap">
                            {new Date(e.timestamp).toLocaleString('en-GB')}
                          </td>
                          <td className="px-3 py-2 border border-slate-800 font-semibold text-white">{e.action}</td>
                          <td className="px-3 py-2 border border-slate-800 text-slate-400">{e.module}</td>
                          <td className="px-3 py-2 border border-slate-800 text-slate-300">{e.description}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Card>
          );
        })}
      </div>
    </div>
  );
}
