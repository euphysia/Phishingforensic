import { useState, useEffect } from 'react';
import { Search, Filter, Calendar, ShieldAlert, AlertTriangle, ShieldCheck, ChevronRight, RefreshCw } from 'lucide-react';
import { Card } from './ui/card';
import { Input } from './ui/input';
import { Button } from './ui/button';
import { Badge } from './ui/badge';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select';

interface HistoryItem {
  id: string;
  subject: string;
  sender: string;
  createdAt: string;
  verdict: 'phishing' | 'suspicious' | 'clean';
  riskScore: number;
}

interface AnalysisHistoryProps {
  onSelectAnalysis: (id: string) => void;
  refreshTrigger?:  number;
  userRole?:        string;
}

export function AnalysisHistory({ onSelectAnalysis, refreshTrigger }: AnalysisHistoryProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [verdictFilter, setVerdictFilter] = useState('all');
  const [historyData, setHistoryData] = useState<HistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchHistory = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/history?limit=50', { credentials: 'include' });
      if (res.status === 401 || res.status === 403) throw new Error('Login to view history');
      if (!res.ok) throw new Error(`Server error: ${res.status}`);
      const data = await res.json();
      setHistoryData(data.analyses || []);
    } catch (err: any) {
      setError(err.message || 'Failed to load history');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [refreshTrigger]);

  const filteredHistory = historyData.filter(item => {
    const matchesSearch =
      item.subject.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.sender.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.id.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesVerdict = verdictFilter === 'all' || item.verdict === verdictFilter;

    return matchesSearch && matchesVerdict;
  });

  const verdictConfig = {
    phishing: {
      icon: ShieldAlert,
      color: 'bg-red-600/20 text-red-400 border-red-600/50',
      label: 'Phishing'
    },
    suspicious: {
      icon: AlertTriangle,
      color: 'bg-orange-600/20 text-orange-400 border-orange-600/50',
      label: 'Suspicious'
    },
    clean: {
      icon: ShieldCheck,
      color: 'bg-green-600/20 text-green-400 border-green-600/50',
      label: 'Clean'
    }
  };

  const formatTime = (isoString: string) => {
    const date = new Date(isoString);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins} minute${diffMins !== 1 ? 's' : ''} ago`;
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`;
    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays} day${diffDays !== 1 ? 's' : ''} ago`;
  };

  return (
    <Card className="bg-slate-900 border-slate-800 p-6">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h3 className="text-lg text-white mb-1">Analysis History</h3>
          <p className="text-sm text-slate-300">
            {historyData.length} email{historyData.length !== 1 ? 's' : ''} analysed — real results from database
          </p>
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={fetchHistory}
          className="text-slate-400 hover:text-white"
          disabled={loading}
        >
          <RefreshCw className={`w-4 h-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      <div className="flex gap-3 mb-6">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <Input
            placeholder="Search by subject, sender, or ID..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-10 bg-slate-800 border-slate-700 text-white"
          />
        </div>
        <Select value={verdictFilter} onValueChange={setVerdictFilter}>
          <SelectTrigger className="w-40 bg-slate-800 border-slate-700 text-white">
            <Filter className="w-4 h-4 mr-2" />
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Verdicts</SelectItem>
            <SelectItem value="phishing">Phishing</SelectItem>
            <SelectItem value="suspicious">Suspicious</SelectItem>
            <SelectItem value="clean">Clean</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Loading state */}
      {loading && (
        <div className="text-center py-12 text-slate-400">
          <RefreshCw className="w-10 h-10 mx-auto mb-3 animate-spin opacity-50" />
          <p>Loading analysis history...</p>
        </div>
      )}

      {/* Error state */}
      {!loading && error && (
        <div className="text-center py-12 text-slate-400">
          <p className="text-red-400 mb-3">⚠️ {error}</p>
          <p className="text-sm">Make sure the backend server is running on port 3001.</p>
          <Button onClick={fetchHistory} variant="outline" size="sm" className="mt-4 border-slate-600 text-slate-300">
            Retry
          </Button>
        </div>
      )}

      {/* History list */}
      {!loading && !error && (
        <div className="space-y-3">
          {filteredHistory.map((item) => {
            const verdict = (item.verdict in verdictConfig ? item.verdict : 'clean') as keyof typeof verdictConfig;
            const config = verdictConfig[verdict];
            const Icon = config.icon;

            return (
              <div
                key={item.id}
                className="p-4 bg-slate-800/50 rounded-lg border border-slate-700 hover:bg-slate-800 transition-colors cursor-pointer"
                onClick={() => onSelectAnalysis(item.id)}
              >
                <div className="flex items-start justify-between mb-2">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <code className="text-xs text-slate-500">{item.id.slice(0, 8)}…</code>
                      <Badge variant="outline" className={`${config.color} border text-xs`}>
                        <Icon className="w-3 h-3 mr-1" />
                        {config.label}
                      </Badge>
                    </div>
                    <h4 className="text-white font-medium mb-1 truncate">
                      {item.subject || '(no subject)'}
                    </h4>
                    <p className="text-sm text-slate-400 truncate">
                      From: {item.sender || '(unknown)'}
                    </p>
                  </div>
                  <div className="text-right ml-4">
                    <div className="text-sm text-slate-400 mb-1">{formatTime(item.createdAt)}</div>
                    <div className="text-lg font-bold text-white">
                      {item.riskScore}
                      <span className="text-sm text-slate-500">/100</span>
                    </div>
                  </div>
                </div>
                <div className="flex items-center justify-between mt-3 pt-3 border-t border-slate-700">
                  <span className="text-xs text-slate-500">
                    {new Date(item.createdAt).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })}
                  </span>
                  <Button variant="ghost" size="sm" className="text-blue-400 hover:text-blue-300 hover:bg-slate-700">
                    View Details
                    <ChevronRight className="w-4 h-4 ml-1" />
                  </Button>
                </div>
              </div>
            );
          })}

          {filteredHistory.length === 0 && (
            <div className="text-center py-12 text-slate-400">
              <Search className="w-12 h-12 mx-auto mb-3 opacity-50" />
              <p>{historyData.length === 0 ? 'No emails analysed yet. Submit your first email above!' : 'No results match your filters.'}</p>
            </div>
          )}
        </div>
      )}
    </Card>
  );
}