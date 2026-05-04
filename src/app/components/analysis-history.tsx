import { useState } from 'react';
import { Search, Filter, Calendar, ShieldAlert, AlertTriangle, ShieldCheck, ChevronRight } from 'lucide-react';
import { Card } from './ui/card';
import { Input } from './ui/input';
import { Button } from './ui/button';
import { Badge } from './ui/badge';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select';

interface HistoryItem {
  id: string;
  subject: string;
  sender: string;
  date: string;
  verdict: 'phishing' | 'suspicious' | 'benign';
  riskScore: number;
  analyzed: string;
}

interface AnalysisHistoryProps {
  onSelectAnalysis: (id: string) => void;
}

export function AnalysisHistory({ onSelectAnalysis }: AnalysisHistoryProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [verdictFilter, setVerdictFilter] = useState('all');
  const [dateFilter, setDateFilter] = useState('all');

  const historyData: HistoryItem[] = [
    {
      id: 'RPT-2026-001',
      subject: 'Urgent: Verify your account immediately',
      sender: 'security@paypa1-verify.com',
      date: '2026-02-08',
      verdict: 'phishing',
      riskScore: 94,
      analyzed: '2 hours ago'
    },
    {
      id: 'RPT-2026-002',
      subject: 'Your invoice is ready',
      sender: 'billing@suspicious-domain.net',
      date: '2026-02-08',
      verdict: 'suspicious',
      riskScore: 67,
      analyzed: '4 hours ago'
    },
    {
      id: 'RPT-2026-003',
      subject: 'Team meeting notes - Q1 Planning',
      sender: 'alice@company.com',
      date: '2026-02-07',
      verdict: 'benign',
      riskScore: 12,
      analyzed: '1 day ago'
    },
    {
      id: 'RPT-2026-004',
      subject: 'Password reset request',
      sender: 'noreply@micros0ft-security.com',
      date: '2026-02-07',
      verdict: 'phishing',
      riskScore: 91,
      analyzed: '1 day ago'
    },
    {
      id: 'RPT-2026-005',
      subject: 'Quarterly report attached',
      sender: 'finance@partner-company.com',
      date: '2026-02-06',
      verdict: 'suspicious',
      riskScore: 45,
      analyzed: '2 days ago'
    },
    {
      id: 'RPT-2026-006',
      subject: 'Weekly newsletter',
      sender: 'newsletter@legitimate-service.com',
      date: '2026-02-06',
      verdict: 'benign',
      riskScore: 8,
      analyzed: '2 days ago'
    }
  ];

  const filteredHistory = historyData.filter(item => {
    const matchesSearch = 
      item.subject.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.sender.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.id.toLowerCase().includes(searchQuery.toLowerCase());
    
    const matchesVerdict = verdictFilter === 'all' || item.verdict === verdictFilter;
    const matchesDate = dateFilter === 'all' || 
      (dateFilter === 'today' && item.date === '2026-02-08') ||
      (dateFilter === 'week' && ['2026-02-08', '2026-02-07', '2026-02-06'].includes(item.date));
    
    return matchesSearch && matchesVerdict && matchesDate;
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
    benign: {
      icon: ShieldCheck,
      color: 'bg-green-600/20 text-green-400 border-green-600/50',
      label: 'Benign'
    }
  };

  return (
    <Card className="bg-slate-900 border-slate-800 p-6">
      <div className="mb-6">
        <h3 className="text-lg text-white mb-1">Analysis History</h3>
        <p className="text-sm text-slate-300">
          View and filter past email submissions and analysis results
        </p>
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
            <SelectItem value="benign">Benign</SelectItem>
          </SelectContent>
        </Select>
        <Select value={dateFilter} onValueChange={setDateFilter}>
          <SelectTrigger className="w-40 bg-slate-800 border-slate-700 text-white">
            <Calendar className="w-4 h-4 mr-2" />
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Dates</SelectItem>
            <SelectItem value="today">Today</SelectItem>
            <SelectItem value="week">This Week</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div className="space-y-3">
        {filteredHistory.map((item) => {
          const config = verdictConfig[item.verdict];
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
                    <code className="text-xs text-slate-500">{item.id}</code>
                    <Badge variant="outline" className={`${config.color} border text-xs`}>
                      <Icon className="w-3 h-3 mr-1" />
                      {config.label}
                    </Badge>
                  </div>
                  <h4 className="text-white font-medium mb-1 truncate">
                    {item.subject}
                  </h4>
                  <p className="text-sm text-slate-400 truncate">
                    From: {item.sender}
                  </p>
                </div>
                <div className="text-right ml-4">
                  <div className="text-sm text-slate-400 mb-1">{item.analyzed}</div>
                  <div className="text-lg font-bold text-white">
                    {item.riskScore}
                    <span className="text-sm text-slate-500">/100</span>
                  </div>
                </div>
              </div>
              <div className="flex items-center justify-between mt-3 pt-3 border-t border-slate-700">
                <span className="text-xs text-slate-500">Analyzed on {item.date}</span>
                <Button variant="ghost" size="sm" className="text-blue-400 hover:text-blue-300 hover:bg-slate-700">
                  View Details
                  <ChevronRight className="w-4 h-4 ml-1" />
                </Button>
              </div>
            </div>
          );
        })}
      </div>

      {filteredHistory.length === 0 && (
        <div className="text-center py-12 text-slate-400">
          <Search className="w-12 h-12 mx-auto mb-3 opacity-50" />
          <p>No analysis results found matching your filters</p>
        </div>
      )}
    </Card>
  );
}