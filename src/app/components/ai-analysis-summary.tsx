import { Brain, AlertCircle, ExternalLink, Database } from 'lucide-react';
import { Card } from './ui/card';
import { Badge } from './ui/badge';

interface Indicator {
  type: string;
  description: string;
  severity: 'high' | 'medium' | 'low';
}

interface ThreatIntel {
  source: string;
  finding: string;
  timestamp: string;
}

interface AIAnalysisSummaryProps {
  summary: string;
  indicators: Indicator[];
  threatIntel: ThreatIntel[];
}

export function AIAnalysisSummary({ summary, indicators, threatIntel }: AIAnalysisSummaryProps) {
  const severityColors = {
    high: 'bg-red-600/20 text-red-400 border-red-600/50',
    medium: 'bg-orange-600/20 text-orange-400 border-orange-600/50',
    low: 'bg-yellow-600/20 text-yellow-400 border-yellow-600/50'
  };

  return (
    <div className="space-y-4">
      <Card className="bg-slate-900 border-slate-800 p-6">
        <div className="flex items-center gap-3 mb-4">
          <Brain className="w-6 h-6 text-purple-400" />
          <h3 className="text-lg text-white">AI-Powered Analysis Summary</h3>
        </div>
        <p className="text-slate-200 leading-relaxed">
          {summary}
        </p>
      </Card>

      <Card className="bg-slate-900 border-slate-800 p-6">
        <div className="flex items-center gap-3 mb-4">
          <AlertCircle className="w-6 h-6 text-orange-400" />
          <h3 className="text-lg text-white">Key Risk Indicators</h3>
        </div>
        <div className="space-y-3">
          {indicators.map((indicator, index) => (
            <div 
              key={index}
              className="flex items-start gap-3 p-3 bg-slate-800/50 rounded-lg border border-slate-700"
            >
              <div className="mt-0.5">
                <div className={`w-2 h-2 rounded-full ${
                  indicator.severity === 'high' ? 'bg-red-500' :
                  indicator.severity === 'medium' ? 'bg-orange-500' : 'bg-yellow-500'
                }`} />
              </div>
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-white font-medium">{indicator.type}</span>
                  <Badge 
                    variant="outline" 
                    className={`text-xs ${severityColors[indicator.severity]} border`}
                  >
                    {indicator.severity}
                  </Badge>
                </div>
                <p className="text-sm text-slate-400">{indicator.description}</p>
              </div>
            </div>
          ))}
        </div>
      </Card>

      <Card className="bg-slate-900 border-slate-800 p-6">
        <div className="flex items-center gap-3 mb-4">
          <Database className="w-6 h-6 text-blue-400" />
          <h3 className="text-lg text-white">Threat Intelligence Integration</h3>
        </div>
        <div className="space-y-3">
          {threatIntel.map((intel, index) => (
            <div 
              key={index}
              className="p-4 bg-slate-800/50 rounded-lg border border-slate-700"
            >
              <div className="flex items-start justify-between mb-2">
                <div className="flex items-center gap-2">
                  <ExternalLink className="w-4 h-4 text-blue-400" />
                  <span className="text-blue-400 font-medium">{intel.source}</span>
                </div>
                <span className="text-xs text-slate-500">{intel.timestamp}</span>
              </div>
              <p className="text-sm text-slate-300">{intel.finding}</p>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}