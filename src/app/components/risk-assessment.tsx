import { AlertTriangle, ShieldAlert, ShieldCheck, TrendingUp } from 'lucide-react';
import { Card } from './ui/card';
import { Badge } from './ui/badge';

interface RiskAssessmentProps {
  verdict: 'phishing' | 'suspicious' | 'benign';
  riskScore: number;
  confidence: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export function RiskAssessment({ verdict, riskScore, confidence, severity }: RiskAssessmentProps) {
  const verdictConfig = {
    phishing: {
      label: 'PHISHING DETECTED',
      icon: ShieldAlert,
      bgColor: 'bg-red-950/50',
      borderColor: 'border-red-900',
      iconColor: 'text-red-500',
      textColor: 'text-red-400',
      glowColor: 'shadow-red-900/50'
    },
    suspicious: {
      label: 'SUSPICIOUS',
      icon: AlertTriangle,
      bgColor: 'bg-orange-950/50',
      borderColor: 'border-orange-900',
      iconColor: 'text-orange-500',
      textColor: 'text-orange-400',
      glowColor: 'shadow-orange-900/50'
    },
    benign: {
      label: 'BENIGN',
      icon: ShieldCheck,
      bgColor: 'bg-green-950/50',
      borderColor: 'border-green-900',
      iconColor: 'text-green-500',
      textColor: 'text-green-400',
      glowColor: 'shadow-green-900/50'
    }
  };

  const severityConfig = {
    critical: { label: 'Critical', color: 'bg-red-600', textColor: 'text-red-400' },
    high: { label: 'High', color: 'bg-orange-600', textColor: 'text-orange-400' },
    medium: { label: 'Medium', color: 'bg-yellow-600', textColor: 'text-yellow-400' },
    low: { label: 'Low', color: 'bg-blue-600', textColor: 'text-blue-400' }
  };

  const config = verdictConfig[verdict];
  const VerdictIcon = config.icon;

  return (
    <Card className={`${config.bgColor} ${config.borderColor} border-2 p-6 ${config.glowColor} shadow-lg`}>
      <div className="flex items-start justify-between mb-6">
        <div className="flex items-center gap-4">
          <div className="relative">
            <VerdictIcon className={`w-12 h-12 ${config.iconColor}`} />
            <div className={`absolute inset-0 ${config.iconColor} opacity-20 blur-xl`} />
          </div>
          <div>
            <h2 className={`text-2xl font-bold ${config.textColor} mb-1`}>
              {config.label}
            </h2>
            <p className="text-sm text-slate-300">
              Automated Forensic Analysis Results
            </p>
          </div>
        </div>
        <Badge variant="outline" className={`${severityConfig[severity].color} text-white border-0`}>
          {severityConfig[severity].label} Severity
        </Badge>
      </div>

      <div className="grid grid-cols-3 gap-6">
        <div>
          <div className="text-sm text-slate-400 mb-2">Risk Score</div>
          <div className="flex items-baseline gap-2">
            <span className={`text-3xl font-bold ${config.textColor}`}>
              {riskScore}
            </span>
            <span className="text-slate-500">/100</span>
          </div>
          <div className="mt-2 w-full bg-slate-800 rounded-full h-2">
            <div 
              className={`h-2 rounded-full ${config.iconColor.replace('text-', 'bg-')}`}
              style={{ width: `${riskScore}%` }}
            />
          </div>
        </div>

        <div>
          <div className="text-sm text-slate-400 mb-2">Confidence Level</div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white">
              {confidence}%
            </span>
          </div>
          <div className="mt-2 flex items-center gap-2 text-sm text-slate-300">
            <TrendingUp className="w-4 h-4" />
            High confidence
          </div>
        </div>

        <div>
          <div className="text-sm text-slate-400 mb-2">Threat Level</div>
          <div className="flex items-center gap-2 mt-1">
            <div className="flex gap-1">
              {[1, 2, 3, 4, 5].map((level) => {
                const filled = 
                  (severity === 'critical' && level <= 5) ||
                  (severity === 'high' && level <= 4) ||
                  (severity === 'medium' && level <= 3) ||
                  (severity === 'low' && level <= 2);
                
                return (
                  <div
                    key={level}
                    className={`w-3 h-8 rounded ${
                      filled ? severityConfig[severity].color : 'bg-slate-800'
                    }`}
                  />
                );
              })}
            </div>
          </div>
          <div className={`mt-2 text-sm ${severityConfig[severity].textColor}`}>
            Immediate action required
          </div>
        </div>
      </div>
    </Card>
  );
}