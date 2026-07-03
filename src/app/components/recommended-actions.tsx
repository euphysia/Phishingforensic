import { AlertTriangle, CheckCircle, Info, ChevronRight, Sparkles } from 'lucide-react';
import { Card } from './ui/card';
import { Badge } from './ui/badge';

interface Recommendation {
  step: string;
  detail: string;
  priority: 'high' | 'medium' | 'low';
}

interface RecommendedActionsProps {
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
  recommendations?: Recommendation[];
}

const priorityConfig = {
  high:   { color: 'border-red-700 bg-red-950/60',     icon: AlertTriangle, iconColor: 'text-red-400',   badge: 'bg-red-600 text-white border-red-500'        },
  medium: { color: 'border-amber-600 bg-amber-950/50', icon: Info,          iconColor: 'text-amber-400', badge: 'bg-amber-500 text-slate-900 border-amber-400' },
  low:    { color: 'border-slate-600 bg-slate-800/60', icon: CheckCircle,   iconColor: 'text-slate-300', badge: 'bg-slate-600 text-white border-slate-500'     },
};

const fallbackSteps: Record<string, Recommendation[]> = {
  critical: [
    { step: 'Do not interact with this email', detail: 'Do not click any links, open attachments, or reply. This email is highly likely to be malicious.', priority: 'high' },
    { step: 'Verify through official channels', detail: 'If the email claims to be from a known organisation, contact them directly using their official website or phone number — not the contact details in the email.', priority: 'high' },
    { step: 'Report and delete', detail: 'Mark as phishing in your email client and permanently delete. Consider reporting to your IT/security team.', priority: 'medium' },
  ],
  high: [
    { step: 'Do not act on any requests', detail: 'Treat every instruction in this email as suspicious until independently verified.', priority: 'high' },
    { step: 'Verify the sender directly', detail: 'Look up the organisation\'s official contact and confirm whether they actually sent this email.', priority: 'high' },
    { step: 'Avoid links and attachments', detail: 'Do not open any attachments or follow any links in this email.', priority: 'medium' },
  ],
  medium: [
    { step: 'Proceed with caution', detail: 'This email contains suspicious signals. Verify the sender before taking any action.', priority: 'medium' },
    { step: 'Check the official source', detail: 'If the email references an account, payment, or service, log in directly via the official website instead of using links in the email.', priority: 'medium' },
  ],
  low: [
    { step: 'Email appears legitimate', detail: 'No significant phishing indicators were detected. Standard caution still applies.', priority: 'low' },
    { step: 'Stay alert', detail: 'Even clean emails can be part of multi-step attacks. Verify unusual requests through official channels.', priority: 'low' },
  ],
};

export function RecommendedActions({ riskLevel, recommendations }: RecommendedActionsProps) {
  const steps: Recommendation[] = (recommendations && recommendations.length > 0)
    ? recommendations
    : fallbackSteps[riskLevel] ?? fallbackSteps.low;

  const isAiGenerated = recommendations && recommendations.length > 0;

  return (
    <Card className="bg-slate-900 border-slate-800 p-6">
      <div className="flex items-start justify-between mb-4">
        <div>
          <h3 className="text-lg text-white mb-1">Recommended Actions</h3>
          <p className="text-sm text-slate-400">
            {isAiGenerated ? 'Specific steps based on this email\'s content' : 'General guidance based on risk level'}
          </p>
        </div>
        {isAiGenerated && (
          <Badge variant="outline" className="bg-violet-900/30 text-violet-300 border-violet-700/50 text-xs shrink-0">
            <Sparkles className="w-3 h-3 mr-1" />
            AI-generated
          </Badge>
        )}
      </div>

      <div className="space-y-3">
        {steps.map((rec, i) => {
          const cfg = priorityConfig[rec.priority] ?? priorityConfig.low;
          const Icon = cfg.icon;
          return (
            <div key={i} className={`p-4 rounded-lg border ${cfg.color}`}>
              <div className="flex items-start gap-3">
                <Icon className={`w-4 h-4 mt-0.5 shrink-0 ${cfg.iconColor}`} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <h4 className="text-white font-medium text-sm">{rec.step}</h4>
                    <span className={`text-[10px] px-1.5 py-0.5 rounded border font-medium ${cfg.badge}`}>
                      {rec.priority}
                    </span>
                  </div>
                  <p className="text-sm text-slate-400 leading-relaxed">{rec.detail}</p>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {!isAiGenerated && (
        <div className="mt-4 p-3 rounded-lg bg-slate-800/40 border border-slate-700">
          <div className="flex items-start gap-2 text-xs text-slate-500">
            <ChevronRight className="w-3.5 h-3.5 mt-0.5 shrink-0" />
            <span>AI-powered context-specific steps were not available — configure a Groq API key for tailored recommendations.</span>
          </div>
        </div>
      )}
    </Card>
  );
}
