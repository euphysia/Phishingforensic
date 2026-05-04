import { ShieldBan, Archive, Search, CheckCircle, ChevronRight } from 'lucide-react';
import { Card } from './ui/card';
import { Button } from './ui/button';

interface RecommendedActionsProps {
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
}

export function RecommendedActions({ riskLevel }: RecommendedActionsProps) {
  const actions = {
    critical: [
      {
        icon: ShieldBan,
        title: 'Block Sender Immediately',
        description: 'Add sender to blocklist and quarantine all emails from this source',
        primary: true,
        action: 'block'
      },
      {
        icon: Archive,
        title: 'Quarantine Related Emails',
        description: 'Isolate all emails matching similar patterns across organization',
        primary: true,
        action: 'quarantine'
      },
      {
        icon: Search,
        title: 'Launch Full Investigation',
        description: 'Create incident ticket and notify security operations team',
        primary: false,
        action: 'investigate'
      }
    ],
    high: [
      {
        icon: Archive,
        title: 'Quarantine Email',
        description: 'Move to quarantine for manual review by security team',
        primary: true,
        action: 'quarantine'
      },
      {
        icon: Search,
        title: 'Investigate Further',
        description: 'Review similar emails and check for compromise indicators',
        primary: false,
        action: 'investigate'
      },
      {
        icon: ShieldBan,
        title: 'Consider Blocking',
        description: 'Monitor sender and consider adding to blocklist',
        primary: false,
        action: 'monitor'
      }
    ],
    medium: [
      {
        icon: Search,
        title: 'Manual Review Recommended',
        description: 'Flag for security analyst review during next triage',
        primary: true,
        action: 'review'
      },
      {
        icon: Archive,
        title: 'Move to Junk',
        description: 'Deliver to junk folder with warning label',
        primary: false,
        action: 'junk'
      }
    ],
    low: [
      {
        icon: CheckCircle,
        title: 'Allow with Monitoring',
        description: 'Deliver email normally, continue monitoring sender',
        primary: true,
        action: 'allow'
      },
      {
        icon: Search,
        title: 'Log for Records',
        description: 'Document analysis results for future reference',
        primary: false,
        action: 'log'
      }
    ]
  };

  const currentActions = actions[riskLevel];

  return (
    <Card className="bg-slate-900 border-slate-800 p-6">
      <div className="mb-4">
        <h3 className="text-lg text-white mb-1">Recommended Actions</h3>
        <p className="text-sm text-slate-300">
          Contextual response based on {riskLevel} risk assessment
        </p>
      </div>

      <div className="space-y-3">
        {currentActions.map((action, index) => {
          const Icon = action.icon;
          return (
            <div
              key={index}
              className={`p-4 rounded-lg border ${
                action.primary
                  ? 'bg-blue-950/30 border-blue-900/50'
                  : 'bg-slate-800/50 border-slate-700'
              }`}
            >
              <div className="flex items-start justify-between">
                <div className="flex items-start gap-3 flex-1">
                  <div className="mt-1">
                    <Icon className={`w-5 h-5 ${
                      action.primary ? 'text-blue-400' : 'text-slate-400'
                    }`} />
                  </div>
                  <div className="flex-1">
                    <h4 className={`font-medium mb-1 ${
                      action.primary ? 'text-blue-400' : 'text-white'
                    }`}>
                      {action.title}
                    </h4>
                    <p className="text-sm text-slate-400">
                      {action.description}
                    </p>
                  </div>
                </div>
                <Button
                  variant={action.primary ? 'default' : 'outline'}
                  size="sm"
                  className={
                    action.primary
                      ? 'bg-blue-600 hover:bg-blue-700 text-white'
                      : 'bg-slate-700 border-slate-600 text-white hover:bg-slate-600'
                  }
                >
                  Execute
                  <ChevronRight className="w-4 h-4 ml-1" />
                </Button>
              </div>
            </div>
          );
        })}
      </div>

      <div className="mt-6 p-4 bg-slate-800/50 rounded-lg border border-slate-700">
        <h4 className="text-white font-medium mb-2">Next Steps</h4>
        <ul className="space-y-1 text-sm text-slate-300">
          <li className="flex items-start gap-2">
            <ChevronRight className="w-4 h-4 mt-0.5 text-slate-500" />
            <span>Review forensic report for detailed evidence</span>
          </li>
          <li className="flex items-start gap-2">
            <ChevronRight className="w-4 h-4 mt-0.5 text-slate-500" />
            <span>Check for similar emails across organization</span>
          </li>
          <li className="flex items-start gap-2">
            <ChevronRight className="w-4 h-4 mt-0.5 text-slate-500" />
            <span>Update threat intelligence feeds with IoCs</span>
          </li>
          <li className="flex items-start gap-2">
            <ChevronRight className="w-4 h-4 mt-0.5 text-slate-500" />
            <span>Document incident response actions taken</span>
          </li>
        </ul>
      </div>
    </Card>
  );
}