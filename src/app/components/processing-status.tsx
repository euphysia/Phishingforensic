import { Shield, CheckCircle2, AlertTriangle } from 'lucide-react';
import { Card } from './ui/card';
import { Progress } from './ui/progress';

interface ProcessingStatusProps {
  isProcessing: boolean;
  progress: number;
  currentStep: string;
}

export function ProcessingStatus({ isProcessing, progress, currentStep }: ProcessingStatusProps) {
  if (!isProcessing && progress === 0) return null;

  const steps = [
    'Extracting email metadata',
    'Analyzing email headers',
    'Scanning URLs and links',
    'Inspecting attachments',
    'Correlating threat intelligence',
    'Generating risk assessment',
    'Finalizing analysis report'
  ];

  return (
    <Card className="bg-slate-900 border-slate-800 p-6">
      <div className="flex items-start gap-4">
        <div className="mt-1">
          {progress === 100 ? (
            <CheckCircle2 className="w-6 h-6 text-green-500" />
          ) : (
            <div className="relative">
              <Shield className="w-6 h-6 text-blue-500 animate-pulse" />
              <div className="absolute inset-0 bg-blue-500/20 rounded-full animate-ping" />
            </div>
          )}
        </div>
        <div className="flex-1">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-lg text-white">
              {progress === 100 ? 'Analysis Complete' : 'Analyzing Email'}
            </h3>
            <span className="text-sm text-slate-300">{progress}%</span>
          </div>
          <Progress value={progress} className="h-2 mb-3" />
          <p className="text-sm text-slate-200">{currentStep}</p>
          
          {isProcessing && (
            <div className="mt-4 space-y-2">
              {steps.map((step, index) => {
                const stepProgress = ((index + 1) / steps.length) * 100;
                const isComplete = progress >= stepProgress;
                const isCurrent = progress < stepProgress && progress >= ((index) / steps.length) * 100;
                
                return (
                  <div key={index} className="flex items-center gap-2 text-xs">
                    {isComplete ? (
                      <CheckCircle2 className="w-3 h-3 text-green-500 flex-shrink-0" />
                    ) : isCurrent ? (
                      <div className="w-3 h-3 rounded-full border-2 border-blue-500 border-t-transparent animate-spin flex-shrink-0" />
                    ) : (
                      <div className="w-3 h-3 rounded-full border-2 border-slate-700 flex-shrink-0" />
                    )}
                    <span className={isComplete ? 'text-slate-400' : isCurrent ? 'text-blue-400' : 'text-slate-600'}>
                      {step}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </Card>
  );
}