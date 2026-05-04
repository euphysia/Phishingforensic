import { useState, useEffect } from 'react';
import { Shield, Menu, X } from 'lucide-react';
import { EmailSubmission } from './components/email-submission';
import { ProcessingStatus } from './components/processing-status';
import { RiskAssessment } from './components/risk-assessment';
import { AIAnalysisSummary } from './components/ai-analysis-summary';
import { AnalysisModules } from './components/analysis-modules';
import { RecommendedActions } from './components/recommended-actions';
import { ForensicReport } from './components/forensic-report';
import { AnalysisHistory } from './components/analysis-history';
import { LayeredViewToggle } from './components/layered-view-toggle';
import { TechnicalDetails } from './components/technical-details';
import { Button } from './components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './components/ui/tabs';

export default function App() {
  const [isProcessing, setIsProcessing] = useState(false);
  const [progress, setProgress] = useState(0);
  const [currentStep, setCurrentStep] = useState('');
  const [showResults, setShowResults] = useState(false);
  const [currentView, setCurrentView] = useState<'executive' | 'analyst' | 'technical'>('analyst');
  const [activeTab, setActiveTab] = useState<'analysis' | 'history'>('analysis');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  // Mock analysis data
  const mockAnalysisData = {
    verdict: 'phishing' as const,
    riskScore: 94,
    confidence: 96,
    severity: 'critical' as const,
    summary: "This email exhibits multiple high-confidence phishing indicators. The analysis detected domain spoofing attempting to impersonate PayPal using a lookalike domain (paypa1-verify.com with number '1' instead of letter 'l'). The sender failed all email authentication checks (SPF, DKIM, DMARC), and the embedded URLs redirect to a credential harvesting page. The message employs urgency-based social engineering tactics to pressure recipients into immediate action. This is a sophisticated phishing attack targeting financial credentials.",
    indicators: [
      {
        type: 'Domain Spoofing',
        description: 'Sender domain "paypa1-verify.com" uses homoglyph attack to mimic legitimate PayPal domain',
        severity: 'high' as const
      },
      {
        type: 'Failed Authentication',
        description: 'Email failed SPF, DKIM, and DMARC validation checks',
        severity: 'high' as const
      },
      {
        type: 'Malicious URL',
        description: 'Embedded link redirects to known phishing infrastructure',
        severity: 'high' as const
      },
      {
        type: 'Social Engineering',
        description: 'Subject line uses urgency and fear tactics to manipulate recipient',
        severity: 'medium' as const
      },
      {
        type: 'Suspicious Timing',
        description: 'Email sent during off-hours typical of automated phishing campaigns',
        severity: 'low' as const
      }
    ],
    threatIntel: [
      {
        source: 'VirusTotal',
        finding: 'Domain flagged by 23/89 security vendors as malicious',
        timestamp: '2 hours ago'
      },
      {
        source: 'PhishTank',
        finding: 'URL reported in active phishing campaign targeting financial services',
        timestamp: '3 hours ago'
      },
      {
        source: 'MISP Threat Sharing',
        finding: 'Similar email pattern observed in 147 incidents across 23 organizations',
        timestamp: '1 day ago'
      }
    ],
    headerAnalysis: {
      spfStatus: 'fail' as const,
      dkimStatus: 'fail' as const,
      dmarcStatus: 'fail' as const,
      senderReputation: 15,
      spoofingIndicators: [
        'Return-Path domain does not match From domain',
        'Display name impersonates legitimate organization',
        'Sender IP address originates from known phishing infrastructure',
        'Message-ID pattern matches automated phishing toolkit'
      ],
      returnPath: 'bounce@suspicious-domain.net',
      receivedFrom: '209.85.220.41 (unknown)'
    },
    urlAnalysis: {
      totalUrls: 3,
      maliciousUrls: 2,
      suspiciousUrls: 1,
      urls: [
        {
          url: 'hxxp://paypa1-verify.com/secure/login',
          status: 'malicious' as const,
          reputation: 5,
          category: 'Phishing/Credential Theft'
        },
        {
          url: 'hxxp://paypa1-verify.com/assets/logo.png',
          status: 'malicious' as const,
          reputation: 5,
          category: 'Phishing Infrastructure'
        },
        {
          url: 'hxxp://tracking-pixel.suspicious-domain.net/track',
          status: 'suspicious' as const,
          reputation: 42,
          category: 'Tracking/Analytics'
        }
      ]
    },
    attachmentAnalysis: {
      totalAttachments: 1,
      riskyAttachments: 0,
      attachments: [
        {
          name: 'invoice.pdf',
          type: 'PDF Document',
          size: '245 KB',
          hash: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
          status: 'safe' as const,
          sandboxResult: 'No malicious behavior detected during sandbox execution'
        }
      ]
    }
  };

  const handleSubmit = (data: { type: string; content: string | File }) => {
    setIsProcessing(true);
    setProgress(0);
    setShowResults(false);
    
    const steps = [
      'Extracting email metadata',
      'Analyzing email headers',
      'Scanning URLs and links',
      'Inspecting attachments',
      'Correlating threat intelligence',
      'Generating risk assessment',
      'Finalizing analysis report'
    ];

    let currentStepIndex = 0;
    const interval = setInterval(() => {
      setProgress(prev => {
        const newProgress = prev + 2;
        if (newProgress >= 100) {
          clearInterval(interval);
          setIsProcessing(false);
          setShowResults(true);
          return 100;
        }
        
        const stepIndex = Math.floor((newProgress / 100) * steps.length);
        if (stepIndex !== currentStepIndex && stepIndex < steps.length) {
          currentStepIndex = stepIndex;
          setCurrentStep(steps[stepIndex]);
        }
        
        return newProgress;
      });
    }, 100);
  };

  const handleSelectAnalysis = (id: string) => {
    setShowResults(true);
    setActiveTab('analysis');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="relative">
                <Shield className="w-8 h-8 text-blue-500" />
                <div className="absolute inset-0 bg-blue-500/20 blur-xl" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-white">
                  Phishing Forensic Analysis System
                </h1>
                <p className="text-xs text-slate-300">
                  Automated Email Threat Detection & Investigation
                </p>
              </div>
            </div>
            <div className="hidden md:flex items-center gap-4">
              <div className="text-right text-sm">
                <div className="text-slate-400">System Status</div>
                <div className="flex items-center gap-2 text-green-400">
                  <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
                  Operational
                </div>
              </div>
            </div>
            <Button
              variant="ghost"
              size="sm"
              className="md:hidden text-white"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            >
              {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
            </Button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-8">
        <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as any)} className="space-y-6">
          <TabsList className="bg-slate-900 border border-slate-800 p-1">
            <TabsTrigger 
              value="analysis" 
              className="data-[state=active]:bg-slate-700 data-[state=active]:text-white px-8 text-[rgb(255,255,255)]"
            >
              New Analysis
            </TabsTrigger>
            <TabsTrigger 
              value="history" 
              className="data-[state=active]:bg-slate-700 data-[state=active]:text-white px-8 text-[rgb(255,255,255)]"
            >
              History
            </TabsTrigger>
          </TabsList>

          <TabsContent value="analysis" className="space-y-6 mt-6">
            {/* Email Submission */}
            <EmailSubmission onSubmit={handleSubmit} isProcessing={isProcessing} />

            {/* Processing Status */}
            <ProcessingStatus 
              isProcessing={isProcessing} 
              progress={progress}
              currentStep={currentStep}
            />

            {/* Analysis Results */}
            {showResults && (
              <div className="space-y-6">
                {/* Risk Assessment */}
                <RiskAssessment
                  verdict={mockAnalysisData.verdict}
                  riskScore={mockAnalysisData.riskScore}
                  confidence={mockAnalysisData.confidence}
                  severity={mockAnalysisData.severity}
                />

                {/* Layered View Toggle */}
                <LayeredViewToggle 
                  currentView={currentView}
                  onViewChange={setCurrentView}
                />

                {/* Executive View */}
                {currentView === 'executive' && (
                  <div className="space-y-6">
                    <AIAnalysisSummary
                      summary={mockAnalysisData.summary}
                      indicators={mockAnalysisData.indicators.slice(0, 3)}
                      threatIntel={mockAnalysisData.threatIntel.slice(0, 1)}
                    />
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                      <RecommendedActions riskLevel={mockAnalysisData.severity} />
                      <ForensicReport
                        reportId="RPT-2026-002547"
                        generatedAt="Feb 8, 2026 08:42 PST"
                        analysisTime="16 seconds"
                      />
                    </div>
                  </div>
                )}

                {/* Analyst View */}
                {currentView === 'analyst' && (
                  <div className="space-y-6">
                    <AIAnalysisSummary
                      summary={mockAnalysisData.summary}
                      indicators={mockAnalysisData.indicators}
                      threatIntel={mockAnalysisData.threatIntel}
                    />
                    <AnalysisModules
                      headerAnalysis={mockAnalysisData.headerAnalysis}
                      urlAnalysis={mockAnalysisData.urlAnalysis}
                      attachmentAnalysis={mockAnalysisData.attachmentAnalysis}
                    />
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                      <RecommendedActions riskLevel={mockAnalysisData.severity} />
                      <ForensicReport
                        reportId="RPT-2026-002547"
                        generatedAt="Feb 8, 2026 08:42 PST"
                        analysisTime="16 seconds"
                      />
                    </div>
                  </div>
                )}

                {/* Technical View */}
                {currentView === 'technical' && (
                  <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    <div className="lg:col-span-2 space-y-6">
                      <TechnicalDetails />
                    </div>
                    <div className="space-y-6">
                      <AnalysisModules
                        headerAnalysis={mockAnalysisData.headerAnalysis}
                        urlAnalysis={mockAnalysisData.urlAnalysis}
                        attachmentAnalysis={mockAnalysisData.attachmentAnalysis}
                      />
                      <ForensicReport
                        reportId="RPT-2026-002547"
                        generatedAt="Feb 8, 2026 08:42 PST"
                        analysisTime="16 seconds"
                      />
                    </div>
                  </div>
                )}
              </div>
            )}
          </TabsContent>

          <TabsContent value="history" className="mt-6">
            <AnalysisHistory onSelectAnalysis={handleSelectAnalysis} />
          </TabsContent>
        </Tabs>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 bg-slate-900/50 mt-16">
        <div className="container mx-auto px-4 py-6">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4 text-sm text-slate-400">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4" />
              <span>Phishing Forensic Analysis System v2.5.1</span>
            </div>
            <div className="flex items-center gap-6">
              <span>© 2026 SecureForensics</span>
              <span>•</span>
              <span>Analyzed 156,847 emails this month</span>
              <span>•</span>
              <span>98.7% accuracy rate</span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}