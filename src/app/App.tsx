import { useState } from 'react';
import { Shield, Menu, X } from 'lucide-react';
import { LandingPage } from './components/landing-page';
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
  const [showLanding, setShowLanding] = useState(true);
  const [isProcessing, setIsProcessing] = useState(false);
  const [progress, setProgress] = useState(0);
  const [currentStep, setCurrentStep] = useState('');
  const [showResults, setShowResults] = useState(false);
  const [currentView, setCurrentView] = useState<'executive' | 'analyst' | 'technical'>('analyst');
  const [activeTab, setActiveTab] = useState<'analysis' | 'history'>('analysis');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [analysisData, setAnalysisData] = useState<any>(null);
  const [analysisError, setAnalysisError] = useState<string | null>(null);
  const [historyRefreshTrigger, setHistoryRefreshTrigger] = useState(0);


  const handleSubmit = async (data: { type: string; content: string | File }) => {
    setIsProcessing(true);
    setProgress(0);
    setShowResults(false);
    setAnalysisData(null);
    setAnalysisError(null);

    const steps = [
      'Extracting email metadata',
      'Analyzing email headers',
      'Scanning URLs and links',
      'Inspecting attachments',
      'Correlating threat intelligence',
      'Generating risk assessment',
      'Finalizing analysis report'
    ];

    // Animate progress while API call runs in background
    let stepIdx = 0;
    let fakeProgress = 0;
    setCurrentStep(steps[0]);

    const progressInterval = setInterval(() => {
      fakeProgress = Math.min(fakeProgress + 1.2, 90); // Cap at 90% until real result
      setProgress(fakeProgress);
      const newStep = Math.floor((fakeProgress / 90) * (steps.length - 1));
      if (newStep !== stepIdx && newStep < steps.length) {
        stepIdx = newStep;
        setCurrentStep(steps[newStep]);
      }
    }, 200);

    try {
      let body: FormData | string;
      let headers: Record<string, string> = {};

      if (data.type === 'file' && data.content instanceof File) {
        const fd = new FormData();
        fd.append('email', data.content);
        body = fd;
        // Don't set Content-Type — browser sets it with boundary
      } else {
        body = JSON.stringify({ rawEmail: data.content as string });
        headers['Content-Type'] = 'application/json';
      }

      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers,
        body,
      });

      clearInterval(progressInterval);

      if (!res.ok) {
        const errData = await res.json().catch(() => ({ message: 'Unknown error' }));
        throw new Error(errData.error || errData.message || `HTTP ${res.status}`);
      }

      const result = await res.json();
      setAnalysisData(result);
      setCurrentStep('Analysis complete');
      setProgress(100);

      // Trigger history refresh
      setHistoryRefreshTrigger(t => t + 1);

      setTimeout(() => {
        setIsProcessing(false);
        setShowResults(true);
      }, 400);

    } catch (err: any) {
      clearInterval(progressInterval);
      console.error('Analysis failed:', err);
      setAnalysisError(err.message);
      setCurrentStep('Failed');
      setProgress(0);
      setIsProcessing(false);
      // Don't show results — show the error banner only
    }
  };

  const handleSelectAnalysis = async (id: string) => {
    setActiveTab('analysis');
    window.scrollTo({ top: 0, behavior: 'smooth' });
    try {
      const res = await fetch(`/api/history/${id}`);
      if (res.ok) {
        const data = await res.json();
        setAnalysisData(data);
        setShowResults(true);
      }
    } catch {
      setShowResults(true);
    }
  };


  if (showLanding) {
    return <LandingPage onGetStarted={() => setShowLanding(false)} />;
  }

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
              <button
                onClick={() => setShowLanding(true)}
                className="text-sm text-slate-400 hover:text-white transition-colors"
              >
                Home
              </button>
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

            {/* Analysis error state */}
            {analysisError && !isProcessing && (
              <div className="p-5 rounded-lg border border-red-700/50 bg-red-950/30 text-sm space-y-2">
                <p className="text-red-400 font-semibold">⚠️ Analysis Failed</p>
                <p className="text-slate-300">{analysisError}</p>
                <p className="text-slate-400 text-xs">
                  Make sure the backend is running: <code className="bg-slate-800 px-1 rounded">npm run dev:server</code>
                </p>
              </div>
            )}

            {/* Analysis Results — only shown when real data is available */}
            {showResults && analysisData && (() => {
              const d = analysisData;
              const reportId = d.id ? d.id.slice(0, 12).toUpperCase() : '—';
              const generatedAt = d.createdAt
                ? new Date(d.createdAt).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' })
                : '—';
              const analysisTimeSec = d.analysisTimeMs
                ? `${(d.analysisTimeMs / 1000).toFixed(1)} seconds`
                : '—';

              return (
                <div className="space-y-6">
                  {/* Risk Assessment */}
                  <RiskAssessment
                    verdict={d.verdict}
                    riskScore={d.riskScore}
                    confidence={d.confidence}
                    severity={d.severity}
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
                        summary={d.summary}
                        indicators={(d.indicators ?? []).slice(0, 3)}
                        threatIntel={[]}
                      />
                      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        <RecommendedActions riskLevel={d.severity} />
                        <ForensicReport
                          reportId={reportId}
                          generatedAt={generatedAt}
                          analysisTime={analysisTimeSec}
                        />
                      </div>
                    </div>
                  )}

                  {/* Analyst View */}
                  {currentView === 'analyst' && (
                    <div className="space-y-6">
                      <AIAnalysisSummary
                        summary={d.summary}
                        indicators={d.indicators ?? []}
                        threatIntel={[]}
                      />
                      <AnalysisModules
                        headerAnalysis={d.headerAnalysis}
                        urlAnalysis={d.urlAnalysis}
                        attachmentAnalysis={d.attachmentAnalysis}
                      />
                      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        <RecommendedActions riskLevel={d.severity} />
                        <ForensicReport
                          reportId={reportId}
                          generatedAt={generatedAt}
                          analysisTime={analysisTimeSec}
                        />
                      </div>
                    </div>
                  )}

                  {/* Technical View */}
                  {currentView === 'technical' && (
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                      <div className="lg:col-span-2 space-y-6">
                        <TechnicalDetails
                          email={d.email}
                          headerAnalysis={d.headerAnalysis}
                          urlAnalysis={d.urlAnalysis}
                          indicators={d.indicators ?? []}
                        />
                      </div>
                      <div className="space-y-6">
                        <AnalysisModules
                          headerAnalysis={d.headerAnalysis}
                          urlAnalysis={d.urlAnalysis}
                          attachmentAnalysis={d.attachmentAnalysis}
                        />
                        <ForensicReport
                          reportId={reportId}
                          generatedAt={generatedAt}
                          analysisTime={analysisTimeSec}
                        />
                      </div>
                    </div>
                  )}
                </div>
              );
            })()}
          </TabsContent>

          <TabsContent value="history" className="mt-6">
            <AnalysisHistory
              onSelectAnalysis={handleSelectAnalysis}
              refreshTrigger={historyRefreshTrigger}
            />
          </TabsContent>
        </Tabs>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 bg-slate-900/50 mt-16">
        <div className="container mx-auto px-4 py-6">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4 text-sm text-slate-400">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4" />
              <span>PhishForensics — Automated Phishing Email Forensic Analysis System</span>
            </div>
            <div className="flex items-center gap-6">
              <button onClick={() => setShowLanding(true)} className="hover:text-white transition-colors">Home</button>
              <span>•</span>
              <span>Sprints 1–4 Active</span>
              <span>•</span>
              <span>Real-time Analysis Enabled</span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
