import { useState } from 'react';
import { Shield, Menu, X, LogOut, LogIn, FlaskConical } from 'lucide-react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { LandingPage }       from './components/landing-page';
import { LoginPage }         from './components/login-page';
import { EmailSubmission }   from './components/email-submission';
import { ProcessingStatus }  from './components/processing-status';
import { RiskAssessment }    from './components/risk-assessment';
import { AIAnalysisSummary } from './components/ai-analysis-summary';
import { AnalysisModules }   from './components/analysis-modules';
import { RecommendedActions } from './components/recommended-actions';
import { ForensicReport }    from './components/forensic-report';
import { AnalysisHistory }   from './components/analysis-history';
import { AuditorDashboard }  from './components/auditor-dashboard';
import { LayeredViewToggle } from './components/layered-view-toggle';
import { TechnicalDetails }  from './components/technical-details';
import { Button }            from './components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './components/ui/tabs';

const ROLE_BADGE: Record<string, string> = {
  admin:   'bg-purple-600/20 text-purple-300 border-purple-500/40',
  analyst: 'bg-blue-600/20 text-blue-300 border-blue-500/40',
  auditor: 'bg-amber-600/20 text-amber-300 border-amber-500/40',
};

// ── Trial limit modal ─────────────────────────────────────────────────────────

function TrialLimitModal({ onLogin, onDismiss }: { onLogin: () => void; onDismiss: () => void }) {
  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-700 rounded-xl p-8 max-w-md w-full text-center space-y-5 shadow-2xl">
        <div className="w-14 h-14 bg-amber-500/10 rounded-full flex items-center justify-center mx-auto">
          <FlaskConical className="w-7 h-7 text-amber-400" />
        </div>
        <div>
          <h3 className="text-lg font-bold text-white mb-2">Free trial limit reached</h3>
          <p className="text-sm text-slate-400 leading-relaxed">
            You've used your 3 free analyses. Sign in to continue with unlimited access and full history.
          </p>
        </div>
        <div className="flex gap-3">
          <Button onClick={onDismiss} variant="outline" className="flex-1 border-slate-700 text-slate-300">
            Maybe later
          </Button>
          <Button onClick={onLogin} className="flex-1 bg-blue-600 hover:bg-blue-700 text-white">
            <LogIn className="w-4 h-4 mr-2" />Sign in
          </Button>
        </div>
      </div>
    </div>
  );
}

// ── Main app (inside AuthProvider) ───────────────────────────────────────────

function AppInner() {
  const { user, trial, logout, updateTrial, loading } = useAuth();

  const [showLanding,    setShowLanding]    = useState(true);
  const [showLogin,      setShowLogin]      = useState(false);
  const [showTrialModal, setShowTrialModal] = useState(false);
  const [isProcessing,   setIsProcessing]   = useState(false);
  const [progress,       setProgress]       = useState(0);
  const [currentStep,    setCurrentStep]    = useState('');
  const [showResults,    setShowResults]    = useState(false);
  const [currentView,    setCurrentView]    = useState<'executive' | 'analyst' | 'technical'>('analyst');
  const [activeTab,      setActiveTab]      = useState<'analysis' | 'history' | 'audit'>('analysis');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [analysisData,   setAnalysisData]   = useState<any>(null);
  const [analysisError,  setAnalysisError]  = useState<string | null>(null);
  const [historyRefreshTrigger, setHistoryRefreshTrigger] = useState(0);

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="w-8 h-8 border-2 border-blue-500/30 border-t-blue-500 rounded-full animate-spin" />
      </div>
    );
  }

  if (showLogin) {
    return (
      <LoginPage
        onSuccess={() => { setShowLogin(false); setShowLanding(false); }}
        onContinueAsGuest={() => { setShowLogin(false); setShowLanding(false); }}
      />
    );
  }

  if (showLanding) {
    return (
      <LandingPage
        onGetStarted={() => setShowLanding(false)}
        isDark={true}
        onToggleDark={() => {}}
      />
    );
  }

  const handleSubmit = async (data: { type: string; content: string | File }) => {
    // Guest limit pre-check (soft)
    if (!user && trial.remaining <= 0) {
      setShowTrialModal(true);
      return;
    }

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
      'Finalizing analysis report',
    ];

    let stepIdx = 0;
    let fakeProgress = 0;
    setCurrentStep(steps[0]);

    const progressInterval = setInterval(() => {
      fakeProgress = Math.min(fakeProgress + 1.2, 90);
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
      } else {
        body = JSON.stringify({ rawEmail: data.content as string });
        headers['Content-Type'] = 'application/json';
      }

      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers,
        body,
        credentials: 'include',
      });

      clearInterval(progressInterval);

      if (!res.ok) {
        const errData = await res.json().catch(() => ({ message: 'Unknown error' }));
        // Trial limit hit on server side
        if (errData.code === 'TRIAL_LIMIT') {
          setShowTrialModal(true);
          setIsProcessing(false);
          return;
        }
        throw new Error(errData.error || errData.message || `HTTP ${res.status}`);
      }

      const result = await res.json();
      setAnalysisData(result);
      setCurrentStep('Analysis complete');
      setProgress(100);

      // Update trial count if guest
      if (!user && result.trialRemaining !== undefined) {
        updateTrial({ count: result.trialCount, remaining: result.trialRemaining });
        if (result.trialRemaining === 0) setShowTrialModal(true);
      }

      setHistoryRefreshTrigger(t => t + 1);
      setTimeout(() => { setIsProcessing(false); setShowResults(true); }, 400);

    } catch (err: any) {
      clearInterval(progressInterval);
      setAnalysisError(err.message);
      setCurrentStep('Failed');
      setProgress(0);
      setIsProcessing(false);
    }
  };

  const handleSelectAnalysis = async (id: string) => {
    setActiveTab('analysis');
    window.scrollTo({ top: 0, behavior: 'smooth' });
    try {
      const res = await fetch(`/api/history/${id}`, { credentials: 'include' });
      if (res.ok) {
        const data = await res.json();
        setAnalysisData(data);
        setShowResults(true);
        setAnalysisError(null);
      } else if (res.status === 401) {
        setShowResults(false);
        setAnalysisError('Sign in as an analyst or admin to view full analysis details.');
      } else {
        const errData = await res.json().catch(() => ({}));
        setShowResults(false);
        setAnalysisError(errData.error || `Could not load analysis (HTTP ${res.status})`);
      }
    } catch (err: any) {
      setShowResults(false);
      setAnalysisError(err.message || 'Could not load analysis');
    }
  };

  const handleLogout = async () => {
    await logout();
    setShowLanding(true);
    setShowResults(false);
    setAnalysisData(null);
  };

  // Which tabs are visible per role
  const isAuditor  = user?.role === 'auditor';
  const isLoggedIn = !!user;

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">

      {showTrialModal && (
        <TrialLimitModal
          onLogin={() => { setShowTrialModal(false); setShowLogin(true); }}
          onDismiss={() => setShowTrialModal(false)}
        />
      )}

      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            {/* Logo */}
            <div className="flex items-center gap-3">
              <div className="relative">
                <Shield className="w-8 h-8 text-blue-500" />
                <div className="absolute inset-0 bg-blue-500/20 blur-xl" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-white">Phishing Forensic Analysis System</h1>
                <p className="text-xs text-slate-300">Automated Email Threat Detection & Investigation</p>
              </div>
            </div>

            {/* Nav right */}
            <div className="hidden md:flex items-center gap-4">
              <button
                onClick={() => setShowLanding(true)}
                className="text-sm text-slate-400 hover:text-white transition-colors"
              >
                Home
              </button>

              {/* Guest trial counter */}
              {!isLoggedIn && (
                <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700">
                  <FlaskConical className="w-3.5 h-3.5 text-amber-400" />
                  <span className="text-xs text-slate-300">
                    <span className={`font-bold ${trial.remaining === 0 ? 'text-red-400' : 'text-amber-400'}`}>
                      {trial.remaining}
                    </span>
                    {' '}free {trial.remaining === 1 ? 'analysis' : 'analyses'} remaining
                  </span>
                </div>
              )}

              {/* Logged-in: name + role badge + logout */}
              {isLoggedIn ? (
                <div className="flex items-center gap-3">
                  <div className="text-right">
                    <p className="text-sm text-white font-medium">{user.email}</p>
                    <span className={`text-[10px] px-2 py-0.5 rounded border font-semibold uppercase ${ROLE_BADGE[user.role]}`}>
                      {user.role}
                    </span>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleLogout}
                    className="border-slate-700 text-slate-300 hover:text-white hover:border-slate-500"
                  >
                    <LogOut className="w-3.5 h-3.5 mr-1.5" />Logout
                  </Button>
                </div>
              ) : (
                <Button
                  size="sm"
                  onClick={() => setShowLogin(true)}
                  className="bg-blue-600 hover:bg-blue-700 text-white"
                >
                  <LogIn className="w-3.5 h-3.5 mr-1.5" />Login
                </Button>
              )}
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

      {/* Mobile menu */}
      {mobileMenuOpen && (
        <div className="md:hidden bg-slate-900 border-b border-slate-800 px-4 py-4 space-y-3">
          {!isLoggedIn && (
            <div className="flex items-center gap-2 text-sm text-slate-300">
              <FlaskConical className="w-4 h-4 text-amber-400" />
              {trial.remaining} free {trial.remaining === 1 ? 'analysis' : 'analyses'} remaining
            </div>
          )}
          {isLoggedIn ? (
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-white">{user.email}</p>
                <span className={`text-[10px] px-2 py-0.5 rounded border font-semibold uppercase ${ROLE_BADGE[user.role]}`}>
                  {user.role}
                </span>
              </div>
              <Button size="sm" variant="outline" onClick={handleLogout} className="border-slate-700 text-slate-300">
                <LogOut className="w-3.5 h-3.5 mr-1" />Logout
              </Button>
            </div>
          ) : (
            <Button size="sm" onClick={() => { setShowLogin(true); setMobileMenuOpen(false); }} className="w-full bg-blue-600 text-white">
              <LogIn className="w-4 h-4 mr-2" />Login
            </Button>
          )}
        </div>
      )}

      {/* Main Content */}
      <main className="container mx-auto px-4 py-8">
        <Tabs
          value={activeTab}
          onValueChange={(v) => setActiveTab(v as any)}
          className="space-y-6"
        >
          <TabsList className="bg-slate-900 border border-slate-800 p-1">
            {/* Auditors skip the analysis tab — they can't submit */}
            {!isAuditor && (
              <TabsTrigger
                value="analysis"
                className="data-[state=active]:bg-slate-700 data-[state=active]:text-white px-8 text-white"
              >
                New Analysis
              </TabsTrigger>
            )}

            {/* History — only logged-in analysts and admins */}
            {isLoggedIn && !isAuditor && (
              <TabsTrigger
                value="history"
                className="data-[state=active]:bg-slate-700 data-[state=active]:text-white px-8 text-white"
              >
                History
              </TabsTrigger>
            )}

            {/* History tab shown to guests but locked */}
            {!isLoggedIn && (
              <TabsTrigger
                value="history"
                onClick={(e) => { e.preventDefault(); setShowLogin(true); }}
                className="px-8 text-slate-500 cursor-not-allowed"
              >
                History
              </TabsTrigger>
            )}

            {/* Audit log — auditor and admin */}
            {isLoggedIn && (user.role === 'auditor' || user.role === 'admin') && (
              <TabsTrigger
                value="audit"
                className="data-[state=active]:bg-slate-700 data-[state=active]:text-white px-8 text-white"
              >
                Audit Log
              </TabsTrigger>
            )}
          </TabsList>

          {/* ── Analysis tab ─────────────────────────────────────────────────── */}
          {!isAuditor && (
            <TabsContent value="analysis" className="space-y-6 mt-6">
              <EmailSubmission
                onSubmit={handleSubmit}
                isProcessing={isProcessing}
                trialRemaining={!isLoggedIn ? trial.remaining : undefined}
                onViewAnalysis={handleSelectAnalysis}
                isLoggedIn={isLoggedIn}
              />

              <ProcessingStatus
                isProcessing={isProcessing}
                progress={progress}
                currentStep={currentStep}
              />

              {analysisError && !isProcessing && (
                <div className="p-5 rounded-lg border border-red-700/50 bg-red-950/30 text-sm space-y-2">
                  <p className="text-red-400 font-semibold">⚠️ Analysis Failed</p>
                  <p className="text-slate-300">{analysisError}</p>
                </div>
              )}

              {showResults && analysisData && (() => {
                const d = analysisData;
                return (
                  <div className="space-y-6">
                    <RiskAssessment
                      verdict={d.verdict}
                      riskScore={d.riskScore}
                      confidence={d.confidence}
                      severity={d.severity}
                    />
                    <LayeredViewToggle currentView={currentView} onViewChange={setCurrentView} />

                    {currentView === 'executive' && (
                      <div className="space-y-6">
                        <AIAnalysisSummary summary={d.summary} indicators={(d.indicators ?? []).slice(0, 3)} threatIntel={[]} />
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                          <RecommendedActions riskLevel={d.severity} recommendations={d.recommendations} />
                          <ForensicReport analysisData={d} />
                        </div>
                      </div>
                    )}

                    {currentView === 'analyst' && (
                      <div className="space-y-6">
                        <AIAnalysisSummary summary={d.summary} indicators={d.indicators ?? []} threatIntel={[]} />
                        <AnalysisModules
                          headerAnalysis={d.headerAnalysis}
                          urlAnalysis={d.urlAnalysis}
                          attachmentAnalysis={d.attachmentAnalysis}
                        />
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                          <RecommendedActions riskLevel={d.severity} recommendations={d.recommendations} />
                          <ForensicReport analysisData={d} />
                        </div>
                      </div>
                    )}

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
                          <ForensicReport analysisData={d} />
                        </div>
                      </div>
                    )}
                  </div>
                );
              })()}
            </TabsContent>
          )}

          {/* ── History tab ──────────────────────────────────────────────────── */}
          <TabsContent value="history" className="mt-6">
            {!isLoggedIn ? (
              <div className="text-center py-20 space-y-4">
                <Shield className="w-12 h-12 text-slate-600 mx-auto" />
                <p className="text-slate-400 font-medium">Login to access analysis history</p>
                <Button onClick={() => setShowLogin(true)} className="bg-blue-600 hover:bg-blue-700 text-white">
                  <LogIn className="w-4 h-4 mr-2" />Sign in
                </Button>
              </div>
            ) : (
              <AnalysisHistory
                onSelectAnalysis={handleSelectAnalysis}
                refreshTrigger={historyRefreshTrigger}
                userRole={user!.role}
              />
            )}
          </TabsContent>

          {/* ── Audit log tab ─────────────────────────────────────────────────── */}
          {isLoggedIn && (user.role === 'auditor' || user.role === 'admin') && (
            <TabsContent value="audit" className="mt-6">
              <AuditorDashboard />
            </TabsContent>
          )}
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
              <span>FYP 2026</span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppInner />
    </AuthProvider>
  );
}
