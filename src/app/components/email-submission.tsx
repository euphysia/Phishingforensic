import { useState, useEffect, useRef } from 'react';
import { Upload, Mail, FileText, ChevronRight, CheckCircle2, AlertCircle, Clock, Copy, Check, Wifi, WifiOff, RefreshCw, ExternalLink, Info, Loader2 } from 'lucide-react';
import { Button } from './ui/button';
import { Card } from './ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs';
import { Textarea } from './ui/textarea';

interface EmailSubmissionProps {
  onSubmit:        (data: { type: string; content: string | File }) => void;
  isProcessing:    boolean;
  trialRemaining?: number; // undefined = logged in (no counter shown)
  onViewAnalysis?: (id: string) => void;
  isLoggedIn?:     boolean;
}

interface SmtpStatus {
  status: 'running' | 'stopped' | 'error' | 'loading';
  port: number;
  domain: string;
  emailAddress: string;
  totalReceived: number;
  error?: string | null;
  recentForwards?: ForwardEntry[];
}

interface ForwardEntry {
  id: string;
  receivedAt: string;
  subject: string;
  from: string;
  senderIp: string;
  status: 'processing' | 'complete' | 'error';
  analysisId?: string | null;
  verdict?: string | null;
  riskScore?: number | null;
  error?: string | null;
}

const verdictColors: Record<string, string> = {
  phishing:   'text-red-400 bg-red-950/50 border-red-700/50',
  suspicious: 'text-amber-400 bg-amber-950/50 border-amber-700/50',
  clean:      'text-emerald-400 bg-emerald-950/50 border-emerald-700/50',
};

export function EmailSubmission({ onSubmit, isProcessing, trialRemaining, onViewAnalysis, isLoggedIn }: EmailSubmissionProps) {
  const [activeTab, setActiveTab]     = useState('upload');
  const [rawHeaders, setRawHeaders]   = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [dragOver, setDragOver]       = useState(false);
  const [copied, setCopied]           = useState(false);
  const [smtpStatus, setSmtpStatus]   = useState<SmtpStatus>({
    status: 'loading', port: 2525, domain: 'phishing-forensics.local',
    emailAddress: 'analyze@phishing-forensics.local', totalReceived: 0,
  });
  const fileInputRef = useRef<HTMLInputElement>(null);
  const eventSourceRef = useRef<EventSource | null>(null);

  // ── Fetch SMTP status & subscribe to SSE ────────────────────────────────
  useEffect(() => {
    // Initial fetch
    fetch('/api/smtp/status')
      .then(r => r.json())
      .then(data => setSmtpStatus(prev => ({ ...prev, ...data })))
      .catch(() => setSmtpStatus(prev => ({ ...prev, status: 'error', error: 'Cannot reach server' })));

    // SSE for real-time updates
    const es = new EventSource('/api/smtp/events');
    eventSourceRef.current = es;

    es.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        if (data.type === 'status') {
          setSmtpStatus(prev => ({ ...prev, ...data }));
        } else if (data.type === 'email-received' || data.type === 'analysis-complete' || data.type === 'analysis-error') {
          setSmtpStatus(prev => ({
            ...prev,
            totalReceived: (prev.totalReceived || 0) + (data.type === 'email-received' ? 1 : 0),
            recentForwards: [
              data,
              ...(prev.recentForwards || []).filter(f => f.id !== data.id),
            ].slice(0, 10),
          }));
        }
      } catch {}
    };

    es.onerror = () => {
      setSmtpStatus(prev => ({ ...prev, status: prev.status === 'loading' ? 'error' : prev.status }));
    };

    return () => { es.close(); };
  }, []);

  const refreshStatus = () => {
    setSmtpStatus(prev => ({ ...prev, status: 'loading' }));
    fetch('/api/smtp/status')
      .then(r => r.json())
      .then(data => setSmtpStatus(prev => ({ ...prev, ...data })))
      .catch(() => setSmtpStatus(prev => ({ ...prev, status: 'error' })));
  };

  // ── File drag & drop ──────────────────────────────────────────────────────
  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) setSelectedFile(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) setSelectedFile(file);
  };

  // ── Submit ────────────────────────────────────────────────────────────────
  const handleSubmit = () => {
    if (activeTab === 'upload' && selectedFile) {
      onSubmit({ type: 'file', content: selectedFile });
    } else if (activeTab === 'paste' && rawHeaders.trim()) {
      onSubmit({ type: 'headers', content: rawHeaders });
    }
  };

  const trialExhausted = trialRemaining !== undefined && trialRemaining <= 0;
  const canSubmit =
    !trialExhausted &&
    ((activeTab === 'upload' && selectedFile) ||
    (activeTab === 'paste' && rawHeaders.trim().length > 20));

  const copyAddress = () => {
    navigator.clipboard.writeText(smtpStatus.emailAddress);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Card className="bg-slate-900 border-slate-800 p-6">
      <div className="mb-5">
        <div className="flex items-center justify-between mb-1">
          <h2 className="text-xl font-semibold text-white">Email Submission</h2>
          {trialRemaining !== undefined && (
            <span className={`text-xs px-2.5 py-1 rounded-full border font-medium ${
              trialRemaining === 0
                ? 'bg-red-950/40 text-red-400 border-red-700/50'
                : trialRemaining === 1
                  ? 'bg-amber-950/40 text-amber-400 border-amber-700/50'
                  : 'bg-slate-800 text-slate-400 border-slate-700'
            }`}>
              {trialRemaining === 0
                ? 'Trial limit reached — login to continue'
                : `${trialRemaining} free ${trialRemaining === 1 ? 'analysis' : 'analyses'} remaining`}
            </span>
          )}
        </div>
        <p className="text-sm text-slate-400">
          Choose how you want to submit a suspicious email for forensic analysis
        </p>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="grid w-full grid-cols-3 bg-slate-800 p-1 rounded-lg">
          <TabsTrigger
            value="upload"
            className="data-[state=active]:bg-slate-700 data-[state=active]:text-white text-slate-300 rounded-md transition-all"
          >
            <Upload className="w-4 h-4 mr-2" />
            Upload File
          </TabsTrigger>
          <TabsTrigger
            value="paste"
            className="data-[state=active]:bg-slate-700 data-[state=active]:text-white text-slate-300 rounded-md transition-all"
          >
            <FileText className="w-4 h-4 mr-2" />
            Paste Headers
          </TabsTrigger>
          <TabsTrigger
            value="forward"
            className="data-[state=active]:bg-slate-700 data-[state=active]:text-white text-slate-300 rounded-md transition-all relative"
          >
            <Mail className="w-4 h-4 mr-2" />
            Forward Email
            {smtpStatus.status === 'running' && (
              <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-emerald-500 rounded-full border-2 border-slate-800" />
            )}
          </TabsTrigger>
        </TabsList>

        {/* ── Upload Tab ──────────────────────────────────────────────────── */}
        <TabsContent value="upload" className="mt-5">
          <div
            className={`border-2 border-dashed rounded-xl p-10 text-center transition-all cursor-pointer
              ${dragOver
                ? 'border-blue-500 bg-blue-950/20'
                : selectedFile
                  ? 'border-emerald-600/60 bg-emerald-950/10'
                  : 'border-slate-700 hover:border-slate-500 bg-slate-800/30'
              }`}
            onClick={() => fileInputRef.current?.click()}
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleDrop}
          >
            {selectedFile ? (
              <>
                <CheckCircle2 className="w-12 h-12 mx-auto mb-3 text-emerald-500" />
                <p className="text-white font-medium mb-1">{selectedFile.name}</p>
                <p className="text-sm text-slate-400">
                  {(selectedFile.size / 1024).toFixed(1)} KB · Click to change file
                </p>
              </>
            ) : (
              <>
                <Upload className="w-12 h-12 mx-auto mb-3 text-slate-500" />
                <p className="text-white font-medium mb-1">Drop your .eml file here</p>
                <p className="text-sm text-slate-400">or click to browse — supports .eml, .msg files (max 10MB)</p>
              </>
            )}
            <input
              ref={fileInputRef}
              type="file"
              accept=".eml,.msg,.txt"
              onChange={handleFileSelect}
              className="hidden"
            />
          </div>

          {/* How to get an .eml file */}
          <div className="mt-4 p-4 rounded-lg bg-slate-800/50 border border-slate-700/50">
            <div className="flex items-center gap-2 text-slate-300 text-sm font-medium mb-2">
              <Info className="w-4 h-4 text-blue-400" />
              How to export an email as .eml
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs text-slate-400">
              <div className="flex gap-2">
                <span className="font-semibold text-blue-400 shrink-0">Gmail:</span>
                <span>Open email → ⋮ More → Download message</span>
              </div>
              <div className="flex gap-2">
                <span className="font-semibold text-blue-400 shrink-0">Outlook:</span>
                <span>Open email → File → Save As → .msg or drag to desktop</span>
              </div>
              <div className="flex gap-2">
                <span className="font-semibold text-blue-400 shrink-0">Apple Mail:</span>
                <span>Drag email from mailbox to Finder</span>
              </div>
            </div>
          </div>
        </TabsContent>

        {/* ── Paste Tab ───────────────────────────────────────────────────── */}
        <TabsContent value="paste" className="mt-5">
          <div className="mb-3 p-3 rounded-lg bg-blue-950/30 border border-blue-800/40 text-xs text-blue-300 flex gap-2">
            <Info className="w-4 h-4 shrink-0 mt-0.5" />
            <div>
              <span className="font-medium">Paste the full raw email</span> — including headers and body.
              In Gmail: open email → ⋮ → Show original → Copy all. In Outlook: File → Properties → Internet headers.
            </div>
          </div>
          <Textarea
            placeholder={`Paste raw email content here...\n\nExample:\nDelivered-To: you@example.com\nReceived: from mail.evil.com (185.220.101.45)\nFrom: "PayPal Security" <security@paypa1.com>\nTo: you@example.com\nSubject: Urgent: Verify Your Account\nDate: Mon, 12 May 2026 10:23:45 +0000\n\nDear Customer, your account has been suspended...`}
            value={rawHeaders}
            onChange={(e) => setRawHeaders(e.target.value)}
            className="min-h-[220px] bg-slate-800 border-slate-700 text-white font-mono text-sm placeholder:text-slate-600 focus:border-blue-600 resize-y"
          />
          {rawHeaders.trim().length > 0 && rawHeaders.trim().length < 20 && (
            <p className="text-xs text-amber-400 mt-2 flex items-center gap-1">
              <AlertCircle className="w-3 h-3" /> Content seems too short — paste the full email including headers
            </p>
          )}
        </TabsContent>

        {/* ── Forward Email Tab ────────────────────────────────────────────── */}
        <TabsContent value="forward" className="mt-5 space-y-5">

          {/* SMTP Status Banner */}
          <SmtpStatusBanner status={smtpStatus} onRefresh={refreshStatus} />

          {/* Forward Address Card */}
          <div className="rounded-xl border border-slate-700 overflow-hidden">
            <div className="bg-slate-800/70 px-5 py-4 border-b border-slate-700">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Mail className="w-4 h-4 text-blue-400" />
                Your Analysis Email Address
              </h3>
            </div>
            <div className="p-5">
              <div className="flex items-center gap-3 p-4 bg-slate-950 rounded-lg border border-slate-700 mb-4">
                <div className={`w-2.5 h-2.5 rounded-full shrink-0 ${smtpStatus.status === 'running' ? 'bg-emerald-500 animate-pulse' : 'bg-slate-600'}`} />
                <code className="text-blue-300 flex-1 text-sm font-mono select-all">
                  {smtpStatus.emailAddress}
                </code>
                <button
                  onClick={copyAddress}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-slate-700 hover:bg-slate-600 text-xs text-slate-300 hover:text-white transition-all"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  {copied ? 'Copied!' : 'Copy'}
                </button>
              </div>

              {smtpStatus.status === 'running' && (
                <div className="grid grid-cols-2 gap-3 text-xs text-slate-400">
                  <div className="flex items-center gap-2 bg-slate-800/50 rounded-lg px-3 py-2">
                    <span className="text-slate-500">SMTP Port:</span>
                    <code className="text-slate-300">{smtpStatus.port}</code>
                  </div>
                  <div className="flex items-center gap-2 bg-slate-800/50 rounded-lg px-3 py-2">
                    <span className="text-slate-500">Received:</span>
                    <span className="text-slate-300 font-medium">{smtpStatus.totalReceived} email{smtpStatus.totalReceived !== 1 ? 's' : ''}</span>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Step-by-Step Instructions */}
          <div className="rounded-xl border border-slate-700 overflow-hidden">
            <div className="bg-slate-800/70 px-5 py-4 border-b border-slate-700">
              <h3 className="text-sm font-semibold text-white">How to forward a phishing email</h3>
            </div>
            <div className="p-5 space-y-0">
              <ForwardStep
                number={1}
                title="Open the suspicious email"
                description="Do NOT click any links inside it. Just open it to view."
                icon="📨"
              />
              <ForwardStep
                number={2}
                title='Forward it "as attachment"'
                description={
                  <span>
                    This preserves the original headers. In Gmail: More <span className="text-slate-500">›</span> Forward as attachment.
                    In Outlook: right-click → Forward as Attachment.
                  </span>
                }
                icon="📎"
                highlight
              />
              <ForwardStep
                number={3}
                title={`Send to: ${smtpStatus.emailAddress}`}
                description="Paste the address above into the To field. No subject or body needed."
                icon="📤"
              />
              <ForwardStep
                number={4}
                title="Wait for automatic analysis (< 1 min)"
                description="Results appear in History automatically. No need to refresh this page."
                icon="⚡"
                last
              />
            </div>
          </div>

          {/* Email Client Quick Guides */}
          <div className="rounded-xl border border-slate-700 overflow-hidden">
            <div className="bg-slate-800/70 px-5 py-4 border-b border-slate-700">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Info className="w-4 h-4 text-blue-400" />
                Email client setup — add this SMTP server once
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                Your email client needs to know how to reach the local SMTP listener
              </p>
            </div>
            <div className="p-5">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <ClientGuide
                  name="Thunderbird"
                  steps={[
                    'Tools → Account Settings',
                    'Outgoing Server (SMTP)',
                    'Add → Server Name: localhost',
                    'Port: 2525, No Auth, No SSL',
                    'Set as default outgoing',
                  ]}
                />
                <ClientGuide
                  name="Outlook"
                  steps={[
                    'File → Add Account',
                    'Manual setup → POP/IMAP',
                    'Outgoing (SMTP): localhost',
                    'Port: 2525, No encryption',
                    'Use only for forwarding',
                  ]}
                />
                <ClientGuide
                  name="Apple Mail"
                  steps={[
                    'Mail → Preferences → Accounts',
                    'Select account → Server Settings',
                    'Outgoing: localhost:2525',
                    'Uncheck "Use SSL"',
                    'Authentication: None',
                  ]}
                />
              </div>
            </div>
          </div>

          {/* Recent Forwards Feed */}
          {(smtpStatus.recentForwards?.length ?? 0) > 0 && (
            <div className="rounded-xl border border-slate-700 overflow-hidden">
              <div className="bg-slate-800/70 px-5 py-4 border-b border-slate-700 flex items-center justify-between">
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  <Clock className="w-4 h-4 text-slate-400" />
                  Recently Forwarded
                </h3>
                <span className="text-xs text-slate-500">{smtpStatus.totalReceived} total received</span>
              </div>
              <div className="divide-y divide-slate-800">
                {smtpStatus.recentForwards!.map((entry) => (
                  <ForwardFeedEntry key={entry.id} entry={entry} onViewAnalysis={onViewAnalysis} isLoggedIn={isLoggedIn} />
                ))}
              </div>
            </div>
          )}
        </TabsContent>
      </Tabs>

      {/* Submit button — only shown for Upload / Paste tabs */}
      {activeTab !== 'forward' && (
        <div className="mt-6 flex justify-end">
          <Button
            onClick={handleSubmit}
            disabled={!canSubmit || isProcessing}
            className="bg-blue-600 hover:bg-blue-700 text-white disabled:opacity-50 disabled:cursor-not-allowed min-w-[180px]"
            size="lg"
          >
            {isProcessing ? (
              <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Analysing...</>
            ) : (
              <>Submit for Analysis<ChevronRight className="w-4 h-4 ml-2" /></>
            )}
          </Button>
        </div>
      )}
    </Card>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

function SmtpStatusBanner({ status, onRefresh }: { status: SmtpStatus; onRefresh: () => void }) {
  if (status.status === 'loading') {
    return (
      <div className="flex items-center gap-3 p-4 rounded-lg bg-slate-800/60 border border-slate-700 text-sm text-slate-400">
        <Loader2 className="w-4 h-4 animate-spin text-slate-500" />
        Checking SMTP server status...
      </div>
    );
  }

  if (status.status === 'running') {
    return (
      <div className="flex items-center gap-3 p-4 rounded-lg bg-emerald-950/30 border border-emerald-700/50 text-sm">
        <Wifi className="w-5 h-5 text-emerald-400 shrink-0" />
        <div className="flex-1">
          <span className="text-emerald-300 font-medium">SMTP listener is active</span>
          <span className="text-slate-400 ml-2">— forwarded emails will be analysed automatically</span>
        </div>
        <button onClick={onRefresh} className="text-slate-500 hover:text-slate-300 transition-colors">
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-3 p-4 rounded-lg bg-red-950/30 border border-red-700/50 text-sm">
      <WifiOff className="w-5 h-5 text-red-400 shrink-0" />
      <div className="flex-1">
        <span className="text-red-300 font-medium">SMTP listener is not running</span>
        <span className="text-slate-400 ml-2">
          {status.error ? `— ${status.error}` : '— start the backend server'}
        </span>
      </div>
      <button onClick={onRefresh} className="text-slate-500 hover:text-slate-300 transition-colors">
        <RefreshCw className="w-4 h-4" />
      </button>
    </div>
  );
}

function ForwardStep({
  number, title, description, icon, highlight = false, last = false,
}: {
  number: number;
  title: string;
  description: React.ReactNode;
  icon: string;
  highlight?: boolean;
  last?: boolean;
}) {
  return (
    <div className={`flex gap-4 ${!last ? 'pb-5 border-b border-slate-800/50' : ''} ${number > 1 ? 'pt-5' : ''}`}>
      <div className="flex flex-col items-center gap-1">
        <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold shrink-0
          ${highlight ? 'bg-blue-600 text-white' : 'bg-slate-700 text-slate-300'}`}>
          {number}
        </div>
        {!last && <div className="w-px flex-1 bg-slate-800" />}
      </div>
      <div className="flex-1 pb-1">
        <div className="flex items-center gap-2 mb-1">
          <span className="text-base">{icon}</span>
          <span className={`text-sm font-medium ${highlight ? 'text-blue-300' : 'text-white'}`}>{title}</span>
        </div>
        <p className="text-xs text-slate-400 leading-relaxed">{description}</p>
      </div>
    </div>
  );
}

function ClientGuide({ name, steps }: { name: string; steps: string[] }) {
  return (
    <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700/50">
      <h4 className="text-sm font-semibold text-white mb-3">{name}</h4>
      <ol className="space-y-1.5">
        {steps.map((step, i) => (
          <li key={i} className="flex gap-2 text-xs text-slate-400">
            <span className="text-slate-600 shrink-0">{i + 1}.</span>
            <span>{step}</span>
          </li>
        ))}
      </ol>
    </div>
  );
}

function ForwardFeedEntry({ entry, onViewAnalysis, isLoggedIn }: { entry: ForwardEntry; onViewAnalysis?: (id: string) => void; isLoggedIn?: boolean }) {
  const timeAgo = (iso: string) => {
    const diff = Date.now() - new Date(iso).getTime();
    if (diff < 60000) return `${Math.round(diff / 1000)}s ago`;
    if (diff < 3600000) return `${Math.round(diff / 60000)}m ago`;
    return new Date(iso).toLocaleTimeString();
  };

  const hasResult = entry.status === 'complete' && !!entry.analysisId && !!onViewAnalysis;
  const canOpen    = hasResult && isLoggedIn;

  return (
    <div
      role={hasResult ? 'button' : undefined}
      tabIndex={hasResult ? 0 : undefined}
      onClick={() => { if (hasResult) onViewAnalysis!(entry.analysisId!); }}
      onKeyDown={(e) => { if (hasResult && (e.key === 'Enter' || e.key === ' ')) onViewAnalysis!(entry.analysisId!); }}
      className={`flex items-center gap-4 px-5 py-3 transition-colors ${hasResult ? 'hover:bg-slate-800/30 cursor-pointer' : ''}`}
    >
      <div className="shrink-0">
        {entry.status === 'processing' && <Loader2 className="w-4 h-4 text-blue-400 animate-spin" />}
        {entry.status === 'complete'   && <CheckCircle2 className="w-4 h-4 text-emerald-400" />}
        {entry.status === 'error'      && <AlertCircle  className="w-4 h-4 text-red-400" />}
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm text-white truncate">{entry.subject || '(no subject)'}</p>
        <p className="text-xs text-slate-500 truncate">{entry.from}</p>
      </div>
      <div className="flex items-center gap-3 shrink-0">
        {entry.status === 'complete' && entry.verdict && (
          <span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${verdictColors[entry.verdict] || verdictColors.clean}`}>
            {entry.verdict} {entry.riskScore != null ? `· ${entry.riskScore}` : ''}
          </span>
        )}
        {entry.status === 'processing' && (
          <span className="text-xs text-slate-500">Analysing...</span>
        )}
        {entry.status === 'error' && (
          <span className="text-xs text-red-400 truncate max-w-[120px]" title={entry.error ?? ''}>Error</span>
        )}
        <span className="text-xs text-slate-600 whitespace-nowrap">{timeAgo(entry.receivedAt)}</span>
        {hasResult && (
          <span
            className={canOpen ? 'text-slate-500 hover:text-blue-400 transition-colors' : 'text-slate-700'}
            title={canOpen ? 'View analysis' : 'Sign in as analyst/admin to view full analysis details'}
          >
            <ExternalLink className="w-3.5 h-3.5" />
          </span>
        )}
      </div>
    </div>
  );
}