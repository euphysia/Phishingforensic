import { Shield, Zap, Search, Lock, AlertTriangle, BarChart3, Globe, Paperclip, ChevronRight, CheckCircle, Mail, ArrowRight } from 'lucide-react';
import { Button } from './ui/button';

interface LandingPageProps {
  onGetStarted: () => void;
}

const features = [
  {
    icon: <Mail className="w-6 h-6" />,
    color: 'blue',
    title: 'Email Header Analysis',
    desc: 'Deep inspection of SPF, DKIM, and DMARC authentication records to detect sender spoofing and domain impersonation.',
  },
  {
    icon: <Globe className="w-6 h-6" />,
    color: 'violet',
    title: 'URL & Link Scanning',
    desc: 'Every link is scanned through VirusTotal, URLScan.io, and PhishTank to detect malicious redirects and phishing pages.',
  },
  {
    icon: <Paperclip className="w-6 h-6" />,
    color: 'amber',
    title: 'Attachment Deep Scan',
    desc: 'MIME spoofing detection, magic byte verification, macro analysis, and VirusTotal hash lookup for every attachment.',
  },
  {
    icon: <BarChart3 className="w-6 h-6" />,
    color: 'emerald',
    title: 'Unified Risk Scoring',
    desc: '5-source weighted scoring combining VirusTotal, URLScan, AbuseIPDB, PhishTank, and heuristic signals into a 0–100 risk score.',
  },
  {
    icon: <Lock className="w-6 h-6" />,
    color: 'rose',
    title: 'Chain of Custody',
    desc: 'Cryptographically-linked forensic audit trail for every analysis step — tamper-evident evidence suitable for investigation reports.',
  },
  {
    icon: <Zap className="w-6 h-6" />,
    color: 'cyan',
    title: 'AI-Powered Summary',
    desc: 'Google Gemini generates plain-English executive summaries so non-technical stakeholders can understand threats instantly.',
  },
];

const steps = [
  {
    num: '01',
    title: 'Submit the Email',
    desc: 'Upload an .eml file, paste raw headers, or forward directly to our SMTP address — works with Gmail, Outlook, and Apple Mail.',
    icon: <Mail className="w-5 h-5" />,
  },
  {
    num: '02',
    title: 'Automated Analysis',
    desc: 'The engine runs header checks, URL scans, attachment forensics, and threat intelligence lookups — all in under 30 seconds.',
    icon: <Search className="w-5 h-5" />,
  },
  {
    num: '03',
    title: 'Review Forensic Report',
    desc: 'Get a risk score, verdict, detailed indicators, chain-of-custody record, and recommended actions — in executive or analyst view.',
    icon: <Shield className="w-5 h-5" />,
  },
];

const stats = [
  { value: '5+', label: 'Threat Intel Sources' },
  { value: '<30s', label: 'Analysis Time' },
  { value: '100+', label: 'Phishing Indicators' },
  { value: '24/7', label: 'SMTP Monitoring' },
];

const colorMap: Record<string, string> = {
  blue:    'bg-blue-500/10 text-blue-400 border-blue-500/20',
  violet:  'bg-violet-500/10 text-violet-400 border-violet-500/20',
  amber:   'bg-amber-500/10 text-amber-400 border-amber-500/20',
  emerald: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  rose:    'bg-rose-500/10 text-rose-400 border-rose-500/20',
  cyan:    'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
};

export function LandingPage({ onGetStarted }: LandingPageProps) {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-white">

      {/* ── Nav ─────────────────────────────────────────────────────────── */}
      <header className="sticky top-0 z-50 border-b border-slate-800/60 bg-slate-950/80 backdrop-blur-md">
        <div className="container mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="relative">
              <Shield className="w-7 h-7 text-blue-500" />
              <div className="absolute inset-0 bg-blue-500/30 blur-lg rounded-full" />
            </div>
            <div>
              <span className="font-bold text-white text-sm">PhishForensics</span>
              <div className="text-[10px] text-slate-500 leading-none">Automated Threat Analysis</div>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <a href="#features" className="hidden md:block text-sm text-slate-400 hover:text-white transition-colors">Features</a>
            <a href="#how-it-works" className="hidden md:block text-sm text-slate-400 hover:text-white transition-colors">How It Works</a>
            <Button
              onClick={onGetStarted}
              size="sm"
              className="bg-blue-600 hover:bg-blue-500 text-white rounded-lg px-4 text-sm"
            >
              Launch App <ChevronRight className="w-4 h-4 ml-1" />
            </Button>
          </div>
        </div>
      </header>

      {/* ── Hero ────────────────────────────────────────────────────────── */}
      <section className="relative pt-24 pb-28 px-6 overflow-hidden">
        {/* Glow blobs */}
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[700px] h-[400px] bg-blue-600/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute top-20 left-1/4 w-[300px] h-[300px] bg-violet-600/8 rounded-full blur-3xl pointer-events-none" />

        <div className="container mx-auto max-w-4xl text-center relative">
          {/* Badge */}
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-medium mb-8">
            <span className="w-1.5 h-1.5 bg-blue-400 rounded-full animate-pulse" />
            FYP — Automated Phishing Forensic System
          </div>

          <h1 className="text-5xl md:text-6xl font-bold leading-tight mb-6">
            Detect Phishing Emails
            <br />
            <span className="bg-gradient-to-r from-blue-400 via-violet-400 to-cyan-400 bg-clip-text text-transparent">
              Before They Strike
            </span>
          </h1>

          <p className="text-lg text-slate-400 max-w-2xl mx-auto mb-10 leading-relaxed">
            Upload a suspicious email and get a full forensic analysis in seconds —
            headers, URLs, attachments, sender IP reputation, and an AI-generated threat summary,
            all with a forensic chain of custody.
          </p>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <Button
              onClick={onGetStarted}
              size="lg"
              className="bg-blue-600 hover:bg-blue-500 text-white rounded-xl px-8 py-6 text-base font-semibold shadow-lg shadow-blue-900/40 transition-all hover:shadow-blue-800/60 hover:-translate-y-0.5"
            >
              Start Analysing Emails
              <ArrowRight className="w-5 h-5 ml-2" />
            </Button>
            <a href="#how-it-works">
              <Button
                variant="outline"
                size="lg"
                className="border-slate-700 text-slate-300 hover:bg-slate-800 rounded-xl px-8 py-6 text-base"
              >
                See How It Works
              </Button>
            </a>
          </div>

          {/* Trust indicators */}
          <div className="flex flex-wrap justify-center gap-x-8 gap-y-3 mt-12 text-xs text-slate-500">
            {['VirusTotal', 'URLScan.io', 'AbuseIPDB', 'PhishTank', 'Google Gemini AI'].map(s => (
              <span key={s} className="flex items-center gap-1.5">
                <CheckCircle className="w-3.5 h-3.5 text-emerald-500" />{s}
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* ── Stats ───────────────────────────────────────────────────────── */}
      <section className="border-y border-slate-800/60 bg-slate-900/40">
        <div className="container mx-auto px-6 py-10">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
            {stats.map(({ value, label }) => (
              <div key={label} className="text-center">
                <div className="text-3xl font-bold text-white mb-1">{value}</div>
                <div className="text-sm text-slate-500">{label}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Features ────────────────────────────────────────────────────── */}
      <section id="features" className="py-24 px-6">
        <div className="container mx-auto max-w-6xl">
          <div className="text-center mb-16">
            <h2 className="text-3xl font-bold text-white mb-4">
              Full-Spectrum Phishing Detection
            </h2>
            <p className="text-slate-400 max-w-xl mx-auto">
              Every analysis combines six layers of forensic intelligence to give you the clearest possible threat picture.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {features.map(({ icon, color, title, desc }) => (
              <div
                key={title}
                className="group relative p-6 rounded-2xl bg-slate-900 border border-slate-800 hover:border-slate-700 transition-all hover:-translate-y-0.5 hover:shadow-xl hover:shadow-slate-950/50"
              >
                <div className={`inline-flex items-center justify-center w-11 h-11 rounded-xl border mb-4 ${colorMap[color]}`}>
                  {icon}
                </div>
                <h3 className="text-white font-semibold mb-2">{title}</h3>
                <p className="text-sm text-slate-400 leading-relaxed">{desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── How It Works ────────────────────────────────────────────────── */}
      <section id="how-it-works" className="py-24 px-6 bg-slate-900/40 border-y border-slate-800/60">
        <div className="container mx-auto max-w-4xl">
          <div className="text-center mb-16">
            <h2 className="text-3xl font-bold text-white mb-4">How It Works</h2>
            <p className="text-slate-400 max-w-xl mx-auto">
              Three simple steps — from suspicious email to full forensic report.
            </p>
          </div>

          <div className="space-y-6">
            {steps.map((step, i) => (
              <div key={step.num} className="flex gap-6 items-start group">
                {/* Left: number + connector */}
                <div className="flex flex-col items-center shrink-0">
                  <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-blue-600 to-violet-600 flex items-center justify-center text-white font-bold text-sm shadow-lg shadow-blue-900/30">
                    {step.icon}
                  </div>
                  {i < steps.length - 1 && (
                    <div className="w-px h-8 bg-gradient-to-b from-blue-600/40 to-transparent mt-2" />
                  )}
                </div>
                {/* Right: content */}
                <div className="flex-1 pb-2">
                  <div className="text-xs font-mono text-blue-500 mb-1">{step.num}</div>
                  <h3 className="text-white font-semibold text-lg mb-2">{step.title}</h3>
                  <p className="text-slate-400 text-sm leading-relaxed">{step.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Who It's For ────────────────────────────────────────────────── */}
      <section className="py-24 px-6">
        <div className="container mx-auto max-w-5xl">
          <div className="text-center mb-14">
            <h2 className="text-3xl font-bold text-white mb-4">Built for Every Stakeholder</h2>
            <p className="text-slate-400 max-w-xl mx-auto">Three layered views so analysts and executives both get the right level of detail.</p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            {[
              { role: 'Executive', icon: '👔', desc: 'Plain-English AI summary and recommended actions — no technical jargon, just clear next steps.', badge: 'Executive View' },
              { role: 'Security Analyst', icon: '🔍', desc: 'Header analysis, URL scan results, attachment risks, phishing indicators, and IP reputation data.', badge: 'Analyst View' },
              { role: 'Digital Forensics', icon: '🧪', desc: 'Raw headers, full chain-of-custody log, score breakdown by source, and evidence-grade SHA-256 hashes.', badge: 'Technical View' },
            ].map(({ role, icon, desc, badge }) => (
              <div key={role} className="p-6 rounded-2xl bg-gradient-to-b from-slate-800/60 to-slate-900/60 border border-slate-700/60 hover:border-slate-600 transition-all">
                <div className="text-3xl mb-4">{icon}</div>
                <div className="text-xs text-blue-400 font-mono mb-2">{badge}</div>
                <h3 className="text-white font-semibold mb-3">{role}</h3>
                <p className="text-sm text-slate-400 leading-relaxed">{desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── CTA ─────────────────────────────────────────────────────────── */}
      <section className="py-24 px-6">
        <div className="container mx-auto max-w-2xl text-center">
          <div className="relative p-12 rounded-3xl bg-gradient-to-br from-blue-950/60 to-violet-950/40 border border-blue-800/40 overflow-hidden">
            <div className="absolute inset-0 bg-gradient-to-br from-blue-600/5 to-violet-600/5" />
            <div className="absolute top-0 left-1/2 -translate-x-1/2 w-64 h-32 bg-blue-600/15 blur-3xl rounded-full" />
            <div className="relative">
              <AlertTriangle className="w-12 h-12 text-amber-400 mx-auto mb-6" />
              <h2 className="text-3xl font-bold text-white mb-4">
                Got a suspicious email?
              </h2>
              <p className="text-slate-400 mb-8">
                Don't click anything. Upload it here for a free, instant forensic analysis.
              </p>
              <Button
                onClick={onGetStarted}
                size="lg"
                className="bg-blue-600 hover:bg-blue-500 text-white rounded-xl px-10 py-6 text-base font-semibold shadow-xl shadow-blue-900/40 hover:-translate-y-0.5 transition-all"
              >
                Analyse an Email Now
                <ArrowRight className="w-5 h-5 ml-2" />
              </Button>
            </div>
          </div>
        </div>
      </section>

      {/* ── Footer ──────────────────────────────────────────────────────── */}
      <footer className="border-t border-slate-800 bg-slate-950/60 py-8 px-6">
        <div className="container mx-auto flex flex-col md:flex-row items-center justify-between gap-4 text-sm text-slate-500">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4" />
            <span>PhishForensics — Automated Phishing Email Forensic Analysis System</span>
          </div>
          <div className="flex items-center gap-4">
            <span>FYP 2026</span>
            <span>·</span>
            <span>Sprints 1–4 Active</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
