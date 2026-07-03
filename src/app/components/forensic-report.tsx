import { useState } from 'react';
import { downloadForensicPdf } from '../utils/pdfExport';
import { Download, Shield, Clock, ChevronDown, ChevronUp, FileJson, FileCode } from 'lucide-react';
import { Card } from './ui/card';
import { Button } from './ui/button';
import { Badge } from './ui/badge';
import {
  analyseSenderIdentity,
  analyseAuthentication,
  analyseRouting,
  analyseContent,
  analyseUrls,
  type SectionResult,
} from '../utils/reportSections';

interface ChainEntry {
  timestamp: string;
  action: string;
  module: string;
  description: string;
}

interface ForensicReportProps {
  analysisData: any;
}

// ── Verdict color helpers ─────────────────────────────────────────────────────

function verdictCell(value: string | undefined | null): string {
  if (!value) return 'text-slate-400';
  const v = value.toLowerCase();
  if (['pass', 'clean', 'safe'].includes(v)) return 'text-green-400 font-semibold';
  if (['fail', 'malicious', 'critical', 'high'].includes(v)) return 'text-red-400 font-semibold';
  if (['softfail', 'suspicious', 'medium'].includes(v)) return 'text-amber-400 font-semibold';
  return 'text-slate-300';
}

function severityBadge(severity: SectionResult['severity']) {
  const map = {
    high:   'bg-red-600/20 text-red-400 border-red-600/40',
    medium: 'bg-amber-600/20 text-amber-400 border-amber-600/40',
    low:    'bg-yellow-600/20 text-yellow-400 border-yellow-600/40',
    info:   'bg-green-600/20 text-green-400 border-green-600/40',
  };
  return map[severity];
}

// ── Reusable table components ─────────────────────────────────────────────────

function DocTable({ headers, rows }: { headers: string[]; rows: (string | React.ReactNode)[][] }) {
  return (
    <table className="w-full text-xs border-collapse">
      <thead>
        <tr className="bg-slate-800">
          {headers.map((h, i) => (
            <th key={i} className="text-left px-3 py-2 text-slate-300 font-semibold uppercase tracking-wide text-[10px] border border-slate-700">
              {h}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((row, i) => (
          <tr key={i} className={i % 2 === 0 ? 'bg-slate-900' : 'bg-slate-950'}>
            {row.map((cell, j) => (
              <td key={j} className="px-3 py-2 border border-slate-800 text-slate-300 align-top">
                {cell}
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function KVTable({ pairs }: { pairs: [string, string | undefined | null][] }) {
  return (
    <table className="w-full text-xs border-collapse">
      <tbody>
        {pairs.filter(([, v]) => v != null && v !== '').map(([k, v], i) => (
          <tr key={i} className={i % 2 === 0 ? 'bg-slate-900' : 'bg-slate-950'}>
            <td className="px-3 py-2 text-slate-400 font-medium border border-slate-800 w-40 shrink-0 align-top">{k}</td>
            <td className="px-3 py-2 text-slate-200 font-mono border border-slate-800 break-all align-top">{v}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// ── Section wrapper ───────────────────────────────────────────────────────────

function Section({
  number,
  title,
  section,
  children,
}: {
  number: number;
  title: string;
  section: SectionResult;
  children: React.ReactNode;
}) {
  return (
    <div className="border border-slate-700 rounded-sm overflow-hidden">
      {/* Banner — uniform dark, color only on the badge */}
      <div className="bg-slate-800 px-4 py-3 flex items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <span className="text-slate-500 text-xs font-bold w-5 shrink-0">{number}.</span>
          <span className="text-white text-sm font-semibold tracking-wide uppercase">{title}</span>
        </div>
        <span className={`text-[10px] px-2 py-0.5 rounded border font-semibold shrink-0 ${severityBadge(section.severity)}`}>
          {section.severity.toUpperCase()}
        </span>
      </div>

      {/* Finding line */}
      <div className="px-4 py-2 bg-slate-900 border-b border-slate-800">
        <p className="text-slate-400 text-xs font-medium italic">{section.finding}</p>
      </div>

      {/* Analysis paragraph */}
      <div className="px-4 py-3 bg-slate-900/60">
        <p className="text-slate-300 text-sm leading-relaxed">{section.analysis}</p>
      </div>

      {/* Evidence — always visible */}
      <div className="px-4 pb-4 pt-2 bg-slate-950/50 border-t border-slate-800">
        <p className="text-[10px] text-slate-500 uppercase tracking-widest font-semibold mb-2">Evidence</p>
        {children}
      </div>
    </div>
  );
}

// ── HTML export ───────────────────────────────────────────────────────────────

function buildHtmlReport(d: any, sections: { number: number; title: string; section: SectionResult; analysisText: string; evidenceHtml: string }[]): string {
  const riskColor   = d.verdict === 'phishing' ? '#ef4444' : d.verdict === 'suspicious' ? '#f59e0b' : '#22c55e';
  const entries: ChainEntry[] = d.chainOfCustody?.entries ?? [];

  const cellColor = (v: string) => {
    const lv = (v ?? '').toLowerCase();
    if (['pass', 'clean', 'safe'].includes(lv)) return '#22c55e';
    if (['fail', 'malicious'].includes(lv)) return '#ef4444';
    if (['softfail', 'suspicious'].includes(lv)) return '#f59e0b';
    return '#94a3b8';
  };

  const scoreBreakdown = d.scoreBreakdown ?? {};
  const scoreRows = Object.entries(scoreBreakdown).map(([key, val]: [string, any]) => {
    const labels: Record<string, string> = {
      header: 'Header Analysis (SPF / DKIM / DMARC)',
      url: 'URL Reputation (VirusTotal · URLScan · PhishTank)',
      ipReputation: 'Sender IP Reputation (AbuseIPDB)',
      attachments: 'Attachment Analysis',
      body: 'Body Content Analysis (AI)',
      indicators: 'Phishing Indicators (Heuristic)',
    };
    return `<tr>
      <td style="padding:7px 10px;border-bottom:1px solid #1e293b">${labels[key] ?? key}</td>
      <td style="padding:7px 10px;border-bottom:1px solid #1e293b;text-align:center">${Math.round(val.weight * 100)}%</td>
      <td style="padding:7px 10px;border-bottom:1px solid #1e293b;text-align:center;color:${val.risk > 60 ? '#ef4444' : val.risk > 30 ? '#f59e0b' : '#22c55e'};font-weight:600">${val.risk}/100</td>
    </tr>`;
  }).join('');

  const sectionsHtml = sections.map(s => {
    const badgeColor = s.section.severity === 'high' ? '#ef4444' : s.section.severity === 'medium' ? '#f59e0b' : s.section.severity === 'low' ? '#eab308' : '#22c55e';
    return `
    <div style="margin-bottom:28px;border:1px solid #1e293b;border-radius:4px;overflow:hidden">
      <div style="background:#0f172a;padding:12px 16px;display:flex;align-items:center;justify-content:space-between">
        <div style="font-size:12px;font-weight:700;color:#f1f5f9;text-transform:uppercase;letter-spacing:.06em">
          ${s.number}. ${s.title}
        </div>
        <span style="font-size:10px;font-weight:700;padding:2px 8px;border-radius:3px;border:1px solid ${badgeColor}44;background:${badgeColor}18;color:${badgeColor}">
          ${s.section.severity.toUpperCase()}
        </span>
      </div>
      <div style="background:#0d1b2a;padding:8px 16px;border-bottom:1px solid #1e293b">
        <p style="margin:0;font-size:11px;color:#94a3b8;font-style:italic">${s.section.finding}</p>
      </div>
      <div style="background:#111827;padding:14px 16px;border-bottom:1px solid #1e293b">
        <p style="margin:0;font-size:13px;color:#cbd5e1;line-height:1.75">${s.analysisText}</p>
      </div>
      <div style="background:#0a0f1a;padding:14px 16px">
        <p style="margin:0 0 8px;font-size:10px;color:#475569;text-transform:uppercase;letter-spacing:.1em;font-weight:700">Evidence</p>
        ${s.evidenceHtml}
      </div>
    </div>`;
  }).join('');

  const iocs = buildIocList(d);
  const iocRows = iocs.map(({ type, value }) => `
    <tr>
      <td style="padding:6px 10px;border-bottom:1px solid #1e293b;color:#94a3b8;font-size:11px">${type}</td>
      <td style="padding:6px 10px;border-bottom:1px solid #1e293b;font-family:monospace;font-size:11px;color:#e2e8f0;word-break:break-all">${value}</td>
    </tr>`).join('');

  const custodyRows = entries.map(e => `
    <tr>
      <td style="padding:6px 10px;border-bottom:1px solid #1e293b;font-family:monospace;font-size:10px;white-space:nowrap;color:#94a3b8">${new Date(e.timestamp).toLocaleString()}</td>
      <td style="padding:6px 10px;border-bottom:1px solid #1e293b;font-size:11px;color:#e2e8f0;font-weight:600">${e.action}</td>
      <td style="padding:6px 10px;border-bottom:1px solid #1e293b;font-size:11px;color:#94a3b8">${e.module}</td>
      <td style="padding:6px 10px;border-bottom:1px solid #1e293b;font-size:11px;color:#cbd5e1">${e.description}</td>
    </tr>`).join('');

  const tblHeader = (cols: string[]) => `<tr style="background:#0f172a">${cols.map(c => `<th style="padding:8px 10px;text-align:left;font-size:10px;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:.06em;border-bottom:1px solid #1e293b">${c}</th>`).join('')}</tr>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>Forensic Report — ${d.id}</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:system-ui,-apple-system,sans-serif;color:#e2e8f0;background:#020817;padding:0}
  .page{max-width:860px;margin:0 auto;padding:40px 32px}
  h2{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:#475569;margin:32px 0 12px;padding-bottom:6px;border-bottom:1px solid #1e293b}
  table{width:100%;border-collapse:collapse;font-size:12px}
  @media print{body{background:#fff;color:#111}.page{padding:24px}@page{margin:1.5cm}}
</style>
</head>
<body>
<div class="page">

  <!-- Cover header -->
  <div style="background:#0f172a;border:1px solid #1e293b;border-radius:6px;padding:28px 32px;margin-bottom:32px">
    <div style="font-size:11px;color:#475569;text-transform:uppercase;letter-spacing:.1em;margin-bottom:8px">
      Phishing Email Forensic Analysis System · FYP 2026
    </div>
    <div style="font-size:22px;font-weight:800;color:#f1f5f9;margin-bottom:20px;line-height:1.2">
      PHISHING EMAIL FORENSIC<br>INVESTIGATION REPORT
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:20px">
      <div><div style="font-size:10px;color:#475569;margin-bottom:3px">REPORT ID</div><div style="font-family:monospace;font-size:12px;color:#94a3b8">${d.id?.toUpperCase().slice(0,16) ?? '—'}</div></div>
      <div><div style="font-size:10px;color:#475569;margin-bottom:3px">GENERATED</div><div style="font-size:12px;color:#94a3b8">${new Date(d.createdAt).toLocaleString()}</div></div>
      <div><div style="font-size:10px;color:#475569;margin-bottom:3px">ANALYSIS TIME</div><div style="font-size:12px;color:#94a3b8">${d.analysisTimeMs ? (d.analysisTimeMs / 1000).toFixed(1) + 's' : '—'}</div></div>
      <div><div style="font-size:10px;color:#475569;margin-bottom:3px">SUBJECT</div><div style="font-size:12px;color:#e2e8f0">${d.email?.subject ?? '—'}</div></div>
      <div><div style="font-size:10px;color:#475569;margin-bottom:3px">FROM</div><div style="font-size:12px;font-family:monospace;color:#e2e8f0">${d.email?.from ?? '—'}</div></div>
      <div><div style="font-size:10px;color:#475569;margin-bottom:3px">SHA-256</div><div style="font-size:10px;font-family:monospace;color:#64748b;word-break:break-all">${d.email?.sha256 ?? '—'}</div></div>
    </div>
    <div style="display:flex;align-items:center;gap:16px;padding-top:16px;border-top:1px solid #1e293b">
      <div style="font-size:40px;font-weight:800;color:${riskColor};line-height:1">${d.riskScore}<span style="font-size:16px;font-weight:400;color:#475569">/100</span></div>
      <div>
        <div style="font-size:18px;font-weight:700;color:${riskColor};text-transform:uppercase">${d.verdict ?? '—'}</div>
        <div style="font-size:11px;color:#64748b">Confidence: ${d.confidence ?? '—'}%</div>
      </div>
    </div>
  </div>

  <!-- Executive Summary -->
  <h2>Executive Summary</h2>
  <div style="background:#0f172a;border:1px solid #1e293b;border-left:3px solid #3b82f6;border-radius:4px;padding:16px 20px;margin-bottom:28px">
    <p style="font-size:13px;color:#cbd5e1;line-height:1.8">${d.summary ?? 'No summary available.'}</p>
  </div>

  <!-- Score Breakdown -->
  ${scoreRows ? `
  <h2>Risk Score Breakdown</h2>
  <div style="border:1px solid #1e293b;border-radius:4px;overflow:hidden;margin-bottom:28px">
    <table>
      ${tblHeader(['Analysis Module', 'Weight', 'Risk Score'])}
      <tbody>${scoreRows}</tbody>
      <tfoot>
        <tr style="background:#0f172a">
          <td style="padding:8px 10px;font-weight:700;color:#f1f5f9;font-size:12px" colspan="2">FINAL WEIGHTED RISK SCORE</td>
          <td style="padding:8px 10px;font-weight:800;color:${riskColor};font-size:14px;text-align:center">${d.riskScore}/100</td>
        </tr>
      </tfoot>
    </table>
  </div>` : ''}

  <!-- Email Metadata -->
  <h2>Email Metadata</h2>
  <div style="border:1px solid #1e293b;border-radius:4px;overflow:hidden;margin-bottom:28px">
    <table>
      <tbody>
        ${[
          ['Subject', d.email?.subject],
          ['From', d.email?.from],
          ['To', d.email?.to],
          ['Reply-To', d.email?.replyTo],
          ['Date', d.email?.date],
          ['Message-ID', d.email?.messageId],
          ['Received From', d.headerAnalysis?.receivedFrom],
          ['Email SHA-256', d.email?.sha256],
        ].filter(([,v]) => v).map(([k, v], i) => `
          <tr style="background:${i % 2 === 0 ? '#0a0f1a' : '#060c16'}">
            <td style="padding:7px 10px;color:#64748b;font-size:11px;font-weight:600;width:140px;border-right:1px solid #1e293b;vertical-align:top">${k}</td>
            <td style="padding:7px 10px;color:#e2e8f0;font-family:monospace;font-size:11px;word-break:break-all">${v}</td>
          </tr>`).join('')}
      </tbody>
    </table>
  </div>

  <!-- Forensic Analysis Sections -->
  <h2>Forensic Analysis</h2>
  ${sectionsHtml}

  <!-- IoCs -->
  ${iocs.length > 0 ? `
  <h2>Indicators of Compromise (IoCs)</h2>
  <div style="border:1px solid #1e293b;border-radius:4px;overflow:hidden;margin-bottom:28px">
    <table>
      ${tblHeader(['Type', 'Indicator'])}
      <tbody>${iocRows}</tbody>
    </table>
  </div>` : ''}

  <!-- Chain of Custody -->
  ${entries.length > 0 ? `
  <h2>Chain of Custody (${entries.length} entries · ${d.chainOfCustody?.chainIntact ? 'Integrity Verified ✓' : 'Integrity Warning ⚠'})</h2>
  <div style="border:1px solid #1e293b;border-radius:4px;overflow:hidden;margin-bottom:28px">
    <table>
      ${tblHeader(['Timestamp', 'Event', 'Module', 'Details'])}
      <tbody>${custodyRows}</tbody>
    </table>
  </div>` : ''}

  <!-- Evidence Integrity -->
  <h2>Evidence Integrity</h2>
  <div style="border:1px solid #1e293b;border-radius:4px;overflow:hidden;margin-bottom:28px">
    <table>
      ${tblHeader(['Artifact', 'SHA-256 Hash'])}
      <tbody>
        <tr style="background:#0a0f1a">
          <td style="padding:7px 10px;font-size:11px;color:#94a3b8;border-right:1px solid #1e293b">Raw Email (.eml)</td>
          <td style="padding:7px 10px;font-family:monospace;font-size:10px;color:#64748b;word-break:break-all">${d.email?.sha256 ?? '—'}</td>
        </tr>
        ${(d.attachmentAnalysis?.attachments ?? []).map((a: any) => `
        <tr style="background:#060c16">
          <td style="padding:7px 10px;font-size:11px;color:#94a3b8;border-right:1px solid #1e293b">${a.name}</td>
          <td style="padding:7px 10px;font-family:monospace;font-size:10px;color:#64748b;word-break:break-all">${a.hash ?? '—'}</td>
        </tr>`).join('')}
      </tbody>
    </table>
  </div>

  <div style="margin-top:32px;padding-top:16px;border-top:1px solid #1e293b;font-size:10px;color:#334155;text-align:center">
    Phishing Email Forensic Analysis System · FYP 2026 ·
    This report was generated automatically. All evidence artifacts are preserved with SHA-256 cryptographic integrity.
  </div>
</div>
</body>
</html>`;
}

// ── IoC extractor ─────────────────────────────────────────────────────────────

function buildIocList(d: any): { type: string; value: string }[] {
  const iocs: { type: string; value: string }[] = [];
  (d.ipReputation?.ips ?? []).filter((r: any) => r.verdict !== 'clean').forEach((r: any) => {
    iocs.push({ type: 'IP Address', value: r.ip });
  });
  (d.urlAnalysis?.urls ?? []).filter((u: any) => u.status !== 'safe').forEach((u: any) => {
    iocs.push({ type: 'URL', value: u.url });
  });
  (d.attachmentAnalysis?.attachments ?? []).filter((a: any) => a.status !== 'safe').forEach((a: any) => {
    if (a.hash) iocs.push({ type: 'SHA-256 Hash', value: a.hash });
  });
  return iocs;
}

function downloadBlob(content: string, filename: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

// ── Main component ────────────────────────────────────────────────────────────

export function ForensicReport({ analysisData: d }: ForensicReportProps) {
  const [showCustody, setShowCustody] = useState(false);

  if (!d) return null;

  const reportId    = d.id ? d.id.slice(0, 16).toUpperCase() : '—';
  const generatedAt = d.createdAt ? new Date(d.createdAt).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' }) : '—';
  const entries: ChainEntry[] = d.chainOfCustody?.entries ?? [];
  const chainIntact: boolean  = d.chainOfCustody?.chainIntact ?? true;
  const riskColor = d.verdict === 'phishing' ? 'text-red-400' : d.verdict === 'suspicious' ? 'text-amber-400' : 'text-green-400';

  const senderSection  = analyseSenderIdentity(d);
  const authSection    = analyseAuthentication(d);
  const routingSection = analyseRouting(d);
  const contentSection = analyseContent(d);
  const urlSection     = analyseUrls(d);

  const iocs = buildIocList(d);

  // Score breakdown rows
  const scoreBreakdown = d.scoreBreakdown ?? {};
  const scoreLabels: Record<string, string> = {
    header:      'Header Analysis (SPF / DKIM / DMARC)',
    url:         'URL Reputation (VirusTotal · URLScan · PhishTank)',
    ipReputation:'Sender IP Reputation (AbuseIPDB)',
    attachments: 'Attachment Analysis',
    body:        'Body Content Analysis (AI)',
    indicators:  'Phishing Indicators (Heuristic)',
  };

  // For HTML export — pre-build evidence HTML per section
  const authEvidenceHtml = `<table style="width:100%;border-collapse:collapse;font-size:11px">
    <tr style="background:#0f172a"><th style="padding:6px 10px;text-align:left;color:#64748b;font-size:10px;border-bottom:1px solid #1e293b">Protocol</th><th style="padding:6px 10px;text-align:left;color:#64748b;font-size:10px;border-bottom:1px solid #1e293b">Result</th><th style="padding:6px 10px;text-align:left;color:#64748b;font-size:10px;border-bottom:1px solid #1e293b">Meaning</th></tr>
    <tr style="background:#0a0f1a"><td style="padding:6px 10px;color:#94a3b8;border-bottom:1px solid #1e293b">SPF</td><td style="padding:6px 10px;border-bottom:1px solid #1e293b;font-weight:600;color:${d.headerAnalysis?.spfStatus === 'pass' ? '#22c55e' : '#ef4444'}">${d.headerAnalysis?.spfStatus?.toUpperCase() ?? '—'}</td><td style="padding:6px 10px;color:#cbd5e1;border-bottom:1px solid #1e293b">Sender server authorisation check</td></tr>
    <tr style="background:#060c16"><td style="padding:6px 10px;color:#94a3b8;border-bottom:1px solid #1e293b">DKIM</td><td style="padding:6px 10px;border-bottom:1px solid #1e293b;font-weight:600;color:${d.headerAnalysis?.dkimStatus === 'pass' ? '#22c55e' : '#ef4444'}">${d.headerAnalysis?.dkimStatus?.toUpperCase() ?? '—'}</td><td style="padding:6px 10px;color:#cbd5e1;border-bottom:1px solid #1e293b">Message content integrity verification</td></tr>
    <tr style="background:#0a0f1a"><td style="padding:6px 10px;color:#94a3b8">DMARC</td><td style="padding:6px 10px;font-weight:600;color:${d.headerAnalysis?.dmarcStatus === 'pass' ? '#22c55e' : '#ef4444'}">${d.headerAnalysis?.dmarcStatus?.toUpperCase() ?? '—'}</td><td style="padding:6px 10px;color:#cbd5e1">Domain owner policy compliance</td></tr>
  </table>`;

  const exportSections = [
    {
      number: 1, title: 'Sender Identity Analysis', section: senderSection,
      analysisText: senderSection.analysis,
      evidenceHtml: `<table style="width:100%;border-collapse:collapse;font-size:11px"><tbody>
        ${[['From', d.email?.from], ['Return-Path', d.headerAnalysis?.returnPath], ['Reply-To', d.email?.replyTo], ['Message-ID', d.email?.messageId]]
          .filter(([,v]) => v).map(([k,v], i) => `<tr style="background:${i%2===0?'#0a0f1a':'#060c16'}"><td style="padding:6px 10px;color:#64748b;border-bottom:1px solid #1e293b;border-right:1px solid #1e293b;width:120px">${k}</td><td style="padding:6px 10px;font-family:monospace;color:#e2e8f0;border-bottom:1px solid #1e293b;word-break:break-all">${v}</td></tr>`).join('')}
        ${(d.headerAnalysis?.spoofingIndicators ?? []).map((s: string, i: number) => `<tr style="background:#060c16"><td style="padding:6px 10px;color:#ef4444;border-bottom:1px solid #1e293b;border-right:1px solid #1e293b">${i===0?'Spoofing Signals':''}</td><td style="padding:6px 10px;color:#fca5a5;border-bottom:1px solid #1e293b">${s}</td></tr>`).join('')}
      </tbody></table>`,
    },
    {
      number: 2, title: 'Email Authentication', section: authSection,
      analysisText: authSection.analysis,
      evidenceHtml: authEvidenceHtml,
    },
    {
      number: 3, title: 'Routing & Origin', section: routingSection,
      analysisText: routingSection.analysis,
      evidenceHtml: `<table style="width:100%;border-collapse:collapse;font-size:11px"><tbody>
        <tr style="background:#0a0f1a"><td style="padding:6px 10px;color:#64748b;border-bottom:1px solid #1e293b;border-right:1px solid #1e293b;width:120px">Received From</td><td style="padding:6px 10px;font-family:monospace;color:#e2e8f0;border-bottom:1px solid #1e293b">${d.headerAnalysis?.receivedFrom ?? '—'}</td></tr>
        ${(d.ipReputation?.ips ?? []).map((ip: any, i: number) => `<tr style="background:${i%2===0?'#060c16':'#0a0f1a'}"><td style="padding:6px 10px;color:#64748b;border-bottom:1px solid #1e293b;border-right:1px solid #1e293b">${ip.ip}</td><td style="padding:6px 10px;color:${ip.verdict==='malicious'?'#ef4444':ip.verdict==='suspicious'?'#f59e0b':'#22c55e'};font-weight:600;border-bottom:1px solid #1e293b">${ip.verdict?.toUpperCase()} · ${ip.abuseScore}% abuse score · ${ip.isp ?? ''} (${ip.countryCode ?? ''})</td></tr>`).join('')}
      </tbody></table>`,
    },
    {
      number: 4, title: 'Content & Social Engineering', section: contentSection,
      analysisText: contentSection.analysis,
      evidenceHtml: `<table style="width:100%;border-collapse:collapse;font-size:11px"><thead><tr style="background:#0f172a"><th style="padding:6px 10px;text-align:left;color:#64748b;font-size:10px;border-bottom:1px solid #1e293b">Tactic</th><th style="padding:6px 10px;text-align:left;color:#64748b;font-size:10px;border-bottom:1px solid #1e293b">Severity</th><th style="padding:6px 10px;text-align:left;color:#64748b;font-size:10px;border-bottom:1px solid #1e293b">Evidence</th></tr></thead><tbody>
        ${(d.bodyAnalysis?.tactics ?? []).length === 0 ? '<tr><td colspan="3" style="padding:8px 10px;color:#64748b;font-style:italic">No tactics detected</td></tr>' :
          (d.bodyAnalysis?.tactics ?? []).map((t: any, i: number) => `<tr style="background:${i%2===0?'#0a0f1a':'#060c16'}"><td style="padding:6px 10px;color:#e2e8f0;border-bottom:1px solid #1e293b">${t.type}</td><td style="padding:6px 10px;color:${t.severity==='high'?'#ef4444':t.severity==='medium'?'#f59e0b':'#eab308'};font-weight:600;border-bottom:1px solid #1e293b">${t.severity?.toUpperCase()}</td><td style="padding:6px 10px;color:#94a3b8;border-bottom:1px solid #1e293b;font-style:italic">${t.evidence ?? t.description ?? '—'}</td></tr>`).join('')}
      </tbody></table>`,
    },
    {
      number: 5, title: 'URL & Link Analysis', section: urlSection,
      analysisText: urlSection.analysis,
      evidenceHtml: `<table style="width:100%;border-collapse:collapse;font-size:11px"><thead><tr style="background:#0f172a"><th style="padding:6px 10px;text-align:left;color:#64748b;font-size:10px;border-bottom:1px solid #1e293b">URL</th><th style="padding:6px 10px;text-align:left;color:#64748b;font-size:10px;border-bottom:1px solid #1e293b">Verdict</th><th style="padding:6px 10px;text-align:left;color:#64748b;font-size:10px;border-bottom:1px solid #1e293b">Details</th></tr></thead><tbody>
        ${(d.urlAnalysis?.urls ?? []).length === 0 ? '<tr><td colspan="3" style="padding:8px 10px;color:#64748b;font-style:italic">No URLs found</td></tr>' :
          (d.urlAnalysis?.urls ?? []).map((u: any, i: number) => `<tr style="background:${i%2===0?'#0a0f1a':'#060c16'}"><td style="padding:6px 10px;font-family:monospace;color:#cbd5e1;border-bottom:1px solid #1e293b;word-break:break-all;max-width:200px">${u.url}</td><td style="padding:6px 10px;color:${u.status==='malicious'?'#ef4444':u.status==='suspicious'?'#f59e0b':'#22c55e'};font-weight:600;border-bottom:1px solid #1e293b;white-space:nowrap">${u.status?.toUpperCase()}</td><td style="padding:6px 10px;color:#94a3b8;border-bottom:1px solid #1e293b">Score: ${u.reputation ?? '—'}/100${u.category ? ` · ${u.category}` : ''}${u.vtDetections > 0 ? ` · VT: ${u.vtDetections}/${u.vtTotal}` : ''}</td></tr>`).join('')}
      </tbody></table>`,
    },
  ];

  const handleDownloadHtml = () => downloadBlob(buildHtmlReport(d, exportSections), `forensic-report-${reportId}.html`, 'text/html');
  const handleDownloadJson = () => downloadBlob(JSON.stringify(d, null, 2), `forensic-report-${reportId}.json`, 'application/json');
  const handleDownloadPdf = () => downloadForensicPdf(d);

  return (
    <Card className="bg-slate-900 border-slate-800 p-6">

      {/* Card header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <h3 className="text-base font-bold text-white uppercase tracking-wide mb-1">
            Forensic Investigation Report
          </h3>
          <p className="text-xs text-slate-500 font-mono">ID: {reportId} · {generatedAt}</p>
        </div>
        <Badge variant="outline" className={chainIntact
          ? 'bg-green-600/20 text-green-400 border-green-600/50'
          : 'bg-amber-600/20 text-amber-400 border-amber-600/50'}>
          <Shield className="w-3 h-3 mr-1" />
          {chainIntact ? 'Chain Intact' : 'Integrity Warning'}
        </Badge>
      </div>

      <div className="space-y-5">

        {/* Executive summary */}
        {d.summary && (
          <div className="border-l-2 border-blue-500 pl-4 py-1">
            <p className="text-[10px] text-slate-500 uppercase tracking-widest font-semibold mb-1">Executive Summary</p>
            <p className="text-slate-300 text-sm leading-relaxed">{d.summary}</p>
          </div>
        )}

        {/* Score breakdown table */}
        {Object.keys(scoreBreakdown).length > 0 && (
          <div>
            <p className="text-[10px] text-slate-500 uppercase tracking-widest font-semibold mb-2">Risk Score Breakdown</p>
            <DocTable
              headers={['Analysis Module', 'Weight', 'Risk Score']}
              rows={Object.entries(scoreBreakdown).map(([key, val]: [string, any]) => [
                scoreLabels[key] ?? key,
                `${Math.round(val.weight * 100)}%`,
                <span className={val.risk > 60 ? 'text-red-400 font-semibold' : val.risk > 30 ? 'text-amber-400 font-semibold' : 'text-green-400 font-semibold'}>
                  {val.risk}/100
                </span>,
              ])}
            />
            <div className="flex justify-between items-center bg-slate-800 border border-slate-700 border-t-0 px-3 py-2">
              <span className="text-xs font-bold text-slate-200 uppercase tracking-wide">Final Weighted Score</span>
              <span className={`text-lg font-bold ${riskColor}`}>{d.riskScore}/100</span>
            </div>
          </div>
        )}

        {/* Email metadata */}
        <div>
          <p className="text-[10px] text-slate-500 uppercase tracking-widest font-semibold mb-2">Email Metadata</p>
          <KVTable pairs={[
            ['Subject',      d.email?.subject],
            ['From',         d.email?.from],
            ['To',           d.email?.to],
            ['Reply-To',     d.email?.replyTo],
            ['Date',         d.email?.date],
            ['Message-ID',   d.email?.messageId],
            ['Received From',d.headerAnalysis?.receivedFrom],
            ['SHA-256',      d.email?.sha256],
          ]} />
        </div>

        {/* ── Section 1: Sender Identity ── */}
        <Section number={1} title="Sender Identity Analysis" section={senderSection}>
          <KVTable pairs={[
            ['From',           d.email?.from],
            ['Return-Path',    d.headerAnalysis?.returnPath],
            ['Reply-To',       d.email?.replyTo],
            ['Message-ID',     d.email?.messageId],
          ]} />
          {(d.headerAnalysis?.spoofingIndicators ?? []).length > 0 && (
            <div className="mt-2">
              {(d.headerAnalysis.spoofingIndicators as string[]).map((s, i) => (
                <div key={i} className="text-xs text-red-400 py-1 border-b border-slate-800 last:border-0">⚠ {s}</div>
              ))}
            </div>
          )}
        </Section>

        {/* ── Section 2: Email Authentication ── */}
        <Section number={2} title="Email Authentication" section={authSection}>
          <DocTable
            headers={['Protocol', 'Result', 'Purpose']}
            rows={[
              ['SPF',   <span className={verdictCell(d.headerAnalysis?.spfStatus)}>{d.headerAnalysis?.spfStatus?.toUpperCase() ?? '—'}</span>, 'Sender server authorisation'],
              ['DKIM',  <span className={verdictCell(d.headerAnalysis?.dkimStatus)}>{d.headerAnalysis?.dkimStatus?.toUpperCase() ?? '—'}</span>, 'Message content integrity'],
              ['DMARC', <span className={verdictCell(d.headerAnalysis?.dmarcStatus)}>{d.headerAnalysis?.dmarcStatus?.toUpperCase() ?? '—'}</span>, 'Domain owner policy compliance'],
            ]}
          />
        </Section>

        {/* ── Section 3: Routing & Origin ── */}
        <Section number={3} title="Routing & Origin" section={routingSection}>
          {d.headerAnalysis?.receivedFrom && (
            <KVTable pairs={[['Received From', d.headerAnalysis.receivedFrom]]} />
          )}
          {(d.ipReputation?.ips ?? []).length > 0 && (
            <DocTable
              headers={['IP Address', 'Verdict', 'Abuse Score', 'ISP / Country']}
              rows={(d.ipReputation.ips as any[]).map(ip => [
                <span className="font-mono">{ip.ip}</span>,
                <span className={verdictCell(ip.verdict)}>{ip.verdict?.toUpperCase()}</span>,
                <span className={ip.abuseScore >= 75 ? 'text-red-400 font-semibold' : ip.abuseScore >= 25 ? 'text-amber-400' : 'text-green-400'}>
                  {ip.abuseScore}%
                </span>,
                `${ip.isp ?? '—'} (${ip.countryCode ?? '—'})${ip.isTor ? ' · Tor exit node' : ''}`,
              ])}
            />
          )}
          {d.ipReputation?.totalIpsChecked === 0 && (
            <p className="text-xs text-slate-500 italic">No sender IPs could be extracted from routing headers.</p>
          )}
        </Section>

        {/* ── Section 4: Content & Social Engineering ── */}
        <Section number={4} title="Content & Social Engineering" section={contentSection}>
          <div className="mb-2">
            <KVTable pairs={[
              ['Body Risk Score',   `${d.bodyAnalysis?.bodyRiskScore ?? 0}/100`],
              ['Threat Level',      d.bodyAnalysis?.overallThreatLevel],
              ['Analysis Source',   d.bodyAnalysis?.source === 'groq' ? 'AI-assisted (Groq / Llama 3)' : 'Rule-based fallback'],
            ]} />
          </div>
          {(d.bodyAnalysis?.tactics ?? []).length > 0 && (
            <DocTable
              headers={['Tactic', 'Severity', 'Evidence']}
              rows={(d.bodyAnalysis.tactics as any[]).map(t => [
                t.type,
                <span className={verdictCell(t.severity)}>{t.severity?.toUpperCase()}</span>,
                <span className="italic text-slate-400">{t.evidence ?? t.description ?? '—'}</span>,
              ])}
            />
          )}
          {(d.bodyAnalysis?.tactics ?? []).length === 0 && (
            <p className="text-xs text-slate-500 italic">No social engineering tactics detected.</p>
          )}
        </Section>

        {/* ── Section 5: URL Analysis ── */}
        <Section number={5} title="URL & Link Analysis" section={urlSection}>
          {(d.urlAnalysis?.urls ?? []).length > 0 ? (
            <DocTable
              headers={['URL', 'Verdict', 'Score', 'Details']}
              rows={(d.urlAnalysis.urls as any[]).map(u => [
                <span className="font-mono text-[10px] break-all">{u.url}</span>,
                <span className={verdictCell(u.status)}>{u.status?.toUpperCase()}</span>,
                `${u.reputation ?? '—'}/100`,
                `${u.category ?? '—'}${u.vtDetections > 0 ? ` · VT: ${u.vtDetections}/${u.vtTotal}` : ''}`,
              ])}
            />
          ) : (
            <p className="text-xs text-slate-500 italic">No URLs found in this email.</p>
          )}
        </Section>

        {/* ── Attachments (if any) ── */}
        {(d.attachmentAnalysis?.attachments ?? []).length > 0 && (
          <div className="border border-slate-700 rounded-sm overflow-hidden">
            <div className="bg-slate-800 px-4 py-3 flex items-center justify-between">
              <span className="text-white text-sm font-semibold tracking-wide uppercase">6. Attachment Analysis</span>
              <span className={`text-[10px] px-2 py-0.5 rounded border font-semibold ${
                d.attachmentAnalysis.maliciousAttachments > 0 ? 'bg-red-600/20 text-red-400 border-red-600/40' : 'bg-green-600/20 text-green-400 border-green-600/40'
              }`}>
                {d.attachmentAnalysis.maliciousAttachments > 0 ? `${d.attachmentAnalysis.maliciousAttachments} MALICIOUS` : 'CLEAN'}
              </span>
            </div>
            <div className="px-4 pb-4 pt-3 bg-slate-950/50">
              <DocTable
                headers={['Filename', 'Type', 'Size', 'SHA-256', 'Verdict']}
                rows={(d.attachmentAnalysis.attachments as any[]).map(a => [
                  <span className="font-mono text-[10px]">{a.name}</span>,
                  a.type,
                  a.size,
                  <span className="font-mono text-[10px] text-slate-500">{a.hash?.slice(0, 16) ?? '—'}…</span>,
                  <span className={verdictCell(a.status)}>{a.status?.toUpperCase()}</span>,
                ])}
              />
              {(d.attachmentAnalysis.attachments as any[]).some(a => a.vtDetections > 0) && (
                <div className="mt-2 space-y-1">
                  {(d.attachmentAnalysis.attachments as any[]).filter(a => a.vtDetections > 0).map((a: any, i: number) => (
                    <p key={i} className="text-xs text-red-400">⚠ {a.name}: {a.vtDetections}/{a.vtTotal} VirusTotal engines flagged</p>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* IoC table */}
        {iocs.length > 0 && (
          <div>
            <p className="text-[10px] text-slate-500 uppercase tracking-widest font-semibold mb-2">Indicators of Compromise (IoCs)</p>
            <DocTable
              headers={['Type', 'Indicator']}
              rows={iocs.map(({ type, value }) => [
                <span className="text-slate-400">{type}</span>,
                <span className="font-mono text-[10px] break-all text-slate-200">{value}</span>,
              ])}
            />
          </div>
        )}

        {/* Chain of custody */}
        {entries.length > 0 && (
          <div>
            <button
              className="w-full flex items-center justify-between mb-2"
              onClick={() => setShowCustody(v => !v)}
            >
              <p className="text-[10px] text-slate-500 uppercase tracking-widest font-semibold">
                Chain of Custody ({entries.length} entries)
              </p>
              <div className="flex items-center gap-1 text-slate-500">
                <Clock className="w-3 h-3" />
                {showCustody ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
              </div>
            </button>
            {showCustody && (
              <DocTable
                headers={['Timestamp', 'Event', 'Module', 'Details']}
                rows={entries.map(e => [
                  <span className="font-mono text-[10px] text-slate-500">{new Date(e.timestamp).toLocaleString('en-GB')}</span>,
                  <span className="font-semibold">{e.action}</span>,
                  <span className="text-slate-400">{e.module}</span>,
                  e.description,
                ])}
              />
            )}
          </div>
        )}

        {/* Evidence integrity */}
        <div>
          <p className="text-[10px] text-slate-500 uppercase tracking-widest font-semibold mb-2">Evidence Integrity</p>
          <KVTable pairs={[
            ['Email SHA-256', d.email?.sha256],
            ...(d.attachmentAnalysis?.attachments ?? []).map((a: any) => [a.name, a.hash] as [string, string]),
          ]} />
        </div>

        {/* Download buttons */}
        <div className="grid grid-cols-3 gap-2 pt-2 border-t border-slate-800">
          <Button variant="outline" size="sm" onClick={handleDownloadPdf}
            className="bg-slate-800 border-slate-700 text-white hover:bg-slate-700 text-xs">
            <Download className="w-3.5 h-3.5 mr-1.5" />PDF
          </Button>
          <Button variant="outline" size="sm" onClick={handleDownloadHtml}
            className="bg-slate-800 border-slate-700 text-white hover:bg-slate-700 text-xs">
            <FileCode className="w-3.5 h-3.5 mr-1.5" />HTML
          </Button>
          <Button variant="outline" size="sm" onClick={handleDownloadJson}
            className="bg-slate-800 border-slate-700 text-white hover:bg-slate-700 text-xs">
            <FileJson className="w-3.5 h-3.5 mr-1.5" />JSON
          </Button>
        </div>
      </div>
    </Card>
  );
}
