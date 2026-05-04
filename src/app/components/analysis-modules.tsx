import { Mail, Link, Paperclip, Shield, ChevronDown, ChevronUp, ExternalLink, AlertTriangle, CheckCircle2, XCircle } from 'lucide-react';
import { Card } from './ui/card';
import { Badge } from './ui/badge';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from './ui/collapsible';
import { useState } from 'react';

interface HeaderAnalysis {
  spfStatus: string;
  dkimStatus: string;
  dmarcStatus: string;
  senderReputation: number;
  spoofingIndicators: string[];
  returnPath: string;
  receivedFrom: string;
}

interface URLAnalysis {
  totalUrls: number;
  maliciousUrls: number;
  suspiciousUrls: number;
  urls: Array<{
    url: string;
    status: string;
    reputation: number;
    category: string;
  }>;
}

interface AttachmentAnalysis {
  totalAttachments: number;
  riskyAttachments: number;
  attachments: Array<{
    name: string;
    type: string;
    size: string;
    hash: string;
    status: string;
    sandboxResult?: string;
  }>;
}

interface AnalysisModulesProps {
  headerAnalysis: HeaderAnalysis;
  urlAnalysis: URLAnalysis;
  attachmentAnalysis: AttachmentAnalysis;
}

export function AnalysisModules({ headerAnalysis, urlAnalysis, attachmentAnalysis }: AnalysisModulesProps) {
  // Safe defaults to prevent crashes if data arrives partially
  const hdr = headerAnalysis ?? { spfStatus: 'none', dkimStatus: 'none', dmarcStatus: 'none', senderReputation: 0, spoofingIndicators: [], returnPath: '', receivedFrom: '' };
  const urlA = urlAnalysis ?? { totalUrls: 0, maliciousUrls: 0, suspiciousUrls: 0, urls: [] };
  const attA = attachmentAnalysis ?? { totalAttachments: 0, riskyAttachments: 0, attachments: [] };

  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    headers: true,
    urls: true,
    attachments: true
  });

  const toggleSection = (section: string) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };

  const StatusBadge = ({ status }: { status: string }) => {
    const config: Record<string, { label: string; color: string; icon: any }> = {
      pass: { label: 'Pass', color: 'bg-green-600/20 text-green-400 border-green-600/50', icon: CheckCircle2 },
      fail: { label: 'Fail', color: 'bg-red-600/20 text-red-400 border-red-600/50', icon: XCircle },
      softfail: { label: 'Soft Fail', color: 'bg-orange-600/20 text-orange-400 border-orange-600/50', icon: AlertTriangle },
      neutral: { label: 'Neutral', color: 'bg-slate-600/20 text-slate-400 border-slate-600/50', icon: AlertTriangle },
      none: { label: 'None', color: 'bg-slate-600/20 text-slate-400 border-slate-600/50', icon: AlertTriangle },
      unknown: { label: 'Unknown', color: 'bg-slate-600/20 text-slate-400 border-slate-600/50', icon: AlertTriangle },
      temperror: { label: 'Temp Error', color: 'bg-orange-600/20 text-orange-400 border-orange-600/50', icon: AlertTriangle },
      permerror: { label: 'Perm Error', color: 'bg-red-600/20 text-red-400 border-red-600/50', icon: XCircle },
      malicious: { label: 'Malicious', color: 'bg-red-600/20 text-red-400 border-red-600/50', icon: XCircle },
      suspicious: { label: 'Suspicious', color: 'bg-orange-600/20 text-orange-400 border-orange-600/50', icon: AlertTriangle },
      safe: { label: 'Safe', color: 'bg-green-600/20 text-green-400 border-green-600/50', icon: CheckCircle2 },
    };

    // Normalize: treat any non-pass result that isn't explicitly mapped as 'unknown'
    const normalizedStatus = (status || 'unknown').toLowerCase();
    const cfg = config[normalizedStatus] ?? config['unknown'];
    const { label, color, icon: Icon } = cfg;

    return (
      <Badge variant="outline" className={`${color} border text-xs`}>
        <Icon className="w-3 h-3 mr-1" />
        {label}
      </Badge>
    );
  };

  return (
    <div className="space-y-4">
      {/* Header Analysis */}
      <Card className="bg-slate-900 border-slate-800">
        <Collapsible open={expandedSections.headers} onOpenChange={() => toggleSection('headers')}>
          <CollapsibleTrigger className="w-full p-6 flex items-center justify-between hover:bg-slate-800/50 transition-colors">
            <div className="flex items-center gap-3">
              <Mail className="w-6 h-6 text-blue-400" />
              <div className="text-left">
                <h3 className="text-lg text-white">Email Header Analysis</h3>
                <p className="text-sm text-slate-300">Sender legitimacy and authentication checks</p>
              </div>
            </div>
            {expandedSections.headers ? (
              <ChevronUp className="w-5 h-5 text-slate-400" />
            ) : (
              <ChevronDown className="w-5 h-5 text-slate-400" />
            )}
          </CollapsibleTrigger>
          <CollapsibleContent>
            <div className="px-6 pb-6 space-y-4">
              <div className="grid grid-cols-3 gap-4">
                <div className="p-4 bg-slate-800/50 rounded-lg">
                  <div className="text-sm text-slate-400 mb-2">SPF Record</div>
                  <StatusBadge status={hdr.spfStatus} />
                </div>
                <div className="p-4 bg-slate-800/50 rounded-lg">
                  <div className="text-sm text-slate-400 mb-2">DKIM Signature</div>
                  <StatusBadge status={hdr.dkimStatus} />
                </div>
                <div className="p-4 bg-slate-800/50 rounded-lg">
                  <div className="text-sm text-slate-400 mb-2">DMARC Policy</div>
                  <StatusBadge status={hdr.dmarcStatus} />
                </div>
              </div>

              <div className="p-4 bg-slate-800/50 rounded-lg">
                <div className="text-sm text-slate-400 mb-2">Sender Reputation Score</div>
                <div className="flex items-center gap-3">
                  <div className="flex-1 bg-slate-700 rounded-full h-2">
                    <div
                      className={`h-2 rounded-full ${
                        hdr.senderReputation >= 70 ? 'bg-green-500' :
                        hdr.senderReputation >= 40 ? 'bg-orange-500' : 'bg-red-500'
                      }`}
                      style={{ width: `${hdr.senderReputation}%` }}
                    />
                  </div>
                  <span className="text-white font-medium">{hdr.senderReputation}/100</span>
                </div>
              </div>

              {(hdr.spoofingIndicators ?? []).length > 0 && (
                <div className="p-4 bg-red-950/30 border border-red-900/50 rounded-lg">
                  <div className="flex items-center gap-2 mb-3">
                    <AlertTriangle className="w-5 h-5 text-red-400" />
                    <span className="text-red-400 font-medium">Spoofing Indicators Detected</span>
                  </div>
                  <ul className="space-y-1 text-sm text-slate-300">
                    {hdr.spoofingIndicators.map((indicator, index) => (
                      <li key={index} className="flex items-start gap-2">
                        <span className="text-red-400">•</span>
                        {indicator}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-slate-400">Return-Path:</span>
                  <code className="ml-2 text-slate-300 bg-slate-800 px-2 py-1 rounded">
                    {hdr.returnPath || '—'}
                  </code>
                </div>
                <div>
                  <span className="text-slate-400">Received From:</span>
                  <code className="ml-2 text-slate-300 bg-slate-800 px-2 py-1 rounded">
                    {hdr.receivedFrom || '—'}
                  </code>
                </div>
              </div>
            </div>
          </CollapsibleContent>
        </Collapsible>
      </Card>

      {/* URL Analysis */}
      <Card className="bg-slate-900 border-slate-800">
        <Collapsible open={expandedSections.urls} onOpenChange={() => toggleSection('urls')}>
          <CollapsibleTrigger className="w-full p-6 flex items-center justify-between hover:bg-slate-800/50 transition-colors">
            <div className="flex items-center gap-3">
              <Link className="w-6 h-6 text-purple-400" />
              <div className="text-left">
                <h3 className="text-lg text-white">URL Analysis & Scanning</h3>
                <p className="text-sm text-slate-400">
                  {urlA.totalUrls} URLs found • {urlA.maliciousUrls} malicious • {urlA.suspiciousUrls} suspicious
                </p>
              </div>
            </div>
            {expandedSections.urls ? (
              <ChevronUp className="w-5 h-5 text-slate-400" />
            ) : (
              <ChevronDown className="w-5 h-5 text-slate-400" />
            )}
          </CollapsibleTrigger>
          <CollapsibleContent>
            <div className="px-6 pb-6 space-y-3">
              {(urlA.urls ?? []).length === 0 ? (
                <p className="text-slate-400 text-sm py-4 text-center">No URLs detected in this email.</p>
              ) : (
                (urlA.urls ?? []).map((url, index) => (
                  <div key={index} className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex items-center gap-2 flex-1 min-w-0">
                        <ExternalLink className="w-4 h-4 text-slate-400 flex-shrink-0" />
                        <code className="text-sm text-blue-400 truncate">{url.url}</code>
                      </div>
                      <StatusBadge status={url.status ?? 'unknown'} />
                    </div>
                    <div className="flex items-center gap-4 text-xs text-slate-400 ml-6">
                      <span>Category: {url.category || 'Unknown'}</span>
                      <span>Reputation: {url.reputation ?? '—'}/100</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </CollapsibleContent>
        </Collapsible>
      </Card>

      {/* Attachment Analysis */}
      <Card className="bg-slate-900 border-slate-800">
        <Collapsible open={expandedSections.attachments} onOpenChange={() => toggleSection('attachments')}>
          <CollapsibleTrigger className="w-full p-6 flex items-center justify-between hover:bg-slate-800/50 transition-colors">
            <div className="flex items-center gap-3">
              <Paperclip className="w-6 h-6 text-green-400" />
              <div className="text-left">
                <h3 className="text-lg text-white">Attachment Analysis</h3>
                <p className="text-sm text-slate-400">
                  {attA.totalAttachments} attachments • {attA.riskyAttachments} flagged as risky
                </p>
              </div>
            </div>
            {expandedSections.attachments ? (
              <ChevronUp className="w-5 h-5 text-slate-400" />
            ) : (
              <ChevronDown className="w-5 h-5 text-slate-400" />
            )}
          </CollapsibleTrigger>
          <CollapsibleContent>
            <div className="px-6 pb-6 space-y-3">
              {(attA.attachments ?? []).length === 0 ? (
                <p className="text-slate-400 text-sm py-4 text-center">No attachments found in this email.</p>
              ) : null}
              {(attA.attachments ?? []).map((attachment, index) => (
                <div key={index} className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-2">
                      <Paperclip className="w-4 h-4 text-slate-400" />
                      <span className="text-white font-medium">{attachment.name}</span>
                    </div>
                    <StatusBadge status={attachment.status} />
                  </div>
                  <div className="grid grid-cols-2 gap-3 text-sm ml-6">
                    <div>
                      <span className="text-slate-400">Type:</span>
                      <span className="ml-2 text-slate-300">{attachment.type}</span>
                    </div>
                    <div>
                      <span className="text-slate-400">Size:</span>
                      <span className="ml-2 text-slate-300">{attachment.size}</span>
                    </div>
                    <div className="col-span-2">
                      <span className="text-slate-400">Hash:</span>
                      <code className="ml-2 text-xs text-slate-300 bg-slate-800 px-2 py-1 rounded">
                        {attachment.hash}
                      </code>
                    </div>
                    {attachment.sandboxResult && (
                      <div className="col-span-2 mt-2 p-3 bg-slate-900 rounded border border-slate-700">
                        <div className="text-slate-400 text-xs mb-1">Sandbox Analysis:</div>
                        <div className="text-slate-300 text-sm">{attachment.sandboxResult}</div>
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </CollapsibleContent>
        </Collapsible>
      </Card>
    </div>
  );
}