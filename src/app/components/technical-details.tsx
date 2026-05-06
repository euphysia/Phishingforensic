import { Code, Copy, Terminal, Hash } from 'lucide-react';
import { Card } from './ui/card';
import { Button } from './ui/button';

interface TechnicalDetailsProps {
  email?: {
    subject?: string;
    from?: string;
    to?: string;
    date?: string;
    sha256?: string;
    messageId?: string;
  };
  headerAnalysis?: {
    spfStatus?: string;
    dkimStatus?: string;
    dmarcStatus?: string;
    senderReputation?: string;
    returnPath?: string;
    receivedFrom?: string;
    spoofingIndicators?: string[];
  };
  urlAnalysis?: {
    totalUrls?: number;
    maliciousUrls?: number;
    suspiciousUrls?: number;
    urls?: Array<{
      url: string;
      status: string;
      reputation?: number;
      category?: string;
      vtDetections?: number;
      vtTotal?: number;
    }>;
  };
  indicators?: Array<{
    type: string;
    description: string;
    severity: string;
  }>;
}

export function TechnicalDetails({
  email,
  headerAnalysis,
  urlAnalysis,
  indicators = [],
}: TechnicalDetailsProps) {
  // Build a readable raw-headers block from the actual parsed fields
  const rawHeaders = [
    headerAnalysis?.receivedFrom ? `Received: ${headerAnalysis.receivedFrom}` : null,
    headerAnalysis?.returnPath   ? `Return-Path: <${headerAnalysis.returnPath}>` : null,
    email?.date                  ? `Date: ${email.date}` : null,
    email?.from                  ? `From: ${email.from}` : null,
    email?.to                    ? `To: ${email.to}` : null,
    email?.messageId             ? `Message-ID: ${email.messageId}` : null,
    email?.subject               ? `Subject: ${email.subject}` : null,
    headerAnalysis?.spfStatus    ? `SPF: ${headerAnalysis.spfStatus}` : null,
    headerAnalysis?.dkimStatus   ? `DKIM: ${headerAnalysis.dkimStatus}` : null,
    headerAnalysis?.dmarcStatus  ? `DMARC: ${headerAnalysis.dmarcStatus}` : null,
  ]
    .filter(Boolean)
    .join('\n') || '(No header data available)';

  // Build IoCs from real data
  const iocs: Array<{ type: string; value: string; category: string }> = [];

  if (headerAnalysis?.returnPath) {
    iocs.push({ type: 'Return-Path', value: headerAnalysis.returnPath, category: 'Sender' });
  }
  if (email?.from) {
    iocs.push({ type: 'Sender', value: email.from, category: 'Sender' });
  }
  if (email?.sha256) {
    iocs.push({ type: 'Email Hash', value: email.sha256, category: 'Hash' });
  }

  // Add URL-based IoCs
  for (const u of urlAnalysis?.urls ?? []) {
    const category =
      u.status === 'malicious'  ? 'Malicious'  :
      u.status === 'suspicious' ? 'Suspicious' : 'Clean';
    iocs.push({ type: 'URL', value: u.url, category });
  }

  // Add spoofing indicator IoCs
  for (const si of headerAnalysis?.spoofingIndicators ?? []) {
    iocs.push({ type: 'Spoofing', value: si, category: 'Spoofed' });
  }

  const extractedUrls = (urlAnalysis?.urls ?? []).map(u => u.url);

  const categoryColor = (cat: string) => {
    switch (cat) {
      case 'Malicious': return 'bg-red-600/20 text-red-400';
      case 'Suspicious': return 'bg-orange-600/20 text-orange-400';
      case 'Spoofed': return 'bg-purple-600/20 text-purple-400';
      case 'Hash': return 'bg-blue-600/20 text-blue-400';
      default: return 'bg-slate-600/20 text-slate-400';
    }
  };

  return (
    <div className="space-y-4">
      {/* Raw Headers */}
      <Card className="bg-slate-900 border-slate-800 p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <Terminal className="w-6 h-6 text-green-400" />
            <h3 className="text-lg text-white">Raw Email Headers</h3>
          </div>
          <Button
            variant="outline"
            size="sm"
            className="bg-slate-800 border-slate-700 text-white hover:bg-slate-700"
            onClick={() => navigator.clipboard.writeText(rawHeaders)}
          >
            <Copy className="w-4 h-4 mr-2" />
            Copy Headers
          </Button>
        </div>
        <div className="bg-slate-950 rounded-lg p-4 border border-slate-800">
          <pre className="text-xs text-green-400 font-mono overflow-x-auto whitespace-pre-wrap">
            {rawHeaders}
          </pre>
        </div>
      </Card>

      {/* Indicators of Compromise */}
      <Card className="bg-slate-900 border-slate-800 p-6">
        <div className="flex items-center gap-3 mb-4">
          <Hash className="w-6 h-6 text-orange-400" />
          <h3 className="text-lg text-white">Indicators of Compromise (IoCs)</h3>
        </div>
        {iocs.length === 0 ? (
          <p className="text-slate-400 text-sm">No IoCs extracted.</p>
        ) : (
          <div className="space-y-2">
            {iocs.map((ioc, index) => (
              <div
                key={index}
                className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg border border-slate-700"
              >
                <div className="flex items-center gap-3 flex-1 min-w-0">
                  <span className="text-sm text-slate-400 w-28 flex-shrink-0">
                    {ioc.type}:
                  </span>
                  <code className="text-sm text-white font-mono truncate">
                    {ioc.value}
                  </code>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`text-xs px-2 py-1 rounded ${categoryColor(ioc.category)}`}>
                    {ioc.category}
                  </span>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-8 w-8 p-0"
                    onClick={() => navigator.clipboard.writeText(ioc.value)}
                  >
                    <Copy className="w-3 h-3" />
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Extracted URLs */}
      <Card className="bg-slate-900 border-slate-800 p-6">
        <div className="flex items-center gap-3 mb-4">
          <Code className="w-6 h-6 text-blue-400" />
          <h3 className="text-lg text-white">Extracted URLs</h3>
        </div>
        {extractedUrls.length === 0 ? (
          <p className="text-slate-400 text-sm">No URLs found in this email.</p>
        ) : (
          <div className="space-y-2">
            {extractedUrls.map((url, index) => (
              <div
                key={index}
                className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg border border-slate-700"
              >
                <code className="text-sm text-blue-400 font-mono flex-1 truncate">
                  {url}
                </code>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-8 w-8 p-0 ml-2"
                  onClick={() => navigator.clipboard.writeText(url)}
                >
                  <Copy className="w-3 h-3" />
                </Button>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Cryptographic Hashes */}
      <Card className="bg-slate-900 border-slate-800 p-6">
        <div className="flex items-center gap-3 mb-4">
          <Hash className="w-6 h-6 text-purple-400" />
          <h3 className="text-lg text-white">Cryptographic Hashes</h3>
        </div>
        {email?.sha256 ? (
          <div className="space-y-3 text-sm">
            <div>
              <div className="text-slate-400 mb-1">SHA-256 (full email)</div>
              <code className="text-white bg-slate-800 px-3 py-2 rounded block font-mono text-xs break-all">
                {email.sha256}
              </code>
            </div>
          </div>
        ) : (
          <p className="text-slate-400 text-sm">No hash data available.</p>
        )}
      </Card>

      {/* Phishing Indicators */}
      {indicators.length > 0 && (
        <Card className="bg-slate-900 border-slate-800 p-6">
          <div className="flex items-center gap-3 mb-4">
            <Hash className="w-6 h-6 text-red-400" />
            <h3 className="text-lg text-white">Phishing Indicators Detail</h3>
          </div>
          <div className="space-y-2">
            {indicators.map((ind, index) => (
              <div
                key={index}
                className="p-3 bg-slate-800/50 rounded-lg border border-slate-700"
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-semibold text-white">{ind.type}</span>
                  <span className={`text-xs px-2 py-1 rounded ${
                    ind.severity === 'high'   ? 'bg-red-600/20 text-red-400' :
                    ind.severity === 'medium' ? 'bg-orange-600/20 text-orange-400' :
                    'bg-blue-600/20 text-blue-400'
                  }`}>
                    {ind.severity}
                  </span>
                </div>
                <p className="text-xs text-slate-400">{ind.description}</p>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}
