import { FileText, Download, Shield, Clock } from 'lucide-react';
import { Card } from './ui/card';
import { Button } from './ui/button';
import { Badge } from './ui/badge';

interface ForensicReportProps {
  reportId: string;
  generatedAt: string;
  analysisTime: string;
}

export function ForensicReport({ reportId, generatedAt, analysisTime }: ForensicReportProps) {
  return (
    <Card className="bg-slate-900 border-slate-800 p-6">
      <div className="flex items-start justify-between mb-6">
        <div>
          <h3 className="text-lg text-white mb-1">Forensic Report & Evidence</h3>
          <p className="text-sm text-slate-300">
            Complete analysis documentation with chain-of-custody
          </p>
        </div>
        <Badge variant="outline" className="bg-green-600/20 text-green-400 border-green-600/50">
          <Shield className="w-3 h-3 mr-1" />
          Verified
        </Badge>
      </div>

      <div className="space-y-4">
        <div className="grid grid-cols-3 gap-4 text-sm">
          <div className="p-3 bg-slate-800/50 rounded-lg">
            <div className="text-slate-400 mb-1">Report ID</div>
            <code className="text-blue-400 text-xs">{reportId}</code>
          </div>
          <div className="p-3 bg-slate-800/50 rounded-lg">
            <div className="text-slate-400 mb-1">Generated</div>
            <div className="text-white">{generatedAt}</div>
          </div>
          <div className="p-3 bg-slate-800/50 rounded-lg">
            <div className="text-slate-400 mb-1">Analysis Time</div>
            <div className="text-white">{analysisTime}</div>
          </div>
        </div>

        <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
          <div className="flex items-center gap-2 mb-3">
            <Shield className="w-4 h-4 text-green-400" />
            <span className="text-white font-medium">Evidence Integrity</span>
          </div>
          <div className="space-y-2 text-sm">
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Hash Verification</span>
              <span className="text-green-400">Valid</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Digital Signature</span>
              <span className="text-green-400">Verified</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Chain of Custody</span>
              <span className="text-green-400">Intact</span>
            </div>
          </div>
        </div>

        <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
          <div className="flex items-center gap-2 mb-3">
            <Clock className="w-4 h-4 text-blue-400" />
            <span className="text-white font-medium">Audit Trail</span>
          </div>
          <div className="space-y-2 text-xs font-mono text-slate-300">
            <div className="flex gap-3">
              <span className="text-slate-500">08:42:15</span>
              <span>Email received and queued for analysis</span>
            </div>
            <div className="flex gap-3">
              <span className="text-slate-500">08:42:16</span>
              <span>Metadata extraction completed</span>
            </div>
            <div className="flex gap-3">
              <span className="text-slate-500">08:42:18</span>
              <span>Header authentication checks performed</span>
            </div>
            <div className="flex gap-3">
              <span className="text-slate-500">08:42:21</span>
              <span>URL analysis and reputation checks completed</span>
            </div>
            <div className="flex gap-3">
              <span className="text-slate-500">08:42:25</span>
              <span>Attachment sandbox analysis completed</span>
            </div>
            <div className="flex gap-3">
              <span className="text-slate-500">08:42:28</span>
              <span>Threat intelligence correlation finished</span>
            </div>
            <div className="flex gap-3">
              <span className="text-slate-500">08:42:30</span>
              <span>Risk assessment generated</span>
            </div>
            <div className="flex gap-3">
              <span className="text-slate-500">08:42:31</span>
              <span>Forensic report finalized and signed</span>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <Button variant="outline" className="bg-slate-800 border-slate-700 text-white hover:bg-slate-700">
            <Download className="w-4 h-4 mr-2" />
            Download PDF Report
          </Button>
          <Button variant="outline" className="bg-slate-800 border-slate-700 text-white hover:bg-slate-700">
            <FileText className="w-4 h-4 mr-2" />
            Export JSON Data
          </Button>
        </div>
      </div>
    </Card>
  );
}