import { useState, useRef } from 'react';
import { Upload, Mail, FileText, ChevronRight } from 'lucide-react';
import { Button } from './ui/button';
import { Card } from './ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs';
import { Textarea } from './ui/textarea';

interface EmailSubmissionProps {
  onSubmit: (data: { type: string; content: string | File }) => void;
  isProcessing: boolean;
}

export function EmailSubmission({ onSubmit, isProcessing }: EmailSubmissionProps) {
  const [activeTab, setActiveTab] = useState('upload');
  const [rawHeaders, setRawHeaders] = useState('');
  const [emailAddress, setEmailAddress] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setSelectedFile(file);
    }
  };

  const handleSubmit = () => {
    if (activeTab === 'upload' && selectedFile) {
      onSubmit({ type: 'file', content: selectedFile });
    } else if (activeTab === 'paste' && rawHeaders.trim()) {
      onSubmit({ type: 'headers', content: rawHeaders });
    } else if (activeTab === 'forward' && emailAddress.trim()) {
      onSubmit({ type: 'forward', content: emailAddress });
    }
  };

  const canSubmit = 
    (activeTab === 'upload' && selectedFile) ||
    (activeTab === 'paste' && rawHeaders.trim()) ||
    (activeTab === 'forward' && emailAddress.trim());

  return (
    <Card className="bg-slate-900 border-slate-800 p-6">
      <div className="mb-4">
        <h2 className="text-xl text-white mb-1">Email Submission</h2>
        <p className="text-sm text-slate-300">
          Upload, paste, or forward an email for automated phishing analysis
        </p>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="grid w-full grid-cols-3 bg-slate-800">
          <TabsTrigger value="upload" className="data-[state=active]:bg-slate-700 text-[rgb(255,248,248)]">
            <Upload className="w-4 h-4 mr-2" />
            Upload
          </TabsTrigger>
          <TabsTrigger value="paste" className="data-[state=active]:bg-slate-700 text-[rgb(255,254,254)]">
            <FileText className="w-4 h-4 mr-2" />
            Paste Headers
          </TabsTrigger>
          <TabsTrigger value="forward" className="data-[state=active]:bg-slate-700 text-[rgb(255,255,255)]">
            <Mail className="w-4 h-4 mr-2" />
            Forward Email
          </TabsTrigger>
        </TabsList>

        <TabsContent value="upload" className="mt-4">
          <div 
            className="border-2 border-dashed border-slate-700 rounded-lg p-8 text-center hover:border-slate-600 transition-colors cursor-pointer"
            onClick={() => fileInputRef.current?.click()}
          >
            <Upload className="w-12 h-12 mx-auto mb-3 text-slate-500" />
            <p className="text-white mb-1">
              {selectedFile ? selectedFile.name : 'Click to upload or drag and drop'}
            </p>
            <p className="text-sm text-slate-400">
              Supports .eml and .msg files (max 25MB)
            </p>
            <input
              ref={fileInputRef}
              type="file"
              accept=".eml,.msg"
              onChange={handleFileSelect}
              className="hidden"
            />
          </div>
        </TabsContent>

        <TabsContent value="paste" className="mt-4">
          <Textarea
            placeholder="Paste raw email headers here...&#10;&#10;Example:&#10;From: sender@example.com&#10;To: recipient@company.com&#10;Subject: Urgent: Account Verification Required&#10;..."
            value={rawHeaders}
            onChange={(e) => setRawHeaders(e.target.value)}
            className="min-h-[200px] bg-slate-800 border-slate-700 text-white font-mono text-sm"
          />
        </TabsContent>

        <TabsContent value="forward" className="mt-4">
          <div className="space-y-4">
            <div>
              <label className="text-sm text-slate-300 mb-2 block">
                Forward suspicious emails to this address:
              </label>
              <div className="flex items-center gap-3 p-4 bg-slate-800 rounded-lg border border-slate-700">
                <Mail className="w-5 h-5 text-blue-400" />
                <code className="text-blue-400 flex-1">
                  analyze@phishing-forensics.local
                </code>
                <Button 
                  variant="outline" 
                  size="sm"
                  className="bg-slate-700 border-slate-600 text-white hover:bg-slate-600"
                  onClick={() => {
                    navigator.clipboard.writeText('analyze@phishing-forensics.local');
                  }}
                >
                  Copy
                </Button>
              </div>
            </div>
            <div className="text-sm text-slate-400 space-y-1">
              <p>• Forward emails as attachments for complete header preservation</p>
              <p>• Analysis begins automatically upon receipt</p>
              <p>• Results available in the History section within 2-5 minutes</p>
            </div>
          </div>
        </TabsContent>
      </Tabs>

      <div className="mt-6 flex justify-end">
        <Button
          onClick={handleSubmit}
          disabled={!canSubmit || isProcessing}
          className="bg-blue-600 hover:bg-blue-700 text-white disabled:opacity-50 disabled:cursor-not-allowed"
          size="lg"
        >
          {isProcessing ? (
            <>Processing...</>
          ) : (
            <>
              Submit for Analysis
              <ChevronRight className="w-4 h-4 ml-2" />
            </>
          )}
        </Button>
      </div>
    </Card>
  );
}