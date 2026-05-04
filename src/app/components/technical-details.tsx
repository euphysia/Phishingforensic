import { Code, Copy, Terminal, Hash } from 'lucide-react';
import { Card } from './ui/card';
import { Button } from './ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs';

export function TechnicalDetails() {
  const rawHeaders = `Received: from mail-sor-f41.google.com ([209.85.220.41])
        by mx.google.com with SMTP id x1234abcd
        for <victim@company.com>
        Sat, 08 Feb 2026 08:42:14 -0800 (PST)
Return-Path: <security@paypa1-verify.com>
Received: by mail-sor-f41.google.com with HTTP; Sat, 8 Feb 2026 08:42:13 -0800 (PST)
Date: Sat, 8 Feb 2026 08:42:13 -0800
From: PayPal Security <security@paypa1-verify.com>
To: victim@company.com
Message-ID: <CABc123def@mail.gmail.com>
Subject: Urgent: Verify your account immediately
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=suspicious-domain.com; s=20230601;
        h=to:subject:message-id:date:from:mime-version;
        bh=abc123def456==;
        b=xyz789uvw012==`;

  const iocs = [
    { type: 'Domain', value: 'paypa1-verify.com', category: 'Malicious' },
    { type: 'IP Address', value: '209.85.220.41', category: 'Suspicious' },
    { type: 'URL', value: 'hxxp://paypa1-verify.com/secure/login', category: 'Malicious' },
    { type: 'Email Hash', value: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6', category: 'Unique' },
    { type: 'Sender', value: 'security@paypa1-verify.com', category: 'Spoofed' }
  ];

  const extractedUrls = [
    'hxxp://paypa1-verify.com/secure/login',
    'hxxp://paypa1-verify.com/assets/logo.png',
    'hxxp://tracking-pixel.suspicious-domain.net/track?id=12345'
  ];

  return (
    <div className="space-y-4">
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

      <Card className="bg-slate-900 border-slate-800 p-6">
        <div className="flex items-center gap-3 mb-4">
          <Hash className="w-6 h-6 text-orange-400" />
          <h3 className="text-lg text-white">Indicators of Compromise (IoCs)</h3>
        </div>
        <div className="space-y-2">
          {iocs.map((ioc, index) => (
            <div 
              key={index}
              className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg border border-slate-700"
            >
              <div className="flex items-center gap-3 flex-1 min-w-0">
                <span className="text-sm text-slate-400 w-24 flex-shrink-0">
                  {ioc.type}:
                </span>
                <code className="text-sm text-white font-mono truncate">
                  {ioc.value}
                </code>
              </div>
              <div className="flex items-center gap-2">
                <span className={`text-xs px-2 py-1 rounded ${
                  ioc.category === 'Malicious' ? 'bg-red-600/20 text-red-400' :
                  ioc.category === 'Suspicious' ? 'bg-orange-600/20 text-orange-400' :
                  ioc.category === 'Spoofed' ? 'bg-purple-600/20 text-purple-400' :
                  'bg-blue-600/20 text-blue-400'
                }`}>
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
      </Card>

      <Card className="bg-slate-900 border-slate-800 p-6">
        <div className="flex items-center gap-3 mb-4">
          <Code className="w-6 h-6 text-blue-400" />
          <h3 className="text-lg text-white">Extracted URLs</h3>
        </div>
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
      </Card>

      <Card className="bg-slate-900 border-slate-800 p-6">
        <div className="flex items-center gap-3 mb-4">
          <Hash className="w-6 h-6 text-purple-400" />
          <h3 className="text-lg text-white">Cryptographic Hashes</h3>
        </div>
        <div className="space-y-3 text-sm">
          <div>
            <div className="text-slate-400 mb-1">MD5</div>
            <code className="text-white bg-slate-800 px-3 py-2 rounded block font-mono text-xs">
              5d41402abc4b2a76b9719d911017c592
            </code>
          </div>
          <div>
            <div className="text-slate-400 mb-1">SHA-1</div>
            <code className="text-white bg-slate-800 px-3 py-2 rounded block font-mono text-xs">
              aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
            </code>
          </div>
          <div>
            <div className="text-slate-400 mb-1">SHA-256</div>
            <code className="text-white bg-slate-800 px-3 py-2 rounded block font-mono text-xs">
              2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
            </code>
          </div>
        </div>
      </Card>
    </div>
  );
}
