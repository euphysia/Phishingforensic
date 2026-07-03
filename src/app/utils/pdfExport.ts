// @ts-ignore
import pdfMake from 'pdfmake/build/pdfmake';
// @ts-ignore
import pdfFonts from 'pdfmake/build/vfs_fonts';

pdfMake.vfs = (pdfFonts as any).vfs ?? (pdfFonts as any).pdfMake?.vfs;

// ── Color helpers ─────────────────────────────────────────────────────────────

function riskHex(verdict: string): string {
  if (verdict === 'phishing') return '#dc2626';
  if (verdict === 'suspicious') return '#d97706';
  return '#16a34a';
}

function verdictHex(v: string | undefined | null): string {
  const lv = (v ?? '').toLowerCase();
  if (['pass', 'clean', 'safe'].includes(lv)) return '#16a34a';
  if (['fail', 'malicious', 'high', 'critical'].includes(lv)) return '#dc2626';
  if (['softfail', 'suspicious', 'medium'].includes(lv)) return '#d97706';
  return '#64748b';
}

function priorityHex(p: string | undefined): string {
  if (p === 'high') return '#dc2626';
  if (p === 'medium') return '#d97706';
  return '#16a34a';
}

function rowFill(i: number): string {
  return i % 2 === 0 ? '#f8fafc' : '#ffffff';
}

// ── Layout / style builders ───────────────────────────────────────────────────

const tableLayout = {
  hLineWidth: (i: number, node: any) =>
    i === 0 || i === node.table.body.length ? 1 : 0.5,
  vLineWidth: () => 0.5,
  hLineColor: () => '#e2e8f0',
  vLineColor: () => '#e2e8f0',
  paddingLeft:   () => 8,
  paddingRight:  () => 8,
  paddingTop:    () => 5,
  paddingBottom: () => 5,
};

function headerRow(cols: string[]) {
  return cols.map(c => ({
    text: c.toUpperCase(),
    fillColor: '#334155',
    color: '#e2e8f0',
    fontSize: 8,
    bold: true,
  }));
}

function sectionHeader(title: string) {
  return {
    table: {
      widths: ['*'],
      body: [[{
        text: title,
        color: 'white',
        bold: true,
        fontSize: 9,
        fillColor: '#1e293b',
        margin: [8, 6, 8, 6],
      }]],
    },
    layout: 'noBorders',
    margin: [0, 18, 0, 6] as [number, number, number, number],
  };
}

function kvTable(pairs: [string, string][]) {
  return {
    table: {
      widths: [130, '*'],
      body: pairs.map(([k, v], i) => [
        { text: k, fontSize: 9, color: '#64748b', bold: true, fillColor: rowFill(i) },
        { text: v, fontSize: 9, color: '#1e293b', fillColor: rowFill(i) },
      ]),
    },
    layout: tableLayout,
  };
}

// ── IoC builder ───────────────────────────────────────────────────────────────

function buildIocs(d: any): { type: string; value: string }[] {
  const iocs: { type: string; value: string }[] = [];
  (d.ipReputation?.ips ?? [])
    .filter((r: any) => r.verdict !== 'clean')
    .forEach((r: any) => iocs.push({ type: 'IP Address', value: r.ip }));
  (d.urlAnalysis?.urls ?? [])
    .filter((u: any) => u.status !== 'safe')
    .forEach((u: any) => iocs.push({ type: 'URL', value: u.url }));
  (d.attachmentAnalysis?.attachments ?? [])
    .filter((a: any) => a.status !== 'safe')
    .forEach((a: any) => {
      if (a.hash) iocs.push({ type: 'SHA-256 Hash', value: a.hash });
    });
  return iocs;
}

// ── Main export ───────────────────────────────────────────────────────────────

export function downloadForensicPdf(d: any): void {
  const reportId    = d.id ? d.id.slice(0, 16).toUpperCase() : 'UNKNOWN';
  const caseRef     = `CASE-${d.id?.slice(-8).toUpperCase() ?? '00000000'}`;
  const generatedAt = d.createdAt ? new Date(d.createdAt).toLocaleString('en-GB') : '—';
  const verdict     = d.verdict ?? 'unknown';
  const riskColor   = riskHex(verdict);

  const urls        = d.urlAnalysis?.urls              ?? [];
  const attachments = d.attachmentAnalysis?.attachments ?? [];
  const ips         = d.ipReputation?.ips               ?? [];
  const entries     = d.chainOfCustody?.entries         ?? [];
  const tactics     = d.bodyAnalysis?.tactics           ?? [];
  const recs        = d.recommendations                 ?? [];
  const iocs        = buildIocs(d);

  const content: any[] = [];

  // ── COVER PAGE ─────────────────────────────────────────────────────────────

  content.push(
    // Colored accent bar at top
    {
      canvas: [{ type: 'rect', x: 0, y: 0, w: 515, h: 5, color: riskColor }],
      margin: [0, 0, 0, 28],
    },
    {
      text: 'PHISHING EMAIL FORENSIC ANALYSIS SYSTEM  ·  FYP 2026',
      fontSize: 8,
      color: '#94a3b8',
      margin: [0, 0, 0, 10],
    },
    {
      text: 'PHISHING EMAIL\nFORENSIC INVESTIGATION\nREPORT',
      fontSize: 26,
      bold: true,
      color: '#0f172a',
      lineHeight: 1.35,
      margin: [0, 0, 0, 36],
    },
    // Metadata grid
    {
      columns: [
        { stack: [
          { text: 'REPORT ID', fontSize: 7, color: '#94a3b8', margin: [0, 0, 0, 2] },
          { text: reportId, fontSize: 10, color: '#1e293b' },
        ]},
        { stack: [
          { text: 'CASE REF', fontSize: 7, color: '#94a3b8', margin: [0, 0, 0, 2] },
          { text: caseRef, fontSize: 10, color: '#1e293b' },
        ]},
        { stack: [
          { text: 'GENERATED', fontSize: 7, color: '#94a3b8', margin: [0, 0, 0, 2] },
          { text: generatedAt, fontSize: 10, color: '#1e293b' },
        ]},
      ],
      margin: [0, 0, 0, 16],
    },
    {
      columns: [
        { stack: [
          { text: 'SUBJECT', fontSize: 7, color: '#94a3b8', margin: [0, 0, 0, 2] },
          { text: d.email?.subject ?? '—', fontSize: 10, color: '#1e293b' },
        ]},
        { stack: [
          { text: 'FROM', fontSize: 7, color: '#94a3b8', margin: [0, 0, 0, 2] },
          { text: d.email?.from ?? '—', fontSize: 10, color: '#1e293b' },
        ]},
        { stack: [
          { text: 'ANALYSIS TIME', fontSize: 7, color: '#94a3b8', margin: [0, 0, 0, 2] },
          { text: d.analysisTimeMs ? `${(d.analysisTimeMs / 1000).toFixed(1)}s` : '—', fontSize: 10, color: '#1e293b' },
        ]},
      ],
      margin: [0, 0, 0, 16],
    },
    { text: 'EMAIL SHA-256', fontSize: 7, color: '#94a3b8', margin: [0, 0, 0, 2] },
    { text: d.email?.sha256 ?? '—', fontSize: 8, color: '#64748b', margin: [0, 0, 0, 32] },
    // Risk verdict block
    {
      table: {
        widths: ['auto', '*'],
        body: [[
          {
            text: `${d.riskScore ?? '—'}`,
            fontSize: 52,
            bold: true,
            color: riskColor,
            border: [false, false, false, false],
            margin: [20, 14, 20, 14],
          },
          {
            stack: [
              { text: '/ 100', fontSize: 13, color: '#94a3b8' },
              { text: verdict.toUpperCase(), fontSize: 20, bold: true, color: riskColor, margin: [0, 4, 0, 4] },
              { text: `Confidence: ${d.confidence ?? '—'}%`, fontSize: 10, color: '#64748b' },
              { text: `Classification: ${d.severity ?? '—'}`, fontSize: 10, color: '#64748b' },
              { text: `Analyst: Generated by System`, fontSize: 10, color: '#64748b', margin: [0, 4, 0, 0] },
            ],
            border: [false, false, false, false],
            margin: [0, 14, 20, 14],
          },
        ]],
      },
      layout: {
        hLineWidth: () => 0,
        vLineWidth: () => 0,
        fillColor: () => '#f8fafc',
      },
    },
    { text: '', pageBreak: 'after' },
  );

  // ── 1. EXECUTIVE SUMMARY ───────────────────────────────────────────────────

  content.push(
    sectionHeader('1. EXECUTIVE SUMMARY'),
    {
      table: {
        widths: ['*'],
        body: [[{
          text: d.summary ?? 'No summary available.',
          fontSize: 10,
          color: '#1e293b',
          lineHeight: 1.6,
          margin: [12, 10, 12, 10],
        }]],
      },
      layout: {
        hLineWidth: (i: number, node: any) => (i === 0 || i === node.table.body.length) ? 1 : 0,
        vLineWidth: (i: number, node: any) => (i === 0 || i === node.table.widths.length) ? 1 : 0,
        hLineColor: () => '#e2e8f0',
        vLineColor: () => '#e2e8f0',
        fillColor: () => '#f8fafc',
        paddingLeft:   () => 12,
        paddingRight:  () => 12,
        paddingTop:    () => 10,
        paddingBottom: () => 10,
      },
    },
  );

  // ── 2. EMAIL METADATA ──────────────────────────────────────────────────────

  const metaPairs: [string, string][] = ([
    ['Subject',       d.email?.subject],
    ['From',          d.email?.from],
    ['To',            d.email?.to],
    ['Reply-To',      d.email?.replyTo],
    ['Date',          d.email?.date],
    ['Message-ID',    d.email?.messageId],
    ['Received From', d.headerAnalysis?.receivedFrom],
    ['Email SHA-256', d.email?.sha256],
  ] as [string, string | undefined][]).filter(([, v]) => !!v) as [string, string][];

  content.push(sectionHeader('2. EMAIL METADATA'), kvTable(metaPairs));

  // ── 3. AUTHENTICATION ANALYSIS ────────────────────────────────────────────

  content.push(
    sectionHeader('3. AUTHENTICATION ANALYSIS (SPF / DKIM / DMARC)'),
    {
      table: {
        widths: [70, 65, '*'],
        body: [
          headerRow(['Protocol', 'Result', 'Purpose']),
          ...[
            ['SPF',   d.headerAnalysis?.spfStatus,   'Verifies the sending server is authorised by the domain owner'],
            ['DKIM',  d.headerAnalysis?.dkimStatus,  'Verifies the message has not been altered in transit'],
            ['DMARC', d.headerAnalysis?.dmarcStatus, "Enforces the domain owner's policy based on SPF and DKIM results"],
          ].map(([proto, status, purpose], i) => [
            { text: proto as string, fontSize: 9, bold: true, color: '#1e293b', fillColor: rowFill(i) },
            { text: ((status ?? '—') as string).toUpperCase(), fontSize: 9, bold: true, color: verdictHex(status as string), fillColor: rowFill(i) },
            { text: purpose as string, fontSize: 9, color: '#64748b', fillColor: rowFill(i) },
          ]),
        ],
      },
      layout: tableLayout,
    },
  );

  if ((d.headerAnalysis?.spoofingIndicators ?? []).length > 0) {
    content.push({
      ul: (d.headerAnalysis.spoofingIndicators as string[]).map(s => ({
        text: s,
        color: '#dc2626',
        fontSize: 9,
      })),
      margin: [0, 6, 0, 0],
    });
  }

  // ── 4. URL ANALYSIS ───────────────────────────────────────────────────────

  content.push(sectionHeader('4. URL ANALYSIS'));

  if (urls.length === 0) {
    content.push({ text: 'No URLs found in this email.', fontSize: 9, color: '#64748b', italics: true });
  } else {
    content.push({
      table: {
        widths: ['*', 60, 45, 90],
        body: [
          headerRow(['URL', 'Verdict', 'Score', 'Details']),
          ...urls.map((u: any, i: number) => [
            { text: u.url, fontSize: 8, color: '#1e293b', fillColor: rowFill(i) },
            { text: (u.status ?? '—').toUpperCase(), fontSize: 9, bold: true, color: verdictHex(u.status), fillColor: rowFill(i) },
            { text: `${u.reputation ?? '—'}/100`, fontSize: 9, color: '#1e293b', fillColor: rowFill(i) },
            {
              text: [
                u.category ?? '—',
                u.vtDetections > 0 ? `\nVT: ${u.vtDetections}/${u.vtTotal}` : '',
                u.domainAge?.ageDays != null ? `\nDomain age: ${u.domainAge.ageDays}d` : '',
              ].join(''),
              fontSize: 8,
              color: '#64748b',
              fillColor: rowFill(i),
            },
          ]),
        ],
      },
      layout: tableLayout,
    });
  }

  // ── 5. ATTACHMENT ANALYSIS ────────────────────────────────────────────────

  content.push(sectionHeader('5. ATTACHMENT ANALYSIS'));

  if (attachments.length === 0) {
    content.push({ text: 'No attachments found in this email.', fontSize: 9, color: '#64748b', italics: true });
  } else {
    content.push({
      table: {
        widths: ['*', 55, 35, 90, 55],
        body: [
          headerRow(['Filename', 'Type', 'Size', 'SHA-256 (partial)', 'Verdict']),
          ...attachments.map((a: any, i: number) => [
            { text: a.name ?? '—', fontSize: 9, color: '#1e293b', fillColor: rowFill(i) },
            { text: a.type ?? '—', fontSize: 8, color: '#64748b', fillColor: rowFill(i) },
            { text: a.size ?? '—', fontSize: 8, color: '#64748b', fillColor: rowFill(i) },
            { text: a.hash ? `${a.hash.slice(0, 20)}…` : '—', fontSize: 8, color: '#64748b', fillColor: rowFill(i) },
            { text: (a.status ?? '—').toUpperCase(), fontSize: 9, bold: true, color: verdictHex(a.status), fillColor: rowFill(i) },
          ]),
        ],
      },
      layout: tableLayout,
    });
  }

  // ── 6. THREAT INTELLIGENCE ────────────────────────────────────────────────

  content.push(sectionHeader('6. THREAT INTELLIGENCE (AbuseIPDB / VirusTotal)'));

  if (ips.length === 0) {
    content.push({ text: 'No IP reputation data available.', fontSize: 9, color: '#64748b', italics: true });
  } else {
    content.push({
      table: {
        widths: [90, 60, 50, 45, '*'],
        body: [
          headerRow(['IP Address', 'Verdict', 'Abuse Score', 'Country', 'ISP']),
          ...ips.map((ip: any, i: number) => [
            { text: ip.ip, fontSize: 9, color: '#1e293b', fillColor: rowFill(i) },
            { text: (ip.verdict ?? '—').toUpperCase(), fontSize: 9, bold: true, color: verdictHex(ip.verdict), fillColor: rowFill(i) },
            {
              text: `${ip.abuseScore ?? '—'}%`,
              fontSize: 9,
              bold: true,
              color: ip.abuseScore >= 75 ? '#dc2626' : ip.abuseScore >= 25 ? '#d97706' : '#16a34a',
              fillColor: rowFill(i),
            },
            { text: ip.countryCode ?? '—', fontSize: 9, color: '#64748b', fillColor: rowFill(i) },
            { text: `${ip.isp ?? '—'}${ip.isTor ? ' (Tor)' : ''}`, fontSize: 9, color: '#64748b', fillColor: rowFill(i) },
          ]),
        ],
      },
      layout: tableLayout,
    });
  }

  // ── 7. SOCIAL ENGINEERING TACTICS ────────────────────────────────────────

  if (tactics.length > 0) {
    content.push(
      sectionHeader('7. SOCIAL ENGINEERING TACTICS'),
      {
        table: {
          widths: ['*', 60, '*'],
          body: [
            headerRow(['Tactic', 'Severity', 'Evidence']),
            ...tactics.map((t: any, i: number) => [
              { text: t.type, fontSize: 9, color: '#1e293b', fillColor: rowFill(i) },
              { text: (t.severity ?? '—').toUpperCase(), fontSize: 9, bold: true, color: verdictHex(t.severity), fillColor: rowFill(i) },
              { text: t.evidence ?? t.description ?? '—', fontSize: 9, italics: true, color: '#64748b', fillColor: rowFill(i) },
            ]),
          ],
        },
        layout: tableLayout,
      },
    );
  }

  // ── 8. INDICATORS OF COMPROMISE ──────────────────────────────────────────

  content.push(sectionHeader('8. INDICATORS OF COMPROMISE (IoCs)'));

  if (iocs.length === 0) {
    content.push({ text: 'No indicators of compromise found.', fontSize: 9, color: '#64748b', italics: true });
  } else {
    content.push({
      table: {
        widths: [100, '*'],
        body: [
          headerRow(['Type', 'Indicator']),
          ...iocs.map((ioc, i) => [
            { text: ioc.type, fontSize: 9, color: '#64748b', fillColor: rowFill(i) },
            { text: ioc.value, fontSize: 8, color: '#1e293b', fillColor: rowFill(i) },
          ]),
        ],
      },
      layout: tableLayout,
    });
  }

  // ── 9. RECOMMENDED ACTIONS ────────────────────────────────────────────────

  content.push(sectionHeader('9. RECOMMENDED ACTIONS'));

  if (recs.length === 0) {
    content.push({ text: 'No recommendations available.', fontSize: 9, color: '#64748b', italics: true });
  } else {
    content.push({
      table: {
        widths: [55, 130, '*'],
        body: [
          headerRow(['Priority', 'Action', 'Detail']),
          ...recs.map((r: any, i: number) => [
            { text: (r.priority ?? '—').toUpperCase(), fontSize: 9, bold: true, color: priorityHex(r.priority), fillColor: rowFill(i) },
            { text: r.step, fontSize: 9, bold: true, color: '#1e293b', fillColor: rowFill(i) },
            { text: r.detail, fontSize: 9, color: '#64748b', fillColor: rowFill(i) },
          ]),
        ],
      },
      layout: tableLayout,
    });
  }

  // ── 10. CHAIN OF CUSTODY ─────────────────────────────────────────────────

  const chainIntact = d.chainOfCustody?.chainIntact ?? true;
  content.push(
    sectionHeader(
      `10. CHAIN OF CUSTODY  (${entries.length} entries · ${chainIntact ? 'Integrity Verified ✓' : 'Integrity Warning ⚠'})`,
    ),
  );

  if (entries.length === 0) {
    content.push({ text: 'No chain of custody entries.', fontSize: 9, color: '#64748b', italics: true });
  } else {
    content.push({
      table: {
        widths: [100, 85, 80, '*'],
        body: [
          headerRow(['Timestamp', 'Event', 'Module', 'Details']),
          ...entries.map((e: any, i: number) => [
            { text: new Date(e.timestamp).toLocaleString('en-GB'), fontSize: 8, color: '#64748b', fillColor: rowFill(i) },
            { text: e.action, fontSize: 9, bold: true, color: '#1e293b', fillColor: rowFill(i) },
            { text: e.module, fontSize: 9, color: '#64748b', fillColor: rowFill(i) },
            { text: e.description, fontSize: 9, color: '#1e293b', fillColor: rowFill(i) },
          ]),
        ],
      },
      layout: tableLayout,
    });
  }

  // ── 11. EVIDENCE INTEGRITY ────────────────────────────────────────────────

  const integrityRows: [string, string][] = [
    ['Raw Email (.eml)', d.email?.sha256 ?? '—'],
    ...attachments.map((a: any) => [a.name as string, a.hash ?? '—']),
  ];

  content.push(
    sectionHeader('11. EVIDENCE INTEGRITY (SHA-256)'),
    {
      table: {
        widths: [150, '*'],
        body: [
          headerRow(['Artifact', 'SHA-256 Hash']),
          ...integrityRows.map(([artifact, hash], i) => [
            { text: artifact, fontSize: 9, color: '#64748b', fillColor: rowFill(i) },
            { text: hash, fontSize: 8, color: '#1e293b', fillColor: rowFill(i) },
          ]),
        ],
      },
      layout: tableLayout,
    },
    {
      text: '\nPhishing Email Forensic Analysis System · FYP 2026 · All evidence artifacts are preserved with SHA-256 cryptographic integrity.',
      fontSize: 8,
      color: '#94a3b8',
      alignment: 'center',
      margin: [0, 16, 0, 0],
    },
  );

  // ── DOCUMENT DEFINITION ───────────────────────────────────────────────────

  const docDefinition: any = {
    content,
    pageSize: 'A4',
    pageMargins: [40, 65, 40, 50],

    header: (currentPage: number) => ({
      margin: [0, 0, 0, 0],
      table: {
        widths: ['*', 'auto'],
        body: [[
          {
            text: 'PHISHING EMAIL FORENSIC INVESTIGATION REPORT',
            fontSize: 7,
            bold: true,
            color: '#e2e8f0',
            fillColor: '#0f172a',
            margin: [40, 11, 0, 11],
          },
          {
            text: `REPORT ID: ${reportId}   ·   PAGE ${currentPage}`,
            fontSize: 7,
            color: '#64748b',
            fillColor: '#0f172a',
            alignment: 'right',
            margin: [0, 11, 40, 11],
          },
        ]],
      },
      layout: 'noBorders',
    }),

    footer: (currentPage: number, pageCount: number) => ({
      margin: [40, 8, 40, 0],
      columns: [
        { text: 'CONFIDENTIAL — For authorised use only', fontSize: 7, color: '#94a3b8' },
        { text: `Page ${currentPage} of ${pageCount}`, fontSize: 7, color: '#94a3b8', alignment: 'right' },
      ],
    }),

    defaultStyle: {
      font: 'Roboto',
      fontSize: 10,
      color: '#1e293b',
    },
  };

  pdfMake.createPdf(docDefinition).download(`forensic-report-${reportId}.pdf`);
}
