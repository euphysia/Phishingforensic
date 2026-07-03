// Rich rule-based analysis paragraph generators for each forensic report section.
// Each function returns { finding, analysis, severity } where:
//   finding  — one-line verdict for the section header
//   analysis — 2-4 sentence paragraph explaining implications in plain English
//   severity — 'high' | 'medium' | 'low' | 'info'

export interface SectionResult {
  finding: string;
  analysis: string;
  severity: 'high' | 'medium' | 'low' | 'info';
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function extractDomain(address: string): string {
  const match = address?.match(/@([\w.-]+)/);
  return match ? match[1].toLowerCase() : '';
}

function extractDisplayName(address: string): string {
  const match = address?.match(/^(.+?)\s*</);
  return match ? match[1].trim().replace(/"/g, '') : '';
}

// ── Section 1: Sender Identity ────────────────────────────────────────────────

export function analyseSenderIdentity(d: any): SectionResult {
  const from       = d.email?.from ?? '';
  const returnPath = d.headerAnalysis?.returnPath ?? '';
  const spoofing   = d.headerAnalysis?.spoofingIndicators ?? [];
  const messageId  = d.email?.messageId ?? '';

  const fromDomain   = extractDomain(from);
  const rpDomain     = extractDomain(returnPath);
  const displayName  = extractDisplayName(from);
  const hasMismatch  = rpDomain && fromDomain && rpDomain !== fromDomain;
  const hasSpoof     = spoofing.length > 0;

  // Display name impersonation — e.g. "Maybank Security" but email is @gmail.com
  const knownBrands  = ['maybank', 'cimb', 'rhb', 'google', 'microsoft', 'shopee', 'grab', 'paypal', 'apple', 'amazon', 'netflix', 'lhdn', 'hasil', 'pdrm', 'mcmc', 'pos malaysia', 'poslaju', 'whatsapp', 'facebook'];
  const nameImpersonates = displayName && knownBrands.some(b => displayName.toLowerCase().includes(b));
  const domainIsTrusted  = fromDomain && knownBrands.some(b => fromDomain.includes(b));
  const fakeNameRealDomain = nameImpersonates && !domainIsTrusted;

  if (fakeNameRealDomain && hasMismatch) {
    return {
      severity: 'high',
      finding:  'Sender identity is forged — display name impersonates a known brand',
      analysis: `The email displays the sender name "${displayName}" to appear trustworthy, but the actual sending address uses the domain "@${fromDomain}", which has no affiliation with that organisation. Additionally, the Return-Path header — which controls where bounced mail actually goes — points to "@${rpDomain}", a different domain entirely. This two-layer discrepancy is a strong signature of a spoofed sender designed to deceive at first glance. Legitimate organisations always send from their own verified domain and have a consistent Return-Path.`,
    };
  }

  if (fakeNameRealDomain) {
    return {
      severity: 'high',
      finding:  'Display name impersonates a known brand but email domain does not match',
      analysis: `The sender name "${displayName}" is designed to make this email appear as though it comes from a legitimate, well-known organisation. However, the actual sending address uses "@${fromDomain}", which is not an official domain for that organisation. Attackers commonly exploit the fact that email clients display the name prominently while hiding the real address. Any email claiming to be from a major brand must originate from that brand's own domain to be considered legitimate.`,
    };
  }

  if (hasMismatch) {
    return {
      severity: 'high',
      finding:  'From address and Return-Path domain do not match — possible spoofing',
      analysis: `The email's From header shows "@${fromDomain}" as the sender domain, but the Return-Path — which reveals where the mail server actually delivered this message from — points to "@${rpDomain}". These should be the same for any legitimately sent email. This mismatch suggests the From address may have been manually crafted to disguise the true origin of the message. This is a common technique used in email spoofing attacks.`,
    };
  }

  if (hasSpoof) {
    return {
      severity: 'medium',
      finding:  'Spoofing signals detected in sender headers',
      analysis: `The email headers contain ${spoofing.length} spoofing indicator${spoofing.length > 1 ? 's' : ''}: ${spoofing.slice(0, 2).join('; ')}. While the From and Return-Path domains appear consistent, these additional signals suggest the email routing may not match what a legitimate sender from "${fromDomain}" would produce. This warrants closer examination of the authentication results.`,
    };
  }

  if (!messageId || !fromDomain) {
    return {
      severity: 'medium',
      finding:  'Sender information is incomplete or missing',
      analysis: `The email is missing key identifying headers that all legitimate mail servers automatically include. A missing or malformed Message-ID and sender domain can indicate the email was crafted manually rather than sent through a standard mail system. While not conclusive on its own, this is unusual for any email from a reputable organisation or service.`,
    };
  }

  return {
    severity: 'info',
    finding:  'Sender identity appears consistent',
    analysis: `The From address ("${from}") and Return-Path ("${returnPath}") both originate from the same domain, "@${fromDomain}". No display-name impersonation of known brands was detected. The sender identity headers are internally consistent, though this alone does not confirm the email is legitimate — authentication checks and content analysis provide further verification.`,
  };
}

// ── Section 2: Email Authentication ──────────────────────────────────────────

export function analyseAuthentication(d: any): SectionResult {
  const spf   = (d.headerAnalysis?.spfStatus  ?? 'none').toLowerCase();
  const dkim  = (d.headerAnalysis?.dkimStatus ?? 'none').toLowerCase();
  const dmarc = (d.headerAnalysis?.dmarcStatus ?? 'none').toLowerCase();

  const spfPass   = spf === 'pass';
  const dkimPass  = dkim === 'pass';
  const dmarcPass = dmarc === 'pass';
  const allPass   = spfPass && dkimPass && dmarcPass;
  const allFail   = !spfPass && !dkimPass && !dmarcPass;
  const passCount = [spfPass, dkimPass, dmarcPass].filter(Boolean).length;

  const spfExplain   = spfPass   ? 'the sending server is authorised to send mail for this domain' : spf === 'softfail' ? 'the sending server is not fully authorised (soft fail)' : 'the sending server is not authorised to send mail for this domain';
  const dkimExplain  = dkimPass  ? 'the message content has not been tampered with in transit' : 'the message cannot be verified as unaltered, or no signature was present';
  const dmarcExplain = dmarcPass ? 'the domain owner\'s policy has been satisfied' : 'the domain owner\'s policy for handling unauthenticated mail has not been met';

  if (allFail) {
    return {
      severity: 'high',
      finding:  'Email failed all three authentication checks — SPF, DKIM, and DMARC',
      analysis: `This email failed every standard email authentication mechanism. SPF failed, meaning ${spfExplain}. DKIM failed, meaning ${dkimExplain}. DMARC failed, meaning ${dmarcExplain}. All three checks failing simultaneously is one of the strongest indicators that an email is not legitimately from who it claims to be. Virtually all major services — banks, government agencies, and tech companies — have all three configured correctly.`,
    };
  }

  if (!dmarcPass && !spfPass) {
    return {
      severity: 'high',
      finding:  'SPF and DMARC both failed — sender domain cannot be verified',
      analysis: `SPF failed, meaning ${spfExplain}. DMARC also failed, meaning ${dmarcExplain}. Together, these two failures indicate the sending server has no authorisation to send on behalf of this domain, and the domain owner's policy has not been satisfied. DKIM ${dkimPass ? 'passed, which provides some content integrity assurance, but' : 'also failed —'} the combination of SPF and DMARC failure is a strong red flag for spoofing.`,
    };
  }

  if (allPass) {
    return {
      severity: 'info',
      finding:  'Email passed all three authentication checks',
      analysis: `SPF passed — ${spfExplain}. DKIM passed — ${dkimExplain}. DMARC passed — ${dmarcExplain}. Passing all three checks confirms the email was sent from an authorised server and the content was not modified in transit. Note that authentication passing does not guarantee the email is safe — a legitimate-looking domain could still be used for phishing — but it does confirm the sender domain is not being spoofed.`,
    };
  }

  return {
    severity: passCount >= 2 ? 'low' : 'medium',
    finding:  `Email passed ${passCount} of 3 authentication checks`,
    analysis: `SPF ${spfPass ? 'passed' : 'failed'} — ${spfExplain}. DKIM ${dkimPass ? 'passed' : 'failed'} — ${dkimExplain}. DMARC ${dmarcPass ? 'passed' : 'failed'} — ${dmarcExplain}. ${passCount === 1 ? 'Passing only one check leaves significant doubt about the email\'s authenticity.' : 'While two checks passed, the failed check still represents a gap in verification that could indicate a partially spoofed or misconfigured sender.'}`,
  };
}

// ── Section 3: Routing & Origin ───────────────────────────────────────────────

export function analyseRouting(d: any): SectionResult {
  const ips         = d.ipReputation?.ips ?? [];
  const receivedFrom = d.headerAnalysis?.receivedFrom ?? '';
  const totalChecked = d.ipReputation?.totalIpsChecked ?? 0;
  const maliciousIps = d.ipReputation?.maliciousIps ?? 0;
  const suspiciousIps = d.ipReputation?.suspiciousIps ?? 0;

  const torIps = ips.filter((r: any) => r.isTor);
  const flaggedIps = ips.filter((r: any) => r.verdict === 'malicious' || r.verdict === 'suspicious');

  if (maliciousIps > 0) {
    const worst = ips.find((r: any) => r.verdict === 'malicious');
    return {
      severity: 'high',
      finding:  `Email originated from a known malicious IP address`,
      analysis: `The email was routed through IP address ${worst?.ip ?? 'unknown'} (${worst?.isp ?? 'unknown ISP'}, ${worst?.countryCode ?? 'unknown country'}), which has an AbuseIPDB confidence score of ${worst?.abuseScore ?? '?'}% and ${worst?.totalReports ?? 0} abuse report${worst?.totalReports !== 1 ? 's' : ''}. ${torIps.length > 0 ? 'The email was also relayed through a Tor exit node, which is used to anonymise the sender\'s true location — a tactic commonly used to evade tracking. ' : ''}This strongly suggests the email was sent from infrastructure associated with malicious activity, and the sender was likely attempting to obscure their true identity and location.`,
    };
  }

  if (suspiciousIps > 0 || torIps.length > 0) {
    const worst = flaggedIps[0];
    return {
      severity: 'medium',
      finding:  `Email routing includes suspicious or flagged IP addresses`,
      analysis: `${flaggedIps.length} of the ${totalChecked} IP address${totalChecked !== 1 ? 'es' : ''} found in the email's routing path ha${flaggedIps.length === 1 ? 's' : 've'} been flagged by AbuseIPDB. ${worst ? `IP ${worst.ip} (${worst.isp ?? 'unknown'}, ${worst.countryCode ?? 'unknown'}) carries an abuse score of ${worst.abuseScore}%. ` : ''}${torIps.length > 0 ? 'The use of Tor exit nodes in the routing path is particularly notable, as legitimate businesses do not send email through anonymising networks. ' : ''}While suspicious IPs alone are not proof of phishing, they indicate the email did not travel through normal, reputable mail infrastructure.`,
    };
  }

  if (totalChecked === 0 || !receivedFrom) {
    return {
      severity: 'medium',
      finding:  'Email routing information is missing or incomplete',
      analysis: `The email is missing standard Received headers that track the path a message takes through mail servers. Every legitimately delivered email accumulates a chain of these headers as it passes from server to server. An absence of routing information can indicate the email was crafted manually to hide its true origin, or that the headers were deliberately stripped before delivery.`,
    };
  }

  const cleanIps = ips.filter((r: any) => r.verdict === 'clean');
  return {
    severity: 'info',
    finding:  'Email routing and sender IPs appear clean',
    analysis: `The email was routed through ${totalChecked} IP address${totalChecked !== 1 ? 'es' : ''}, all of which returned clean results from AbuseIPDB reputation checks. ${receivedFrom ? `The outermost relay was "${receivedFrom}". ` : ''}No Tor exit nodes or anonymising proxies were detected in the routing path. Clean IP reputation is a positive signal, though it does not rule out phishing from newly registered or previously unseen infrastructure.`,
  };
}

// ── Section 4: Content & Social Engineering ───────────────────────────────────

export function analyseContent(d: any): SectionResult {
  const tactics     = d.bodyAnalysis?.tactics ?? [];
  const threatLevel = d.bodyAnalysis?.overallThreatLevel ?? 'none';
  const bodyScore   = d.bodyAnalysis?.bodyRiskScore ?? 0;
  const source      = d.bodyAnalysis?.source ?? 'rule-based';

  const highTactics = tactics.filter((t: any) => t.severity === 'high');
  const medTactics  = tactics.filter((t: any) => t.severity === 'medium');

  if (tactics.length === 0) {
    return {
      severity: 'info',
      finding:  'No social engineering tactics detected in email body',
      analysis: `Content analysis (${source === 'groq' ? 'AI-assisted' : 'rule-based'}) found no significant social engineering tactics in the email body. The message does not appear to use urgency, fear, authority impersonation, or other common manipulation techniques. A body risk score of ${bodyScore}/100 was assigned. While this is a positive signal, content analysis is one factor among many — header and URL analysis may still reveal concerns.`,
    };
  }

  if (threatLevel === 'critical' || threatLevel === 'high') {
    const topTactic = highTactics[0] ?? tactics[0];
    const evidenceSnippet = topTactic?.evidence ? `"${topTactic.evidence}"` : null;
    return {
      severity: 'high',
      finding:  `${highTactics.length} high-severity social engineering tactic${highTactics.length !== 1 ? 's' : ''} detected`,
      analysis: `Content analysis (${source === 'groq' ? 'AI-assisted' : 'rule-based'}) identified ${tactics.length} manipulation tactic${tactics.length !== 1 ? 's' : ''} across the email body, ${highTactics.length} of which are high-severity. The most prominent is "${topTactic?.type ?? 'unknown'}" — ${topTactic?.description ?? ''}${evidenceSnippet ? ` The exact language used was: ${evidenceSnippet}.` : ''} ${medTactics.length > 0 ? `An additional ${medTactics.length} medium-severity tactic${medTactics.length !== 1 ? 's' : ''} (${medTactics.slice(0, 2).map((t: any) => t.type).join(', ')}) compound the social engineering pressure. ` : ''}This content pattern is consistent with phishing emails designed to override the recipient's critical judgement through psychological pressure.`,
    };
  }

  if (threatLevel === 'medium') {
    return {
      severity: 'medium',
      finding:  `${tactics.length} social engineering tactic${tactics.length !== 1 ? 's' : ''} detected — medium threat level`,
      analysis: `Content analysis (${source === 'groq' ? 'AI-assisted' : 'rule-based'}) identified ${tactics.length} suspicious tactic${tactics.length !== 1 ? 's' : ''} in the email body, including: ${tactics.slice(0, 3).map((t: any) => t.type).join(', ')}. ${tactics[0]?.description ? `Notably, ${tactics[0].description}` : ''} The overall body risk score is ${bodyScore}/100. These patterns are commonly used in phishing and scam emails to manipulate recipients into acting without thinking. The medium threat level warrants treating this email with caution.`,
    };
  }

  return {
    severity: 'low',
    finding:  `Minor content concerns — ${tactics.length} low-severity tactic${tactics.length !== 1 ? 's' : ''} noted`,
    analysis: `Content analysis (${source === 'groq' ? 'AI-assisted' : 'rule-based'}) found ${tactics.length} low-severity tactic${tactics.length !== 1 ? 's' : ''}: ${tactics.map((t: any) => t.type).join(', ')}. ${tactics[0]?.description ?? ''} While none of these alone are conclusive indicators of phishing, they may still reflect persuasive writing techniques. The body risk score of ${bodyScore}/100 suggests the content is largely benign, but these signals are noted for completeness.`,
  };
}

// ── Section 5: URL & Link Analysis ───────────────────────────────────────────

export function analyseUrls(d: any): SectionResult {
  const urls          = d.urlAnalysis?.urls ?? [];
  const totalUrls     = d.urlAnalysis?.totalUrls ?? 0;
  const maliciousUrls = d.urlAnalysis?.maliciousUrls ?? 0;
  const suspiciousUrls = d.urlAnalysis?.suspiciousUrls ?? 0;

  if (totalUrls === 0) {
    return {
      severity: 'info',
      finding:  'No URLs found in this email',
      analysis: `No hyperlinks or URLs were extracted from the email body. This is common for plain-text notifications, internal communications, or simple informational emails. The absence of links removes one of the primary attack vectors used in phishing — credential-harvesting pages or malware download sites. Other risk factors such as sender identity and attachments still apply.`,
    };
  }

  if (maliciousUrls > 0) {
    const worst = urls.find((u: any) => u.status === 'malicious');
    return {
      severity: 'high',
      finding:  `${maliciousUrls} malicious URL${maliciousUrls !== 1 ? 's' : ''} detected out of ${totalUrls} link${totalUrls !== 1 ? 's' : ''}`,
      analysis: `Of the ${totalUrls} URL${totalUrls !== 1 ? 's' : ''} found in this email, ${maliciousUrls} ${maliciousUrls === 1 ? 'has' : 'have'} been confirmed malicious by external threat intelligence sources (VirusTotal, URLScan.io, or PhishTank). ${worst ? `The highest-risk link — "${worst.url}" — received a threat score indicating it is ${worst.category ? `categorised as "${worst.category}"` : 'known malicious infrastructure'}. ` : ''}${suspiciousUrls > 0 ? `A further ${suspiciousUrls} URL${suspiciousUrls !== 1 ? 's' : ''} ${suspiciousUrls === 1 ? 'was' : 'were'} flagged as suspicious. ` : ''}Clicking any link in this email carries significant risk. The presence of even one confirmed malicious URL is sufficient to classify an email as a phishing attempt.`,
    };
  }

  if (suspiciousUrls > 0) {
    const worst = urls.find((u: any) => u.status === 'suspicious');
    return {
      severity: 'medium',
      finding:  `${suspiciousUrls} suspicious URL${suspiciousUrls !== 1 ? 's' : ''} out of ${totalUrls} total link${totalUrls !== 1 ? 's' : ''}`,
      analysis: `${totalUrls} URL${totalUrls !== 1 ? 's' : ''} ${totalUrls === 1 ? 'was' : 'were'} found in this email, of which ${suspiciousUrls} ${suspiciousUrls === 1 ? 'has' : 'have'} been flagged as suspicious by threat intelligence checks. ${worst ? `The most concerning is "${worst.url}"${worst.category ? `, categorised as "${worst.category}"` : ''}. ` : ''}Suspicious URLs may not yet be in threat databases but display characteristics common to phishing infrastructure — such as recently registered domains, IP-based addresses, URL shorteners, or domains that closely mimic well-known brands. Exercise caution with any links in this email.`,
    };
  }

  return {
    severity: 'info',
    finding:  `All ${totalUrls} URL${totalUrls !== 1 ? 's' : ''} appear clean`,
    analysis: `All ${totalUrls} URL${totalUrls !== 1 ? 's' : ''} extracted from this email were checked against VirusTotal, URLScan.io, and PhishTank and returned no confirmed malicious or suspicious results. This is a positive signal. Note that threat intelligence databases are not exhaustive — a newly created phishing page may not yet be indexed. URL reputation should be considered alongside other findings rather than in isolation.`,
  };
}

// ── Overall severity helper ───────────────────────────────────────────────────

export function sectionSeverityToColor(severity: SectionResult['severity']) {
  switch (severity) {
    case 'high':   return { bg: 'bg-red-900/30',    border: 'border-red-700/50',    text: 'text-red-400',    badge: 'bg-red-600/20 text-red-400 border-red-600/40' };
    case 'medium': return { bg: 'bg-amber-900/30',  border: 'border-amber-700/50',  text: 'text-amber-400',  badge: 'bg-amber-600/20 text-amber-400 border-amber-600/40' };
    case 'low':    return { bg: 'bg-yellow-900/20', border: 'border-yellow-700/40', text: 'text-yellow-400', badge: 'bg-yellow-600/20 text-yellow-400 border-yellow-600/40' };
    case 'info':   return { bg: 'bg-green-900/20',  border: 'border-green-700/40',  text: 'text-green-400',  badge: 'bg-green-600/20 text-green-400 border-green-600/40' };
  }
}
