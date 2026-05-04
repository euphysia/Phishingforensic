/**
 * Analyzes parsed email headers for spoofing indicators and sender reputation.
 */

// Common homoglyph lookalike brands (domain → display keywords)
const BRAND_LOOKALIKES = {
  paypal: ['paypa1', 'pay-pal', 'paypalverify', 'paypal-secure'],
  google: ['g00gle', 'googie', 'google-secure', 'accounts-google'],
  microsoft: ['micros0ft', 'microsofft', 'microsoft-verify'],
  apple: ['app1e', 'apple-id', 'icloud-verify'],
  amazon: ['amaz0n', 'amazon-secure', 'amazonprime-update'],
  netflix: ['netfl1x', 'netflix-billing'],
  facebook: ['faceb00k', 'facebook-verify'],
  instagram: ['lnstagram', 'instagram-support'],
  bank: ['bankverify', 'bank-secure', 'bankofamerica-update'],
};

const SUSPICIOUS_TLDS = [
  '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq',
  '.click', '.link', '.work', '.date', '.racing', '.win',
  '.stream', '.download', '.review', '.accountant',
];

const FREE_EMAIL_PROVIDERS = [
  'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
  'protonmail.com', 'yandex.com', 'mail.ru', 'aol.com',
];

/**
 * Analyzes email headers and returns spoofing indicators + reputation score.
 * @param {object} parsed - Output from emailParser.parseEmail()
 * @returns {HeaderAnalysisResult}
 */
export function analyzeHeaders(parsed) {
  const indicators = [];

  const fromDomain = extractDomain(parsed.fromAddress);
  const returnPathDomain = extractDomain(parsed.returnPath);
  const replyToDomain = extractDomain(parsed.replyTo);

  // ── 1. From vs Return-Path mismatch ──────────────────────────────────────
  if (returnPathDomain && fromDomain && returnPathDomain !== fromDomain) {
    indicators.push({
      type: 'Domain Mismatch',
      description: `Return-Path domain (${returnPathDomain}) does not match From domain (${fromDomain})`,
      severity: 'high',
    });
  }

  // ── 2. Display name impersonation ────────────────────────────────────────
  const fromNameLower = (parsed.fromName || '').toLowerCase();
  for (const [brand, lookalikes] of Object.entries(BRAND_LOOKALIKES)) {
    if (fromNameLower.includes(brand)) {
      // Check if the actual sending domain looks like a spoofed version
      if (fromDomain && !fromDomain.includes(brand)) {
        indicators.push({
          type: 'Display Name Spoofing',
          description: `Display name claims to be "${parsed.fromName}" but sender domain is "${fromDomain}"`,
          severity: 'high',
        });
      }
      // Check for lookalike domain
      for (const fake of lookalikes) {
        if (fromDomain && fromDomain.includes(fake)) {
          indicators.push({
            type: 'Homoglyph Domain',
            description: `Domain "${fromDomain}" uses character substitution to impersonate ${brand}`,
            severity: 'high',
          });
        }
      }
    }
  }

  // ── 3. Reply-To differs from From ────────────────────────────────────────
  if (replyToDomain && fromDomain && replyToDomain !== fromDomain) {
    indicators.push({
      type: 'Reply-To Hijack',
      description: `Reply-To (${replyToDomain}) is different from sender domain (${fromDomain}) — replies will go to a different party`,
      severity: 'medium',
    });
  }

  // ── 4. Free email provider for claimed brand ─────────────────────────────
  if (fromDomain && FREE_EMAIL_PROVIDERS.includes(fromDomain)) {
    const subjectLower = (parsed.subject || '').toLowerCase();
    const brandKeywords = ['account', 'verify', 'security', 'password', 'billing', 'payment', 'bank'];
    if (brandKeywords.some(k => subjectLower.includes(k))) {
      indicators.push({
        type: 'Free Provider Mismatch',
        description: `Legitimate services don't send security/billing emails from free providers like ${fromDomain}`,
        severity: 'medium',
      });
    }
  }

  // ── 5. Suspicious TLD ────────────────────────────────────────────────────
  if (fromDomain && SUSPICIOUS_TLDS.some(tld => fromDomain.endsWith(tld))) {
    const tld = SUSPICIOUS_TLDS.find(t => fromDomain.endsWith(t));
    indicators.push({
      type: 'Suspicious TLD',
      description: `Sender domain uses high-risk TLD "${tld}"`,
      severity: 'medium',
    });
  }

  // ── 6. Authentication failures ───────────────────────────────────────────
  if (parsed.spfStatus === 'fail' || parsed.spfStatus === 'softfail') {
    indicators.push({
      type: 'SPF Failure',
      description: `SPF check ${parsed.spfStatus} — the sending server is not authorized by the domain`,
      severity: 'high',
    });
  }
  if (parsed.dkimStatus === 'fail') {
    indicators.push({
      type: 'DKIM Failure',
      description: 'DKIM signature failed verification — email may have been modified in transit',
      severity: 'high',
    });
  }
  if (parsed.dmarcStatus === 'fail') {
    indicators.push({
      type: 'DMARC Failure',
      description: 'DMARC policy violation — domain owner has flagged this pattern as unauthenticated',
      severity: 'high',
    });
  }

  // ── 7. No authentication at all ──────────────────────────────────────────
  if (parsed.spfStatus === 'none' && parsed.dkimStatus === 'none' && parsed.dmarcStatus === 'none') {
    indicators.push({
      type: 'Missing Authentication',
      description: 'No SPF, DKIM, or DMARC records found — sender domain has no email authentication configured',
      severity: 'medium',
    });
  }

  // ── 8. Urgency in subject ────────────────────────────────────────────────
  const urgencyKeywords = [
    'urgent', 'immediate', 'action required', 'verify now', 'limited time',
    'suspended', 'locked', 'unusual activity', 'confirm your', 'update your',
    'compromised', 'unauthorized', 'expires today', 'act now', 'final notice',
  ];
  const subjectLower = (parsed.subject || '').toLowerCase();
  const foundUrgency = urgencyKeywords.filter(k => subjectLower.includes(k));
  if (foundUrgency.length > 0) {
    indicators.push({
      type: 'Urgency Social Engineering',
      description: `Subject line uses pressure tactics: "${foundUrgency.slice(0, 2).join('", "')}"`,
      severity: 'medium',
    });
  }

  // ── Reputation Score (0 = malicious, 100 = clean) ────────────────────────
  let score = 100;
  for (const ind of indicators) {
    if (ind.severity === 'high') score -= 25;
    else if (ind.severity === 'medium') score -= 12;
    else score -= 5;
  }
  // Auth bonus
  if (parsed.spfStatus === 'pass') score = Math.min(100, score + 10);
  if (parsed.dkimStatus === 'pass') score = Math.min(100, score + 10);
  if (parsed.dmarcStatus === 'pass') score = Math.min(100, score + 5);

  score = Math.max(0, Math.min(100, score));

  return {
    spfStatus: parsed.spfStatus || 'none',
    dkimStatus: parsed.dkimStatus || 'none',
    dmarcStatus: parsed.dmarcStatus || 'none',
    senderReputation: score,
    returnPath: parsed.returnPath || '',
    receivedFrom: parsed.receivedFrom || '',
    messageId: parsed.messageId || '',
    spoofingIndicators: indicators.map(i => i.description),
    indicators,
  };
}

function extractDomain(emailOrPath) {
  if (!emailOrPath) return null;
  // Handle <email@domain.com> format
  const match = emailOrPath.match(/<([^>]+)>/) || emailOrPath.match(/([^\s@]+@[^\s@>]+)/);
  const addr = match ? match[1] : emailOrPath;
  const atIdx = addr.lastIndexOf('@');
  if (atIdx === -1) return addr.toLowerCase().trim();
  return addr.substring(atIdx + 1).toLowerCase().trim();
}
