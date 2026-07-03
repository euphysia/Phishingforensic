// Body Analyzer — uses Groq (free, global) with rule-based fallback
// Get a free key at: https://console.groq.com/keys

const GROQ_API_URL = 'https://api.groq.com/openai/v1/chat/completions';
const GROQ_MODELS  = ['llama-3.3-70b-versatile', 'llama-3.1-8b-instant'];

function getGroqKey() {
  const key = process.env.GROQ_API_KEY;
  return key && key !== 'your-groq-api-key-here' ? key : null;
}

const SYSTEM_PROMPT = `You are an expert cybersecurity analyst specialising in phishing and social-engineering email forensics.
Analyse the email (body, subject, sender, and recipient) and identify manipulation tactics and logical inconsistencies.

CATEGORIES to evaluate:
1. Urgency / Scarcity — pressures the reader to act immediately
2. Fear / Threat — threatens negative consequences to force compliance
3. Authority Impersonation — pretends to be a bank, government, IT dept, university admin, CEO
4. Credential Harvesting — requests passwords, PINs, card numbers, personal IDs
5. Suspicious Calls to Action — directs user to click a link, download a file, or reply with personal details
6. Reward / Prize Bait — false promises of prizes, refunds, or rewards
7. Unusual Financial Request — requests money transfer, bank account details, payment to personal account, e-wallet, gift cards
8. Sender-Claim Mismatch — the sender's actual email address does not match the authority or organisation they claim to represent (e.g. a student email claiming to be from finance, a Gmail address claiming to be a bank, a personal email claiming to be IT support)
9. Peer-to-Peer Scam Pattern — an individual posing as a peer, classmate, or colleague asking recipients to send money, pay a shared bill, or participate in a collection, especially when targeting a group

IMPORTANT REASONING INSTRUCTIONS:
- Look at the FROM address carefully. If the body claims to be from an official department (finance office, IT, admin, bank) but the sender domain is a personal email, student email, or free provider — that is a strong Sender-Claim Mismatch indicator regardless of whether authentication passed.
- If the email asks recipients to send money to a personal bank account, e-wallet (GrabPay, Touch 'n Go, DuitNow), or asks them to pay on behalf of a group — treat that as high severity.
- A legitimate organisation NEVER asks for payment via personal accounts or informal channels.
- Consider the RECIPIENT: if the email is addressed to multiple students or a group list and requests payment, that pattern strongly suggests a peer scam.

OUTPUT FORMAT — respond with ONLY valid JSON (no markdown, no explanation):
{
  "bodyRiskScore": <integer 0-100>,
  "overallThreatLevel": "<none|low|medium|high|critical>",
  "confidence": <integer 0-100>,
  "tactics": [
    {
      "type": "<category name from above>",
      "severity": "<low|medium|high>",
      "evidence": "<exact quote or short description from the email>",
      "description": "<one sentence explaining why this is suspicious>"
    }
  ],
  "summary": "<2-3 sentence plain-English summary for a non-technical user>"
}`;

async function callGroq(apiKey, model, subject, from, to, replyTo, body) {
  const userPrompt = `Analyse this email for phishing, social-engineering tactics, and logical inconsistencies.

From: "${from}"
To: "${to || '(unknown)'}"${replyTo ? `\nReply-To: "${replyTo}" (DIFFERENT from sender — reply goes somewhere else)` : ''}
Subject: "${subject}"

--- EMAIL BODY ---
${body || '(empty body)'}
--- END ---

Pay special attention to whether the sender's email address is consistent with any authority or organisation claimed in the body.`;

  const res = await fetch(GROQ_API_URL, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model,
      messages: [
        { role: 'system', content: SYSTEM_PROMPT },
        { role: 'user',   content: userPrompt },
      ],
      max_tokens: 800,
      temperature: 0,
    }),
  });

  if (!res.ok) {
    const body = await res.text();
    const err = new Error(`Groq API error ${res.status}: ${body}`);
    err.status = res.status;
    throw err;
  }

  const data = await res.json();
  return data.choices?.[0]?.message?.content?.trim() ?? '';
}

export async function analyzeEmailBody({ textBody = '', htmlBody = '', subject = '', from = '', to = '', replyTo = '' }) {
  const apiKey = getGroqKey();

  const strippedHtml   = htmlBody.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
  const bodyContent    = textBody.length >= strippedHtml.length ? textBody : strippedHtml;
  const truncatedBody  = bodyContent.slice(0, 4000);

  if (!apiKey) {
    return ruleBasedBodyAnalysis(truncatedBody, subject);
  }

  for (const model of GROQ_MODELS) {
    try {
      const raw = await callGroq(apiKey, model, subject, from, to, replyTo, truncatedBody);

      const jsonMatch = raw.match(/\{[\s\S]*\}/);
      if (!jsonMatch) throw new Error('No JSON in response');

      const parsed = JSON.parse(jsonMatch[0]);
      console.log(`[BodyAnalyzer] Groq ${model}: score=${clamp(parsed.bodyRiskScore ?? 0, 0, 100)}, threat=${parsed.overallThreatLevel ?? 'none'}, tactics=${Array.isArray(parsed.tactics) ? parsed.tactics.length : 0}`);

      return {
        bodyRiskScore:      clamp(parsed.bodyRiskScore ?? 0, 0, 100),
        overallThreatLevel: parsed.overallThreatLevel ?? 'none',
        confidence:         clamp(parsed.confidence ?? 50, 0, 100),
        tactics:            Array.isArray(parsed.tactics) ? parsed.tactics : [],
        summary:            parsed.summary ?? '',
        source:             'groq',
      };
    } catch (err) {
      console.warn(`[BodyAnalyzer] ${model} failed (${err.status ?? 'unknown'}): ${err.message?.slice(0, 100)}`);
    }
  }

  console.warn('[BodyAnalyzer] All Groq models failed — using rule-based fallback.');
  return ruleBasedBodyAnalysis(truncatedBody, subject);
}

// ── Rule-based fallback ───────────────────────────────────────────────────────

const URGENCY_PATTERNS = [
  { pattern: /urgent|immediately|right away|as soon as possible/i,              label: 'Urgency Language',             severity: 'medium' },
  { pattern: /account.*suspended|suspended.*account|account.*locked/i,          label: 'Account Suspension Threat',    severity: 'high'   },
  { pattern: /expires? (today|in \d+ hours?|within \d+)/i,                      label: 'Expiry Pressure',              severity: 'medium' },
  { pattern: /final notice|last chance|last warning/i,                           label: 'Final Warning Language',       severity: 'high'   },
  { pattern: /act now|limited time|don'?t delay/i,                               label: 'Scarcity \/ Time Pressure',    severity: 'medium' },
  { pattern: /verify your (account|identity|email|password|information)/i,       label: 'Verification Request',         severity: 'high'   },
  { pattern: /enter your (password|pin|credit card|social security|ssn)/i,       label: 'Credential Harvesting',        severity: 'high'   },
  { pattern: /click (here|the link|below) (to verify|to confirm|now)/i,          label: 'Suspicious Call to Action',    severity: 'medium' },
  { pattern: /you (have won|are a winner|won a prize|won a reward)/i,             label: 'Prize \/ Reward Bait',         severity: 'high'   },
  { pattern: /wire transfer|gift card|western union|money order/i,                label: 'Unusual Financial Request',    severity: 'high'   },
  { pattern: /compromised|unauthorized (access|login|activity)/i,                label: 'Security Scare',               severity: 'high'   },
];

function ruleBasedBodyAnalysis(body, subject) {
  const text    = `${subject} ${body}`.toLowerCase();
  const tactics = [];

  for (const { pattern, label, severity } of URGENCY_PATTERNS) {
    const match = text.match(pattern);
    if (match) {
      tactics.push({ type: label, severity, evidence: match[0], description: `Detected pattern: "${match[0]}"` });
    }
  }

  const highCount      = tactics.filter(t => t.severity === 'high').length;
  const medCount       = tactics.filter(t => t.severity === 'medium').length;
  const bodyRiskScore  = Math.min(100, highCount * 20 + medCount * 10);
  const overallThreatLevel =
    bodyRiskScore >= 70 ? 'high' :
    bodyRiskScore >= 40 ? 'medium' :
    bodyRiskScore >= 10 ? 'low' : 'none';

  return {
    bodyRiskScore,
    overallThreatLevel,
    confidence: tactics.length > 0 ? 65 : 30,
    tactics,
    summary: tactics.length > 0
      ? `Rule-based analysis detected ${tactics.length} suspicious pattern(s), including ${tactics.slice(0, 2).map(t => t.type).join(' and ')}.`
      : 'No significant manipulation tactics detected in the email body.',
    source: 'rule-based',
  };
}

function clamp(val, min, max) {
  return Math.max(min, Math.min(max, val));
}
