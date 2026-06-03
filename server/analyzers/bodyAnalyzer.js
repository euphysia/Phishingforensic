import { GoogleGenerativeAI } from '@google/generative-ai';

let genAI = null;

function getClient() {
  if (!genAI && process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'your-gemini-api-key-here') {
    genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
  }
  return genAI;
}

/**
 * SYSTEM PROMPT — Email Body Phishing Analysis
 *
 * This prompt instructs Gemini to act as a specialised phishing analyst that
 * examines the raw text/HTML content of an email body and returns a structured
 * JSON assessment of manipulation tactics, urgency signals, social-engineering
 * patterns, and credential-harvesting language.
 */
const BODY_ANALYSIS_SYSTEM_PROMPT = `
You are an expert cybersecurity analyst specialising in phishing email forensics.
Your task is to analyse the BODY TEXT of an email and identify social-engineering
and psychological manipulation tactics commonly used in phishing attacks.

ANALYSIS CATEGORIES you must evaluate:
1. **Urgency / Scarcity** — Language that pressures the reader to act immediately
   (e.g. "account will be suspended", "respond within 24 hours", "limited time").
2. **Fear / Threat** — Threats of negative consequences to force compliance
   (e.g. "your account has been compromised", "legal action will be taken").
3. **Authority Impersonation** — Pretending to be a trusted authority
   (e.g. bank, government agency, CEO, IT department, tech support).
4. **Credential Harvesting** — Requesting sensitive information such as passwords,
   PINs, credit card numbers, Social Security Numbers, or login credentials.
5. **Suspicious Calls to Action** — Directing the user to click a link, download
   a file, or reply with personal details.
6. **Reward / Prize Bait** — False promises of prizes, refunds, or rewards to lure
   the victim (e.g. "You have won", "claim your refund").
7. **Impersonation Language** — Mimicking legitimate business communication style
   to appear trustworthy while containing inconsistencies.
8. **Unusual Sender Requests** — Out-of-character requests, especially financial
   wire transfers, gift card purchases, or secrecy instructions.

OUTPUT FORMAT — Respond with ONLY valid JSON (no markdown, no explanation):
{
  "bodyRiskScore": <integer 0–100>,
  "overallThreatLevel": "<none|low|medium|high|critical>",
  "confidence": <integer 0–100>,
  "tactics": [
    {
      "type": "<tactic name from categories above>",
      "severity": "<low|medium|high>",
      "evidence": "<exact quote or short description from the email body>",
      "description": "<one sentence explaining why this is suspicious>"
    }
  ],
  "summary": "<2–3 sentence plain-English summary of the body analysis for a non-technical user>"
}

SCORING GUIDE:
- bodyRiskScore 0–20: No significant manipulation detected
- bodyRiskScore 21–45: Mild urgency or suspicious phrasing, could be legitimate
- bodyRiskScore 46–65: Multiple manipulation tactics, treat with caution
- bodyRiskScore 66–85: Strong phishing signals, very likely malicious
- bodyRiskScore 86–100: Classic phishing playbook, almost certainly malicious

CONFIDENCE reflects how certain you are given the available body text:
- Low confidence (< 50) if the body is very short, empty, or ambiguous
- High confidence (> 80) if you have clear, unambiguous evidence of tactics

If the body text is empty or too short to analyse, return bodyRiskScore: 0,
overallThreatLevel: "none", confidence: 10, tactics: [], and an appropriate summary.
`.trim();

/**
 * Analyse the email body text using Gemini AI.
 *
 * @param {object} params
 * @param {string} params.textBody   - Plain-text version of the email body
 * @param {string} params.htmlBody   - HTML version of the email body (stripped of tags)
 * @param {string} params.subject    - Email subject line
 * @param {string} params.from       - Sender address
 * @returns {Promise<BodyAnalysisResult>}
 */
export async function analyzeEmailBody({ textBody = '', htmlBody = '', subject = '', from = '' }) {
  const client = getClient();

  // Strip HTML tags to get readable text from HTML body
  const strippedHtml = htmlBody.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();

  // Use whichever is longer / more informative
  const bodyContent = textBody.length >= strippedHtml.length ? textBody : strippedHtml;
  const truncatedBody = bodyContent.slice(0, 4000); // Keep within token limits

  // Rule-based fallback (no Gemini key)
  if (!client) {
    return ruleBasedBodyAnalysis(truncatedBody, subject);
  }

  try {
    const userPrompt = `
Analyse the following email for phishing / social-engineering tactics.

Subject: "${subject}"
From: "${from}"

--- EMAIL BODY START ---
${truncatedBody || '(empty body)'}
--- EMAIL BODY END ---
`.trim();

    const model = client.getGenerativeModel({
      model: 'gemini-2.0-flash',
      systemInstruction: BODY_ANALYSIS_SYSTEM_PROMPT,
    });

    const result = await model.generateContent(userPrompt);
    const raw = result.response.text().trim();

    // Extract JSON (handle cases where model wraps in markdown code fences)
    const jsonMatch = raw.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error('No JSON object found in Gemini response');

    const parsed = JSON.parse(jsonMatch[0]);

    // Normalise and validate
    console.log(`[BodyAnalyzer] Gemini body analysis complete: score=${clamp(parsed.bodyRiskScore ?? 0, 0, 100)}, threat=${parsed.overallThreatLevel ?? 'none'}, tactics=${Array.isArray(parsed.tactics) ? parsed.tactics.length : 0}`);
    return {
      bodyRiskScore:     clamp(parsed.bodyRiskScore ?? 0, 0, 100),
      overallThreatLevel: parsed.overallThreatLevel ?? 'none',
      confidence:        clamp(parsed.confidence ?? 50, 0, 100),
      tactics:           Array.isArray(parsed.tactics) ? parsed.tactics : [],
      summary:           parsed.summary ?? '',
      source:            'gemini',
    };

  } catch (err) {
    console.warn('[BodyAnalyzer] Gemini body analysis failed, using rule-based fallback.');
    console.warn('[BodyAnalyzer] Error:', err.message);
    return ruleBasedBodyAnalysis(truncatedBody, subject);
  }
}

// ── Rule-based fallback (when Gemini is unavailable) ─────────────────────────

const URGENCY_PATTERNS = [
  { pattern: /urgent|immediately|right away|as soon as possible/i, label: 'Urgency Language', severity: 'medium' },
  { pattern: /account.*suspended|suspended.*account|account.*locked|locked.*account/i, label: 'Account Suspension Threat', severity: 'high' },
  { pattern: /expires? (today|in \d+ hours?|within \d+)/i, label: 'Expiry Pressure', severity: 'medium' },
  { pattern: /final notice|last chance|last warning/i, label: 'Final Warning Language', severity: 'high' },
  { pattern: /act now|limited time|don'?t delay/i, label: 'Scarcity / Time Pressure', severity: 'medium' },
  { pattern: /verify your (account|identity|email|password|information)/i, label: 'Verification Request', severity: 'high' },
  { pattern: /enter your (password|pin|credit card|social security|ssn)/i, label: 'Credential Harvesting', severity: 'high' },
  { pattern: /click (here|the link|below) (to verify|to confirm|now)/i, label: 'Suspicious Call to Action', severity: 'medium' },
  { pattern: /you (have won|are a winner|won a prize|won a reward)/i, label: 'Prize / Reward Bait', severity: 'high' },
  { pattern: /wire transfer|gift card|western union|money order/i, label: 'Unusual Financial Request', severity: 'high' },
  { pattern: /compromised|unauthorized (access|login|activity)/i, label: 'Security Scare', severity: 'high' },
];

function ruleBasedBodyAnalysis(body, subject) {
  const text = `${subject} ${body}`.toLowerCase();
  const tactics = [];

  for (const { pattern, label, severity } of URGENCY_PATTERNS) {
    const match = text.match(pattern);
    if (match) {
      tactics.push({
        type: label,
        severity,
        evidence: match[0],
        description: `Detected pattern associated with phishing: "${match[0]}"`,
      });
    }
  }

  const highCount   = tactics.filter(t => t.severity === 'high').length;
  const medCount    = tactics.filter(t => t.severity === 'medium').length;
  const bodyRiskScore = Math.min(100, highCount * 20 + medCount * 10);
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
      ? `Rule-based analysis detected ${tactics.length} suspicious pattern(s) in the email body, including ${tactics.slice(0, 2).map(t => t.type).join(' and ')}.`
      : 'No significant manipulation tactics detected in the email body.',
    source: 'rule-based',
  };
}

function clamp(val, min, max) {
  return Math.max(min, Math.min(max, val));
}
