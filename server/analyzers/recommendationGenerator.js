// Generates context-aware, email-specific next steps using Groq
const GROQ_API_URL = 'https://api.groq.com/openai/v1/chat/completions';

function getGroqKey() {
  const key = process.env.GROQ_API_KEY;
  return key && key !== 'your-groq-api-key-here' ? key : null;
}

async function callGroq(apiKey, prompt) {
  const res = await fetch(GROQ_API_URL, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: 'llama-3.3-70b-versatile',
      messages: [{ role: 'user', content: prompt }],
      max_tokens: 600,
      temperature: 0,
    }),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Groq ${res.status}: ${body.slice(0, 120)}`);
  }

  const data = await res.json();
  return data.choices?.[0]?.message?.content?.trim() ?? '';
}

/**
 * Generate specific, actionable next steps tailored to the email's content.
 * Returns an array of { step: string, detail: string } objects.
 */
export async function generateRecommendations({
  verdict,
  riskScore,
  parsed,
  indicators,
  scoredUrls,
  bodyAnalysis,
  headerResult,
}) {
  const apiKey = getGroqKey();
  if (!apiKey) return fallbackRecommendations(verdict, riskScore);

  const subject  = parsed.subject || '(no subject)';
  const from     = parsed.from    || 'unknown';
  const to       = parsed.to      || 'unknown';
  const replyTo  = parsed.replyTo || null;
  const bodyText = (parsed.textBody || parsed.htmlBody || '').replace(/<[^>]+>/g, ' ').slice(0, 1500);
  const highInds = indicators.filter(i => i.severity === 'high').map(i => i.type).join(', ') || 'none';
  const malUrls  = scoredUrls.filter(u => u.status === 'malicious').length;
  const tactics  = (bodyAnalysis?.tactics ?? []).map(t => t.type).join(', ') || 'none';

  const prompt = `You are a cybersecurity advisor helping a regular person who received a suspicious email.

Here is the analysis of the email:
- Subject: "${subject}"
- Sender: "${from}"
- Recipient: "${to}"${replyTo ? `\n- Reply-To: "${replyTo}" (replies go to a DIFFERENT address than the sender)` : ''}
- Verdict: ${verdict.toUpperCase()} (risk score: ${riskScore}/100)
- High-severity indicators: ${highInds}
- Malicious URLs found: ${malUrls}
- Body manipulation tactics: ${tactics}
- SPF: ${headerResult.spfStatus}, DKIM: ${headerResult.dkimStatus}
- Email body excerpt: "${bodyText.slice(0, 800)}"

Generate exactly 4 specific, actionable next steps for the recipient. The steps must be:
1. SPECIFIC to this email's actual content and context (e.g. if it's about a fee, mention verifying through the official portal; if it's about a bank, name the verification method; if it claims to be from a company, suggest how to verify that)
2. Practical and concrete — not generic security advice
3. Written for a non-technical person
4. In order of priority (most important first)

Respond ONLY with valid JSON — no markdown, no explanation:
[
  { "step": "<short action title>", "detail": "<1-2 sentence specific instruction>", "priority": "high|medium|low" },
  ...
]`;

  try {
    const raw  = await callGroq(apiKey, prompt);
    const match = raw.match(/\[[\s\S]*\]/);
    if (!match) throw new Error('No JSON array in response');
    const steps = JSON.parse(match[0]);
    if (!Array.isArray(steps) || steps.length === 0) throw new Error('Empty steps array');
    console.log(`[Recommendations] Generated ${steps.length} AI-powered steps for "${subject}"`);
    return steps.slice(0, 5); // cap at 5
  } catch (err) {
    console.warn(`[Recommendations] AI generation failed (${err.message}), using fallback.`);
    return fallbackRecommendations(verdict, riskScore);
  }
}

function fallbackRecommendations(verdict, riskScore) {
  if (verdict === 'phishing' || riskScore >= 75) {
    return [
      { step: 'Do not click any links', detail: 'Avoid clicking any links or buttons in this email. They may redirect to credential-harvesting pages.', priority: 'high' },
      { step: 'Do not reply or call back', detail: 'Do not reply to this email or call any phone numbers mentioned. The sender may be impersonating a legitimate organisation.', priority: 'high' },
      { step: 'Verify through official channels', detail: 'If the email claims to be from a known organisation, contact them directly using the number or website you already know — not what is in the email.', priority: 'high' },
      { step: 'Report and delete', detail: 'Mark the email as phishing in your email client and permanently delete it.', priority: 'medium' },
    ];
  } else if (verdict === 'suspicious' || riskScore >= 45) {
    return [
      { step: 'Do not act immediately', detail: 'Treat this email with caution. Do not follow any instructions until you have independently verified the sender.', priority: 'high' },
      { step: 'Verify the sender', detail: 'Look up the organisation\'s official contact details and confirm whether they sent this email.', priority: 'high' },
      { step: 'Avoid attachments and links', detail: 'Do not open attachments or click links until the email is confirmed legitimate.', priority: 'medium' },
      { step: 'Monitor for follow-up', detail: 'If you have already interacted with this email, monitor your accounts for unusual activity.', priority: 'low' },
    ];
  } else {
    return [
      { step: 'Email appears clean', detail: 'No significant phishing indicators were detected. Standard caution still applies.', priority: 'low' },
      { step: 'Stay alert to follow-ups', detail: 'Even clean emails can be part of a multi-step attack. Verify any unusual requests through official channels.', priority: 'low' },
    ];
  }
}
