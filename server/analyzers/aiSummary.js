// AI Summary — uses Groq (free, global) with rule-based fallback
// Get a free key at: https://console.groq.com/keys

const GROQ_API_URL = 'https://api.groq.com/openai/v1/chat/completions';
// Model priority: fast + capable → lighter fallback
const GROQ_MODELS = ['llama-3.3-70b-versatile', 'llama-3.1-8b-instant'];

function getGroqKey() {
  const key = process.env.GROQ_API_KEY;
  return key && key !== 'your-groq-api-key-here' ? key : null;
}

async function callGroq(apiKey, model, userMessage) {
  const res = await fetch(GROQ_API_URL, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model,
      messages: [{ role: 'user', content: userMessage }],
      max_tokens: 300,
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

export async function generateAISummary({
  verdict,
  riskScore,
  confidence,
  headerResult,
  scoredUrls,
  indicators,
  parsed,
  fallbackSummary,
  attachmentResults,
  ipReputations,
  bodyAnalysis,
}) {
  const apiKey = getGroqKey();
  if (!apiKey) return fallbackSummary;

  const maliciousUrls  = scoredUrls.filter(u => u.status === 'malicious').length;
  const suspiciousUrls = scoredUrls.filter(u => u.status === 'suspicious').length;
  const highIndicators = indicators.filter(i => i.severity === 'high');
  const medIndicators  = indicators.filter(i => i.severity === 'medium');
  const confidenceLabel = confidence >= 80 ? 'High' : confidence >= 50 ? 'Medium' : 'Low';
  const bodyThreat = bodyAnalysis?.overallThreatLevel ?? 'unknown';
  const bodyScore  = bodyAnalysis?.bodyRiskScore ?? 0;

  const prompt = `You are a cybersecurity assistant helping non-technical users understand phishing email analysis results.

Write a SHORT, CLEAR summary (3-5 sentences max) in plain English that a non-technical person can easily understand.
Do NOT use jargon. Do NOT use bullet points. Write in a friendly, reassuring tone.
You MUST mention the confidence level of the verdict (e.g. "We are highly confident this is phishing").
Explain what was found and what the person should do.

Analysis data:
- Email subject: "${parsed.subject || '(no subject)'}"
- Sender: "${parsed.from || 'unknown'}"
- Verdict: ${verdict.toUpperCase()} (risk score: ${riskScore}/100, confidence: ${confidence}% — ${confidenceLabel})
- SPF: ${headerResult.spfStatus}, DKIM: ${headerResult.dkimStatus}, DMARC: ${headerResult.dmarcStatus}
- Malicious URLs: ${maliciousUrls}, Suspicious URLs: ${suspiciousUrls}
- High-severity indicators: ${highIndicators.length} (${highIndicators.slice(0, 3).map(i => i.type).join(', ') || 'none'})
- Medium-severity indicators: ${medIndicators.length}
- Body threat level: ${bodyThreat} (score: ${bodyScore}/100)
- Body tactics detected: ${bodyAnalysis?.tactics?.length ?? 0}

Write the summary now:`;

  for (const model of GROQ_MODELS) {
    try {
      const text = await callGroq(apiKey, model, prompt);
      if (text && text.length >= 20) {
        console.log(`[AI Summary] Generated via Groq ${model}`);
        return text;
      }
    } catch (err) {
      console.warn(`[AI Summary] ${model} failed (${err.status ?? 'unknown'} ${err.message?.slice(0, 80)})`);
    }
  }

  console.warn('[AI Summary] All Groq models failed — using rule-based fallback.');
  return fallbackSummary;
}

export function isAIEnabled() {
  return !!getGroqKey();
}
