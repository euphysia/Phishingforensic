import { GoogleGenerativeAI } from '@google/generative-ai';

let genAI = null;

function getClient() {
  if (!genAI && process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'your-gemini-api-key-here') {
    genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
  }
  return genAI;
}

/**
 * Generate a plain-English summary using Gemini AI.
 * Falls back to the rule-based summary if Gemini is unavailable.
 *
 * @param {object} params
 * @param {string} params.verdict  - 'phishing' | 'suspicious' | 'clean'
 * @param {number} params.riskScore
 * @param {number} params.confidence
 * @param {object} params.headerResult
 * @param {Array}  params.scoredUrls
 * @param {Array}  params.indicators
 * @param {object} params.parsed   - parsed email fields
 * @param {string} params.fallbackSummary - rule-based summary to fall back on
 * @returns {Promise<string>}
 */
export async function generateGeminiSummary({
  verdict,
  riskScore,
  confidence,
  headerResult,
  scoredUrls,
  indicators,
  parsed,
  fallbackSummary,
}) {
  const client = getClient();
  if (!client) return fallbackSummary;

  try {
    const maliciousUrls = scoredUrls.filter(u => u.status === 'malicious').length;
    const suspiciousUrls = scoredUrls.filter(u => u.status === 'suspicious').length;
    const highIndicators = indicators.filter(i => i.severity === 'high');
    const medIndicators  = indicators.filter(i => i.severity === 'medium');

    const prompt = `
You are a cybersecurity assistant helping non-technical users understand phishing email analysis results.

Write a SHORT, CLEAR summary (3-5 sentences max) in plain English that a non-technical person can easily understand.
Do NOT use jargon. Do NOT use bullet points. Write in a friendly, reassuring tone.
Explain what was found and what the person should do.

Here is the analysis data:
- Email subject: "${parsed.subject || '(no subject)'}"
- Sender: "${parsed.from || 'unknown'}"
- Overall verdict: ${verdict.toUpperCase()} (risk score: ${riskScore}/100, confidence: ${confidence}%)
- SPF authentication: ${headerResult.spfStatus}
- DKIM authentication: ${headerResult.dkimStatus}
- DMARC authentication: ${headerResult.dmarcStatus}
- Suspicious URLs found: ${suspiciousUrls}
- Malicious URLs found: ${maliciousUrls}
- High-severity threat indicators: ${highIndicators.length} (${highIndicators.slice(0, 3).map(i => i.type).join(', ') || 'none'})
- Medium-severity indicators: ${medIndicators.length}
- Total phishing indicators: ${indicators.length}

Write the summary now:
`.trim();

    const model = client.getGenerativeModel({ model: 'gemini-1.5-flash' });
    const result = await model.generateContent(prompt);
    const text = result.response.text().trim();

    if (!text || text.length < 20) return fallbackSummary;
    return text;

  } catch (err) {
    console.warn('[Gemini] Summary generation failed, using fallback:', err.message);
    
    // If it's a 404, let's list available models to debug
    if (err.message.includes('404')) {
      try {
        const result = await client.listModels();
        const modelNames = result.models.map(m => m.name.replace('models/', ''));
        console.log('[Gemini] Available models for this key:', modelNames.join(', '));
      } catch (listErr) {
        // Ignore listing errors
      }
    }
    
    return fallbackSummary;
  }
}

/**
 * Returns true if the Gemini API key is configured.
 */
export function isGeminiEnabled() {
  return !!(
    process.env.GEMINI_API_KEY &&
    process.env.GEMINI_API_KEY !== 'your-gemini-api-key-here'
  );
}
