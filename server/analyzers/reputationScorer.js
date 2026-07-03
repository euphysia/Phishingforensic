/**
 * Sprint 4: Unified Reputation Scorer
 * Combines VirusTotal, URLScan, AbuseIPDB, PhishTank, attachment risks,
 * and heuristic signals into a single weighted risk score.
 *
 * Source trustworthiness weights:
 *   VirusTotal    — 0.25 (multi-engine, high coverage)
 *   URLScan.io    — 0.15 (behavioral, screenshot)
 *   PhishTank     — 0.20 (verified phishing DB, high precision)
 *   AbuseIPDB     — 0.15 (IP reputation, sender context)
 *   Attachments   — 0.10 (file risk signals)
 *   Heuristics    — 0.15 (pattern-based indicators)
 */

/**
 * Compute a unified reputation score (0–100) and verdict for a URL.
 * 0 = definitely malicious, 100 = clean.
 * @param {object} vtResult       - VirusTotal result
 * @param {object} urlScanResult  - URLScan result
 * @param {object} extractedUrl   - ExtractedUrl object (isShortener, isIpBased)
 * @param {Array}  phishingFlags  - PhishingIndicator[] for this URL
 * @param {object} phishTankResult - PhishTank result (Sprint 4)
 * @returns {{ score: number, status: 'malicious'|'suspicious'|'safe', category: string }}
 */
export function scoreUrl(vtResult, urlScanResult, extractedUrl, phishingFlags = [], phishTankResult = null, domainAgeResult = null) {
  let score = 100; // Start clean
  const categories = [];

  // ── VirusTotal weight ─────────────────────────────────────────────────────
  if (vtResult) {
    const { detections, total } = vtResult;
    if (total > 0) {
      const vtRatio = detections / total;
      if (vtRatio >= 0.1) {
        score -= Math.round(vtRatio * 55); // up to -55 pts
        if (vtResult.categories?.length > 0) categories.push(...vtResult.categories);
      }
    }
  }

  // ── URLScan weight ────────────────────────────────────────────────────────
  if (urlScanResult) {
    const { score: urlScore, malicious } = urlScanResult;
    if (malicious) score -= 35;
    else if (urlScore > 50) score -= Math.round((urlScore - 50) * 0.45);
    if (urlScanResult.brands?.length > 0) categories.push('Brand Impersonation');
    if (urlScanResult.redirected) score -= 5;
  }

  // ── PhishTank weight (Sprint 4) — high precision, verified phishing DB ────
  if (phishTankResult?.available) {
    if (phishTankResult.isPhishing && phishTankResult.verified) {
      // Verified by PhishTank community — very high confidence
      score -= 70;
      categories.push('Verified Phishing URL');
      if (phishTankResult.target) categories.push(`Impersonating ${phishTankResult.target}`);
    } else if (phishTankResult.isPhishing) {
      // In DB but not community-verified
      score -= 45;
      categories.push('Known Phishing URL');
    } else if (phishTankResult.inDatabase && !phishTankResult.isPhishing) {
      // In DB but marked invalid — slight negative signal
      score -= 10;
    }
  }

  // ── Heuristic flags weight ────────────────────────────────────────────────
  for (const flag of phishingFlags) {
    if (flag.severity === 'high') score -= 20;
    else if (flag.severity === 'medium') score -= 10;
    else score -= 5;

    if (!categories.includes(flag.type)) categories.push(flag.type);
  }

  // ── Domain age penalties ──────────────────────────────────────────────────
  if (domainAgeResult?.ageRisk === 'high') {
    score -= 15;
    categories.push('Newly Registered Domain (<30 days)');
  } else if (domainAgeResult?.ageRisk === 'medium') {
    score -= 8;
    categories.push('Recently Registered Domain (<90 days)');
  }

  // ── Structural penalties ──────────────────────────────────────────────────
  if (extractedUrl?.isIpBased) score -= 15;
  if (extractedUrl?.isShortener) score -= 8;

  score = Math.max(0, Math.min(100, score));

  // ── Map score to status ───────────────────────────────────────────────────
  let status;
  if (score <= 30) status = 'malicious';
  else if (score <= 60) status = 'suspicious';
  else status = 'safe';

  return {
    score,
    status,
    category: categories.slice(0, 4).join(', ') || 'Unknown',
  };
}

/**
 * Sprint 4: Compute unified email risk score integrating all modules.
 * Weights reflect source trustworthiness and intelligence recency.
 *
 * @param {object} headerResult      - Output from headerAnalyzer
 * @param {Array}  urlResults        - Array of scored URL results
 * @param {Array}  allIndicators     - All phishing indicators
 * @param {Array}  ipReputations     - AbuseIPDB results (Sprint 4)
 * @param {Array}  attachmentResults - Attachment analysis results (Sprint 3)
 * @returns {{ riskScore, confidence, verdict, severity, scoreBreakdown }}
 */
export function computeEmailRiskScore(
  headerResult,
  urlResults,
  allIndicators,
  ipReputations     = [],
  attachmentResults = [],
  bodyAnalysis      = null
) {
  const breakdown = {};

  // ── Header (always present, base weight 0.30) ─────────────────────────────
  const headerRisk = 100 - (headerResult?.senderReputation ?? 100);
  breakdown.header = { risk: headerRisk, weight: 0.30 };

  // ── URL score — only included when email actually has URLs ────────────────
  if (urlResults.length > 0) {
    const worstScore = Math.min(...urlResults.map(u => u.score ?? 100));
    breakdown.url = { risk: 100 - worstScore, weight: 0.30 };
  }

  // ── AbuseIPDB — only included when sender IPs were found ─────────────────
  if (ipReputations.length > 0) {
    let ipRisk = Math.max(...ipReputations.map(r => r.abuseScore ?? 0));
    if (ipReputations.some(r => r.isTor)) ipRisk = Math.min(100, ipRisk + 30);
    breakdown.ipReputation = { risk: ipRisk, weight: 0.15 };
  }

  // ── Attachments — only included when email has attachments ───────────────
  if (attachmentResults.length > 0) {
    const statusScores = { safe: 0, suspicious: 50, malicious: 100 };
    let attachmentRisk = Math.max(...attachmentResults.map(a => statusScores[a.status] ?? 0));
    if (attachmentResults.some(a => a.vtResult?.detections > 0)) {
      attachmentRisk = Math.min(100, attachmentRisk + 20);
    }
    breakdown.attachments = { risk: attachmentRisk, weight: 0.10 };
  }

  // ── Body analysis — direct AI score (most accurate signal for body-only threats)
  // bodyRiskScore from Groq is used directly so the qualitative summary and the
  // numeric score always agree. Body tactics in allIndicators are kept for display
  // but excluded from indicator scoring here to avoid double-counting.
  if (bodyAnalysis?.bodyRiskScore > 0) {
    breakdown.body = { risk: bodyAnalysis.bodyRiskScore, weight: 0.25 };
  }

  // ── Indicator score — hard indicators only (body-ai source excluded) ──────
  // Body-sourced tactics are already represented by bodyRiskScore above.
  const hardInds      = allIndicators.filter(i => i.source !== 'body-ai');
  const indicatorRisk = Math.min(100,
    hardInds.filter(i => i.severity === 'high').length   * 20 +
    hardInds.filter(i => i.severity === 'medium').length * 10
  );
  breakdown.indicators = { risk: indicatorRisk, weight: 0.20 };

  // ── Normalize weights across only active sources, then compute score ──────
  const entries     = Object.values(breakdown);
  const totalWeight = entries.reduce((s, e) => s + e.weight, 0);
  const riskScore   = Math.round(
    Math.min(100, entries.reduce((sum, e) => sum + e.risk * (e.weight / totalWeight), 0))
  );

  // ── Confidence: more active signal sources = higher confidence ────────────
  const signalCount = Object.keys(breakdown).length; // only counts active sources
  const confidence = Math.min(98, 55 + signalCount * 9);

  // ── Verdict & severity ────────────────────────────────────────────────────
  let verdict, severity;
  if (riskScore >= 70) {
    verdict  = 'phishing';
    severity = riskScore >= 88 ? 'critical' : 'high';
  } else if (riskScore >= 30) {
    verdict  = 'suspicious';
    severity = riskScore >= 55 ? 'medium' : 'low';
  } else {
    verdict  = 'clean';
    severity = 'low';
  }

  return { riskScore, confidence, verdict, severity, scoreBreakdown: breakdown };
}

/**
 * Sprint 4: Score a sender IP using AbuseIPDB result.
 * @param {object} ipResult - From checkIpReputation()
 * @returns {{ risk: number, verdict: string, summary: string }}
 */
export function scoreIpReputation(ipResult) {
  if (!ipResult?.available) {
    return { risk: 0, verdict: 'unknown', summary: 'IP reputation data unavailable' };
  }

  const score = ipResult.abuseScore ?? 0;
  let verdict;
  if (score >= 75) verdict = 'malicious';
  else if (score >= 25) verdict = 'suspicious';
  else verdict = 'clean';

  // Recency bonus: reports in last 30 days weigh more
  let adjustedScore = score;
  if (ipResult.lastReportedAt) {
    const daysSince = (Date.now() - new Date(ipResult.lastReportedAt).getTime()) / 86400000;
    if (daysSince <= 7)  adjustedScore = Math.min(100, score * 1.3);
    else if (daysSince <= 30) adjustedScore = Math.min(100, score * 1.1);
  }

  return {
    risk:    Math.round(adjustedScore),
    verdict,
    summary: ipResult.summary || `IP ${ipResult.ip}: abuse score ${score}%`,
  };
}
