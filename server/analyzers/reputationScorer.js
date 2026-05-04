/**
 * Composite reputation scorer combining VirusTotal, URLScan, and heuristic signals.
 */

/**
 * Compute a unified reputation score (0–100) and verdict for a URL.
 * 0 = definitely malicious, 100 = clean.
 * @param {object} vtResult - VirusTotal result
 * @param {object} urlScanResult - URLScan result
 * @param {object} extractedUrl - ExtractedUrl object (isShortener, isIpBased)
 * @param {Array} phishingFlags - PhishingIndicator[] for this URL
 * @returns {{ score: number, status: 'malicious'|'suspicious'|'safe', category: string }}
 */
export function scoreUrl(vtResult, urlScanResult, extractedUrl, phishingFlags = []) {
  let score = 100; // Start clean
  const categories = [];

  // ── VirusTotal weight (40% of total signal) ───────────────────────────────
  if (vtResult) {
    const { detections, total } = vtResult;
    if (total > 0) {
      const vtRatio = detections / total;
      if (vtRatio >= 0.1) {       // 10%+ detections
        score -= Math.round(vtRatio * 60); // up to -60 pts
        if (vtResult.categories?.length > 0) categories.push(...vtResult.categories);
      }
    }
  }

  // ── URLScan weight (30% of total signal) ──────────────────────────────────
  if (urlScanResult) {
    const { score: urlScore, malicious } = urlScanResult;
    if (malicious) score -= 40;
    else if (urlScore > 50) score -= Math.round((urlScore - 50) * 0.5); // up to -25
    if (urlScanResult.brands?.length > 0) categories.push('Brand Impersonation');
    if (urlScanResult.redirected) score -= 5;
  }

  // ── Heuristic flags weight (30% of total signal) ──────────────────────────
  for (const flag of phishingFlags) {
    if (flag.severity === 'high') score -= 20;
    else if (flag.severity === 'medium') score -= 10;
    else score -= 5;

    if (!categories.includes(flag.type)) categories.push(flag.type);
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
    category: categories.slice(0, 3).join(', ') || 'Unknown',
  };
}

/**
 * Compute overall email risk score from all analysis modules.
 * @param {object} headerResult - Output from headerAnalyzer
 * @param {Array} urlResults - Array of scored URL results
 * @param {Array} allIndicators - All phishing indicators (header + content + URL)
 * @returns {{ riskScore: number, confidence: number, verdict: string, severity: string }}
 */
export function computeEmailRiskScore(headerResult, urlResults, allIndicators) {
  let score = 0;
  let weight = 0;

  // Header score (35% weight)
  const headerScore = 100 - (headerResult.senderReputation || 100);
  score += headerScore * 0.35;
  weight += 0.35;

  // URL score (45% weight)
  if (urlResults.length > 0) {
    const worstUrlScore = Math.min(...urlResults.map(u => u.score));
    const urlRisk = 100 - worstUrlScore;
    score += urlRisk * 0.45;
  }
  weight += 0.45;

  // Indicator count score (20% weight)
  const highCount = allIndicators.filter(i => i.severity === 'high').length;
  const medCount = allIndicators.filter(i => i.severity === 'medium').length;
  const indicatorScore = Math.min(100, highCount * 20 + medCount * 10);
  score += indicatorScore * 0.20;
  weight += 0.20;

  const riskScore = Math.round(Math.min(100, score));
  
  // Confidence based on how many signals we have
  const signalCount = (urlResults.length > 0 ? 1 : 0) + (allIndicators.length > 0 ? 1 : 0) + 1;
  const confidence = Math.min(98, 70 + signalCount * 9);

  // Verdict
  let verdict, severity;
  if (riskScore >= 75) {
    verdict = 'phishing';
    severity = riskScore >= 90 ? 'critical' : 'high';
  } else if (riskScore >= 45) {
    verdict = 'suspicious';
    severity = 'medium';
  } else {
    verdict = 'clean';
    severity = 'low';
  }

  return { riskScore, confidence, verdict, severity };
}
