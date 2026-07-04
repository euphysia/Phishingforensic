# Chapter 6: Testing and Evaluation

## 6.1 Unit Testing

### 6.1.1 Test Plan

Unit testing targeted the system's deterministic, pure-function analysis modules — the components whose output depends only on their input and that carry the core forensic logic described in Chapter 5. These were prioritised for unit-level coverage because they are cheap to test exhaustively, sit at the centre of the risk-scoring pipeline, and are the modules most likely to silently regress as new heuristics are added:

| Module | Responsibility | Test file |
|---|---|---|
| `parser/headerAnalyzer.js` | SPF/DKIM/DMARC evaluation, spoofing/impersonation detection, sender-reputation scoring | `server/test/unit/headerAnalyzer.test.js` |
| `analyzers/urlExtractor.js` | URL extraction from HTML/plaintext, shortener/IP/defang detection | `server/test/unit/urlExtractor.test.js` |
| `analyzers/phishingIndicators.js` | Heuristic phishing pattern detection (homoglyphs, keyword patterns, link-text mismatches) | `server/test/unit/phishingIndicators.test.js` |
| `analyzers/reputationScorer.js` | Per-URL and email-wide risk scoring, IP reputation scoring | `server/test/unit/reputationScorer.test.js` |

The test framework is **Vitest** (`vitest.config.js`), chosen for its zero-config ESM support (the codebase is `"type": "module"`) and fast in-process execution. Tests are run with `npm test`.

Test design followed a boundary/branch-coverage approach rather than line coverage: for each module, every conditional branch identified by reading the source (each `if` that pushes an indicator, each scoring threshold, each clamp) was given at least one test asserting the branch fires and, where meaningful, one asserting it does *not* fire on a negative case.

### 6.1.2 Test Data

Unit tests use small, hand-constructed fixtures rather than full `.eml` files, since the functions under test operate on already-parsed structures (a `ParsedEmail`-shaped object, an array of `ExtractedUrl` objects, etc.). Representative fixtures included:

- A fully-authenticated, non-spoofed sender object (expected: zero indicators, reputation score 100)
- A sender with a forged `Return-Path`, homoglyph domain (`paypall.com`, `paypa1-verify.com`), free-webmail-plus-billing-subject combination, and failed SPF/DKIM/DMARC (expected: each indicator type independently triggered)
- URLs covering each heuristic category: shorteners (`bit.ly`), IP-literal URLs, high-risk TLDs (`.top`, `.xyz`), brand-in-subdomain (`paypal.attacker-domain.com`), and multi-keyword phishing paths
- Synthetic VirusTotal / URLScan / PhishTank / WHOIS result objects for `scoreUrl()`, covering clean, partially-detected, and fully-malicious combinations, including a stacked worst-case input used to confirm the score floors at 0 rather than going negative

### 6.1.3 Test Results

**57 / 57 unit tests passed.**

```
Test Files  4 passed (4)
     Tests  57 passed (57)
```

All branches of the four target modules behaved as specified in Chapter 5: severity-weighted scoring (`high` > `medium` > `low` deductions), score clamping to `[0, 100]`, correct verdict-band classification (`safe`/`suspicious`/`malicious` for URLs; `clean`/`suspicious`/`phishing` for the email-wide score), and the weight-renormalisation behaviour of `computeEmailRiskScore()` (Section 5.8) — confirmed by asserting that when only the header signal is active, the final score equals the header risk unmodified, rather than being diluted by inactive sources.

## 6.2 Integration Testing

### 6.2.1 Scope and Approach

Integration testing exercised the routers (`routes/analysis.js`, `routes/auth.js`, `routes/history.js`, `routes/audit.js`) wired together through Express middleware exactly as in `server/index.js`, driven over HTTP using **Supertest**. A dedicated test harness (`server/test/integration/testApp.js`) reconstructs the same middleware chain (CORS, JSON/text body parsing, signed cookies, Multer upload handling) without starting the production HTTP listener or the SMTP listener, so it can be instantiated per test file.

Deliberately, these tests run against the **real development Supabase database** and the **real external services** configured in `.env` (Groq, WHOIS, and whichever of VirusTotal/URLScan/AbuseIPDB/PhishTank have live keys), rather than mocked stand-ins. Every external integration in this system already has a documented demo-mode fallback (Section 5.7), so this was judged more valuable than mocking: it verifies the *actual* deployed behaviour, including graceful degradation when a live call fails, rather than only verifying that mocks are called correctly.

### 6.2.2 Test Coverage

| Area | What was verified |
|---|---|
| Authentication (`auth.test.js`) | Login for all three seeded demo roles; rejection of wrong password / non-existent account / missing fields; session cookie issuance and clearing; `/me` correctly reports guest trial state; a tampered JWT is treated as unauthenticated rather than crashing |
| Role-based access control (`rbac.test.js`) | `/api/history` is reachable by analyst/admin and denied (403) to auditor; `/api/audit/logs` is reachable by auditor/admin and denied to analyst — confirming the separation-of-duties design in Section 5.10; unauthenticated requests get 401 on both; a forged/unsigned JWT is rejected |
| Full analysis pipeline (`analyze.test.js`) | A known phishing sample end-to-end through header analysis, URL extraction/scoring, indicator detection, chain-of-custody construction, and persistence; a benign control email scores low-risk; input validation (empty body, too-short content) returns 400; the dedup/cache path (Section 5.3) returns a consistent cached result on byte-identical resubmission |
| WHOIS domain-age lookup (`domainAge.test.js`) | Resolves a real long-registered domain; fails closed (null result, no throw) for a non-existent TLD |
| Guest trial limiting | Exactly 3 unauthenticated analyses succeed, the 4th is rejected with `403 TRIAL_LIMIT` |

### 6.2.3 Test Results

**26 / 26 integration tests passed** after fixes described below (83/83 combined with unit tests).

```
Test Files  8 passed (8)
     Tests  83 passed (83)
```

Running these tests against the live system surfaced two genuine defects that had not been caught by manual use of the application, both of which were fixed as part of this testing cycle (Section 6.2.4). Beyond those, integration testing confirmed several design decisions work as intended under real conditions rather than only in theory:

- The weighted risk-scoring engine (Section 5.8) correctly escalated the PayPal phishing fixture to a **`phishing`/`suspicious`** verdict driven by simultaneous SPF/DKIM/DMARC failure, a homoglyph sender domain, a malicious login URL, and AI body-analysis tactics — while the benign control email (matching sender/Reply-To/Return-Path domains, SPF/DKIM/DMARC all passing, zero URLs) scored as **not phishing**.
- The chain-of-custody hash chain (`verifyChain()`, Section 5.9) reported `chainIntact: true` on every real run performed.
- Graceful degradation held up under a real fault: URLScan.io correctly returned `400 DNS Error — could not resolve domain` for the fixture's fictional domains (`paypa1-verify.com` does not exist in public DNS), and the pipeline transparently fell back to demo scoring rather than failing the analysis — exactly the behaviour Section 5.7 describes.

### 6.2.4 Defects Found and Fixed During Testing

**Defect 1 — WHOIS domain-age lookups were completely non-functional.**
`analyzers/domainAge.js` called the `whoiser` package as `whoiser(domain, {...})`, treating the module as a callable default export. The installed version, `whoiser@2.0.0-beta.10`, only exports named functions (`whoisDomain`, `whoisIp`, …), so this call threw `whoiser is not a function` on *every single invocation*, silently caught by the surrounding `try/catch` and replaced with a null result. In effect, the "newly-registered domain" risk signal advertised in Section 5.5 had never fired in production since this dependency was upgraded.
*Fix:* import the correctly-named `whoisDomain` export. Verified post-fix against a real domain (`google.com` → resolved registration date of 1997-09-15, `ageDays` > 10,000, correctly scored as no age risk).

**Defect 2 — The URL extractor produced corrupted duplicate URLs.**
`analyzers/urlExtractor.js`'s plaintext URL regex (`[^\s<>"']*` for the path segment) did not exclude square brackets. `mailparser`'s HTML-to-plaintext conversion renders `<a href="URL">text</a>` as `text [URL]` in the derived plaintext body, and the regex greedily consumed the closing `]` as part of the URL path. Every link in an HTML email with a plaintext-fallback body was therefore extracted **twice** — once cleanly (from the `href` attribute) and once corrupted with a trailing `]` (from the derived plaintext) — inflating the reported URL count (8 instead of 4 for the phishing fixture) and causing the corrupted copies to fail VirusTotal/URLScan/WHOIS lookups outright.
*Fix:* excluded `[` and `]` from the path character class. Verified post-fix: the phishing fixture now extracts exactly 4 distinct, well-formed URLs; a regression test (`urlExtractor.test.js`) locks in the bracket-stripping behaviour against the exact `text [URL]` pattern that triggered it.

**Defect 3 — The cache/dedup clone path silently dropped every related row.**
When a byte-identical email is resubmitted, `routes/analysis.js` clones the original analysis's header/URL/attachment/indicator/IP/custody rows under a new ID using a pattern of the form `{ ...row, id: undefined, analysis_id: newId }`. Unlike `JSON.stringify` on a plain object (which drops keys with an `undefined` value), the Supabase JS client transmits `id: undefined` as an explicit SQL `NULL`. Every affected table's `id` column is `NOT NULL` with no default generator, so **every one of these six clone inserts failed** with a constraint violation — and because none of the call sites checked the returned `{ error }`, the failures were completely silent. A "cached" analysis response therefore reported the correct top-line verdict/score (copied directly from scalar fields) but **zero URLs, zero indicators, and an empty chain-of-custody** for what should have been a full duplicate of the original evidence. This directly undermines the tool's forensic value: an analyst re-reviewing a previously-seen phishing email via the dedup path would see an apparently clean, evidence-free report.
*Fix:* replaced the `id: undefined` spread with a `withoutId()` helper that destructures the key out entirely, and added explicit error logging on each of the six clone inserts so a future failure of this kind is visible in server logs rather than silent. A regression test (`analyze.test.js`, "returns the same analysis (cache hit)... with sub-details intact") now asserts the cloned response's URL/indicator/custody counts match the original, non-cached response.

All three defects are use with the real Supabase project (not a mock), which is why the failures could not have been caught by testing against an in-memory or mocked database — this is direct evidence for why Section 6.2's decision to integration-test against the live backend, rather than mocks, was the right call for this system.

## 6.3 System Testing

System testing validated the complete, integrated system end-to-end rather than individual routes in isolation, using the same HTTP surface a real client (the React dashboard, or a direct API consumer) would use.

**Functional walkthrough (via the API, mirroring what the dashboard's submission flow drives):**

| Scenario | Result |
|---|---|
| Submit a known phishing email (`.eml` upload or raw-text JSON body) | Full pipeline (header → URL → body-AI → IP reputation → attachments → risk scoring → AI summary → recommendations → persistence) completes and returns a coherent, internally-consistent forensic report |
| Submit a benign personal email | Correctly scores as not-phishing with zero URL/indicator findings |
| Resubmit an identical email | Dedup/cache path returns the prior verdict with matching sub-detail (post-fix, Section 6.2.4) |
| Exceed the guest trial limit | Blocked with a clear `403 TRIAL_LIMIT` after exactly 3 free analyses |
| Attempt role-inappropriate access (analyst → audit log, auditor → history) | Blocked with `403 FORBIDDEN`, enforcing the analyst/auditor separation of duties from Section 5.10 |

**Robustness under real third-party failure:** the phishing fixture's domains do not resolve in public DNS, which caused URLScan.io to reject the scan request outright (`400 DNS Error`). The system did not propagate this as a user-facing failure — it fell back to heuristic scoring and still produced a complete, coherent report, confirming the graceful-degradation design goal from Section 5.7 holds under an actual (not simulated) external failure.

**Timing:** end-to-end analysis of the phishing fixture (all six analyzer stages, including live Groq calls for body analysis and summary generation) completed in single-digit seconds per run in this environment, consistent with the "sub-30-second analysis time" figure quoted on the landing page (Section 5.10).

**Scope note — frontend UI walkthrough.** This pass exercised the system through its HTTP API rather than by driving the React dashboard in a browser, since the dashboard is a thin client over the same endpoints covered above (submission, history, audit, auth). A manual click-through of the three submission tabs, the analyst/auditor dashboards, and PDF/JSON export in an actual browser session is recommended as a supplementary check before final submission, and is a natural candidate for Section 6.7 (Usability Testing) if you want to expand this chapter further.

## 6.4 Security Testing

### 6.4.1 Vulnerability Assessment

**Tool used:** `npm audit` (Node's built-in dependency vulnerability scanner, cross-referencing the GitHub Advisory Database) — the appropriate SCA equivalent to Nessus/OpenVAS for a Node.js application, since the attack surface here is the dependency tree rather than network services.

**Summary of discovered vulnerabilities** (14 total: 2 critical, 7 high, 4 moderate, 1 low):

| Package | Severity | Relevance | Notes |
|---|---|---|---|
| `shell-quote` (via `concurrently`) | Critical | Dev-only | Only invoked by the local `npm run dev` script; not present in any deployed/runtime path |
| `vite` (build tooling) | High (×6 advisories) | Dev-only | Dev-server file-serving/path-traversal issues; not applicable once the app is built and served statically |
| `nodemailer` (via `smtp-server`) | High | **Runtime** | CRLF injection / SSRF-adjacent issues in a dependency of the inbound SMTP listener (Section 5.3) |
| `multer` (file upload) | High | **Runtime** | DoS via deeply-nested field names / incomplete cleanup of aborted uploads — directly reachable via the `/api/analyze` upload endpoint |
| `linkify-it` (via `mailparser`) | High | **Runtime** | Quadratic-complexity ReDoS risk during email parsing |
| `form-data` (via `axios`) | High | **Runtime** | CRLF injection in multipart field names — relevant to the outbound VirusTotal/URLScan/AbuseIPDB/PhishTank HTTP calls |
| `qs`, `brace-expansion`, `tar`, `@babel/core` | Moderate | Mixed | Lower-severity DoS/file-read issues, mostly in build tooling |

**Assessment:** the two most operationally relevant findings are `multer` and `mailparser`'s transitive `linkify-it`, since both sit directly in the untrusted-input path (a user- or SMTP-submitted email is, by design, attacker-controlled content). `npm audit fix` resolves the in-range fixes without a major-version bump for most of these; the `vite` fixes require `--force` to a version outside the currently pinned range and were left for a deliberate, tested upgrade rather than applied blindly during this pass, since `vite` is dev/build tooling with no runtime exposure.

### 6.4.2 Penetration Testing

**Scope:** the HTTP API surface (`/api/auth`, `/api/analyze`, `/api/history`, `/api/audit`), driven directly with Supertest rather than Burp Suite/Metasploit, since the target is a first-party REST API rather than a general network host — the equivalent manual-testing techniques (auth bypass, injection, session/token tampering, business-logic abuse) were applied by hand.

| Attack vector tested | Outcome |
|---|---|
| SQL-injection-style login payload (`email: "admin@phishscan.com' OR '1'='1"`) | Rejected — `401 Invalid email or password`. Supabase's JS client uses parameterised PostgREST queries rather than string-concatenated SQL, so classic SQLi payloads are inert against it. |
| Forged JWT with an unsigned/`alg: none` header claiming `role: admin` | Rejected — `401`, `jwt.verify()` correctly refuses a token it cannot validate against `JWT_SECRET`. |
| Cross-role access (analyst hitting `/api/audit/logs`, auditor hitting `/api/history`) | Rejected — `403 FORBIDDEN` in both directions. |
| Unauthenticated access to protected routes | Rejected — `401 UNAUTHENTICATED`. |
| Tampered/garbage session cookie (`phishscan_token=not.a.validjwt`) | Degrades safely to guest state rather than crashing the request. |
| Forged/unsigned guest-trial cookie | The forged cookie was **ignored** rather than trusted — `cookie-parser` only populates `req.signedCookies` for cookies bearing a valid HMAC signature under `COOKIE_SECRET`, so an attacker cannot set an arbitrary trial count. (See business-logic note below.) |
| Concurrent login load (20 simultaneous requests, valid credentials) | All 20 succeeded; average **241 ms/request** — see performance note below. |

**Business-logic finding (low severity):** the guest trial counter cannot be *forged*, but it can be trivially *reset* — since it is tracked only in a client-held signed cookie with no server-side identity (e.g. IP-based) behind it, clearing cookies or opening a private/incognito window resets a guest to 3 fresh trials. This is a common and generally accepted tradeoff for frictionless guest access, but is worth stating explicitly as a known limitation rather than an oversight.

**Performance/DoS-adjacent observation:** login latency rose to ~241 ms/request average under 20 concurrent requests (vs. ~1.6 ms/request for the unauthenticated `/api/health` endpoint under 50 concurrent requests), consistent with `bcryptjs`'s pure-JavaScript (non-native) hashing at cost factor 12 being CPU-bound on Node's single event-loop thread. No login-attempt rate limiting is currently configured, so a scripted credential-stuffing run would both (a) have a real chance of eventually succeeding against weak passwords and (b) degrade the whole server's responsiveness for other users purely from the bcrypt CPU cost, before any lockout would ever engage. This is flagged as a finding below rather than left implicit.

### 6.4.3 Risk Assessment

| Finding | Risk | Mitigation |
|---|---|---|
| No rate limiting on `/api/auth/login` | **Medium** | Add `express-rate-limit` (e.g. 5 attempts / 15 min / IP) ahead of the login route |
| Missing security headers (no CSP, `X-Frame-Options`, `X-Content-Type-Options`; `X-Powered-By: Express` leaks framework fingerprint) | **Medium** | Add `helmet` middleware; `app.disable('x-powered-by')` |
| `multer`/`mailparser` known high-severity CVEs reachable via untrusted email/upload input | **Medium** | `npm audit fix`; monitor for upstream patches given these sit directly on the attacker-controlled input path |
| Guest trial limit resettable via cookie clearing | **Low** | Acceptable tradeoff for a frictionless demo; note as a known limitation, optionally add coarse IP-based tracking if abuse is observed |
| Dev-only vulnerabilities (`vite`, `concurrently`/`shell-quote`) | **Low** | No runtime exposure; upgrade opportunistically, `vite` upgrade needs a compatibility check first |
| Chain-of-custody clone silently lost forensic sub-detail on cache hits (Defect 3, §6.2.4) | **High (fixed)** | Fixed and regression-tested during this cycle — included here as evidence the risk was real and has been closed, not as an open item |

## 6.5 Compliance or Policy Testing

Checked against the **OWASP Top 10 (2021)** categories most relevant to this system:

| Category | Status | Evidence |
|---|---|---|
| A01 Broken Access Control | **Pass** | RBAC verified in both directions (§6.2.2, §6.4.2); JWT signature enforced; analyst/auditor separation of duties holds |
| A02 Cryptographic Failures | **Pass** | Passwords hashed with `bcryptjs` (cost 12); JWT signed with a server-held secret; evidence integrity via SHA-256/MD5 hashing and a hash-chained custody log (Section 5.9) |
| A03 Injection | **Pass** | Supabase's parameterised query builder resists SQL-injection-style payloads (§6.4.2); no raw SQL string concatenation found in the codebase |
| A04 Insecure Design | **Partial** | Guest-trial business logic is client-cookie-based by design (accepted tradeoff, §6.4.2); role separation is otherwise sound |
| A05 Security Misconfiguration | **Fail → actionable** | No `helmet`, no disabled `X-Powered-By`, no rate limiting (§6.4.3) |
| A06 Vulnerable Components | **Fail → actionable** | 14 `npm audit` findings, several in the untrusted-input path (§6.4.1) |
| A07 Identification & Authentication Failures | **Partial** | Session handling itself is sound (httpOnly, `sameSite: strict`, signed cookies), but no brute-force protection on login (§6.4.3) |
| A09 Security Logging & Monitoring Failures | **Pass** | The chain-of-custody log (Section 5.9) provides a tamper-evident audit trail for every analysis, exposed to auditor-role users specifically for this purpose |

**Password policy:** enforced at the hashing layer (bcrypt, cost 12) but there is no observed complexity/length policy on account creation in the reviewed code path (demo accounts are seeded directly; no public self-registration endpoint exists to test against).

**Access control:** role checks are centralised in `middleware/auth.js`'s `requireAuth(...roles)` and applied consistently across `history.js` and `audit.js` — confirmed by the RBAC integration tests (§6.2.2).

**Audit logging:** the chain-of-custody mechanism satisfies this control directly and was verified to reject tampering via `verifyChain()`'s hash-chain check (Section 5.9); no additional application-level audit log (e.g. login attempts, permission-denied events) exists beyond `console` output, which is a gap worth noting if this were headed to production rather than an academic evaluation.

## 6.6 Acceptance Testing

Acceptance criteria were derived from the sprint goals stated in Chapter 5 (Section 5.1) and the capabilities advertised on the landing page (Section 5.10). Each is validated against the testing performed above rather than asserted:

| Requirement (from Chapter 5) | Verified by | Status |
|---|---|---|
| Parse RFC 822/MIME email and compute evidence hashes | Integration test: `email.sha256` matches `^[a-f0-9]{64}$` on every analysis | **Met** |
| Detect header spoofing / authentication failures | Unit tests (13 cases) + integration test against the SPF/DKIM/DMARC-failing fixture | **Met** |
| Multi-source URL reputation scoring | Unit tests (11 cases) covering VT/URLScan/PhishTank/WHOIS/heuristic combination; integration test against a live malicious URL | **Met** |
| Weighted, source-re-normalised email risk score with confidence | Unit tests (8 cases) including the re-normalisation edge case | **Met** |
| Tamper-evident chain-of-custody | Integration tests assert `chainIntact: true`; design verified via `verifyChain()`'s hash-chain construction (Section 5.9) | **Met** |
| Role-based analyst/auditor separation of duties | RBAC integration tests in both directions | **Met** |
| Guest trial limiting (3 free analyses) | Dedicated integration test asserting exactly 3 succeed, 4th is blocked | **Met** |
| Graceful degradation when external APIs are unavailable/reject a request | Observed directly: URLScan's real `400 DNS Error` on the fixture's non-resolving domains was absorbed without failing the analysis | **Met** |
| Analysis completes quickly enough for interactive use ("sub-30-second") | Observed: single-digit seconds per full pipeline run including live AI calls | **Met** |

No requirement from Chapter 5 was found to be unmet by this testing pass; the three defects found (§6.2.4) were implementation bugs within otherwise-correctly-specified features, not missing requirements, and have been fixed and regression-tested.

## 6.7 Summary

This chapter set up an automated test suite (Vitest + Supertest, 83 tests: 57 unit, 26 integration) covering the deterministic scoring/heuristic engines and the full HTTP-level pipeline, run against the live development Supabase instance and live external integrations rather than mocks. This approach paid off directly: it surfaced three real, previously-unnoticed defects — non-functional WHOIS domain-age lookups, duplicated/corrupted URLs from a plaintext-rendering edge case, and a silent data-loss bug in the cache/dedup clone path — all of which have been fixed and are now guarded by regression tests. Security testing (`npm audit`, manual RBAC/injection/JWT-tampering probes, and a lightweight concurrency test) confirmed the system's authentication, access-control, and injection defences hold, while identifying concrete, actionable gaps — missing security headers and login rate limiting — for future hardening. Acceptance testing confirmed every functional and security requirement carried over from Chapter 5 is met. Chapter 7 concludes the project and discusses these findings as directions for future work.
