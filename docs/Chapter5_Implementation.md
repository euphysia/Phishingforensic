# Chapter 5: Implementation

## 5.1 Overview

This chapter describes the implementation of the phishing email forensic analysis system developed for this project. The system was built as a full-stack web application comprising a Node.js/Express backend that performs the forensic analysis pipeline, and a React/Vite frontend that presents an analyst-facing dashboard for submitting emails, reviewing results, and exporting forensic reports.

The backend was written in JavaScript using Express 5 and follows a modular, component-based architecture: each forensic capability (header analysis, URL analysis, attachment analysis, threat intelligence lookups, AI-assisted body analysis, risk scoring, and chain-of-custody logging) is implemented as an independent analyzer module under `server/analyzers/`, which is orchestrated by a single analysis pipeline function. This design mirrors the sprint-based development approach used throughout the project, where each sprint added a self-contained analysis capability that could be developed, tested, and integrated independently of the others (e.g. Sprint 1–2 delivered header/URL analysis and the base pipeline; Sprint 3 added attachment forensics and chain-of-custody logging; Sprint 4 added external threat-intelligence integrations (PhishTank, AbuseIPDB) and SMTP-based ingestion; Sprint 5 added authentication, role-based access control, and the analyst/auditor dashboards).

Data persistence is handled by Supabase (PostgreSQL), and results are exposed to the frontend through a REST API. Two ingestion paths are supported: emails may be submitted through the web interface (file upload or pasted raw source), or forwarded to a built-in SMTP listener, allowing the system to be used either interactively or as a passive intake mailbox.

## 5.2 Development Environment and Tools

The system was developed using the following stack:

**Backend**
- Node.js (ES modules) with Express 5.2.1 as the HTTP server framework
- Supabase (`@supabase/supabase-js`) for PostgreSQL-backed persistence
- `multer` for multipart file uploads, `cookie-parser` and `jsonwebtoken` for session handling, `bcryptjs` for password hashing
- `mailparser` for RFC 822 / MIME email parsing
- `smtp-server` for the inbound SMTP listener
- `whoiser` for WHOIS-based domain age lookups
- Node's built-in `crypto` module for SHA-256/MD5 hashing

**Frontend**
- React 18 with TypeScript, built using Vite 6
- Tailwind CSS 4 and Radix UI for the dashboard component library
- `recharts` for risk visualisations, `react-hook-form` for form handling
- `pdfmake` for client-side PDF report generation

**External APIs / threat intelligence sources**
- VirusTotal API v3 — URL and file-hash reputation
- URLScan.io API v1 — URL sandboxing and screenshotting
- PhishTank — community-verified phishing URL database
- AbuseIPDB API v2 — IP reputation for sender/routing IPs
- Groq (LLaMA 3.3 70B / 3.1 8B) — used for AI-assisted email body analysis, executive summary generation, and recommended-action generation

Each external integration was implemented behind an environment-variable API key check with a deterministic **demo mode** fallback (e.g. heuristic/keyword-based scoring, or a seeded pseudo-random score derived from the IP/URL itself) so that the full pipeline remains functional and reproducible for demonstration and testing even without live API credentials. The `/api/health` endpoint reports which services are running against live keys versus demo mode, which was useful during development and evaluation.

## 5.3 Email Parsing Module

Email ingestion is handled by two entry points that converge on a single parsing and analysis pipeline (`runAnalysisPipeline()` in `server/index.js`):

- **HTTP submission** (`POST /api/analyze`) — accepts a `.eml`/`.txt` file upload (via Multer, 10 MB limit), a raw email string in the request body, or pasted plaintext.
- **SMTP listener** (`server/smtp/smtpListener.js`) — an `smtp-server` instance listening on port 2525 under a configurable local domain, which accepts any inbound message addressed to it, buffers the raw MIME payload, and asynchronously feeds it into the same analysis pipeline. This allows an analyst to simply forward a suspicious email to the intake address rather than manually uploading it. The listener also detects the common case where a user forwards an email as an `.eml` attachment and unwraps the inner message for analysis rather than analysing the forwarding wrapper.

Parsing itself is performed in `server/parser/emailParser.js` using the `mailparser` library's `simpleParser()`, which decodes the raw RFC 822 message into a structured object. The parser extracts:

- Envelope/header fields: `From`, `Reply-To`, `Return-Path`, `To`, `Subject`, `Date`, `Message-ID`
- The full chain of `Received` headers (used later for routing/IP analysis)
- SPF, DKIM and DMARC results, parsed from the `Authentication-Results` header via regular expression extraction
- The plaintext and HTML message bodies
- MIME attachments, each reduced to `{filename, contentType, sizeBytes, content}`

As part of parsing, the system computes a **SHA-256 hash of the raw email** and a SHA-256 (and MD5) hash of each attachment. These hashes serve two purposes: they act as an evidence-integrity fingerprint referenced throughout the chain-of-custody log, and they are used to deduplicate repeated submissions — if an email with an identical hash has already been analysed, the cached result is returned rather than re-running the full pipeline.

## 5.4 Header Analysis

Header analysis is implemented in `server/analyzers/headerAnalyzer.js` and is the first forensic module to run against a parsed email. It inspects the extracted headers for anomalies commonly associated with spoofed or malicious mail:

- **Authentication failures** — SPF, DKIM and DMARC results are read from the parsed `Authentication-Results` header and classified as pass/fail/softfail/neutral/missing.
- **Return-Path vs. Reply-To vs. From discrepancies** — the sender's visible `From` domain is compared against the `Return-Path` (bounce address) and `Reply-To` domain; a mismatch is flagged, since legitimate mail rarely routes replies or bounces to an unrelated domain.
- **Display-name impersonation** — the visible sender name is checked against a list of commonly spoofed brands (PayPal, banks, couriers, etc.) and their homoglyph variants (e.g. `paypa1`, `micros0ft`), flagging cases where the display name claims a trusted brand but the underlying address does not match.
- **Free-mail-provider abuse** — flags cases where a sender claims to represent a financial institution or similar sensitive entity while sending from a free consumer webmail domain.
- **Suspicious sender TLDs** and **routing anomalies** in the `Received` header chain.

Each detected anomaly is emitted as an indicator object of the form `{type, description, severity}`, and the module also produces an aggregate `senderReputation` score (0–100) that feeds into the overall risk-scoring engine described in Section 5.8.

## 5.5 URL Analysis Module

URL analysis begins with extraction (`server/analyzers/urlExtractor.js`), which pulls URLs from both the HTML body (`href`/`src` attributes) and the plaintext body of the email, and produces a defanged form of each (`http://` → `hxxp://`) for safe display in the report UI.

Each extracted URL is then run through several independent checks, whose results are combined by the reputation scorer (Section 5.8):

- **VirusTotal** (`virusTotal.js`) — submits the URL for scanning via the v3 API and polls for results (up to 30 seconds), returning the vendor detection ratio and category tags.
- **URLScan.io** (`urlScan.js`) — submits the URL for sandboxed scanning (private visibility) and polls for a verdict, score, and screenshot metadata.
- **PhishTank** (`phishTank.js`) — checks the URL against PhishTank's crowd-verified phishing database, returning whether it is a known (and verified) phishing entry, and the impersonated brand if available. Requests are rate-limited to respect PhishTank's 50 requests/minute policy.
- **Heuristic indicator detection** (`phishingIndicators.js`) — a rule-based engine that independently flags:
  - Homoglyph/typosquatted domains against a list of 18 commonly-impersonated brands (using a Levenshtein-distance check)
  - URL shorteners (bit.ly, tinyurl.com, etc.)
  - IP-address-based URLs (no domain name)
  - Suspicious top-level domains (`.xyz`, `.tk`, `.click`, etc.)
  - Credential-harvesting/phishing keywords in the URL path
  - Brand names appearing in a subdomain while the root domain is unrelated (e.g. `paypal.attacker.com`)
  - Mismatches between visible link text and the actual `href` target
- **Domain age** (`domainAge.js`) — performs a WHOIS lookup (via `whoiser`) and flags newly-registered domains (under 30 days = high risk, under 90 days = medium risk), a strong indicator for freshly-stood-up phishing infrastructure.

The results of these checks are combined per-URL into a single 0–100 reputation score by `scoreUrl()` in `reputationScorer.js`, described further in Section 5.8.

## 5.6 Attachment Analysis Module

Attachment forensics (`server/analyzers/attachmentAnalyzer.js`) applies a ten-step pipeline to every attachment found during MIME parsing:

1. Chain-of-custody entry recorded for receipt of the artefact
2. SHA-256 and MD5 hashing for integrity/identification
3. **MIME-type spoofing detection** — the declared `Content-Type` is compared against the file extension to detect mismatches
4. **Magic-byte / file-signature verification** — the first bytes of the file are checked against known signatures (e.g. `MZ` for Windows executables, `PK` for ZIP/Office formats, `%PDF` for PDF, OLE2 for legacy Office) to detect files whose true type does not match their claimed type
5. **Extension risk classification** — extensions are bucketed into high-risk (`.exe`, `.scr`, `.js`, `.vbs`, `.ps1`, `.hta`, etc.) and medium-risk (`.doc`, `.docm`, `.zip`, `.pdf`, etc.) categories
6. **Suspicious filename pattern detection** — double extensions (`invoice.pdf.exe`), padding with excess spaces to hide the true extension, Unicode right-to-left-override characters used to visually disguise an extension, and social-engineering filename lures ("invoice", "payment", "password")
7. **Embedded content analysis** — detection of Office auto-executing macros, embedded JavaScript or auto-launch actions in PDFs, obfuscated PowerShell, and Base64-encoded executable payloads
8. **VirusTotal file-hash lookup** — the computed SHA-256 is checked against VirusTotal's database of previously-scanned files
9. **Password-protected archive detection** — inspection of ZIP/RAR/PDF structural flags to identify encrypted archives, a common technique used to evade static/AV scanning
10. **Status escalation** — the attachment is ultimately classified as `safe`, `suspicious`, or `malicious` based on the accumulated findings

Every step above generates a corresponding chain-of-custody entry, so the full forensic history of how an attachment verdict was reached is auditable end-to-end.

## 5.7 Threat Intelligence Integration

In addition to the per-URL and per-attachment lookups described above, the system aggregates IP-based threat intelligence via **AbuseIPDB** (`server/analyzers/abuseIPDB.js`). Sender and routing IP addresses are extracted from the `Received` header chain (both IPv4 and IPv6), capped at five unique IPs per email to respect API rate limits. Private/reserved address ranges (e.g. `10.x`, `192.168.x`, loopback, link-local) are excluded from external lookups and marked as `private`.

For each remaining public IP, AbuseIPDB is queried for its abuse confidence score, total report count, and reported abuse categories. A recency weighting is applied — reports from the last 7 days are weighted more heavily (×1.3) than older reports (×1.1 for 8–30 days) — on the basis that recently-reported infrastructure is more likely to still be actively malicious. IPs are classified as `malicious` (≥75), `suspicious` (≥25), or `clean`.

To manage the free-tier rate limits of the underlying APIs (AbuseIPDB: 1,000 requests/day; PhishTank: 50 requests/minute), each threat-intelligence module implements in-memory caching with source-appropriate TTLs — 6 hours for IP reputation and 24 hours for PhishTank URL results, since phishing infrastructure and IP reputations do not typically become "clean" again quickly. All modules also implement graceful degradation: if an API key is absent or a request fails/times out, the module falls back to deterministic heuristic scoring rather than failing the overall analysis, and the failure/fallback is surfaced through the `/api/health` endpoint.

## 5.8 Risk Scoring Engine

The unified risk-scoring logic lives in `server/analyzers/reputationScorer.js` and operates in two stages.

**Per-URL scoring** (`scoreUrl()`) combines the signals from Section 5.5 into a single 0–100 score per URL (0 = confirmed malicious, 100 = clean), applying point deductions such as: up to −55 for VirusTotal detections, −35 for a URLScan "malicious" verdict (or a proportional penalty for elevated URLScan scores), −70 for a PhishTank-verified phishing entry (−45 if unverified), −5 to −20 for heuristic indicators depending on severity, −15/−8 for newly-registered domains, and −15/−8 for IP-based or shortened URLs.

**Email-wide scoring** (`computeEmailRiskScore()`) then aggregates results across all analysis modules into an overall email risk score using a weighted sum, where each source's weight is only applied if that source produced a signal for the given email (i.e. weights are re-normalised over the active sources):

| Signal source | Weight |
|---|---|
| Header analysis (SPF/DKIM/DMARC, spoofing) | 0.30 |
| URL analysis (worst-scoring URL) | 0.30 |
| AbuseIPDB (sender/routing IPs) | 0.15 |
| Attachment analysis | 0.10 |
| Heuristic phishing indicators | 0.20 |
| AI body analysis (social-engineering score) | 0.25 |

The resulting score is mapped to a verdict:

- **Clean** — score ≥ 70
- **Suspicious** — score 30–69
- **Phishing** — score ≤ 30

with severity sub-classified as critical/high/medium/low based on how far into the band the score falls. A confidence value is also computed as `min(98, 55 + 9 × number_of_active_signal_sources)`, reflecting the intuition that a verdict corroborated by more independent evidence sources is more trustworthy.

IOC (Indicator of Compromise) extraction — malicious URLs, sender/routing IPs, and file hashes — is derived directly from the per-module results at report-generation time, so that a SOC analyst can hand off a concise list of artefacts for blocking without re-deriving it from the full report.

## 5.9 Forensic Report Generator

Once all analysis modules have completed, results are assembled into a single analysis record and persisted to Supabase, alongside a **chain-of-custody log** (`server/analyzers/chainOfCustody.js`). Every significant action performed during analysis — evidence receipt, header analysis, hash computation, MIME/magic-byte checks, each external API call, and final verdict — is appended as a timestamped entry containing the acting component name, a human-readable detail string, and (where applicable) the SHA-256 of the artefact being processed.

To make the log tamper-evident, each entry's hash is computed as `SHA-256(previous_entry_hash + entry_JSON)`, forming a hash chain analogous to a lightweight blockchain: any modification to an earlier entry changes its hash and invalidates every subsequent entry, which is verified via `verifyChain()`. This chain is exposed to auditor-role users through the audit dashboard (Section 5.10) so that the integrity of an analysis's evidence trail can be independently checked.

Reports can be exported in three forms:
- **On-screen HTML** — the interactive forensic report view within the dashboard
- **JSON** — the complete analysis object, suitable for machine ingestion by other tooling
- **PDF** — generated client-side using `pdfmake`, with colour-coded verdict sections (red/amber/green), tabulated header/URL/attachment/IP findings, the chain-of-custody trail, and an IOC summary section for SOC handoff

## 5.10 Analyst Dashboard Interface

The frontend is a React/TypeScript single-page application providing role-appropriate views for three user types (analyst, admin, auditor), plus a limited-trial guest mode (3 free analyses, tracked via a signed cookie and displayed to the user as a persistent "3 free analyses remaining" badge in the header).

**Landing page.** The public-facing landing page (`landing-page.tsx`, Figure 5.1) introduces the system as an "Automated Phishing Forensic System" and summarises its capabilities before the user logs in: authentication checks, URL scanning, attachment analysis, sender IP reputation, and an AI-generated threat summary, all backed by a cryptographic chain of custody. It also surfaces headline statistics (5+ threat-intel sources, sub-30-second analysis time, 3 export formats, 24/7 SMTP monitoring) and the integrated third-party services (VirusTotal, URLScan.io, AbuseIPDB, PhishTank, and the AI provider used for summarisation), before leading into a "Six Layers of Analysis" section and a "Start Analysing Emails" call-to-action that launches the application.

**Email submission.** The submission screen (`email-submission.tsx`) offers three input modes, selected via tabs:
1. **Upload File** — drag-and-drop or browse for a `.eml`/`.msg` file (max 10 MB), with inline instructions for exporting a message as `.eml` from Gmail, Outlook, and Apple Mail.
2. **Paste Headers** — a textarea for pasting the full raw email source (headers and body), with provider-specific instructions for retrieving it (e.g. Gmail's "Show original" → "Copy all").
3. **Forward Email** — displays the live status of the built-in SMTP listener (address `analyze@phishing-forensics.local`, port 2525) and a running count of received emails, together with step-by-step guidance for forwarding a suspicious email as an attachment (which preserves the original headers, as opposed to an inline forward which would overwrite them) so that it can be picked up automatically by the SMTP intake path described in Section 5.3.

In all three modes, the number of remaining guest trials is shown, and submission triggers the backend analysis pipeline.

**Analysis history.** Once authenticated (e.g. as the "analyst" role, shown in the top-right of the header with a role badge), the user gains access to a "History" tab (`analysis-history.tsx`) listing previously analysed emails, with search by subject/sender/ID and a verdict filter ("All Verdicts" dropdown). Results are scoped to the logged-in analyst's own submissions unless the user holds the admin role.

**Forensic report and recommended actions.** Selecting a completed analysis opens the forensic report view (`forensic-report.tsx`), broken into sender identity, authentication (SPF/DKIM/DMARC), routing, content analysis, URL analysis, attachment forensics, chain-of-custody, and IOC sections, each colour-coded by severity. Alongside it, `recommended-actions.tsx` surfaces AI-generated (or rule-based fallback) next-step guidance for the analyst, prioritised high/medium/low.

**Auditor dashboard.** A separate, role-gated view (`auditor-dashboard.tsx`) is available to users with the auditor role, exposing the chain-of-custody log for every analysis and its tamper-verification status, without granting the ability to submit new analyses — enforcing separation of duties between analysts who generate evidence and auditors who verify its integrity.

**Authentication.** Login (`login-page.tsx`, `AuthContext.tsx`) uses JWT-cookie-based sessions with bcrypt-hashed credentials, with demo accounts provided for each of the three roles so the system can be evaluated without a full user-registration flow.

Real-time feedback during analysis (progress through each pipeline stage) is surfaced to the user while the backend pipeline executes, and every report view offers export to PDF/JSON as described in Section 5.9.

## 5.11 Summary

This chapter has described the implementation of the phishing forensic analysis system's core components: RFC 822/MIME email parsing with SHA-256 evidence hashing; header-based spoofing and authentication analysis; multi-source URL reputation analysis combining VirusTotal, URLScan.io, PhishTank, WHOIS domain-age lookups, and heuristic detection; a ten-step attachment forensics pipeline covering MIME/magic-byte verification, macro/script detection, and VirusTotal hash lookups; AbuseIPDB-based IP threat intelligence with caching and rate-limit handling; a weighted risk-scoring engine that aggregates all of the above into a single verdict and confidence value; a tamper-evident, hash-chained chain-of-custody log; and a role-based analyst/auditor dashboard supporting both interactive submission and passive SMTP-based intake, with PDF/JSON forensic report export. Together these components form a complete, modular pipeline from raw email ingestion through to an actionable, evidentially-sound forensic report, implemented incrementally across five development sprints. Chapter 6 evaluates the system's effectiveness against these design goals.
