# CYBERSHIELD — Web Vulnerability Scanner as a Service (v4.0)

CyberShield is a full-stack, enterprise-grade web vulnerability scanner and threat intelligence platform built with **Next.js 16 (Turbopack) + React 19 + Tailwind CSS**.

Engineered with a **"Safe by Design"** philosophy, CyberShield solves the fundamental pitfalls of automated scanners: abuse prevention, anti-SSRF perimeter isolation, domain ownership verification, and human-in-the-loop workflows with confidence ratings.

---

## 🛡️ Architecture & Threat Model

### 1. Two-Tier Scan Model (Intrusiveness Separation)

| Scan Tier | Scope & Intrusiveness | Target Prerequisites | Checks Performed |
|---|---|---|---|
| **Basic Tier** | **Passive & Non-Intrusive**<br>(Equivalent to standard browser inspection) | Any non-denylisted target | • **Security Headers:** HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy<br>• **TLS/SSL Handshake:** TLS 1.3/1.2 validation, cipher suites, certificate authority chain, expiry countdown, SHA-256 fingerprint<br>• **Cookie Isolation:** `Secure`, `HttpOnly`, `SameSite`<br>• **Supply Chain & Scripts:** Subresource Integrity (SRI) on 3rd-party scripts, mixed content audit, known-vulnerable JS libraries (jQuery, Bootstrap, AngularJS, Lodash)<br>• **DNS & Email Posture:** SPF, DMARC, and MX records<br>• **Information Leakage:** Server banners, `robots.txt`, and RFC 9116 `security.txt`<br>• **OWASP Top 10 (2021)** compliance matrix |
| **Deep Tier** | **Active Probing & Exploit Indicators**<br>(Safe non-destructive canary payloads) | **Cryptographic Proof of Control Required** + Signed Legal Scope Attestation | • **Reflected XSS:** Non-executable canary tokens injected into query parameters<br>• **Open Redirects:** Destination validation against external probes<br>• **SQL Injection:** Safe single-quote syntax anomaly detection (non-destructive)<br>• **Sensitive File Exposure:** `.env`, `.git/HEAD`, `phpinfo.php`, and administrative panels<br>• **Active CORS:** Origin reflection and credential theft probes<br>• **Authentication Hygiene:** Rate-limiting detection on login endpoints |

---

### 2. Abuse Prevention & Target Authorization

- **High-Profile Denylist:** Scanning high-profile domains (e.g., `google.com`, `apple.com`, `gov.in`, critical infrastructure) is automatically blocked.
- **Proof of Ownership Verification (`/api/verify`):** Deep scans require the user to verify domain control via:
  1. **DNS TXT Record:** `cybershield-verify=<token>`
  2. **Well-Known File:** `https://<domain>/.well-known/cybershield-verify.txt`
  3. **HTML `<meta>` Tag:** `<meta name="cybershield-verify" content="<token>">`
- **Legal Attestation & Scope Agreement:** Explicit checkbox agreement required, binding the tester to responsible disclosure laws (Section 43/66 of the Indian IT Act, US CFAA).
- **Abuse Controls:** Target rate-limiting, concurrency caps, and kill-switch capabilities.

---

### 3. Platform Self-Defense (Anti-SSRF & Sandboxing)

- **Pre-Resolution SSRF Shield:** Resolves DNS before dispatching HTTP requests and verifies that the destination IP does not belong to loopback (`127.0.0.1`), RFC 1918 private subnets (`10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`), link-local, or cloud metadata endpoints (`169.254.169.254`), neutralizing DNS rebinding attacks.
- **Hostile Response Sanitization:** All untrusted target responses, error snippets, and banners are escaped before DOM insertion to neutralize stored XSS attacks targeting SecOps analysts.
- **Non-Destructive Payloads:** Detection probes exclusively inspect reflection and syntax errors; strictly zero `DROP`, `UPDATE`, `exec()`, or data modifications.

---

### 4. Human-in-the-Loop & Standing Out

- **Confidence Levels:** Eliminates false positive fatigue by tagging every finding with:
  - `Confirmed`: Cryptographically or mathematically proven flaw.
  - `Likely`: Strong heuristic indicators detected.
  - `Needs Human Verification`: Complex state requiring manual inspection.
- **Guided Manual Tester Checklist:** Context-aware prompts for manual testers covering business logic flaws, 2-account IDOR validation, race conditions with safe bursts, and session fixation.
- **Actionable Remediation:** Code snippets for Nginx, Apache, Cloudflare, Next.js, and Caddy.
- **Dual Audiences:** Instant toggle between **Executive Summary** (plain English for leadership) and **Technical Detail** (for engineers).
- **DevSecOps Integration:** Export reports in standard JSON, Executive Markdown, and **SARIF 2.1.0** (Static Analysis Results Interchange Format) for direct integration into GitHub Security and CI/CD pipelines.

---

## 💻 Running Locally

### 1. Install Dependencies
```bash
npm install
```

### 2. Start the Development Server
```bash
npm run dev
```

Visit [http://localhost:3000](http://localhost:3000) in your web browser.

### 3. Run the Automated Verification Suite
```bash
node scripts/verify-all.js
```

---

## 🧪 Automated Verification Suite Results

```text
═══════════════════════════════════════════════════════
CYBERSHIELD TEST SUITE: END-TO-END SYSTEM VERIFICATION
═══════════════════════════════════════════════════════

[PASS] Denylist Protection: google.com is blocked from scanning
[PASS] SSRF Protection: 127.0.0.1 loopback blocked pre-connection
[PASS] SSRF Protection: 169.254.169.254 AWS metadata IP blocked
[PASS] Domain Verification: Issues verification token and multi-method instructions (DNS/File/Meta)
[PASS] Deep Scan Authorization Gate: Rejects intrusive scans without verified domain ownership
[PASS] Deep Scan Execution: Generates findings with confidence levels, OWASP/CWE mappings, and manual checklist
[PASS] Confidence Grading: Every finding has verified confidence levels (confirmed, likely, needs-manual-review)
[PASS] Human-in-the-Loop: Guided manual checklist generated for business logic, IDOR, and race conditions
[PASS] Passive Audit: Network, TLS, HTTP, and Security Headers evaluated
[PASS] DNS & Email Posture: SPF, DMARC, and MX records evaluated
[PASS] OWASP Top 10 (2021): Compliant classification matrix produced
[PASS] Web Attack Surface: CORS, SRI, and vulnerable library checks evaluated

═══════════════════════════════════════════════════════
FINAL RESULT: 12/12 TESTS PASSED (100% COMPLIANCE)
═══════════════════════════════════════════════════════
```
