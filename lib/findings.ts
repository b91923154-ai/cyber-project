/**
 * findings.ts — normalised findings, guided manual checks, JSON schema, SARIF.
 *
 * Every finding carries: severity, CONFIDENCE (confirmed | likely | manual),
 * evidence, CWE, OWASP Top 10:2025 category, WSTG reference, and a fix.
 * Confidence is what separates "we observed this" from "a human must verify".
 *
 * Category labels follow OWASP Top 10:2025 (released Nov 2025). Re-check
 * names/numbers at https://owasp.org/Top10/ before printing them on slides.
 */
export const SCHEMA_VERSION = "1.0";

export type Severity = "Critical" | "High" | "Medium" | "Low" | "Info";
export type Confidence = "confirmed" | "likely" | "needs-manual-review" | "manual";

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  tier: "basic" | "deep";
  evidence: string;
  cwe: string;
  owasp: string;
  wstg: string;
  remediation: string;
}

export interface ManualCheck {
  id: string;
  wstg: string;
  title: string;
  why: string;
  steps: string[];
  needs: string[];
  status: "pending";
}

export const OWASP = {
  A01: "A01:2025 Broken Access Control",
  A02: "A02:2025 Security Misconfiguration",
  A04: "A04:2025 Cryptographic Failures",
  A05: "A05:2025 Injection",
  A06: "A06:2025 Insecure Design",
  A07: "A07:2025 Authentication Failures",
  A08: "A08:2025 Software or Data Integrity Failures",
} as const;

/* -------- minimal structural types (decoupled from the route's types) ----- */
interface BasicInput {
  tls: { error?: string; cert_valid: boolean; cert_expires_in_days: number; tls_version: string; protocol_secure: boolean; authorized?: boolean };
  http: {
    error?: string;
    redirect_secure: boolean;
    missing_headers: { name: string; severity: string; description: string }[];
    present_headers: Record<string, string>;
    cookies: { name: string; secure: boolean; httponly: boolean; samesite: string }[];
    leakage: { header: string; value: string; risk: string }[];
  };
}

const HDR_META: Record<string, { cwe: string; wstg: string; fix: string; sev: Severity }> = {
  "Strict-Transport-Security": { cwe: "CWE-319", wstg: "WSTG-CONF-07", sev: "High", fix: "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains" },
  "Content-Security-Policy": { cwe: "CWE-693", wstg: "WSTG-CONF-12", sev: "High", fix: "Start with a report-only CSP, then enforce: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'" },
  "X-Frame-Options": { cwe: "CWE-1021", wstg: "WSTG-CLNT-09", sev: "Medium", fix: "Add X-Frame-Options: DENY (or CSP frame-ancestors 'none')." },
  "X-Content-Type-Options": { cwe: "CWE-693", wstg: "WSTG-CONF-06", sev: "Medium", fix: "Add: X-Content-Type-Options: nosniff" },
  "Referrer-Policy": { cwe: "CWE-200", wstg: "WSTG-CONF-12", sev: "Low", fix: "Add: Referrer-Policy: strict-origin-when-cross-origin" },
  "Permissions-Policy": { cwe: "CWE-693", wstg: "WSTG-CONF-12", sev: "Low", fix: "Add Permissions-Policy: camera=(), microphone=(), geolocation=()" },
  "Cross-Origin-Opener-Policy": { cwe: "CWE-693", wstg: "WSTG-CONF-12", sev: "Info", fix: "Add: Cross-Origin-Opener-Policy: same-origin (if no cross-window features are used)." },
  "Cross-Origin-Embedder-Policy": { cwe: "CWE-693", wstg: "WSTG-CONF-12", sev: "Info", fix: "Add Cross-Origin-Embedder-Policy: require-corp only if you need cross-origin isolation." },
  "Cross-Origin-Resource-Policy": { cwe: "CWE-693", wstg: "WSTG-CONF-12", sev: "Info", fix: "Add Cross-Origin-Resource-Policy: same-site (or same-origin)." },
};

export function buildBasicFindings(d: BasicInput): Finding[] {
  const f: Finding[] = [];
  let n = 1;
  const add = (x: Omit<Finding, "id" | "tier">) => f.push({ id: `CS-B-${String(n++).padStart(3, "0")}`, tier: "basic", ...x });

  if (d.tls.error) {
    add({ title: "TLS handshake failed", severity: "High", confidence: "confirmed", evidence: d.tls.error, cwe: "CWE-319", owasp: OWASP.A04, wstg: "WSTG-CRYP-01", remediation: "Serve HTTPS on 443 with a valid certificate chain." });
  } else {
    if (d.tls.authorized === false) add({ title: "Certificate chain is not trusted", severity: "High", confidence: "confirmed", evidence: "Handshake completed but certificate verification failed (self-signed, incomplete chain, or wrong hostname).", cwe: "CWE-295", owasp: OWASP.A04, wstg: "WSTG-CRYP-01", remediation: "Install a certificate from a public CA and serve the full chain." });
    if (d.tls.cert_expires_in_days < 0) add({ title: "Certificate expired", severity: "High", confidence: "confirmed", evidence: `Expired ${-d.tls.cert_expires_in_days} day(s) ago.`, cwe: "CWE-298", owasp: OWASP.A04, wstg: "WSTG-CRYP-01", remediation: "Renew now and automate renewal (e.g. ACME)." });
    else if (d.tls.cert_expires_in_days < 30) add({ title: "Certificate expires soon", severity: "Low", confidence: "confirmed", evidence: `${d.tls.cert_expires_in_days} day(s) remaining.`, cwe: "CWE-298", owasp: OWASP.A04, wstg: "WSTG-CRYP-01", remediation: "Automate renewal and alert at 30 days." });
    if (!d.tls.protocol_secure) add({ title: "Obsolete TLS version negotiated", severity: "High", confidence: "confirmed", evidence: `Negotiated ${d.tls.tls_version}.`, cwe: "CWE-326", owasp: OWASP.A04, wstg: "WSTG-CRYP-01", remediation: "Allow only TLS 1.2 and 1.3." });
  }
  if (!d.http.error && !d.http.redirect_secure) add({ title: "HTTP is not redirected to HTTPS", severity: "Medium", confidence: "confirmed", evidence: "Plain-HTTP request did not return a 3xx to an https:// URL.", cwe: "CWE-319", owasp: OWASP.A04, wstg: "WSTG-CRYP-03", remediation: "Redirect all HTTP to HTTPS (301) and enable HSTS." });

  for (const m of d.http.missing_headers) {
    const meta = HDR_META[m.name];
    if (!meta) continue;
    add({ title: `Missing header: ${m.name}`, severity: meta.sev, confidence: "confirmed", evidence: `Header absent from the HTTPS response. ${m.description}`, cwe: meta.cwe, owasp: OWASP.A02, wstg: meta.wstg, remediation: meta.fix });
  }
  const hsts = d.http.present_headers["Strict-Transport-Security"];
  if (hsts) {
    const age = Number(/max-age=(\d+)/i.exec(hsts)?.[1] ?? 0);
    if (age < 15552000) add({ title: "HSTS max-age is short", severity: "Low", confidence: "confirmed", evidence: `Value: ${hsts}`, cwe: "CWE-319", owasp: OWASP.A02, wstg: "WSTG-CONF-07", remediation: "Use max-age of at least 31536000." });
  }
  const csp = d.http.present_headers["Content-Security-Policy"];
  if (csp && /'unsafe-inline'|'unsafe-eval'|script-src[^;]*\*/.test(csp)) add({ title: "CSP allows unsafe script sources", severity: "Medium", confidence: "likely", evidence: "Policy contains 'unsafe-inline', 'unsafe-eval' or a wildcard script source.", cwe: "CWE-693", owasp: OWASP.A02, wstg: "WSTG-CONF-12", remediation: "Use nonces/hashes and remove unsafe-* keywords." });

  for (const c of d.http.cookies) {
    if (!c.secure) add({ title: `Cookie '${c.name}' lacks Secure`, severity: "Medium", confidence: "confirmed", evidence: "Set-Cookie has no Secure attribute.", cwe: "CWE-614", owasp: OWASP.A02, wstg: "WSTG-SESS-02", remediation: "Add Secure." });
    if (!c.httponly) add({ title: `Cookie '${c.name}' lacks HttpOnly`, severity: "Medium", confidence: "likely", evidence: "Set-Cookie has no HttpOnly. Only a risk if this cookie is a session/auth token.", cwe: "CWE-1004", owasp: OWASP.A02, wstg: "WSTG-SESS-02", remediation: "Add HttpOnly to session cookies." });
    if (c.samesite === "None") add({ title: `Cookie '${c.name}' has no SameSite restriction`, severity: "Low", confidence: "likely", evidence: "SameSite absent or None.", cwe: "CWE-1275", owasp: OWASP.A02, wstg: "WSTG-SESS-02", remediation: "Set SameSite=Lax or Strict." });
  }
  for (const l of d.http.leakage) add({ title: `Technology disclosure: ${l.header}`, severity: "Low", confidence: "confirmed", evidence: `${l.header}: ${l.value}`, cwe: "CWE-200", owasp: OWASP.A02, wstg: "WSTG-INFO-02", remediation: "Remove or genericise the header." });
  return f;
}

/* ------------------------- guided manual checks -------------------------- */
export interface Signals { hasPasswordForm: boolean; hasFileUpload: boolean; reflectsInput: boolean; hasForms: boolean }

export function buildManualChecks(s: Signals): ManualCheck[] {
  const m: ManualCheck[] = [];
  const add = (x: Omit<ManualCheck, "status">) => m.push({ ...x, status: "pending" });
  add({ id: "CS-M-001", wstg: "WSTG-ATHZ-04", title: "Insecure direct object references (IDOR)", why: "Automation cannot know which object IDs belong to which user.", needs: ["Two test accounts you own"], steps: ["Log in as account A and note a resource URL/ID that contains an identifier.", "Log in as account B and request A's resource directly.", "Expected: access denied. Any data returned is a finding."] });
  add({ id: "CS-M-002", wstg: "WSTG-BUSL-01", title: "Business-logic validation", why: "Logic flaws (price, quantity, step order) are application-specific.", needs: ["Documented workflow", "Staging or test data"], steps: ["Map each multi-step flow (checkout, signup, reset).", "Try skipping, repeating and reordering steps; submit boundary values.", "Verify the server enforces every rule, not just the UI."] });
  if (s.hasPasswordForm) add({ id: "CS-M-003", wstg: "WSTG-ATHN-03", title: "Login lock-out and brute-force resistance", why: "A password form was detected.", needs: ["A test account you own"], steps: ["Submit a small number of wrong passwords for the test account only.", "Check for lock-out, throttling or CAPTCHA and uniform error messages.", "Do not test against real users' accounts."] });
  if (s.reflectsInput) add({ id: "CS-M-004", wstg: "WSTG-INPV-01", title: "Reflected input handling", why: "A harmless probe string was reflected in the response.", needs: ["Browser dev tools"], steps: ["Identify the reflection context (HTML body, attribute, script).", "Confirm output is context-encoded and CSP limits script execution.", "Escalate to a finding only if encoding is demonstrably missing."] });
  if (s.hasFileUpload) add({ id: "CS-M-005", wstg: "WSTG-BUSL-08", title: "File upload restrictions", why: "A file upload field was detected.", needs: ["Test files you created"], steps: ["Upload an allowed type, then a renamed/oversized/wrong-MIME file.", "Verify type, size and content validation happen server-side.", "Verify uploads are not served from an executable path."] });
  if (s.hasForms) add({ id: "CS-M-006", wstg: "WSTG-SESS-05", title: "CSRF protection on state-changing forms", why: "Forms were detected.", needs: ["Logged-in test session"], steps: ["Check each state-changing request for an anti-CSRF token or SameSite cookie.", "Replay the request without the token from a different origin in a lab."] });
  return m;
}

export function getFullManualChecklist(): ManualCheck[] {
  return buildManualChecks({
    hasPasswordForm: true,
    hasFileUpload: true,
    reflectsInput: true,
    hasForms: true,
  });
}

/* ------------------------------- SARIF ----------------------------------- */
export function toSarif(target: string, findings: Finding[]) {
  const level = (s: Severity) => (s === "Critical" || s === "High" ? "error" : s === "Medium" ? "warning" : "note");
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: "CyberShield", informationUri: "https://example.invalid/cybershield", rules: findings.map((x) => ({ id: x.id, name: x.title, shortDescription: { text: x.title }, help: { text: x.remediation }, properties: { cwe: x.cwe, owasp: x.owasp, wstg: x.wstg, confidence: x.confidence } })) } },
      results: findings.map((x) => ({ ruleId: x.id, level: level(x.severity), message: { text: `${x.title}. ${x.evidence}` }, locations: [{ physicalLocation: { artifactLocation: { uri: target } } }] })),
    }],
  };
}
