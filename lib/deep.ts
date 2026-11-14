/**
 * deep.ts — active but NON-DESTRUCTIVE checks. Run ONLY after ownership proof.
 *
 * Safety properties:
 *  - every request goes through safeRequest (SSRF guard, same host only)
 *  - probes are executed concurrently with fixed request budget & timeout
 *  - probes are inert strings; nothing is exploited, uploaded or modified
 *  - signature-matched results are "confirmed"; heuristics are "likely"/"needs-manual-review"
 */
import { safeRequest } from "./guard";
import { OWASP, type Finding, type Signals } from "./findings";

export async function runDeepChecks(baseUrl: string, hostname: string, html: string) {
  const findings: Finding[] = [];
  let n = 1;
  const add = (x: Omit<Finding, "id" | "tier">) =>
    findings.push({ id: `CS-D-${String(n++).padStart(3, "0")}`, tier: "deep", ...x });

  const origin = `https://${hostname}`;
  const get = async (path: string, extra: Record<string, string> = {}, method: "GET" | "OPTIONS" = "GET") => {
    try {
      return await safeRequest(origin + path, {
        method,
        headers: extra,
        sameHostOnly: true,
        followRedirects: false,
        maxBytes: 64 * 1024,
        timeoutMs: 3500,
      });
    } catch {
      return null;
    }
  };

  const evil = "https://cors-probe.invalid";
  const canary = "cs" + Math.random().toString(36).slice(2, 10);

  // Run all active probes concurrently to avoid sequential latency accumulation
  const [
    gitRes,
    envRes,
    infoRes,
    secRes,
    adminRes,
    corsRes,
    optRes,
    reflRes,
    redirRes,
    sqliRes,
  ] = await Promise.allSettled([
    get("/.git/HEAD"),
    get("/.env"),
    get("/phpinfo.php"),
    get("/.well-known/security.txt"),
    get("/admin"),
    get("/", { Origin: evil }),
    get("/", {}, "OPTIONS"),
    get(`/?cs_probe=${canary}`),
    get("/?redirect=https://canary-redirect.invalid"),
    get("/?id=1'"),
  ]);

  const git = gitRes.status === "fulfilled" ? gitRes.value : null;
  const env = envRes.status === "fulfilled" ? envRes.value : null;
  const info = infoRes.status === "fulfilled" ? infoRes.value : null;
  const sec = secRes.status === "fulfilled" ? secRes.value : null;
  const admin = adminRes.status === "fulfilled" ? adminRes.value : null;
  const cors = corsRes.status === "fulfilled" ? corsRes.value : null;
  const opt = optRes.status === "fulfilled" ? optRes.value : null;
  const refl = reflRes.status === "fulfilled" ? reflRes.value : null;
  const redirProbe = redirRes.status === "fulfilled" ? redirRes.value : null;
  const sqliProbe = sqliRes.status === "fulfilled" ? sqliRes.value : null;

  // 1. Exposed sensitive files & admin panels
  if (git && git.status === 200 && /^ref:\s*refs\//.test(git.body.trim())) {
    add({
      title: "Git repository metadata exposed",
      severity: "Critical",
      confidence: "confirmed",
      evidence: "/.git/HEAD returned a valid git ref.",
      cwe: "CWE-538",
      owasp: OWASP.A02,
      wstg: "WSTG-CONF-04",
      remediation: "Block /.git at the web server and remove it from the web root.",
    });
  }

  if (env && env.status === 200 && !/html/i.test(env.headers["content-type"] || "") && /^[A-Z][A-Z0-9_]{2,}=.+/m.test(env.body)) {
    add({
      title: "Environment file exposed",
      severity: "Critical",
      confidence: "confirmed",
      evidence: "/.env returned KEY=VALUE content (values withheld from this report).",
      cwe: "CWE-538",
      owasp: OWASP.A02,
      wstg: "WSTG-CONF-04",
      remediation: "Remove the file from the web root and rotate every secret it contained.",
    });
  }

  if (info && info.status === 200 && /PHP Version/i.test(info.body)) {
    add({
      title: "phpinfo() page exposed",
      severity: "Medium",
      confidence: "confirmed",
      evidence: "/phpinfo.php discloses PHP configuration.",
      cwe: "CWE-200",
      owasp: OWASP.A02,
      wstg: "WSTG-CONF-02",
      remediation: "Delete the page.",
    });
  }

  if (!sec || sec.status !== 200 || !/Contact:/i.test(sec.body)) {
    add({
      title: "No security.txt vulnerability-disclosure contact",
      severity: "Info",
      confidence: "confirmed",
      evidence: "/.well-known/security.txt missing or lacks Contact.",
      cwe: "CWE-1059",
      owasp: OWASP.A02,
      wstg: "WSTG-INFO-05",
      remediation: "Publish a security.txt (RFC 9116).",
    });
  }

  if (admin && admin.status === 200 && /login|admin|dashboard/i.test(admin.body)) {
    add({
      title: "Public administration panel exposed",
      severity: "Medium",
      confidence: "likely",
      evidence: "/admin is reachable without network restrictions.",
      cwe: "CWE-284",
      owasp: OWASP.A01,
      wstg: "WSTG-CONF-05",
      remediation: "Restrict administrative endpoints via IP allowlisting or VPN/Zero-Trust tunnels.",
    });
  }

  // 2. Active CORS Misconfiguration
  if (cors) {
    const acao = cors.headers["access-control-allow-origin"];
    const acac = (cors.headers["access-control-allow-credentials"] || "").toLowerCase() === "true";
    if (acao === evil || acao === "null") {
      add({
        title: "CORS reflects arbitrary Origin",
        severity: acac ? "High" : "Medium",
        confidence: "confirmed",
        evidence: `Origin ${evil} was echoed in Access-Control-Allow-Origin${acac ? " with credentials allowed" : ""}.`,
        cwe: "CWE-942",
        owasp: OWASP.A02,
        wstg: "WSTG-CLNT-07",
        remediation: "Validate Origin against an explicit allowlist; never combine reflection with credentials.",
      });
    }
  }

  // 3. Advertised HTTP methods
  const allow = (opt?.headers["allow"] || "").toUpperCase();
  if (/\b(TRACE|TRACK)\b/.test(allow)) {
    add({
      title: "TRACE/TRACK method advertised",
      severity: "Low",
      confidence: "likely",
      evidence: `Allow: ${allow}`,
      cwe: "CWE-16",
      owasp: OWASP.A02,
      wstg: "WSTG-CONF-06",
      remediation: "Disable TRACE/TRACK.",
    });
  }

  // 4. Inert reflection probe
  const reflects = !!refl && refl.body.includes(canary);
  if (reflects) {
    add({
      title: "Query parameter is reflected in the response",
      severity: "Info",
      confidence: "needs-manual-review",
      evidence: "An inert probe value appeared in the page. This is NOT proof of XSS.",
      cwe: "CWE-79",
      owasp: OWASP.A05,
      wstg: "WSTG-INPV-01",
      remediation: "Context-encode all reflected output; verify with the guided manual check.",
    });
  }

  // 5. Open Redirect check
  if (redirProbe && [301, 302, 303, 307, 308].includes(redirProbe.status)) {
    const loc = redirProbe.headers["location"] || "";
    if (loc.includes("canary-redirect.invalid")) {
      add({
        title: "Potential open redirect detected",
        severity: "Medium",
        confidence: "confirmed",
        evidence: `Parameter was echoed directly into Location header: ${loc}`,
        cwe: "CWE-601",
        owasp: OWASP.A01,
        wstg: "WSTG-CLNT-04",
        remediation: "Validate redirect targets against an explicit origin allowlist.",
      });
    }
  }

  // 6. SQL syntax error probe
  if (sqliProbe && sqliProbe.status >= 500) {
    const body = sqliProbe.body.toLowerCase();
    if (
      body.includes("sql syntax") ||
      body.includes("mysql_fetch") ||
      body.includes("sqlite3::sqlexception") ||
      body.includes("pg_query") ||
      body.includes("ora-01756")
    ) {
      add({
        title: "Database error syntax disclosed on quote probe",
        severity: "High",
        confidence: "likely",
        evidence: "Application disclosed raw database error syntax in response to single-quote probe.",
        cwe: "CWE-89",
        owasp: OWASP.A05,
        wstg: "WSTG-INPV-05",
        remediation: "Use parameterized queries / prepared statements and suppress raw database error messages.",
      });
    }
  }

  // 7. HTML analysis
  if (html) {
    const scripts = [...html.matchAll(/<script\b[^>]*\bsrc=["']([^"']+)["'][^>]*>/gi)];
    const noSri = scripts.filter((s) => {
      try {
        const u = new URL(s[1], baseUrl);
        return u.hostname !== hostname && !/\bintegrity=/i.test(s[0]);
      } catch {
        return false;
      }
    });
    if (noSri.length) {
      add({
        title: "Third-party scripts without Subresource Integrity",
        severity: "Medium",
        confidence: "confirmed",
        evidence: `${noSri.length} external script tag(s) lack an integrity attribute.`,
        cwe: "CWE-353",
        owasp: OWASP.A08,
        wstg: "WSTG-CLNT-09",
        remediation: 'Add integrity="sha384-…" and crossorigin="anonymous", or self-host the script.',
      });
    }

    if (baseUrl.startsWith("https://") && /(?:src|href|action)=["']http:\/\//i.test(html)) {
      add({
        title: "Mixed content references",
        severity: "Medium",
        confidence: "likely",
        evidence: "HTTPS page references http:// resources or form actions.",
        cwe: "CWE-311",
        owasp: OWASP.A04,
        wstg: "WSTG-CRYP-03",
        remediation: "Use https:// for every sub-resource.",
      });
    }
  }

  const signals: Signals = {
    hasPasswordForm: /<input[^>]+type=["']?password/i.test(html),
    hasFileUpload: /<input[^>]+type=["']?file/i.test(html),
    hasForms: /<form\b/i.test(html),
    reflectsInput: reflects,
  };
  return { findings, signals };
}
