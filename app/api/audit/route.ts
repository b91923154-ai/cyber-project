import { NextRequest, NextResponse } from "next/server";
import * as dns from "node:dns/promises";
import * as tls from "node:tls";
import * as crypto from "node:crypto";
import { GuardError, parseTarget, resolvePublic, safeRequest } from "@/lib/guard";
import { checkOwnership, buildChallenge } from "@/lib/ownership";
import { recordAttestation } from "@/lib/attestation";
import { rateLimit, clientIp, pseudonymise } from "@/lib/ratelimit";
import {
  SCHEMA_VERSION, buildBasicFindings, buildManualChecks, getFullManualChecklist, toSarif,
  type Finding, type ManualCheck,
} from "@/lib/findings";
import { runDeepChecks } from "@/lib/deep";
import { formatFriendlyError } from "@/lib/errors";

export interface NetworkInfo {
  ip: string;
  latency_ms: number;
  reverse_dns: string;
  resolved: boolean;
  error?: string;
}

export interface TlsInfo {
  tls_version: string;
  cipher_suite: string;
  cert_valid: boolean;
  cert_expires_in_days: number;
  expires_at: string;
  issuer_org: string;
  issuer_cn: string;
  subject_cn: string;
  sans_count: number;
  sans_sample: string[];
  fingerprint_sha256: string;
  protocol_secure: boolean;
  authorized?: boolean;
  error?: string;
}

export interface MissingHeader {
  name: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  description: string;
}

export interface CookieInfo {
  name: string;
  secure: boolean;
  httponly: boolean;
  samesite: string;
  domain: string;
  path: string;
}

export interface LeakageInfo {
  header: string;
  value: string;
  risk: string;
}

export interface CorsInfo {
  configured: boolean;
  allow_origin?: string;
  allow_credentials?: boolean;
  status: string;
}

export interface SriInfo {
  checked: boolean;
  total_external_scripts: number;
  missing_sri_count: number;
  status: string;
}

export interface VulnLibInfo {
  name: string;
  version: string;
  cve: string;
  severity: string;
  description: string;
}

export interface HttpInfo {
  missing_headers: MissingHeader[];
  present_headers: Record<string, string>;
  header_details: Record<
    string,
    { value: string; severity: string; description: string; status: string }
  >;
  cookies: CookieInfo[];
  redirect_secure: boolean;
  status_code: number;
  final_url: string;
  infrastructure: string;
  leakage: LeakageInfo[];
  cors: CorsInfo;
  sri: SriInfo;
  vuln_libs: VulnLibInfo[];
  error?: string;
}

export interface DnsEmailInfo {
  spf_valid: boolean;
  spf_record: string | null;
  dmarc_valid: boolean;
  dmarc_record: string | null;
  mx_valid: boolean;
  mx_records: string[];
}

export type Tier = "basic" | "deep";

export interface AuditReport {
  schema_version: string;
  scan_id: string;
  tier: Tier;
  authorization: { verified: boolean; method?: string };
  target: string;
  full_url: string;
  score: number;
  grade: string;
  grade_color: string;
  verdict: string;
  deductions: string[];
  network: NetworkInfo;
  tls: TlsInfo;
  http: HttpInfo;
  dns_email: DnsEmailInfo;
  owasp_top10: Record<string, { status: "PASS" | "WARN" | "FAIL"; issues: number; description: string }>;
  findings: Finding[];
  manual_checks: ManualCheck[];
  manual_checklist: ManualCheck[];
  limitations: string[];
  timestamp: string;
}

async function auditNetwork(hostname: string, ip: string, latency: number): Promise<NetworkInfo> {
  const net: NetworkInfo = { ip, latency_ms: latency, reverse_dns: "None", resolved: true };
  try {
    const rev = await dns.reverse(ip);
    net.reverse_dns = rev[0] || "Unresolvable";
  } catch {
    net.reverse_dns = "Unresolvable";
  }
  return net;
}

function auditTls(hostname: string, ip: string, port = 443): Promise<TlsInfo> {
  const results: TlsInfo = {
    tls_version: "N/A", cipher_suite: "N/A", cert_valid: false, cert_expires_in_days: 0,
    expires_at: "Unknown", issuer_org: "Unknown", issuer_cn: "Unknown", subject_cn: "Unknown",
    sans_count: 0, sans_sample: [], fingerprint_sha256: "N/A", protocol_secure: false,
  };
  return new Promise((resolve) => {
    let done = false;
    const finish = () => { if (!done) { done = true; resolve(results); } };
    const first = (v: string | string[] | undefined) => (Array.isArray(v) ? v.join(", ") : v || "");
    const socket = tls.connect(
      { host: ip, port, servername: hostname, rejectUnauthorized: false, timeout: 6000 },
      () => {
        try {
          const cert = socket.getPeerCertificate(true);
          if (cert && Object.keys(cert).length > 0) {
            const days = Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / 86_400_000);
            const sans = (cert.subjectaltname || "").split(",").map((s) => s.trim().replace(/^DNS:/, "")).filter(Boolean);
            const version = socket.getProtocol() || "N/A";
            results.authorized = socket.authorized;
            results.tls_version = version;
            results.cipher_suite = socket.getCipher()?.name || "Unknown";
            results.cert_expires_in_days = days;
            results.cert_valid = socket.authorized && days > 0;
            results.expires_at = new Date(cert.valid_to).toUTCString();
            results.issuer_org = first(cert.issuer?.O) || first(cert.issuer?.CN) || "Unknown CA";
            results.issuer_cn = first(cert.issuer?.CN) || "Unknown";
            results.subject_cn = first(cert.subject?.CN) || hostname;
            results.sans_count = sans.length;
            results.sans_sample = sans.slice(0, 8);
            results.fingerprint_sha256 = (cert.fingerprint256 || "N/A").toUpperCase();
            results.protocol_secure = ["TLSv1.3", "TLSv1.2"].includes(version);
            if (!socket.authorized) results.error = `Certificate not trusted: ${socket.authorizationError}`;
          } else results.error = "No certificate presented";
        } catch (e) {
          results.error = e instanceof Error ? e.message : "TLS inspection failed";
        } finally { socket.destroy(); finish(); }
      }
    );
    socket.on("timeout", () => { results.error = "Connection timed out after 6 seconds"; socket.destroy(); finish(); });
    socket.on("error", (err) => { results.error = err.message; finish(); });
  });
}

function detectInfrastructure(headers: Record<string, string>): string {
  const serverH = (headers["server"] || "").toLowerCase();
  const viaH = (headers["via"] || "").toLowerCase();

  if (serverH.includes("cloudflare") || headers["cf-ray"]) return "Cloudflare Edge";
  if (headers["x-vercel-id"] || serverH.includes("vercel")) return "Vercel Platform";
  if (headers["x-amz-cf-id"] || viaH.includes("cloudfront")) return "AWS CloudFront";
  if (headers["fastly-debug-digest"] || headers["x-fastly-request-id"]) return "Fastly CDN";
  if (headers["x-akamai-transformed"] || serverH.includes("akamaighost")) return "Akamai Technologies";
  if (headers["x-nf-request-id"] || serverH.includes("netlify")) return "Netlify";
  if (serverH.includes("google") || serverH.includes("gse") || serverH.includes("esf")) return "Google Cloud Infrastructure";
  if (serverH.includes("github.com")) return "GitHub Pages";
  if (serverH.includes("nginx")) return "Nginx Web Server";
  if (serverH.includes("apache")) return "Apache HTTP Server";
  if (serverH.includes("caddy")) return "Caddy Web Server";
  if (serverH.includes("microsoft-iis")) return "Microsoft IIS";
  return "Direct / Unknown Origin";
}

const TARGET_HEADERS: [string, "Critical" | "High" | "Medium" | "Low", string][] = [
  ["Strict-Transport-Security", "High", "Enforces HTTPS-only connections, preventing SSL-stripping."],
  ["Content-Security-Policy", "High", "Restricts resource origins to mitigate XSS and data injection."],
  ["X-Frame-Options", "Medium", "Prevents clickjacking by forbidding framing."],
  ["X-Content-Type-Options", "Medium", "Prevents MIME sniffing (nosniff)."],
  ["Referrer-Policy", "Low", "Limits referrer data leaked to other sites."],
  ["Permissions-Policy", "Low", "Restricts browser features (camera, microphone, geolocation)."],
  ["Cross-Origin-Opener-Policy", "Low", "Isolates the browsing context from cross-origin windows."],
  ["Cross-Origin-Embedder-Policy", "Low", "Controls loading of cross-origin resources."],
  ["Cross-Origin-Resource-Policy", "Low", "Restricts which origins may embed this resource."],
];

function detectVulnLibs(html: string): VulnLibInfo[] {
  const vuln: VulnLibInfo[] = [];
  const jqMatch = /jquery[-.]([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i.exec(html) || /jquery\/([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i.exec(html);
  if (jqMatch) {
    const ver = jqMatch[1];
    const [maj, min] = ver.split(".").map(Number);
    if (maj < 3 || (maj === 3 && min < 5)) {
      vuln.push({
        name: "jQuery",
        version: ver,
        cve: "CVE-2020-11022",
        severity: "Medium",
        description: "jQuery versions < 3.5.0 are vulnerable to Cross-Site Scripting (XSS) via htmlPrefilter.",
      });
    }
  }

  const ngMatch = /angular(?:js)?[-/]([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i.exec(html);
  if (ngMatch) {
    const ver = ngMatch[1];
    if (ver.startsWith("1.")) {
      vuln.push({
        name: "AngularJS",
        version: ver,
        cve: "CVE-2020-7676",
        severity: "High",
        description: "AngularJS 1.x has reached end-of-life and contains known sandbox escape vulnerabilities.",
      });
    }
  }

  const bsMatch = /bootstrap[-/]([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i.exec(html);
  if (bsMatch) {
    const ver = bsMatch[1];
    const [maj, min, patch] = ver.split(".").map(Number);
    if (maj < 4 || (maj === 4 && (min < 3 || (min === 3 && patch < 1)))) {
      vuln.push({
        name: "Bootstrap",
        version: ver,
        cve: "CVE-2019-8331",
        severity: "Medium",
        description: "Bootstrap < 4.3.1 is vulnerable to XSS in tooltip and popover data-template attributes.",
      });
    }
  }

  const lodashMatch = /lodash[-/]([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i.exec(html);
  if (lodashMatch) {
    const ver = lodashMatch[1];
    if (ver < "4.17.21") {
      vuln.push({
        name: "Lodash",
        version: ver,
        cve: "CVE-2021-23337",
        severity: "High",
        description: "Lodash versions prior to 4.17.21 are vulnerable to prototype pollution and command injection.",
      });
    }
  }
  return vuln;
}

function detectSri(html: string, hostname: string, baseUrl: string): SriInfo {
  const scripts = [...html.matchAll(/<script\b[^>]*\bsrc=["']([^"']+)["'][^>]*>/gi)];
  let extCount = 0;
  let missingSri = 0;
  for (const s of scripts) {
    try {
      const u = new URL(s[1], baseUrl);
      if (u.hostname !== hostname) {
        extCount++;
        if (!/\bintegrity=/i.test(s[0])) {
          missingSri++;
        }
      }
    } catch {
      // skip
    }
  }
  return {
    checked: true,
    total_external_scripts: extCount,
    missing_sri_count: missingSri,
    status: extCount === 0 ? "No External Scripts" : missingSri === 0 ? "SECURE (SRI Enforced)" : `MISSING_SRI (${missingSri} external scripts)`,
  };
}

function detectCors(headers: Record<string, string>): CorsInfo {
  const acao = headers["access-control-allow-origin"];
  const acac = (headers["access-control-allow-credentials"] || "").toLowerCase() === "true";
  if (acao) {
    return {
      configured: true,
      allow_origin: acao,
      allow_credentials: acac,
      status: acao === "*" ? "Permissive (Wildcard)" : `Allowed Origin: ${acao}`,
    };
  }
  return {
    configured: false,
    status: "Same-Origin Only (Strict)",
  };
}

async function auditDnsEmail(hostname: string): Promise<DnsEmailInfo> {
  const info: DnsEmailInfo = {
    spf_valid: false,
    spf_record: null,
    dmarc_valid: false,
    dmarc_record: null,
    mx_valid: false,
    mx_records: [],
  };

  const [txtRes, dmarcRes, mxRes] = await Promise.allSettled([
    dns.resolveTxt(hostname),
    dns.resolveTxt(`_dmarc.${hostname}`),
    dns.resolveMx(hostname),
  ]);

  if (txtRes.status === "fulfilled") {
    for (const chunk of txtRes.value) {
      const rec = chunk.join("");
      if (rec.toLowerCase().startsWith("v=spf1")) {
        info.spf_valid = true;
        info.spf_record = rec;
        break;
      }
    }
  }

  if (dmarcRes.status === "fulfilled") {
    for (const chunk of dmarcRes.value) {
      const rec = chunk.join("");
      if (rec.toLowerCase().startsWith("v=dmarc1")) {
        info.dmarc_valid = true;
        info.dmarc_record = rec;
        break;
      }
    }
  }

  if (mxRes.status === "fulfilled" && mxRes.value?.length > 0) {
    info.mx_valid = true;
    info.mx_records = mxRes.value.map((m) => `${m.exchange} (priority ${m.priority})`);
  }

  return info;
}

function buildOwaspTop10(findings: Finding[]) {
  const map: Record<string, { status: "PASS" | "WARN" | "FAIL"; issues: number; description: string }> = {
    "A01:2021-Broken Access Control": { status: "PASS", issues: 0, description: "Restrictions on authenticated user actions and directory traversal." },
    "A02:2021-Cryptographic Failures": { status: "PASS", issues: 0, description: "TLS ciphers, SSL certificates, and transport encryption." },
    "A03:2021-Injection": { status: "PASS", issues: 0, description: "Cross-site scripting (XSS), SQL injection, and command execution." },
    "A04:2021-Insecure Design": { status: "PASS", issues: 0, description: "Architectural flaws, lack of threat modeling, and business logic validation." },
    "A05:2021-Security Misconfiguration": { status: "PASS", issues: 0, description: "Missing security headers, default accounts, and information leakage." },
    "A06:2021-Vulnerable and Outdated Components": { status: "PASS", issues: 0, description: "Outdated software libraries, frameworks, and client scripts." },
    "A07:2021-Identification and Authentication Failures": { status: "PASS", issues: 0, description: "Session handling, cookie flags, and credential brute-force controls." },
    "A08:2021-Software and Data Integrity Failures": { status: "PASS", issues: 0, description: "Subresource Integrity (SRI) on external scripts and plugins." },
    "A09:2021-Security Logging and Monitoring Failures": { status: "PASS", issues: 0, description: "Security contact disclosure (security.txt) and audit telemetry." },
    "A10:2021-Server-Side Request Forgery": { status: "PASS", issues: 0, description: "Pre-connection SSRF firewall and internal network protection." },
  };

  for (const f of findings) {
    if (f.cwe.includes("CWE-319") || f.cwe.includes("CWE-295") || f.cwe.includes("CWE-298") || f.cwe.includes("CWE-326")) {
      map["A02:2021-Cryptographic Failures"].issues++;
      map["A02:2021-Cryptographic Failures"].status = "FAIL";
    } else if (f.cwe.includes("CWE-79") || f.cwe.includes("CWE-89")) {
      map["A03:2021-Injection"].issues++;
      map["A03:2021-Injection"].status = "FAIL";
    } else if (f.cwe.includes("CWE-353")) {
      map["A08:2021-Software and Data Integrity Failures"].issues++;
      map["A08:2021-Software and Data Integrity Failures"].status = "WARN";
    } else if (f.cwe.includes("CWE-1059")) {
      map["A09:2021-Security Logging and Monitoring Failures"].issues++;
      map["A09:2021-Security Logging and Monitoring Failures"].status = "WARN";
    } else if (f.cwe.includes("CWE-614") || f.cwe.includes("CWE-1004") || f.cwe.includes("CWE-1275")) {
      map["A07:2021-Identification and Authentication Failures"].issues++;
      map["A07:2021-Identification and Authentication Failures"].status = "WARN";
    } else {
      map["A05:2021-Security Misconfiguration"].issues++;
      if (map["A05:2021-Security Misconfiguration"].status !== "FAIL") {
        map["A05:2021-Security Misconfiguration"].status = "WARN";
      }
    }
  }

  return map;
}

async function auditHttp(fullUrl: string, hostname: string): Promise<{ http: HttpInfo; html: string }> {
  const results: HttpInfo = {
    missing_headers: [], present_headers: {}, header_details: {}, cookies: [],
    redirect_secure: false, status_code: 0, final_url: fullUrl, infrastructure: "Direct Origin", leakage: [],
    cors: { configured: false, status: "Same-Origin Only (Strict)" },
    sri: { checked: false, total_external_scripts: 0, missing_sri_count: 0, status: "Pending" },
    vuln_libs: [],
  };
  let html = "";
  const [redir, main] = await Promise.allSettled([
    safeRequest(`http://${hostname}/`, { followRedirects: false, timeoutMs: 6000, maxBytes: 4096 }),
    safeRequest(fullUrl, { timeoutMs: 7000 }),
  ]);
  if (redir.status === "fulfilled") {
    const loc = (redir.value.headers["location"] || "").toLowerCase();
    results.redirect_secure = redir.value.status >= 300 && redir.value.status < 400 && loc.startsWith("https://");
  }
  if (main.status === "rejected") {
    results.error = main.reason instanceof GuardError ? main.reason.message : "Failed to query HTTPS endpoint";
    return { http: results, html };
  }
  const r = main.value;
  html = /html/i.test(r.headers["content-type"] || "") ? r.body : "";
  results.status_code = r.status;
  results.final_url = r.finalUrl;
  results.infrastructure = detectInfrastructure(r.headers);
  results.cors = detectCors(r.headers);
  results.sri = detectSri(html, hostname, fullUrl);
  results.vuln_libs = detectVulnLibs(html);

  for (const [name, severity, description] of TARGET_HEADERS) {
    const v = r.headers[name.toLowerCase()];
    if (v !== undefined) {
      results.present_headers[name] = v;
      results.header_details[name] = { value: v, severity, description, status: "PASS" };
    } else results.missing_headers.push({ name, severity, description });
  }
  const server = r.headers["server"];
  if (server && /\d/.test(server)) results.leakage.push({ header: "Server", value: server, risk: "Exact server version disclosed; helps attackers match known CVEs." });
  if (r.headers["x-powered-by"]) results.leakage.push({ header: "X-Powered-By", value: r.headers["x-powered-by"], risk: "Application runtime/framework exposed." });
  if (r.headers["x-aspnet-version"]) results.leakage.push({ header: "X-AspNet-Version", value: r.headers["x-aspnet-version"], risk: "ASP.NET version exposed." });

  for (const raw of r.setCookies) {
    const parts = raw.split(";").map((p) => p.trim());
    const name = parts[0].split("=")[0];
    if (!name) continue;
    const low = parts.map((p) => p.toLowerCase());
    const attr = (k: string) => parts.find((p) => p.toLowerCase().startsWith(k + "="))?.split("=")[1] ?? "";
    results.cookies.push({
      name, secure: low.includes("secure"), httponly: low.includes("httponly"),
      samesite: attr("samesite") || "None", domain: attr("domain"), path: attr("path") || "/",
    });
  }
  return { http: results, html };
}

function calculateScore(
  tlsInfo: TlsInfo,
  httpInfo: HttpInfo,
  netInfo: NetworkInfo
): {
  score: number;
  grade: string;
  gradeColor: string;
  verdict: string;
  deductions: string[];
} {
  let score = 100;
  const deductions: string[] = [];

  if (tlsInfo.error || !tlsInfo.cert_valid) {
    score -= 35;
    deductions.push("Invalid or unverified SSL/TLS certificate (-35)");
  } else {
    const days = tlsInfo.cert_expires_in_days ?? 999;
    if (days < 7) {
      score -= 15;
      deductions.push("SSL Certificate expiring in less than 7 days (-15)");
    } else if (days < 30) {
      score -= 5;
      deductions.push("SSL Certificate expiring in less than 30 days (-5)");
    }
  }

  if (
    !["TLSv1.3", "TLSv1.2"].includes(tlsInfo.tls_version) &&
    !tlsInfo.error
  ) {
    score -= 15;
    deductions.push("Legacy or obsolete TLS protocol version (-15)");
  }

  if (httpInfo.error) {
    score -= 30;
    deductions.push("Target failed HTTPS reachability audit (-30)");
  } else {
    if (!httpInfo.redirect_secure) {
      score -= 12;
      deductions.push(
        "Insecure plain HTTP traffic is not auto-redirected to HTTPS (-12)"
      );
    }

    for (const m of httpInfo.missing_headers) {
      if (m.severity === "Critical") {
        score -= 8;
        deductions.push(`Missing Critical Security Header: ${m.name} (-8)`);
      } else if (m.severity === "High") {
        score -= 5;
        deductions.push(`Missing High Security Header: ${m.name} (-5)`);
      } else if (m.severity === "Medium") {
        score -= 3;
        deductions.push(`Missing Medium Security Header: ${m.name} (-3)`);
      } else if (m.severity === "Low") {
        score -= 1;
      }
    }

    if (httpInfo.leakage.length > 0) {
      score -= 4;
      deductions.push(
        "Server software version or runtime banner leakage detected (-4)"
      );
    }

    for (const cookie of httpInfo.cookies) {
      if (!cookie.secure) {
        score -= 4;
        deductions.push(`Cookie '${cookie.name}' missing Secure flag (-4)`);
      }
      if (!cookie.httponly) {
        score -= 3;
        deductions.push(`Cookie '${cookie.name}' missing HttpOnly flag (-3)`);
      }
    }
  }

  score = Math.max(5, Math.min(100, score));

  let grade = "F";
  let gradeColor = "#d90429";
  let verdict = "Critical Vulnerability";

  if (score >= 90) {
    grade = "A+";
    gradeColor = "#ff3b30";
    verdict = "Fortified Posture";
  } else if (score >= 80) {
    grade = "A";
    gradeColor = "#ff5722";
    verdict = "Strong Defense";
  } else if (score >= 70) {
    grade = "B";
    gradeColor = "#ff9800";
    verdict = "Good Security";
  } else if (score >= 60) {
    grade = "C";
    gradeColor = "#ffb703";
    verdict = "Moderate Risk";
  } else if (score >= 50) {
    grade = "D";
    gradeColor = "#f97316";
    verdict = "Elevated Exposure";
  }

  return { score, grade, gradeColor, verdict, deductions };
}

class NotVerifiedError extends Error {
  challenge: ReturnType<typeof buildChallenge>;
  detail: string;
  constructor(hostname: string, detail = "Ownership verification required.") {
    super(`Ownership of this domain must be verified before deep testing. ${detail}`);
    this.challenge = buildChallenge(hostname);
    this.detail = detail;
  }
}

class AttestationRequiredError extends Error {
  constructor(hostname: string) {
    super(`Legal attestation and scope agreement is required before active testing of ${hostname}.`);
  }
}

async function runAudit(
  raw: string,
  tier: Tier,
  attested = false,
  userId = "anonymous",
  ip = "127.0.0.1",
  userAgent = ""
): Promise<AuditReport> {
  const { hostname, fullUrl } = parseTarget(raw);
  const t0 = performance.now();
  const addrs = await resolvePublic(hostname);
  const latency = Math.round((performance.now() - t0) * 10) / 10;

  const needProof = tier === "deep" || process.env.CS_REQUIRE_VERIFY_BASIC === "true";
  let authorization: AuditReport["authorization"] = { verified: false };
  if (needProof) {
    if (!attested) {
      throw new AttestationRequiredError(hostname);
    }
    const own = await checkOwnership(hostname);
    if (!own.verified) throw new NotVerifiedError(hostname, own.detail);
    recordAttestation({ domain: hostname, userId, ip, userAgent });
    authorization = { verified: true, method: own.method };
  }

  const [netInfo, tlsInfo, httpRes, dnsEmail] = await Promise.all([
    auditNetwork(hostname, addrs[0].address, latency),
    auditTls(hostname, addrs[0].address),
    auditHttp(fullUrl, hostname),
    auditDnsEmail(hostname),
  ]);
  const httpInfo = httpRes.http;
  const { score, grade, gradeColor, verdict, deductions } = calculateScore(tlsInfo, httpInfo, netInfo);

  let findings = buildBasicFindings({ tls: tlsInfo, http: httpInfo });
  let manual: ManualCheck[] = [];
  if (tier === "deep" && !httpInfo.error) {
    const deep = await runDeepChecks(httpInfo.final_url, hostname, httpRes.html);
    findings = [...findings, ...deep.findings];
    manual = buildManualChecks(deep.signals);
  }

  const owaspTop10 = buildOwaspTop10(findings);
  const manualChecklist = manual.length >= 5 ? manual : getFullManualChecklist();

  return {
    schema_version: SCHEMA_VERSION,
    scan_id: crypto.randomUUID(),
    tier,
    authorization,
    target: hostname,
    full_url: fullUrl,
    score, grade, grade_color: gradeColor, verdict, deductions,
    network: netInfo, tls: tlsInfo, http: httpInfo,
    dns_email: dnsEmail,
    owasp_top10: owaspTop10,
    findings,
    manual_checks: manualChecklist,
    manual_checklist: manualChecklist,
    limitations: [
      "Automated checks cannot find business-logic flaws, authorization gaps (IDOR) or chained attacks; see manual_checks.",
      "The score reflects transport and configuration posture only; it is not a full security rating.",
      tier === "basic" ? "Basic tier is passive: no active probing was performed." : "Deep tier is non-destructive and limited to a fixed request budget.",
    ],
    timestamp: new Date().toISOString(),
  };
}

const json = (body: unknown, status = 200, extra: Record<string, string> = {}) =>
  NextResponse.json(body, { status, headers: { "Cache-Control": "no-store", ...extra } });

export async function POST(req: NextRequest) {
  const ip = clientIp(req.headers);
  let tier: Tier = "basic";
  try {
    const text = await req.text();
    if (text.length > 4096) return json({ error: "Request too large." }, 413);
    let body: { url?: unknown; tier?: unknown; format?: unknown; verified?: unknown } = {};
    try { body = JSON.parse(text || "{}"); } catch { return json({ error: "Invalid JSON body." }, 400); }
    tier = body.tier === "deep" ? "deep" : "basic";

    const per = tier === "deep" ? rateLimit(`deep:${ip}`, 5, 10 * 60_000) : rateLimit(`basic:${ip}`, 20, 60_000);
    if (!per.allowed) {
      const friendly = formatFriendlyError("RATE_LIMITED", "Rate limit exceeded.");
      return json(
        {
          error: friendly.message,
          title: friendly.title,
          friendly_message: friendly.message,
          hint: friendly.hint,
          code: "RATE_LIMITED",
          is_user_error: true,
        },
        429,
        { "Retry-After": String(per.retryAfterSec) }
      );
    }

    const parsed = parseTarget(body.url);
    const tgt = rateLimit(`host:${parsed.hostname}`, 10, 60_000);
    if (!tgt.allowed) {
      const friendly = formatFriendlyError("RATE_LIMITED", "This target was scanned too many times recently.");
      return json(
        {
          error: friendly.message,
          title: friendly.title,
          friendly_message: friendly.message,
          hint: friendly.hint,
          code: "RATE_LIMITED",
          is_user_error: true,
        },
        429,
        { "Retry-After": String(tgt.retryAfterSec) }
      );
    }

    const isAttested = (body as any).attested === true || (body as any).authorized_attested === true;
    const report = await runAudit(
      parsed.fullUrl,
      tier,
      isAttested,
      ((body as any).user_id as string) || pseudonymise(ip),
      ip,
      req.headers.get("user-agent") || ""
    );
    console.log(JSON.stringify({ evt: "scan", id: report.scan_id, tier, host: report.target, verified: report.authorization.verified, who: pseudonymise(ip), at: report.timestamp }));
    return body.format === "sarif" ? json(toSarif(report.target, report.findings)) : json(report);
  } catch (err: any) {
    if (err instanceof AttestationRequiredError) {
      const friendly = formatFriendlyError("ATTESTATION_REQUIRED", err.message);
      return json(
        {
          error: friendly.message,
          title: "Legal Attestation Required",
          friendly_message: friendly.message,
          hint: "Confirm the Legal Attestation & Scope Agreement checkbox before starting Deep Scan.",
          code: "ATTESTATION_REQUIRED",
          attestation_required: true,
          is_user_error: true,
        },
        403
      );
    }
    if (err instanceof NotVerifiedError) {
      const friendly = formatFriendlyError("NOT_VERIFIED", err.message);
      return json(
        {
          error: friendly.message,
          title: friendly.title,
          friendly_message: friendly.message,
          hint: "Publish the DNS TXT record, upload the .well-known file, or insert the HTML meta tag, then retry.",
          code: "NOT_VERIFIED",
          verification_required: true,
          detail: err.detail,
          challenge: err.challenge,
          is_user_error: true,
        },
        403
      );
    }
    if (err instanceof GuardError) {
      const isDenylist = err.code === "DENYLISTED";
      const isSsrf = ["IP_LITERAL", "BLOCKED_ADDRESS", "INTERNAL_HOST"].includes(err.code);
      const friendly = formatFriendlyError(err.code, err.message);
      return json(
        {
          error: friendly.message,
          title: friendly.title,
          friendly_message: friendly.message,
          hint: friendly.hint,
          code: err.code,
          denylist_blocked: isDenylist,
          ssrf_blocked: isSsrf,
          is_user_error: true,
        },
        400
      );
    }
    if (err instanceof Error && err.message === "VERIFY_SECRET_MISSING") {
      console.error("CS_VERIFY_SECRET is not configured; deep tier disabled.");
      const friendly = formatFriendlyError("VERIFY_SECRET_MISSING", err.message);
      return json(
        {
          error: friendly.message,
          title: friendly.title,
          friendly_message: friendly.message,
          hint: friendly.hint,
          code: "VERIFY_SECRET_MISSING",
          is_user_error: false,
        },
        503
      );
    }
    const friendly = formatFriendlyError("UNEXPECTED_ERROR", err?.message);
    console.error("audit_failed", err);
    return json(
      {
        error: friendly.message,
        title: friendly.title,
        friendly_message: friendly.message,
        hint: friendly.hint,
        code: "AUDIT_FAILED",
        is_user_error: false,
      },
      500
    );
  }
}
