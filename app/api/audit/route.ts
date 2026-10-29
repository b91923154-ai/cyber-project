import { NextRequest, NextResponse } from "next/server";
import * as dns from "node:dns/promises";
import * as tls from "node:tls";
import * as http from "node:http";
import * as https from "node:https";
import * as crypto from "node:crypto";

const USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 CyberShield/3.0";

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
  error?: string;
}

export interface AuditReport {
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
  timestamp: string;
}

function extractTargetInfo(rawInput: string): { hostname: string; fullUrl: string } {
  let raw = rawInput.trim();
  if (!raw) {
    throw new Error("Target URL or domain cannot be empty.");
  }
  if (!/^https?:\/\//i.test(raw)) {
    raw = `https://${raw}`;
  }
  const parsed = new URL(raw);
  let hostname = parsed.hostname.toLowerCase();
  if (hostname.includes(":")) {
    hostname = hostname.split(":")[0];
  }
  return { hostname, fullUrl: raw };
}

async function auditNetwork(hostname: string): Promise<NetworkInfo> {
  const netInfo: NetworkInfo = {
    ip: "Unknown",
    latency_ms: 0,
    reverse_dns: "None",
    resolved: false,
  };

  const t0 = performance.now();
  try {
    const lookupRes = await dns.lookup(hostname);
    const latency = Math.round((performance.now() - t0) * 10) / 10;
    netInfo.ip = lookupRes.address;
    netInfo.latency_ms = latency;
    netInfo.resolved = true;

    try {
      const rev = await dns.reverse(lookupRes.address);
      netInfo.reverse_dns = rev[0] || "Unresolvable";
    } catch {
      netInfo.reverse_dns = "Unresolvable";
    }
  } catch (err: any) {
    netInfo.error = err.message || "DNS lookup failed";
  }
  return netInfo;
}

async function auditTls(hostname: string, port = 443): Promise<TlsInfo> {
  const results: TlsInfo = {
    tls_version: "N/A",
    cipher_suite: "N/A",
    cert_valid: false,
    cert_expires_in_days: 0,
    expires_at: "Unknown",
    issuer_org: "Unknown",
    issuer_cn: "Unknown",
    subject_cn: "Unknown",
    sans_count: 0,
    sans_sample: [],
    fingerprint_sha256: "N/A",
    protocol_secure: false,
  };

  return new Promise((resolve) => {
    let resolved = false;

    const finalize = (res: TlsInfo) => {
      if (!resolved) {
        resolved = true;
        resolve(res);
      }
    };

    const socket = tls.connect(
      {
        host: hostname,
        port,
        servername: hostname,
        rejectUnauthorized: false, // allow inspection even if self-signed/expired
        timeout: 6000,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate(true);
          const cipher = socket.getCipher();
          const version = socket.getProtocol();

          if (cert && Object.keys(cert).length > 0) {
            const expireDate = new Date(cert.valid_to);
            const now = new Date();
            const daysLeft = Math.floor(
              (expireDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
            );

            let sans: string[] = [];
            if (cert.subjectaltname) {
              sans = cert.subjectaltname
                .split(",")
                .map((s) => s.trim().replace(/^DNS:/, ""))
                .filter(Boolean);
            }

            let formattedFp = "N/A";
            if (cert.fingerprint256) {
              formattedFp = cert.fingerprint256.toUpperCase();
            } else if (cert.raw) {
              const hash = crypto.createHash("sha256").update(cert.raw).digest("hex");
              formattedFp = (hash.match(/.{1,2}/g) || []).join(":").toUpperCase();
            }

            const formatCertField = (val: string | string[] | undefined): string => {
              if (Array.isArray(val)) return val.join(", ");
              return val || "";
            };

            const issuerOrg =
              formatCertField(cert.issuer?.O) || formatCertField(cert.issuer?.CN) || "Unknown CA";
            const issuerCn = formatCertField(cert.issuer?.CN) || "Unknown";
            const subjectCn = formatCertField(cert.subject?.CN) || hostname;

            results.tls_version = version || "N/A";
            results.cipher_suite = cipher?.name || "Unknown";
            results.cert_expires_in_days = daysLeft;
            results.cert_valid = daysLeft > 0;
            results.expires_at = expireDate.toUTCString();
            results.issuer_org = issuerOrg;
            results.issuer_cn = issuerCn;
            results.subject_cn = subjectCn;
            results.sans_count = sans.length;
            results.sans_sample = sans.slice(0, 8);
            results.fingerprint_sha256 = formattedFp;
            results.protocol_secure = ["TLSv1.3", "TLSv1.2"].includes(
              version || ""
            );
          } else {
            results.error = "No certificate presented";
          }
        } catch (e: any) {
          results.error = e.message;
        } finally {
          socket.destroy();
          finalize(results);
        }
      }
    );

    socket.on("timeout", () => {
      results.error = "Connection timed out after 6 seconds";
      socket.destroy();
      finalize(results);
    });

    socket.on("error", (err) => {
      results.error = err.message;
      finalize(results);
    });
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

async function auditHttpHeaders(url: string, hostname: string): Promise<HttpInfo> {
  const results: HttpInfo = {
    missing_headers: [],
    present_headers: {},
    header_details: {},
    cookies: [],
    redirect_secure: false,
    status_code: 0,
    final_url: url,
    infrastructure: "Direct Origin",
    leakage: [],
  };

  // 1. Check HTTP to HTTPS redirect
  try {
    const httpRes = await fetch(`http://${hostname}`, {
      method: "GET",
      redirect: "manual",
      headers: { "User-Agent": USER_AGENT },
      signal: AbortSignal.timeout(6000),
    });
    const loc = httpRes.headers.get("location") || "";
    if (
      (httpRes.status >= 300 && httpRes.status < 400) &&
      loc.toLowerCase().startsWith("https://")
    ) {
      results.redirect_secure = true;
    }
  } catch {
    results.redirect_secure = false;
  }

  // 2. Inspect HTTPS headers
  try {
    const r = await fetch(url, {
      method: "GET",
      redirect: "follow",
      headers: {
        "User-Agent": USER_AGENT,
        Accept:
          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
      signal: AbortSignal.timeout(7000),
    });

    results.status_code = r.status;
    results.final_url = r.url;

    const lowerHeaders: Record<string, string> = {};
    r.headers.forEach((val, key) => {
      lowerHeaders[key.toLowerCase()] = val;
    });

    results.infrastructure = detectInfrastructure(lowerHeaders);

    const targetHeaders: [string, "Critical" | "High" | "Medium" | "Low", string][] = [
      [
        "Strict-Transport-Security",
        "Critical",
        "Enforces browser to connect only via HTTPS, eliminating SSL stripping attacks.",
      ],
      [
        "Content-Security-Policy",
        "Critical",
        "Restricts resource origins (scripts, images) to neutralize XSS and data injection.",
      ],
      [
        "X-Frame-Options",
        "High",
        "Guards against clickjacking attacks by forbidding nested iframe rendering.",
      ],
      [
        "X-Content-Type-Options",
        "High",
        "Prevents MIME-type sniffing by forcing adherence to declared Content-Type (nosniff).",
      ],
      [
        "Referrer-Policy",
        "Medium",
        "Controls how much referral information is sent with requests, preventing URL token leaks.",
      ],
      [
        "Permissions-Policy",
        "Medium",
        "Enforces strict browser feature access control (camera, microphone, geolocation).",
      ],
      [
        "Cross-Origin-Opener-Policy",
        "Low",
        "Isolates the browsing context to defend against Spectre-style side-channel attacks.",
      ],
      [
        "Cross-Origin-Embedder-Policy",
        "Low",
        "Prevents a document from loading cross-origin resources that do not explicitly grant permission.",
      ],
      [
        "Cross-Origin-Resource-Policy",
        "Low",
        "Restricts which origins can read and embed the resource.",
      ],
    ];

    for (const [hName, severity, description] of targetHeaders) {
      const lower = hName.toLowerCase();
      if (lower in lowerHeaders) {
        const val = lowerHeaders[lower];
        results.present_headers[hName] = val;
        results.header_details[hName] = {
          value: val,
          severity,
          description,
          status: "PASS",
        };
      } else {
        results.missing_headers.push({
          name: hName,
          severity,
          description,
        });
      }
    }

    // Check information leakage
    if (lowerHeaders["server"]) {
      const serverVal = lowerHeaders["server"];
      if (/\d/.test(serverVal)) {
        results.leakage.push({
          header: "Server",
          value: serverVal,
          risk: "Exact web server version disclosed. Attackers can pinpoint known CVEs for this build.",
        });
      }
    }
    if (lowerHeaders["x-powered-by"]) {
      results.leakage.push({
        header: "X-Powered-By",
        value: lowerHeaders["x-powered-by"],
        risk: "Underlying application runtime / framework exposed (e.g. PHP, Express, ASP.NET).",
      });
    }
    if (lowerHeaders["x-aspnet-version"]) {
      results.leakage.push({
        header: "X-AspNet-Version",
        value: lowerHeaders["x-aspnet-version"],
        risk: "Internal ASP.NET framework version exposed.",
      });
    }

    // Check cookies (from set-cookie headers)
    const setCookieHeader = r.headers.get("set-cookie");
    if (setCookieHeader) {
      // Split on comma not in date
      const cookieStrings = setCookieHeader.split(/,(?=\s*[a-zA-Z0-9_\-]+=)/);
      for (const rawCookie of cookieStrings) {
        const parts = rawCookie.split(";").map((p) => p.trim());
        const first = parts[0] || "";
        const [cName] = first.split("=");
        if (!cName) continue;

        const lowerParts = parts.map((p) => p.toLowerCase());
        const secure = lowerParts.includes("secure");
        const httponly = lowerParts.includes("httponly");

        let samesite = "None";
        for (const p of parts) {
          if (p.toLowerCase().startsWith("samesite=")) {
            samesite = p.split("=")[1] || "None";
          }
        }

        let domain = "";
        let path = "/";
        for (const p of parts) {
          if (p.toLowerCase().startsWith("domain=")) domain = p.split("=")[1];
          if (p.toLowerCase().startsWith("path=")) path = p.split("=")[1];
        }

        results.cookies.push({
          name: cName,
          secure,
          httponly,
          samesite,
          domain,
          path,
        });
      }
    }
  } catch (err: any) {
    results.error = err.message || "Failed to query HTTPS endpoint";
  }

  return results;
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

  // TLS deductions
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

  // HTTP deductions
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

async function runAudit(targetDomain: string): Promise<AuditReport> {
  const { hostname, fullUrl } = extractTargetInfo(targetDomain);

  const [netInfo, tlsInfo] = await Promise.all([
    auditNetwork(hostname),
    auditTls(hostname),
  ]);

  const httpInfo = await auditHttpHeaders(fullUrl, hostname);
  const { score, grade, gradeColor, verdict, deductions } = calculateScore(
    tlsInfo,
    httpInfo,
    netInfo
  );

  const now = new Date();
  const timestamp = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")} ${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}:${String(now.getSeconds()).padStart(2, "0")}`;

  return {
    target: hostname,
    full_url: fullUrl,
    score,
    grade,
    grade_color: gradeColor,
    verdict,
    deductions,
    network: netInfo,
    tls: tlsInfo,
    http: httpInfo,
    timestamp,
  };
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => ({}));
    const targetUrl = (body.url || "").trim();

    if (!targetUrl) {
      return NextResponse.json(
        { error: "Please specify a target domain or website URL." },
        { status: 400 }
      );
    }

    const report = await runAudit(targetUrl);
    return NextResponse.json(report);
  } catch (err: any) {
    return NextResponse.json(
      { error: err.message || "Audit execution encountered an unexpected error." },
      { status: 500 }
    );
  }
}

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const targetUrl = searchParams.get("url");
  if (!targetUrl) {
    return NextResponse.json(
      { error: "Please provide a 'url' query parameter." },
      { status: 400 }
    );
  }
  try {
    const report = await runAudit(targetUrl);
    return NextResponse.json(report);
  } catch (err: any) {
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
