/**
 * guard.ts — target validation and SSRF-safe outbound HTTP for the scanner.
 *
 * Threat: the scanner makes network requests to a user-supplied host. Without
 * controls, a user can point it at localhost, cloud metadata (169.254.169.254),
 * or internal services (OWASP Top 10:2025 A01 — SSRF is now part of Broken
 * Access Control; CWE-918), or use it as an anonymous attack relay.
 *
 * Controls implemented here:
 *  1. Strict URL parsing: http/https only, no credentials, ports 80/443 only,
 *     no IP-literal targets, no single-label / internal-looking hostnames.
 *  2. Hard denylist of sensitive suffixes (gov/mil/etc.) + env-configurable list.
 *  3. DNS resolved by us; if ANY returned address is non-public, reject.
 *  4. DNS pinning: connections go to the exact IPs we validated (defeats
 *     DNS rebinding between check and use).
 *  5. Redirects are followed manually and every hop is re-validated.
 *  6. Response size and time caps.
 */
import * as dns from "node:dns/promises";
import * as http from "node:http";
import * as https from "node:https";
import * as net from "node:net";

export class GuardError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "GuardError";
    this.code = code;
  }
}

/* ------------------------------ IP blocklist ----------------------------- */

const blocklist = new net.BlockList();
const V4: [string, number][] = [
  ["0.0.0.0", 8], // "this" network
  ["10.0.0.0", 8], // RFC1918
  ["100.64.0.0", 10], // CGNAT
  ["127.0.0.0", 8], // loopback
  ["169.254.0.0", 16], // link-local incl. cloud metadata
  ["172.16.0.0", 12], // RFC1918
  ["192.0.0.0", 24], // IETF protocol assignments
  ["192.0.2.0", 24], // TEST-NET-1
  ["192.88.99.0", 24], // 6to4 relay (deprecated)
  ["192.168.0.0", 16], // RFC1918
  ["198.18.0.0", 15], // benchmarking
  ["198.51.100.0", 24], // TEST-NET-2
  ["203.0.113.0", 24], // TEST-NET-3
  ["224.0.0.0", 4], // multicast
  ["240.0.0.0", 4], // reserved + broadcast
];
const V6: [string, number][] = [
  ["::", 128], // unspecified
  ["::1", 128], // loopback
  ["64:ff9b::", 96], // NAT64 (can embed private IPv4)
  ["100::", 64], // discard-only
  ["2001::", 32], // Teredo
  ["2001:db8::", 32], // documentation
  ["2002::", 16], // 6to4 (embeds IPv4)
  ["fc00::", 7], // unique local
  ["fe80::", 10], // link-local
  ["fec0::", 10], // site-local (deprecated)
  ["ff00::", 8], // multicast
];
for (const [a, p] of V4) blocklist.addSubnet(a, p, "ipv4");
for (const [a, p] of V6) blocklist.addSubnet(a, p, "ipv6");

/** Convert ::ffff:a.b.c.d (IPv4-mapped IPv6) to a.b.c.d, else return as is. */
function unmapV4(ip: string): string {
  const m = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(ip);
  if (m) return m[1];
  // hex form, e.g. ::ffff:7f00:1
  const h = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(ip);
  if (h) {
    const hi = parseInt(h[1], 16);
    const lo = parseInt(h[2], 16);
    return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }
  return ip;
}

/** True if the address is NOT safely public (or is not a valid IP at all). */
export function isBlockedIp(rawIp: string): boolean {
  const ip = unmapV4(rawIp.trim().replace(/^\[|\]$/g, "").split("%")[0]);
  const family = net.isIP(ip);
  if (family === 0) return true; // fail closed on anything unparseable
  return blocklist.check(ip, family === 4 ? "ipv4" : "ipv6");
}

/* ------------------------------ denylist --------------------------------- */

/** Always refused, for every tier. Government, military, and infrastructure / high-profile targets. */
const HARD_DENY_SUFFIXES = [
  ".gov", ".mil", ".int", ".gov.in", ".nic.in", ".gov.uk", ".gov.au",
  ".gob.mx", ".gouv.fr", ".edu.in", "google.com", "apple.com",
];
/** Never a legitimate public scan target. */
const INTERNAL_SUFFIXES = [
  ".local", ".localhost", ".internal", ".intranet", ".lan", ".home",
  ".corp", ".localdomain", ".arpa", ".test", ".invalid", ".example",
];

function envDenylist(): string[] {
  return (process.env.CS_DENYLIST || "")
    .split(",")
    .map((s) => s.trim().toLowerCase().replace(/^\./, ""))
    .filter(Boolean);
}

function hostMatches(host: string, suffix: string): boolean {
  const s = suffix.startsWith(".") ? suffix.slice(1) : suffix;
  return host === s || host.endsWith("." + s);
}

/* ------------------------------ parsing ---------------------------------- */

export interface ParsedTarget {
  hostname: string;
  url: URL;
  fullUrl: string;
}

export function parseTarget(rawInput: unknown): ParsedTarget {
  if (typeof rawInput !== "string") {
    throw new GuardError("BAD_INPUT", "Target must be a string.");
  }
  let raw = rawInput.trim();
  if (!raw) throw new GuardError("BAD_INPUT", "Target URL or domain cannot be empty.");
  if (raw.length > 2048) throw new GuardError("BAD_INPUT", "Target is too long.");
  if (/[\u0000-\u001f\u007f\s]/.test(raw)) {
    throw new GuardError("BAD_INPUT", "Target contains invalid characters.");
  }
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) raw = `https://${raw}`;

  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new GuardError("BAD_INPUT", "Target is not a valid URL.");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new GuardError("BAD_SCHEME", "Only http and https targets are allowed.");
  }
  if (url.username || url.password) {
    throw new GuardError("BAD_INPUT", "Credentials in the URL are not allowed.");
  }
  if (url.port && url.port !== "80" && url.port !== "443") {
    throw new GuardError("BAD_PORT", "Only the standard ports 80 and 443 are allowed.");
  }

  const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
  if (!hostname) throw new GuardError("BAD_INPUT", "Target has no hostname.");
  if (hostname.startsWith("[") || net.isIP(hostname) !== 0 || /^[\d.]+$/.test(hostname) || /^0x[0-9a-f]+$/i.test(hostname)) {
    throw new GuardError("IP_LITERAL", "IP addresses are not accepted. Use a domain name you own.");
  }
  if (!hostname.includes(".") || hostname === "localhost") {
    throw new GuardError("INTERNAL_HOST", "Single-label and internal hostnames are not allowed.");
  }
  if (INTERNAL_SUFFIXES.some((s) => hostMatches(hostname, s))) {
    throw new GuardError("INTERNAL_HOST", "Internal hostnames are not allowed.");
  }
  if (
    HARD_DENY_SUFFIXES.some((s) => hostMatches(hostname, s)) ||
    envDenylist().some((s) => hostMatches(hostname, s))
  ) {
    throw new GuardError(
      "DENYLISTED",
      "This target is on the platform denylist and cannot be scanned."
    );
  }
  return { hostname, url, fullUrl: url.toString() };
}

/* ------------------------------ DNS -------------------------------------- */

export interface ResolvedAddress {
  address: string;
  family: 4 | 6;
}

/** Resolve and require EVERY answer to be public; otherwise reject. */
export async function resolvePublic(hostname: string): Promise<ResolvedAddress[]> {
  let answers: { address: string; family: number }[];
  try {
    answers = await dns.lookup(hostname, { all: true, verbatim: true });
  } catch {
    throw new GuardError("DNS_FAIL", "The hostname could not be resolved.");
  }
  if (!answers.length) throw new GuardError("DNS_FAIL", "The hostname has no DNS records.");
  for (const a of answers) {
    if (isBlockedIp(a.address)) {
      throw new GuardError(
        "BLOCKED_ADDRESS",
        "The hostname resolves to a non-public address and cannot be scanned."
      );
    }
  }
  return answers.map((a) => ({ address: a.address, family: a.family === 6 ? 6 : 4 }));
}

/* ------------------------------ safe HTTP -------------------------------- */

export interface SafeResponse {
  status: number;
  headers: Record<string, string>;
  setCookies: string[];
  body: string;
  finalUrl: string;
  redirects: string[];
  tlsAuthorized: boolean | null; // null for plain http
}

export interface SafeRequestOptions {
  method?: "GET" | "HEAD" | "OPTIONS";
  headers?: Record<string, string>;
  followRedirects?: boolean;
  maxRedirects?: number;
  /** Refuse redirects that leave the original hostname (used for verification). */
  sameHostOnly?: boolean;
  timeoutMs?: number;
  maxBytes?: number;
}

function singleRequest(
  url: URL,
  addrs: ResolvedAddress[],
  opts: Required<Pick<SafeRequestOptions, "method" | "timeoutMs" | "maxBytes">> & {
    headers: Record<string, string>;
  }
): Promise<{
  status: number;
  headers: Record<string, string>;
  setCookies: string[];
  body: string;
  tlsAuthorized: boolean | null;
}> {
  return new Promise((resolve, reject) => {
    const isHttps = url.protocol === "https:";
    const mod = isHttps ? https : http;
    let idx = 0;
    // DNS pinning: whatever the HTTP stack asks to resolve, answer with a
    // validated address only. (Node may request all addresses.)
    const lookup = ((_h: string, o: { all?: boolean }, cb: (...a: unknown[]) => void) => {
      if (o && o.all) {
        cb(null, addrs.map((a) => ({ address: a.address, family: a.family })));
      } else {
        const a = addrs[idx++ % addrs.length];
        cb(null, a.address, a.family);
      }
    }) as unknown as net.LookupFunction;

    const req = mod.request(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port || (isHttps ? 443 : 80),
        path: url.pathname + url.search,
        method: opts.method,
        headers: { Host: url.host, Connection: "close", ...opts.headers },
        lookup,
        timeout: opts.timeoutMs,
        // Inspection tool: we want headers even from sites with bad certs.
        // We record `socket.authorized` so the report never calls such a cert valid.
        ...(isHttps ? { rejectUnauthorized: false } : {}),
      } as https.RequestOptions,
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        const headers: Record<string, string> = {};
        for (const [k, v] of Object.entries(res.headers)) {
          if (k === "set-cookie") continue;
          headers[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : String(v ?? "");
        }
        const rawSetCookie = res.headers["set-cookie"];
        const setCookies = Array.isArray(rawSetCookie) ? rawSetCookie : [];
        const sock = res.socket as unknown as { authorized?: boolean };
        const tlsAuthorized = isHttps ? Boolean(sock?.authorized) : null;
        const finish = () =>
          resolve({
            status: res.statusCode || 0,
            headers,
            setCookies,
            body: Buffer.concat(chunks).toString("utf8"),
            tlsAuthorized,
          });
        res.on("data", (c: Buffer) => {
          size += c.length;
          if (size > opts.maxBytes) {
            chunks.push(c.subarray(0, Math.max(0, c.length - (size - opts.maxBytes))));
            res.destroy(); // cap reached
            finish();
            return;
          }
          chunks.push(c);
        });
        res.on("end", finish);
        res.on("error", () => finish());
      }
    );
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", (e) => reject(e));
    req.end();
  });
}

export async function safeRequest(
  startUrl: string | URL,
  options: SafeRequestOptions = {}
): Promise<SafeResponse> {
  const method = options.method ?? "GET";
  const timeoutMs = options.timeoutMs ?? 6000;
  const maxBytes = options.maxBytes ?? 512 * 1024;
  const follow = options.followRedirects ?? true;
  const maxRedirects = options.maxRedirects ?? 5;
  const headers = {
    "User-Agent": "CyberShield-Scanner/1.0 (+authorized security assessment)",
    Accept: "text/html,application/xhtml+xml,*/*;q=0.8",
    ...(options.headers || {}),
  };

  const first = parseTarget(startUrl.toString());
  let current = first.url;
  const redirects: string[] = [];

  for (let hop = 0; hop <= maxRedirects; hop++) {
    const parsed = parseTarget(current.toString()); // re-validate every hop
    if (options.sameHostOnly && parsed.hostname !== first.hostname) {
      throw new GuardError("CROSS_HOST_REDIRECT", "Redirect left the original host.");
    }
    const addrs = await resolvePublic(parsed.hostname);
    const r = await singleRequest(parsed.url, addrs, { method, timeoutMs, maxBytes, headers });

    const loc = r.headers["location"];
    if (follow && r.status >= 300 && r.status < 400 && loc) {
      let next: URL;
      try {
        next = new URL(loc, parsed.url);
      } catch {
        throw new GuardError("BAD_REDIRECT", "Invalid redirect location.");
      }
      redirects.push(next.toString());
      current = next;
      continue;
    }
    return {
      status: r.status,
      headers: r.headers,
      setCookies: r.setCookies,
      body: r.body,
      finalUrl: parsed.url.toString(),
      redirects,
      tlsAuthorized: r.tlsAuthorized,
    };
  }
  throw new GuardError("TOO_MANY_REDIRECTS", "Too many redirects.");
}
