/**
 * ownership.ts — Proof of domain control before any active ("deep") testing.
 *
 * Three technical methods supported (modelled after Google Search Console):
 *   1. DNS TXT:     _cybershield-verify.<hostname> = "cybershield-verify=<token>"
 *   2. HTTPS File:  https://<hostname>/.well-known/cybershield-verify.txt containing <token>
 *   3. HTML Meta:   <meta name="cybershield-verify" content="<token>"> in homepage <head>
 *
 * Safe-by-design guarantees:
 *   - Tokens are cryptographically derived on the server: HMAC-SHA256(SERVER_SECRET, hostname)
 *   - Client-supplied tokens are NEVER accepted.
 *   - No client-side bypasses or "demo mode" shortcuts exist.
 *   - Ownership is verified live via SSRF-safe requests and DNS lookups.
 *   - On any error, timeout, or mismatch, fails closed (verified: false).
 */
import * as dns from "node:dns/promises";
import { safeRequest } from "./guard.ts";
import { makeToken, tokensEqual } from "./token.ts";

export const TXT_PREFIX = "_cybershield-verify";
export const FILE_PATH = "/.well-known/cybershield-verify.txt";

export const dnsResolver = {
  resolveTxt: dns.resolveTxt,
};

export interface Challenge {
  hostname: string;
  token: string;
  dns: { type: "TXT"; name: string; value: string };
  file: { url: string; content: string };
  meta: { tag: string; name: string; content: string };
}

export function buildChallenge(hostname: string): Challenge {
  const token = makeToken(hostname);
  return {
    hostname,
    token,
    dns: {
      type: "TXT",
      name: `${TXT_PREFIX}.${hostname}`,
      value: `cybershield-verify=${token}`,
    },
    file: {
      url: `https://${hostname}${FILE_PATH}`,
      content: token,
    },
    meta: {
      tag: `<meta name="cybershield-verify" content="${token}">`,
      name: "cybershield-verify",
      content: token,
    },
  };
}

export type VerifyMethod = "dns_txt" | "well_known_file" | "html_meta";

export interface OwnershipResult {
  verified: boolean;
  method?: VerifyMethod;
  detail: string;
  checked_at: string;
}

/**
 * Checks domain ownership live using one or all methods.
 * Fails closed: Never returns true on timeout, error, or missing records.
 */
export async function checkOwnership(
  hostname: string,
  preferredMethod?: "dns" | "file" | "meta"
): Promise<OwnershipResult> {
  const expected = makeToken(hostname);
  const now = new Date().toISOString();

  // Method 1: DNS TXT Record
  if (!preferredMethod || preferredMethod === "dns") {
    try {
      const records = await dnsResolver.resolveTxt(`${TXT_PREFIX}.${hostname}`);
      for (const parts of records) {
        const v = parts.join("").trim();
        // Accept either "cybershield-verify=<token>" or pure "<token>"
        if (
          (v.startsWith("cybershield-verify=") &&
            tokensEqual(v.slice("cybershield-verify=".length).trim(), expected)) ||
          tokensEqual(v, expected)
        ) {
          return {
            verified: true,
            method: "dns_txt",
            detail: `DNS TXT challenge verified at ${TXT_PREFIX}.${hostname}`,
            checked_at: now,
          };
        }
      }
    } catch {
      // DNS lookup failed or no TXT record found; fall through
    }
  }

  // Method 2: HTTPS .well-known File
  if (!preferredMethod || preferredMethod === "file") {
    try {
      const res = await safeRequest(`https://${hostname}${FILE_PATH}`, {
        sameHostOnly: true,
        maxBytes: 512,
        timeoutMs: 5000,
      });

      if (res.status === 200 && res.body) {
        const bodyText = res.body.trim();
        if (tokensEqual(bodyText, expected)) {
          return {
            verified: true,
            method: "well_known_file",
            detail: `Well-known challenge file verified at https://${hostname}${FILE_PATH}`,
            checked_at: now,
          };
        }
      }
    } catch {
      // Network unreachable, timeout, or SSRF-blocked; fall through
    }
  }

  // Method 3: HTML Meta Tag in Homepage Head
  if (!preferredMethod || preferredMethod === "meta") {
    try {
      const home = await safeRequest(`https://${hostname}/`, {
        sameHostOnly: true,
        maxBytes: 128 * 1024,
        timeoutMs: 5000,
      });

      if (home.status === 200 && home.body) {
        // Strict regex matching <meta name="cybershield-verify" content="<token>">
        const metaPattern = /<meta\s+[^>]*name=["']cybershield-verify["'][^>]*content=["']([^"']+)["']/i;
        const altPattern = /<meta\s+[^>]*content=["']([^"']+)["'][^>]*name=["']cybershield-verify["']/i;
        const match = metaPattern.exec(home.body) || altPattern.exec(home.body);

        if (match && tokensEqual(match[1].trim(), expected)) {
          return {
            verified: true,
            method: "html_meta",
            detail: `HTML meta verification tag matched on homepage https://${hostname}/`,
            checked_at: now,
          };
        }
      }
    } catch {
      // Unreachable or blocked
    }
  }

  return {
    verified: false,
    detail: `Verification failed: No valid DNS TXT record at ${TXT_PREFIX}.${hostname}, well-known file at ${FILE_PATH}, or HTML meta tag was found matching the expected token.`,
    checked_at: now,
  };
}
