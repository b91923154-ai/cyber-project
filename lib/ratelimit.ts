/**
 * ratelimit.ts — fixed-window, in-memory limiter + client identification.
 *
 * LIMITATION (be upfront in the pitch): on serverless platforms (Vercel) each
 * instance has its own memory, so this is best-effort. For production, back it
 * with a shared store (Redis / Upstash / Vercel KV) using the same interface.
 */
import { createHmac } from "node:crypto";

interface Bucket { count: number; resetAt: number }
const buckets = new Map<string, Bucket>();
let lastSweep = 0;

export function rateLimit(key: string, limit: number, windowMs: number) {
  const now = Date.now();
  if (now - lastSweep > 60_000) {
    lastSweep = now;
    for (const [k, b] of buckets) if (b.resetAt <= now) buckets.delete(k);
    if (buckets.size > 50_000) buckets.clear(); // memory-exhaustion guard
  }
  const b = buckets.get(key);
  if (!b || b.resetAt <= now) {
    buckets.set(key, { count: 1, resetAt: now + windowMs });
    return { allowed: true, remaining: limit - 1, retryAfterSec: 0 };
  }
  b.count += 1;
  const allowed = b.count <= limit;
  return {
    allowed,
    remaining: Math.max(0, limit - b.count),
    retryAfterSec: allowed ? 0 : Math.ceil((b.resetAt - now) / 1000),
  };
}

/**
 * Client IP. Only trust forwarding headers set by YOUR platform edge
 * (Vercel sets x-vercel-forwarded-for / x-real-ip and strips client-supplied
 * values). Behind any other proxy, configure that proxy's header instead.
 */
export function clientIp(headers: Headers): string {
  return (
    headers.get("x-vercel-forwarded-for")?.split(",")[0].trim() ||
    headers.get("x-real-ip")?.trim() ||
    headers.get("x-forwarded-for")?.split(",")[0].trim() ||
    "unknown"
  );
}

/** Pseudonymise IPs in audit logs (privacy by design). */
export function pseudonymise(value: string): string {
  const secret = process.env.CS_LOG_SALT || "dev-only-salt";
  return createHmac("sha256", secret).update(value).digest("hex").slice(0, 16);
}
