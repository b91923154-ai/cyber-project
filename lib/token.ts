/**
 * token.ts — deterministic ownership-challenge token (leaf module, no I/O).
 *
 * token = HMAC-SHA256(CS_VERIFY_SECRET, "v1:" + hostname)
 * The token is not secret once published in DNS; its job is to be unguessable
 * WITHOUT the server secret, so nobody can fabricate a valid challenge for a
 * domain by copying someone else's. Only whoever controls the domain can place
 * it in DNS or under /.well-known/.
 */
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

let devSecret: string | null = null;

export function verifySecret(): string {
  const s = process.env.CS_VERIFY_SECRET;
  if (s && s.length >= 16) return s;
  if (process.env.NODE_ENV === "production") {
    // Fail closed: never run the deep tier with a guessable or per-instance secret.
    throw new Error("VERIFY_SECRET_MISSING");
  }
  devSecret ||= randomBytes(24).toString("hex"); // dev only; changes on restart
  return devSecret;
}

export function makeToken(hostname: string, secret = verifySecret()): string {
  return createHmac("sha256", secret).update(`v1:${hostname.toLowerCase()}`).digest("hex").slice(0, 32);
}

export function tokensEqual(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
