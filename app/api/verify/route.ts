import { NextRequest, NextResponse } from "next/server";
import { GuardError, parseTarget, resolvePublic } from "@/lib/guard";
import { buildChallenge, checkOwnership } from "@/lib/ownership";
import { clientIp, rateLimit } from "@/lib/ratelimit";
import { formatFriendlyError } from "@/lib/errors";

const json = (b: unknown, s = 200, h: Record<string, string> = {}) =>
  NextResponse.json(b, { status: s, headers: { "Cache-Control": "no-store", ...h } });

function formatInstructions(hostname: string, token: string) {
  return {
    dns: {
      type: "TXT",
      name: `_cybershield-verify.${hostname}`,
      value: `cybershield-verify=${token}`,
      instruction: `Add a DNS TXT record for _cybershield-verify.${hostname} with value: cybershield-verify=${token}`,
    },
    file: {
      url: `https://${hostname}/.well-known/cybershield-verify.txt`,
      content: token,
      instruction: `Create file at https://${hostname}/.well-known/cybershield-verify.txt with content: ${token}`,
    },
    meta: {
      tag: `<meta name="cybershield-verify" content="${token}">`,
      instruction: `Insert <meta name="cybershield-verify" content="${token}"> into the <head> of https://${hostname}/`,
    },
  };
}

/**
 * GET /api/verify?hostname=example.com&action=issue
 * Issues cryptographic challenge token or tests live verification.
 * Rate limit: 20 requests per 10 minutes per IP.
 */
export async function GET(req: NextRequest) {
  const ip = clientIp(req.headers);
  const rl = rateLimit(`verify:${ip}`, 20, 10 * 60_000);
  if (!rl.allowed) {
    const friendly = formatFriendlyError("RATE_LIMITED", "Rate limit exceeded for domain verification.");
    return json(
      { error: friendly.message, title: friendly.title, hint: friendly.hint, code: "RATE_LIMITED", is_user_error: true },
      429,
      { "Retry-After": String(rl.retryAfterSec) }
    );
  }

  try {
    const { searchParams } = new URL(req.url);
    const rawHost = searchParams.get("hostname") || searchParams.get("domain") || searchParams.get("url");
    if (!rawHost) return json({ error: "Hostname or domain query parameter required." }, 400);

    const { hostname } = parseTarget(rawHost);
    const challenge = buildChallenge(hostname);
    const instructions = formatInstructions(hostname, challenge.token);

    const action = searchParams.get("action");
    if (action === "verify" || searchParams.get("check") === "true") {
      await resolvePublic(hostname);
      const method = searchParams.get("method") as "dns" | "file" | "meta" | undefined;
      const result = await checkOwnership(hostname, method);
      return json({
        token: challenge.token,
        hostname,
        challenge,
        instructions,
        ...result,
      });
    }

    return json({
      token: challenge.token,
      hostname,
      challenge,
      instructions,
    });
  } catch (e: any) {
    if (e instanceof GuardError) {
      const friendly = formatFriendlyError(e.code, e.message);
      return json({ error: friendly.message, title: friendly.title, hint: friendly.hint, code: e.code, is_user_error: true }, 400);
    }
    if (e instanceof Error && e.message === "VERIFY_SECRET_MISSING") {
      const friendly = formatFriendlyError("VERIFY_SECRET_MISSING", e.message);
      return json({ error: friendly.message, title: friendly.title, hint: friendly.hint, code: "CONFIG_ERROR", is_user_error: false }, 503);
    }
    const friendly = formatFriendlyError("UNKNOWN", e?.message);
    console.error("verify_get_failed", e);
    return json({ error: friendly.message, title: friendly.title, hint: friendly.hint, code: "VERIFY_FAILED", is_user_error: false }, 500);
  }
}

/**
 * POST /api/verify
 * Body: { domain: string, check?: boolean, method?: "dns" | "file" | "meta" }
 * Rate limit: 20 requests per 10 minutes per IP.
 */
export async function POST(req: NextRequest) {
  const ip = clientIp(req.headers);
  const rl = rateLimit(`verify:${ip}`, 20, 10 * 60_000);
  if (!rl.allowed) {
    const friendly = formatFriendlyError("RATE_LIMITED", "Rate limit exceeded for domain verification.");
    return json(
      { error: friendly.message, title: friendly.title, hint: friendly.hint, code: "RATE_LIMITED", is_user_error: true },
      429,
      { "Retry-After": String(rl.retryAfterSec) }
    );
  }

  try {
    const text = await req.text();
    if (text.length > 2048) return json({ error: "Request too large." }, 413);
    const body = JSON.parse(text || "{}");
    const rawTarget = body.domain || body.hostname || body.url;
    if (!rawTarget) return json({ error: "Target domain is required." }, 400);

    const { hostname } = parseTarget(rawTarget);
    const challenge = buildChallenge(hostname);
    const instructions = formatInstructions(hostname, challenge.token);

    if (!body.check) {
      return json({
        challenge,
        token: challenge.token,
        instructions,
        hostname,
      });
    }

    // SSRF pre-check
    await resolvePublic(hostname);

    // Live technical verification (DNS, .well-known file, or HTML meta tag)
    const result = await checkOwnership(hostname, body.method);
    return json({
      challenge,
      token: challenge.token,
      instructions,
      hostname,
      ...result,
    });
  } catch (e: any) {
    if (e instanceof GuardError) {
      const friendly = formatFriendlyError(e.code, e.message);
      return json({ error: friendly.message, title: friendly.title, hint: friendly.hint, code: e.code, is_user_error: true }, 400);
    }
    if (e instanceof Error && e.message === "VERIFY_SECRET_MISSING") {
      const friendly = formatFriendlyError("VERIFY_SECRET_MISSING", e.message);
      return json({ error: friendly.message, title: friendly.title, hint: friendly.hint, code: "CONFIG_ERROR", is_user_error: false }, 503);
    }
    if (e instanceof SyntaxError) {
      const friendly = formatFriendlyError("BAD_INPUT", "Invalid JSON body.");
      return json({ error: friendly.message, title: friendly.title, hint: friendly.hint, code: "BAD_INPUT", is_user_error: true }, 400);
    }
    const friendly = formatFriendlyError("UNKNOWN", e?.message);
    console.error("verify_post_failed", e);
    return json({ error: friendly.message, title: friendly.title, hint: friendly.hint, code: "VERIFY_FAILED", is_user_error: false }, 500);
  }
}
