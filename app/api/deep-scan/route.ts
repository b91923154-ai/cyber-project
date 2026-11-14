import { NextRequest, NextResponse } from "next/server";
import { GuardError, parseTarget, resolvePublic } from "@/lib/guard";
import { checkOwnership, buildChallenge } from "@/lib/ownership";
import { recordAttestation } from "@/lib/attestation";
import { clientIp, rateLimit, pseudonymise } from "@/lib/ratelimit";
import {
  SCHEMA_VERSION,
  getFullManualChecklist,
  type Finding,
} from "@/lib/findings";
import { runDeepChecks } from "@/lib/deep";
import { formatFriendlyError } from "@/lib/errors";

const json = (b: unknown, s = 200, h: Record<string, string> = {}) =>
  NextResponse.json(b, { status: s, headers: { "Cache-Control": "no-store", ...h } });

export async function POST(req: NextRequest) {
  const ip = clientIp(req.headers);
  const rl = rateLimit(`deep-scan:${ip}`, 5, 10 * 60_000);
  if (!rl.allowed) {
    const friendly = formatFriendlyError("RATE_LIMITED", "Rate limit exceeded for deep scanning.");
    return json(
      { error: friendly.message, title: friendly.title, hint: friendly.hint, code: "RATE_LIMITED", is_user_error: true },
      429,
      { "Retry-After": String(rl.retryAfterSec) }
    );
  }

  try {
    const text = await req.text();
    if (text.length > 4096) return json({ error: "Request too large." }, 413);
    const body = JSON.parse(text || "{}");
    const rawUrl = body.url || body.target;
    if (!rawUrl) return json({ error: "Missing 'url' parameter in request body." }, 400);

    const { hostname, fullUrl } = parseTarget(rawUrl);

    // 1. Legal Attestation Gate (Must be explicitly agreed by the user)
    const isAttested = body.attested === true || body.authorized_attested === true;
    if (!isAttested) {
      const friendly = formatFriendlyError(
        "ATTESTATION_REQUIRED",
        "Legal attestation is required before executing active Deep Scan tests. You must attest to holding explicit written permission."
      );
      return json(
        {
          error: friendly.message,
          title: "Legal Attestation Required",
          friendly_message: friendly.message,
          hint: "Check the 'Legal Attestation & Scope Agreement' box in the verification panel.",
          code: "ATTESTATION_REQUIRED",
          attestation_required: true,
          is_user_error: true,
        },
        403
      );
    }

    // 2. Strict Live Technical Verification Gate (Re-verified on EVERY request; no client bypass)
    const own = await checkOwnership(hostname);
    if (!own.verified) {
      const challenge = buildChallenge(hostname);
      const friendly = formatFriendlyError(
        "NOT_VERIFIED",
        `Domain ownership verification required. ${own.detail}`
      );
      return json(
        {
          error: friendly.message,
          title: friendly.title,
          friendly_message: friendly.message,
          hint: "Publish the DNS TXT record, upload the .well-known file, or insert the HTML meta tag, then retry.",
          code: "NOT_VERIFIED",
          verification_required: true,
          detail: own.detail,
          challenge,
          instructions: {
            dns: challenge.dns,
            file: challenge.file,
            meta: challenge.meta,
          },
          is_user_error: true,
        },
        403
      );
    }

    // 3. Record Audit Attestation on the server
    const attestation = recordAttestation({
      domain: hostname,
      userId: body.user_id || pseudonymise(ip),
      ip,
      userAgent: req.headers.get("user-agent") || "",
    });

    // 4. SSRF Gate
    const addrs = await resolvePublic(hostname);

    // 5. Run Active Deep Probing
    const deepResult = await runDeepChecks(fullUrl, hostname, "");
    const findings: Finding[] = deepResult.findings.map((f) => ({
      ...f,
      confidence: (f.confidence === "manual" ? "needs-manual-review" : f.confidence) as any,
    }));

    // If findings is empty, provide a clean verified baseline finding
    if (findings.length === 0) {
      findings.push({
        id: "CS-D-000",
        title: "Active Attack Surface Baseline Verified",
        severity: "Info",
        confidence: "confirmed",
        tier: "deep",
        evidence: `Probed ${hostname} across CORS, HTTP methods, sensitive file exposures and reflection; no direct anomalies observed.`,
        cwe: "CWE-693",
        owasp: "A05:2021-Security Misconfiguration",
        wstg: "WSTG-CONF-01",
        remediation: "Continue regular automated scans and conduct periodic manual penetration tests.",
      });
    }

    const manualChecklist = getFullManualChecklist();

    const scanSummary = {
      target: hostname,
      full_url: fullUrl,
      scan_tier: "deep",
      verified: true,
      verification_method: own.method,
      attestation_id: attestation.id,
      total_findings: findings.length,
      critical_count: findings.filter((f) => f.severity === "Critical").length,
      high_count: findings.filter((f) => f.severity === "High").length,
      medium_count: findings.filter((f) => f.severity === "Medium").length,
      low_count: findings.filter((f) => f.severity === "Low").length,
      info_count: findings.filter((f) => f.severity === "Info").length,
      manual_checks_recommended: manualChecklist.length,
    };

    return json({
      schema_version: SCHEMA_VERSION,
      scan_tier: "deep",
      tier: "deep",
      target: hostname,
      full_url: fullUrl,
      verified: true,
      verification_method: own.method,
      attestation_id: attestation.id,
      findings,
      scan_summary: scanSummary,
      manual_checklist: manualChecklist,
      manual_checks: manualChecklist,
      timestamp: new Date().toISOString(),
    });
  } catch (err: any) {
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
    const friendly = formatFriendlyError("DEEP_SCAN_FAILED", err?.message);
    console.error("deep_scan_failed", err);
    return json(
      {
        error: friendly.message,
        title: friendly.title,
        friendly_message: friendly.message,
        hint: friendly.hint,
        code: "DEEP_SCAN_FAILED",
        is_user_error: false,
      },
      500
    );
  }
}
