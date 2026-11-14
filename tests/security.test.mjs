// Run: node --experimental-strip-types --test tests/
import test from "node:test";
import assert from "node:assert/strict";
import { isBlockedIp, parseTarget, resolvePublic, GuardError } from "../lib/guard.ts";
import { makeToken, tokensEqual } from "../lib/token.ts";
import { rateLimit } from "../lib/ratelimit.ts";
import { buildBasicFindings, buildManualChecks, toSarif } from "../lib/findings.ts";

test("blocks private, loopback, metadata, CGNAT, multicast IPv4", () => {
  for (const ip of ["127.0.0.1","10.1.2.3","172.16.0.1","172.31.255.255","192.168.1.1","169.254.169.254","100.64.0.1","0.0.0.0","224.0.0.1","255.255.255.255"])
    assert.equal(isBlockedIp(ip), true, ip);
});
test("allows public IPv4/IPv6", () => {
  for (const ip of ["8.8.8.8","1.1.1.1","93.184.216.34","2606:4700:4700::1111","2001:4860:4860::8888"])
    assert.equal(isBlockedIp(ip), false, ip);
});
test("blocks IPv6 loopback/ULA/link-local and IPv4-mapped bypasses", () => {
  for (const ip of ["::1","::","fc00::1","fd12:3456::1","fe80::1","::ffff:127.0.0.1","::ffff:7f00:1","::ffff:169.254.169.254","::ffff:a00:1","64:ff9b::7f00:1","2002:7f00:1::1"])
    assert.equal(isBlockedIp(ip), true, ip);
});
test("fails closed on garbage", () => { for (const x of ["", "abc", "999.1.1.1"]) assert.equal(isBlockedIp(x), true); });

test("parseTarget accepts normal domains and URLs", () => {
  assert.equal(parseTarget("Example.COM").hostname, "example.com");
  assert.equal(parseTarget("https://example.com/path?q=1").hostname, "example.com");
  assert.equal(parseTarget("http://example.com:80/").hostname, "example.com");
  assert.equal(parseTarget("example.com.").hostname, "example.com");
});
test("parseTarget rejects SSRF / abuse inputs", () => {
  const bad = ["http://127.0.0.1","http://[::1]/","http://localhost","http://2130706433","http://0x7f.0.0.1","http://169.254.169.254/latest/meta-data",
    "ftp://example.com","file:///etc/passwd","gopher://example.com","javascript:alert(1)","https://user:pw@example.com","https://example.com:8080","https://example.com:22",
    "http://intranet","http://printer.local","http://svc.internal","https://a.gov","https://x.nic.in","https://army.mil","", "  ", "ex ample.com","http://example.com\n.evil.com"];
  for (const b of bad) assert.throws(() => parseTarget(b), GuardError, JSON.stringify(b));
  assert.throws(() => parseTarget(null), GuardError);
  assert.throws(() => parseTarget({}), GuardError);
  assert.throws(() => parseTarget("a".repeat(3000)), GuardError);
});
test("env denylist is honoured (incl. subdomains)", () => {
  process.env.CS_DENYLIST = "bigbank.com";
  assert.throws(() => parseTarget("www.bigbank.com"), GuardError);
  assert.doesNotThrow(() => parseTarget("notbigbank.com"));
  delete process.env.CS_DENYLIST;
});
test("resolvePublic rejects hostnames that resolve to loopback", async () => {
  await assert.rejects(resolvePublic("localhost"), (e) => e instanceof GuardError && e.code === "BLOCKED_ADDRESS");
});

test("token: deterministic, host-bound, secret-bound", () => {
  const s = "a-test-secret-of-sufficient-length";
  assert.equal(makeToken("example.com", s), makeToken("EXAMPLE.com", s));
  assert.notEqual(makeToken("example.com", s), makeToken("evil.com", s));
  assert.notEqual(makeToken("example.com", s), makeToken("example.com", s + "x"));
  assert.equal(makeToken("example.com", s).length, 32);
  assert.equal(tokensEqual("abc", "abc"), true);
  assert.equal(tokensEqual("abc", "abd"), false);
  assert.equal(tokensEqual("abc", "abcd"), false);
});
test("production without CS_VERIFY_SECRET fails closed", () => {
  const prev = process.env.NODE_ENV; process.env.NODE_ENV = "production"; delete process.env.CS_VERIFY_SECRET;
  assert.throws(() => makeToken("example.com"), /VERIFY_SECRET_MISSING/);
  process.env.NODE_ENV = prev;
});

test("rate limiter enforces window", () => {
  for (let i = 0; i < 3; i++) assert.equal(rateLimit("t1", 3, 60000).allowed, true);
  const r = rateLimit("t1", 3, 60000); assert.equal(r.allowed, false); assert.ok(r.retryAfterSec > 0);
  assert.equal(rateLimit("t2", 3, 60000).allowed, true);
});

const sample = {
  tls: { cert_valid: false, cert_expires_in_days: 10, tls_version: "TLSv1.2", protocol_secure: true, authorized: false },
  http: { redirect_secure: false, missing_headers: [{ name: "Content-Security-Policy", severity: "High", description: "d" }],
    present_headers: { "Strict-Transport-Security": "max-age=60", "Content-Security-Policy": "script-src 'unsafe-inline'" },
    cookies: [{ name: "sid", secure: false, httponly: false, samesite: "None" }], leakage: [{ header: "Server", value: "nginx/1.18", risk: "r" }] },
};
test("findings: every finding has CWE, OWASP 2025, WSTG, confidence and fix", () => {
  const f = buildBasicFindings(sample);
  assert.ok(f.length >= 8);
  for (const x of f) {
    assert.match(x.cwe, /^CWE-\d+$/); assert.match(x.owasp, /^A\d\d:2025 /); assert.match(x.wstg, /^WSTG-/);
    assert.ok(["confirmed","likely","manual"].includes(x.confidence)); assert.ok(x.remediation.length > 5);
  }
  assert.ok(f.some((x) => x.title.includes("not trusted") && x.confidence === "confirmed"));
  assert.equal(new Set(f.map((x) => x.id)).size, f.length);
});
test("manual checks are conditional on detected signals", () => {
  const base = buildManualChecks({ hasPasswordForm:false, hasFileUpload:false, reflectsInput:false, hasForms:false });
  const all = buildManualChecks({ hasPasswordForm:true, hasFileUpload:true, reflectsInput:true, hasForms:true });
  assert.equal(base.length, 2); assert.equal(all.length, 6);
  assert.ok(all.every((c) => c.status === "pending" && c.steps.length >= 2));
});
test("SARIF output is structurally valid 2.1.0", () => {
  const s = toSarif("example.com", buildBasicFindings(sample));
  assert.equal(s.version, "2.1.0"); assert.equal(s.runs[0].results.length, s.runs[0].tool.driver.rules.length);
  assert.ok(s.runs[0].results.every((r) => ["error","warning","note"].includes(r.level)));
});
