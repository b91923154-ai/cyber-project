import test from "node:test";
import assert from "node:assert/strict";
import * as dns from "node:dns/promises";
import { buildChallenge, checkOwnership, TXT_PREFIX, FILE_PATH, dnsResolver } from "../lib/ownership.ts";
import { makeToken, tokensEqual } from "../lib/token.ts";
import { recordAttestation, getAttestationHistory } from "../lib/attestation.ts";

test("Token generation is deterministic and unguessable without secret", () => {
  const challenge1 = buildChallenge("example.com");
  const challenge2 = buildChallenge("example.com");
  const challengeDifferent = buildChallenge("google.com");

  assert.equal(challenge1.token, challenge2.token);
  assert.notEqual(challenge1.token, challengeDifferent.token);
  assert.equal(challenge1.token.length, 32);
  assert.equal(challenge1.dns.name, `${TXT_PREFIX}.example.com`);
  assert.equal(challenge1.dns.value, `cybershield-verify=${challenge1.token}`);
  assert.equal(challenge1.file.url, `https://example.com${FILE_PATH}`);
  assert.equal(challenge1.file.content, challenge1.token);
  assert.ok(challenge1.meta.tag.includes(challenge1.token));
});

test("Live check: Rejects domain you do NOT control (google.com)", async () => {
  const res = await checkOwnership("google.com");
  assert.equal(res.verified, false);
  assert.ok(res.detail.includes("Verification failed"));
});

test("Live check: Rejects domain you do NOT control (cloudflare.com)", async () => {
  const res = await checkOwnership("cloudflare.com");
  assert.equal(res.verified, false);
  assert.ok(res.detail.includes("Verification failed"));
});

test("Live check: Rejects fabricated / non-existent domain", async () => {
  const res = await checkOwnership("random-nonexistent-domain-4982749284.org");
  assert.equal(res.verified, false);
});

test("DNS TXT verification: succeeds ONLY when published record matches token", async () => {
  const target = "controlled-test.com";
  const expectedToken = makeToken(target);

  // 1. Mock DNS resolving nothing -> must fail
  const origResolveTxt = dnsResolver.resolveTxt;
  try {
    dnsResolver.resolveTxt = async (name) => {
      if (name === `${TXT_PREFIX}.${target}`) {
        throw new Error("ENODATA: no txt record");
      }
      return origResolveTxt(name);
    };

    const beforePublish = await checkOwnership(target, "dns");
    assert.equal(beforePublish.verified, false, "Must fail before record is published");

    // 2. Mock DNS resolving wrong token -> must fail
    dnsResolver.resolveTxt = async (name) => {
      if (name === `${TXT_PREFIX}.${target}`) {
        return [["cybershield-verify=wrong-fake-token"]];
      }
      return origResolveTxt(name);
    };

    const wrongTokenResult = await checkOwnership(target, "dns");
    assert.equal(wrongTokenResult.verified, false, "Must fail when token is wrong");

    // 3. Mock DNS resolving published valid record -> must succeed!
    dnsResolver.resolveTxt = async (name) => {
      if (name === `${TXT_PREFIX}.${target}`) {
        return [[`cybershield-verify=${expectedToken}`]];
      }
      return origResolveTxt(name);
    };

    const publishedResult = await checkOwnership(target, "dns");
    assert.equal(publishedResult.verified, true, "Must succeed when record is published");
    assert.equal(publishedResult.method, "dns_txt");

    // 4. Revocation: when record is removed -> must immediately fail again (no cached state)
    dnsResolver.resolveTxt = async () => {
      throw new Error("NXDOMAIN");
    };
    const afterRevoke = await checkOwnership(target, "dns");
    assert.equal(afterRevoke.verified, false, "Must fail immediately after record is removed");
  } finally {
    dnsResolver.resolveTxt = origResolveTxt;
  }
});

test("Legal attestation is recorded server-side for audit compliance", () => {
  const record = recordAttestation({
    domain: "security-audit-target.com",
    userId: "analyst@company.org",
    ip: "203.0.113.42",
    userAgent: "Mozilla/5.0 CyberShieldAuditClient/4.0",
  });

  assert.ok(record.id.startsWith("attest_"));
  assert.equal(record.domain, "security-audit-target.com");
  assert.equal(record.userId, "analyst@company.org");
  assert.equal(record.ip, "203.0.113.42");
  assert.ok(record.timestamp);

  const history = getAttestationHistory("security-audit-target.com");
  assert.ok(history.length >= 1);
  assert.equal(history[0].id, record.id);
});
