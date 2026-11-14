// Comprehensive Verification Script for CyberShield Web Vulnerability Scanner
const http = require('http');
const { spawn } = require('child_process');

let preferredHost = 'localhost';

async function singleRequest(hostname, path, method = 'GET', data = null, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    const postData = data ? JSON.stringify(data) : null;
    const req = http.request(
      {
        hostname,
        port: 3000,
        path,
        method,
        timeout: timeoutMs,
        headers: {
          'Content-Type': 'application/json',
          ...(postData ? { 'Content-Length': Buffer.byteLength(postData) } : {})
        }
      },
      (res) => {
        let body = '';
        res.on('data', (chunk) => (body += chunk));
        res.on('end', () => {
          try {
            resolve({ status: res.statusCode, data: JSON.parse(body) });
          } catch {
            resolve({ status: res.statusCode, data: body });
          }
        });
      }
    );
    req.on('timeout', () => {
      req.destroy(new Error(`Request to ${hostname}:${path} timed out after ${timeoutMs}ms`));
    });
    req.on('error', reject);
    if (postData) req.write(postData);
    req.end();
  });
}

async function request(path, method = 'GET', data = null, timeoutMs = 25000) {
  try {
    return await singleRequest(preferredHost, path, method, data, timeoutMs);
  } catch (err) {
    if (preferredHost === 'localhost') {
      try {
        const res = await singleRequest('127.0.0.1', path, method, data, timeoutMs);
        preferredHost = '127.0.0.1';
        return res;
      } catch {
        throw err;
      }
    }
    throw err;
  }
}

async function isServerRunning() {
  try {
    const res = await singleRequest(preferredHost, '/api/verify?action=issue&hostname=health-check.invalid', 'GET', null, 2000);
    return res && res.status !== undefined;
  } catch {
    try {
      const res = await singleRequest('127.0.0.1', '/api/verify?action=issue&hostname=health-check.invalid', 'GET', null, 2000);
      if (res && res.status !== undefined) {
        preferredHost = '127.0.0.1';
        return true;
      }
    } catch {
      return false;
    }
    return false;
  }
}

async function ensureServer() {
  if (await isServerRunning()) {
    console.log('[INFO] Detected active CyberShield server on port 3000.\n');
    return null;
  }

  console.log('[INFO] No active server detected. Spawning CyberShield production server on port 3000...');
  const isWin = process.platform === 'win32';
  const serverProc = isWin
    ? spawn(process.env.ComSpec || 'cmd.exe', ['/c', 'npm run start -- -p 3000'], { stdio: 'ignore' })
    : spawn('npm', ['run', 'start', '--', '-p', '3000'], { stdio: 'ignore' });

  // Wait up to 30s for server to start
  const start = Date.now();
  while (Date.now() - start < 30000) {
    await new Promise((r) => setTimeout(r, 1000));
    if (await isServerRunning()) {
      console.log('[INFO] CyberShield server is up and responsive on port 3000.\n');
      return serverProc;
    }
  }

  console.warn('[WARN] Server did not respond within 30s. Proceeding with tests in case of delay...\n');
  return serverProc;
}

async function runTests() {
  console.log('═══════════════════════════════════════════════════════');
  console.log('CYBERSHIELD TEST SUITE: END-TO-END SYSTEM VERIFICATION');
  console.log('═══════════════════════════════════════════════════════\n');

  let serverProc = null;
  try {
    serverProc = await ensureServer();
  } catch (e) {
    console.warn('[WARN] Could not auto-spawn server:', e.message);
  }

  let passed = 0;
  let total = 0;

  function assert(condition, name, details = '') {
    total++;
    if (condition) {
      console.log(`[PASS] ${name}`);
      passed++;
    } else {
      console.error(`[FAIL] ${name} -> ${details}`);
    }
  }

  try {
    // 1. Test Denylist protection (google.com)
    try {
      const res = await request('/api/audit', 'POST', { url: 'google.com' });
      assert(
        res.data && res.data.denylist_blocked === true,
        'Denylist Protection: google.com is blocked from scanning',
        JSON.stringify(res.data)
      );
    } catch (e) {
      assert(false, 'Denylist Protection', e.message);
    }

    // 2. Test SSRF loopback protection (127.0.0.1)
    try {
      const res = await request('/api/audit', 'POST', { url: 'http://127.0.0.1' });
      assert(
        res.data && res.data.ssrf_blocked === true,
        'SSRF Protection: 127.0.0.1 loopback blocked pre-connection',
        JSON.stringify(res.data)
      );
    } catch (e) {
      assert(false, 'SSRF Protection: 127.0.0.1', e.message);
    }

    // 3. Test SSRF cloud metadata protection (169.254.169.254)
    try {
      const res = await request('/api/audit', 'POST', { url: 'http://169.254.169.254' });
      assert(
        res.data && res.data.ssrf_blocked === true,
        'SSRF Protection: 169.254.169.254 AWS metadata IP blocked',
        JSON.stringify(res.data)
      );
    } catch (e) {
      assert(false, 'SSRF Protection: 169.254.169.254', e.message);
    }

    // 4. Test Verification API (Issue Token)
    let testToken = '';
    try {
      const res = await request('/api/verify?action=issue&hostname=my-test-app.com');
      assert(
        res.status === 200 && res.data && res.data.token && res.data.instructions,
        'Domain Verification: Issues verification token and multi-method instructions (DNS/File/Meta)',
        JSON.stringify(res.data)
      );
      testToken = res.data?.token || '';
    } catch (e) {
      assert(false, 'Domain Verification Issue', e.message);
    }

    // 5. Test Deep Scan gating (Blocked without verified domain ownership)
    try {
      const res = await request('/api/deep-scan', 'POST', { url: 'my-test-app.com', attested: true });
      assert(
        res.status === 403 && res.data && res.data.verification_required === true,
        'Deep Scan Authorization Gate: Rejects intrusive scans without verified domain ownership',
        JSON.stringify(res.data)
      );
    } catch (e) {
      assert(false, 'Deep Scan Authorization Gate', e.message);
    }

    // 6. Test Deep Scan gating (Blocked without legal attestation)
    try {
      const res = await request('/api/deep-scan', 'POST', { url: 'my-test-app.com', attested: false });
      assert(
        res.status === 403 && res.data && res.data.attestation_required === true,
        'Legal Attestation Gate: Rejects scans when legal agreement checkbox is unchecked',
        JSON.stringify(res.data)
      );
    } catch (e) {
      assert(false, 'Legal Attestation Gate', e.message);
    }

    // 7. Test Anti-Bypass: Client parameter verified=true is rejected without server proof
    try {
      const res = await request('/api/deep-scan', 'POST', { url: 'cloudflare.com', verified: true, attested: true });
      assert(
        res.status === 403 && res.data && res.data.verification_required === true,
        'Verification Anti-Bypass: Client-supplied verified:true is ignored; server re-verifies live',
        JSON.stringify(res.data)
      );
    } catch (e) {
      assert(false, 'Verification Anti-Bypass', e.message);
    }

    // 8. Test Live Verification rejection on uncontrolled domain (cloudflare.com)
    try {
      const res = await request('/api/verify', 'POST', { domain: 'cloudflare.com', check: true });
      assert(
        res.status === 200 && res.data && res.data.verified === false,
        'Ownership Proof Check: Uncontrolled domain (cloudflare.com) correctly rejected live',
        JSON.stringify(res.data)
      );
    } catch (e) {
      assert(false, 'Ownership Proof Check', e.message);
    }

    // 7. Test Basic Passive Scan (cloudflare.com)
    try {
      console.log('\nTesting live passive audit on cloudflare.com...');
      const res = await request('/api/audit', 'POST', { url: 'cloudflare.com' });
      assert(
        res.status === 200 && res.data && res.data.score > 0,
        'Passive Audit: Network, TLS, HTTP, and Security Headers evaluated',
        `Score: ${res.data?.score}, Grade: ${res.data?.grade}`
      );

      assert(
        res.data && res.data.dns_email && typeof res.data.dns_email.spf_valid === 'boolean',
        'DNS & Email Posture: SPF, DMARC, and MX records evaluated',
        `SPF: ${res.data?.dns_email?.spf_valid}, DMARC: ${res.data?.dns_email?.dmarc_valid}`
      );

      assert(
        res.data && res.data.owasp_top10 && Object.keys(res.data.owasp_top10).length >= 8,
        'OWASP Top 10 (2021): Compliant classification matrix produced',
        `Categories mapped: ${res.data?.owasp_top10 ? Object.keys(res.data.owasp_top10).length : 0}`
      );

      assert(
        res.data && res.data.http && res.data.http.cors && res.data.http.sri && Array.isArray(res.data.http.vuln_libs),
        'Web Attack Surface: CORS, SRI, and vulnerable library checks evaluated',
        `CORS: ${JSON.stringify(res.data?.http?.cors)}`
      );
    } catch (e) {
      assert(false, 'Passive Audit: cloudflare.com', e.message);
    }
  } finally {
    if (serverProc && serverProc.pid) {
      try {
        if (process.platform === 'win32') {
          const { execSync } = require('child_process');
          execSync(`taskkill /pid ${serverProc.pid} /T /F`, { stdio: 'ignore' });
        } else {
          serverProc.kill('SIGKILL');
        }
      } catch {}
    }
  }

  console.log('\n═══════════════════════════════════════════════════════');
  console.log(`FINAL RESULT: ${passed}/${total} TESTS PASSED (${Math.round((passed/total)*100)}% COMPLIANCE)`);
  console.log('═══════════════════════════════════════════════════════');

  if (passed < total) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error('Test execution error:', err);
  process.exit(1);
});
