# Security upgrade — what changed and why

## Added
| File | Purpose |
|---|---|
| `lib/guard.ts` | SSRF defence: URL/port/scheme validation, IP-literal and internal-host rejection, gov/mil denylist, public-IP-only DNS, DNS pinning, per-hop redirect re-validation, size/time caps |
| `lib/token.ts`, `lib/ownership.ts` | Domain-ownership proof (DNS TXT or `/.well-known/` file), checked live on every deep scan; fails closed without `CS_VERIFY_SECRET` |
| `lib/ratelimit.ts` | Per-IP and per-target rate limits; pseudonymised audit logging |
| `lib/findings.ts` | Findings with severity, confidence (confirmed/likely/manual), CWE, OWASP Top 10:2025, WSTG; guided manual checks; SARIF export |
| `lib/deep.ts` | Non-destructive deep checks (exposed .git/.env, CORS, methods, SRI, mixed content, inert reflection probe); max 9 requests |
| `app/api/verify/route.ts` | Issues and checks the ownership challenge |
| `app/ScanExtras.tsx` | UI: findings list, manual-check checklist, verification instructions |
| `tests/security.test.mjs` | 14 unit tests |

## Fixed
- **SSRF / open scanning relay** (critical): previously any host, including localhost and 169.254.169.254, could be scanned.
- **Self-signed certs reported as valid**: `cert_valid` only checked expiry; now requires a trusted chain.
- **Cookie parsing**: comma-splitting broke on `Expires` dates; now uses the real `Set-Cookie` list.
- **State-changing GET endpoint removed**; POST only, with body size cap and JSON validation.
- **Error leakage**: raw exception messages no longer returned to clients.
- **Severity calibration**: missing headers are no longer "Critical".
- **Flask `debug=True`** disabled in the legacy files (delete them: `vercel.json` deploys Next.js).
- App now sets its own security headers (see `next.config.ts`).

## API
`POST /api/audit` `{ "url": "example.com", "tier": "basic" | "deep", "format": "json" | "sarif" }`
Deep on an unverified domain → `403 { code: "NOT_VERIFIED", challenge }`.

## Run
```
cp .env.example .env.local   # fill CS_VERIFY_SECRET
npm run dev
node --experimental-strip-types --no-warnings --test tests/security.test.mjs
```
