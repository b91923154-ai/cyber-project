import ssl
import socket
import requests
import hashlib
import time
from datetime import datetime, timezone
from urllib.parse import urlparse
import sys
import os
import webbrowser
import threading
from flask import Flask, request, jsonify, render_template_string, send_from_directory

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 CyberShield/3.0"

def extract_target_info(raw_input):
    """Parses raw user input into a clean hostname and full HTTPS URL."""
    raw_input = raw_input.strip()
    if not raw_input:
        raise ValueError("Target URL or domain cannot be empty.")
    
    if not raw_input.startswith(("http://", "https://")):
        full_url = f"https://{raw_input}"
    else:
        full_url = raw_input
        
    parsed = urlparse(full_url)
    hostname = parsed.netloc or parsed.path.split('/')[0]
    if ":" in hostname:
        hostname = hostname.split(":")[0]
    hostname = hostname.strip().lower()
    return hostname, full_url

def audit_network(hostname):
    """Resolves DNS, measures connection latency, and detects reverse DNS."""
    net_info = {
        "ip": "Unknown",
        "latency_ms": 0,
        "reverse_dns": "None",
        "resolved": False
    }
    t0 = time.perf_counter()
    try:
        ip = socket.gethostbyname(hostname)
        latency = round((time.perf_counter() - t0) * 1000, 1)
        net_info["ip"] = ip
        net_info["latency_ms"] = latency
        net_info["resolved"] = True
        try:
            rev = socket.gethostbyaddr(ip)[0]
            net_info["reverse_dns"] = rev
        except Exception:
            net_info["reverse_dns"] = "Unresolvable"
    except Exception as e:
        net_info["error"] = str(e)
    return net_info

def audit_tls(hostname, port=443):
    """Deep TLS verification: protocol version, cipher suite, certificate chain, issuer, SANs, and SHA-256 fingerprint."""
    results = {
        "tls_version": "N/A",
        "cipher_suite": "N/A",
        "cert_valid": False,
        "cert_expires_in_days": 0,
        "expires_at": "Unknown",
        "issuer_org": "Unknown",
        "issuer_cn": "Unknown",
        "subject_cn": "Unknown",
        "sans_count": 0,
        "sans_sample": [],
        "fingerprint_sha256": "N/A",
        "protocol_secure": False
    }
    context = ssl.create_default_context()
    
    try:
        with socket.create_connection((hostname, port), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                der = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                version = ssock.version()
                
                expire_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_left = (expire_date - now).days
                
                issuer_dict = dict(x[0] for x in cert.get('issuer', ()))
                subject_dict = dict(x[0] for x in cert.get('subject', ()))
                sans = [v for k, v in cert.get('subjectAltName', ()) if k == 'DNS']
                
                fp = hashlib.sha256(der).hexdigest()
                formatted_fp = ":".join(fp[i:i+2].upper() for i in range(0, len(fp), 2))
                
                results['tls_version'] = version
                results['cipher_suite'] = cipher[0] if cipher else "Unknown"
                results['cert_expires_in_days'] = days_left
                results['cert_valid'] = days_left > 0
                results['expires_at'] = expire_date.strftime("%Y-%m-%d %H:%M:%S UTC")
                results['issuer_org'] = issuer_dict.get('organizationName', issuer_dict.get('commonName', 'Unknown CA'))
                results['issuer_cn'] = issuer_dict.get('commonName', 'Unknown')
                results['subject_cn'] = subject_dict.get('commonName', hostname)
                results['sans_count'] = len(sans)
                results['sans_sample'] = sans[:8]
                results['fingerprint_sha256'] = formatted_fp
                results['protocol_secure'] = version in ("TLSv1.3", "TLSv1.2")
    except Exception as e:
        results['error'] = str(e)
        results['cert_valid'] = False
        
    return results

def detect_infrastructure(headers):
    """Identifies CDN, edge proxy, and hosting platform from response headers."""
    server_h = headers.get('Server', '').lower()
    via_h = headers.get('Via', '').lower()
    
    if 'cloudflare' in server_h or 'cf-ray' in headers:
        return "Cloudflare Edge"
    if 'x-vercel-id' in headers or 'vercel' in server_h:
        return "Vercel Platform"
    if 'x-amz-cf-id' in headers or 'cloudfront' in via_h:
        return "AWS CloudFront"
    if 'fastly-debug-digest' in headers or 'x-fastly-request-id' in headers:
        return "Fastly CDN"
    if 'x-akamai-transformed' in headers or 'akamaighost' in server_h:
        return "Akamai Technologies"
    if 'x-nf-request-id' in headers or 'netlify' in server_h:
        return "Netlify"
    if 'google' in server_h or 'gse' in server_h or 'esf' in server_h:
        return "Google Cloud Infrastructure"
    if 'github.com' in server_h:
        return "GitHub Pages"
    if 'nginx' in server_h:
        return "Nginx Web Server"
    if 'apache' in server_h:
        return "Apache HTTP Server"
    if 'caddy' in server_h:
        return "Caddy Web Server"
    if 'microsoft-iis' in server_h:
        return "Microsoft IIS"
    return "Direct / Unknown Origin"

def audit_http_headers(url, hostname):
    """Evaluates HTTP response headers, HTTPS redirect enforcement, cookies, and information disclosure."""
    results = {
        "missing_headers": [],
        "present_headers": {},
        "header_details": {},
        "cookies": [],
        "redirect_secure": False,
        "status_code": 0,
        "final_url": url,
        "infrastructure": "Direct Origin",
        "leakage": []
    }

    headers_req = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}

    # 1. Check HTTP to HTTPS redirect
    try:
        http_url = f"http://{hostname}"
        r_http = requests.get(http_url, allow_redirects=False, timeout=6, headers=headers_req)
        if r_http.is_redirect and r_http.headers.get('Location', '').lower().startswith('https://'):
            results['redirect_secure'] = True
    except requests.RequestException:
        results['redirect_secure'] = False

    # 2. Inspect HTTPS headers
    try:
        r = requests.get(url, timeout=7, headers=headers_req, allow_redirects=True)
        headers = r.headers
        results['status_code'] = r.status_code
        results['final_url'] = r.url
        results['infrastructure'] = detect_infrastructure(headers)

        target_headers = [
            ("Strict-Transport-Security", "Critical", "Enforces browser to connect only via HTTPS, eliminating SSL stripping attacks."),
            ("Content-Security-Policy", "Critical", "Restricts resource origins (scripts, images) to neutralize XSS and data injection."),
            ("X-Frame-Options", "High", "Guards against clickjacking attacks by forbidding nested iframe rendering."),
            ("X-Content-Type-Options", "High", "Prevents MIME-type sniffing by forcing adherence to declared Content-Type (nosniff)."),
            ("Referrer-Policy", "Medium", "Controls how much referral information is sent with requests, preventing URL token leaks."),
            ("Permissions-Policy", "Medium", "Enforces strict browser feature access control (camera, microphone, geolocation)."),
            ("Cross-Origin-Opener-Policy", "Low", "Isolates the browsing context to defend against Spectre-style side-channel attacks."),
            ("Cross-Origin-Embedder-Policy", "Low", "Prevents a document from loading cross-origin resources that do not explicitly grant permission."),
            ("Cross-Origin-Resource-Policy", "Low", "Restricts which origins can read and embed the resource.")
        ]

        for h_name, severity, description in target_headers:
            if h_name in headers:
                val = headers[h_name]
                results['present_headers'][h_name] = val
                results['header_details'][h_name] = {
                    "value": val,
                    "severity": severity,
                    "description": description,
                    "status": "PASS"
                }
            else:
                results['missing_headers'].append({
                    "name": h_name,
                    "severity": severity,
                    "description": description
                })

        # Check information leakage headers
        if "Server" in headers:
            server_val = headers["Server"]
            if any(char.isdigit() for char in server_val):
                results['leakage'].append({
                    "header": "Server",
                    "value": server_val,
                    "risk": "Exact web server version disclosed. Attackers can pinpoint known CVEs for this build."
                })
        if "X-Powered-By" in headers:
            results['leakage'].append({
                "header": "X-Powered-By",
                "value": headers["X-Powered-By"],
                "risk": "Underlying application runtime / framework exposed (e.g. PHP, Express, ASP.NET)."
            })
        if "X-AspNet-Version" in headers:
            results['leakage'].append({
                "header": "X-AspNet-Version",
                "value": headers["X-AspNet-Version"],
                "risk": "Internal ASP.NET framework version exposed."
            })

        # 3. Check Cookie Security
        for cookie in r.cookies:
            httponly = cookie.has_nonstandard_attr('HttpOnly') or 'httponly' in cookie._rest
            samesite = cookie.get_nonstandard_attr('SameSite')
            results['cookies'].append({
                "name": cookie.name,
                "secure": bool(cookie.secure),
                "httponly": bool(httponly),
                "samesite": samesite if samesite else "None",
                "domain": cookie.domain,
                "path": cookie.path
            })

    except requests.RequestException as e:
        results['error'] = str(e)

    return results

def calculate_score(tls_info, http_info, net_info):
    """Computes an enterprise threat score (0-100) and letter grade."""
    score = 100
    deductions = []

    # TLS deductions
    if tls_info.get('error') or not tls_info.get('cert_valid', True):
        score -= 35
        deductions.append("Invalid or unverified SSL/TLS certificate (-35)")
    else:
        days = tls_info.get('cert_expires_in_days', 999)
        if days < 7:
            score -= 15
            deductions.append("SSL Certificate expiring in less than 7 days (-15)")
        elif days < 30:
            score -= 5
            deductions.append("SSL Certificate expiring in less than 30 days (-5)")
            
    if tls_info.get('tls_version') not in ("TLSv1.3", "TLSv1.2") and not tls_info.get('error'):
        score -= 15
        deductions.append("Legacy or obsolete TLS protocol version (-15)")

    # HTTP deductions
    if http_info.get('error'):
        score -= 30
        deductions.append("Target failed HTTPS reachability audit (-30)")
    else:
        if not http_info.get('redirect_secure'):
            score -= 12
            deductions.append("Insecure plain HTTP traffic is not auto-redirected to HTTPS (-12)")
            
        missing = http_info.get('missing_headers', [])
        for m in missing:
            sev = m.get('severity')
            if sev == "Critical":
                score -= 8
                deductions.append(f"Missing Critical Security Header: {m['name']} (-8)")
            elif sev == "High":
                score -= 5
                deductions.append(f"Missing High Security Header: {m['name']} (-5)")
            elif sev == "Medium":
                score -= 3
                deductions.append(f"Missing Medium Security Header: {m['name']} (-3)")
            elif sev == "Low":
                score -= 1

        # Leakage deductions
        if len(http_info.get('leakage', [])) > 0:
            score -= 4
            deductions.append("Server software version or runtime banner leakage detected (-4)")

        # Insecure cookies
        for cookie in http_info.get('cookies', []):
            if not cookie.get('secure'):
                score -= 4
                deductions.append(f"Cookie '{cookie.get('name')}' missing Secure flag (-4)")
            if not cookie.get('httponly'):
                score -= 3
                deductions.append(f"Cookie '{cookie.get('name')}' missing HttpOnly flag (-3)")
            
    score = max(5, min(100, score))
    
    if score >= 90:
        grade = "A+"
        color = "#ff3b30"
        verdict = "Fortified Posture"
    elif score >= 80:
        grade = "A"
        color = "#ff5722"
        verdict = "Strong Defense"
    elif score >= 70:
        grade = "B"
        color = "#ff9800"
        verdict = "Good Security"
    elif score >= 60:
        grade = "C"
        color = "#ffb703"
        verdict = "Moderate Risk"
    elif score >= 50:
        grade = "D"
        color = "#f97316"
        verdict = "Elevated Exposure"
    else:
        grade = "F"
        color = "#d90429"
        verdict = "Critical Vulnerability"
        
    return score, grade, color, verdict, deductions

def run_audit(target_domain):
    hostname, full_url = extract_target_info(target_domain)
    print(f"[*] CyberShield Auditing: {hostname}")
    
    net_info = audit_network(hostname)
    tls_info = audit_tls(hostname)
    http_info = audit_http_headers(full_url, hostname)
    score, grade, score_color, verdict, deductions = calculate_score(tls_info, http_info, net_info)
    
    return {
        "target": hostname,
        "full_url": full_url,
        "score": score,
        "grade": grade,
        "grade_color": score_color,
        "verdict": verdict,
        "deductions": deductions,
        "network": net_info,
        "tls": tls_info,
        "http": http_info,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

# --- FLASK APPLICATION ---
app = Flask(__name__)

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0, viewport-fit=cover">
    <title>CYBERSHIELD &mdash; Threat Intelligence &amp; Cryptographic Assurance Platform</title>
    <meta name="description" content="CyberShield is a next-generation security intelligence and cryptographic auditor platform.">
    <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🛡️</text></svg>">
    
    <!-- Modern Typography: Plus Jakarta Sans, Space Grotesk, JetBrains Mono -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800;900&family=Space+Grotesk:wght@500;700;800&display=swap" rel="stylesheet">
    
    <style>
        /* ═══════════════════════════════════════════════════════════════
           CUSTOM DISPLAY FONT + DESIGN TOKENS
           (RED / ORANGE / OBSIDIAN VELVET + CHROMATIC PRISMATIC DISPERSION)
           ═══════════════════════════════════════════════════════════════ */
        @font-face {
            font-family: 'Kapiler';
            src: url('/fonts/Kapiler.otf') format('opentype'),
                 url('/fonts/Kapiler.ttf') format('truetype');
            font-weight: normal;
            font-style: normal;
            font-display: swap;
        }

        @font-face {
            font-family: 'Zeta Drive';
            src: url('/fonts/ZetaDrive-MA8zp.ttf') format('truetype');
            font-weight: normal;
            font-style: normal;
            font-display: swap;
        }

        @font-face {
            font-family: 'Escape Artist';
            src: url('/fonts/EscapeArtistBold-ovy4B.otf') format('opentype');
            font-weight: 700;
            font-style: normal;
            font-display: swap;
        }

        :root {
            /* Dark Mode (Tactical Carbon Obsidian + Luminous Amber Glass) */
            --bg-base: #070406;
            --bg-surface: #0e0608;
            --bg-elevated: #16080b;
            --bg-card: rgba(18, 8, 11, 0.88);
            --bg-input: rgba(13, 5, 7, 0.94);

            /* Sleek Obsidian Glass Card Surface (No Muddy Stains) */
            --ember-card-surface: linear-gradient(145deg, rgba(22, 10, 13, 0.9) 0%, rgba(13, 6, 8, 0.95) 100%);
            --ember-card-border: rgba(255, 106, 0, 0.28);
            --ember-card-shadow: inset 0 1px 1px rgba(255, 200, 150, 0.2), inset 0 0 24px rgba(255, 70, 20, 0.05), 0 16px 40px rgba(0, 0, 0, 0.75);

            /* Fiery Flame Gradients */
            --flame-red: #ff223f;
            --flame-orange: #ff6a00;
            --flame-amber: #ffaa00;
            --flame-glow: rgba(255, 106, 0, 0.3);
            --flame-red-glow: rgba(255, 34, 63, 0.3);
            --gradient-flame: linear-gradient(135deg, #ff223f 0%, #ff6a00 50%, #ffaa00 100%);

            /* Prismatic Chromatic Dispersion Conic (Exact Image 2 Style) */
            --chromatic-conic: conic-gradient(from 220deg, #ff8800 0%, #ff0055 24%, #00f2fe 48%, #4facfe 62%, #ffe600 78%, #ff8800 100%);
            --chromatic-glow: 0 0 20px rgba(255, 110, 0, 0.4), 0 0 32px rgba(0, 210, 255, 0.25);

            /* Text Tokens - High Contrast & Crisp Readability */
            --text-primary: #fff5f2;
            --text-secondary: #ffab96;
            --text-muted: #b86856;
            --text-dim: #6e3328;

            /* Status Shades */
            --success: #00e676;
            --warning: #ffaa00;
            --danger: #ff223f;

            /* Typography */
            --font-display: 'Kapiler', 'Zeta Drive', 'Texas Tango', 'Space Grotesk', 'Plus Jakarta Sans', sans-serif;
            --font-heading: 'Space Grotesk', 'Plus Jakarta Sans', sans-serif;
            --font-body: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
            --font-mono: 'JetBrains Mono', monospace;
            --nav-height: 72px;
        }

        /* Light Mode Overrides */
        [data-theme="light"] {
            --bg-base: #fbf5f1;
            --bg-surface: #ffffff;
            --bg-elevated: #f8e5dc;
            --bg-card: rgba(255, 255, 255, 0.95);
            --bg-input: #ffffff;
            --ember-card-surface: radial-gradient(circle at 16% 16%, rgba(255, 110, 30, 0.12) 0%, rgba(255, 255, 255, 0.98) 45%, #ffffff 100%);
            --ember-card-border: rgba(255, 106, 0, 0.22);
            --ember-card-shadow: inset 0 1.5px 2px #ffffff, 0 8px 30px rgba(180, 50, 10, 0.07);
            --text-primary: #1e0905;
            --text-secondary: #7a2c16;
            --text-muted: #a65842;
            --text-dim: #c78977;
        }

        /* Light Mode Component Refinements (No Black BGs or Shadows) */
        [data-theme="light"] .nav-bar {
            background: linear-gradient(180deg, rgba(251, 245, 241, 0.92) 0%, rgba(251, 245, 241, 0.55) 70%, transparent 100%);
            border-bottom: none;
            box-shadow: none;
        }
        [data-theme="light"] .chromatic-circle-inner {
            background: #ffffff;
            box-shadow: inset 0 1px 2px rgba(255, 255, 255, 0.9), 0 2px 6px rgba(180, 60, 20, 0.1);
        }
        [data-theme="light"] .chromatic-circle-inner svg {
            color: var(--text-primary);
            filter: drop-shadow(0 1px 2px rgba(180, 60, 20, 0.12));
        }
        [data-theme="light"] .chromatic-capsule {
            background: transparent;
            border-color: rgba(255, 106, 0, 0.2);
        }
        [data-theme="light"] .auth-pill-btn {
            background: #ffffff;
            color: var(--text-primary);
            border-color: rgba(255, 106, 0, 0.3);
            box-shadow: 0 4px 15px rgba(255, 106, 0, 0.1);
        }
        [data-theme="light"] .auth-pill-btn:hover {
            border-color: var(--flame-orange);
            box-shadow: 0 6px 20px rgba(255, 106, 0, 0.2);
            color: var(--flame-orange);
        }
        [data-theme="light"] .brand-logo-mark .logo-mark-frame {
            background: #ffffff;
            border-color: rgba(255, 115, 29, 0.35);
            box-shadow: inset 0 1px 2px #ffffff, 0 3px 10px rgba(200, 60, 20, 0.1);
        }
        [data-theme="light"] .cyber-status-pill {
            background: rgba(34, 197, 94, 0.12);
            border-color: rgba(34, 197, 94, 0.45);
            color: #15803d;
            box-shadow: 0 0 10px rgba(34, 197, 94, 0.12);
        }
        [data-theme="light"] .profile-dropdown {
            background: #ffffff;
            border-color: rgba(255, 106, 0, 0.2);
            box-shadow: 0 15px 40px rgba(180, 60, 20, 0.12);
        }
        [data-theme="light"] .profile-dropdown-header {
            border-bottom-color: rgba(255, 106, 0, 0.12);
        }
        [data-theme="light"] .profile-dropdown-divider {
            background: rgba(255, 106, 0, 0.12);
        }
        [data-theme="light"] .target-input {
            background: #ffffff;
            border-color: rgba(255, 106, 0, 0.28);
            color: var(--text-primary);
            box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.04);
        }
        [data-theme="light"] .target-input:focus {
            border-color: var(--flame-orange);
            box-shadow: 0 0 0 3px rgba(255, 106, 0, 0.2);
        }
        [data-theme="light"] .audit-btn-inner {
            background: var(--gradient-flame);
            color: #ffffff;
            box-shadow: 0 4px 15px rgba(255, 80, 20, 0.3);
        }
        [data-theme="light"] .audit-btn-inner svg {
            stroke: #ffffff;
        }
        [data-theme="light"] .quick-chip {
            background: #ffffff;
            border-color: rgba(255, 106, 0, 0.2);
            color: var(--text-secondary);
        }
        [data-theme="light"] .quick-chip:hover {
            background: rgba(255, 106, 0, 0.12);
            color: var(--flame-orange);
        }
        [data-theme="light"] .terminal-container {
            background: #ffffff;
            border-color: rgba(255, 106, 0, 0.25);
            box-shadow: 0 15px 45px rgba(180, 60, 20, 0.1);
        }
        [data-theme="light"] .terminal-topbar {
            background: #fbf5f1;
            border-bottom-color: rgba(255, 106, 0, 0.15);
        }
        [data-theme="light"] .terminal-body {
            color: #5a2416;
        }
        [data-theme="light"] .term-msg {
            color: #1e0905;
        }
        [data-theme="light"] .drawer-panel {
            background: #ffffff;
            border-left-color: rgba(255, 106, 0, 0.2);
            box-shadow: -10px 0 40px rgba(180, 60, 20, 0.1);
        }
        [data-theme="light"] .drawer-item {
            background: #ffffff;
            border-color: rgba(255, 106, 0, 0.18);
            box-shadow: 0 2px 8px rgba(180, 50, 10, 0.05);
        }

        /* Light Mode Modal & Auth UI Perfection */
        [data-theme="light"] .modal-backdrop {
            background: rgba(30, 12, 8, 0.45);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
        }
        [data-theme="light"] .modal-window {
            background: #ffffff !important;
            border: 1px solid rgba(255, 106, 0, 0.25);
            box-shadow: 0 24px 60px rgba(180, 50, 10, 0.16), 0 4px 16px rgba(0, 0, 0, 0.05);
        }
        [data-theme="light"] .modal-window h3 {
            color: #1e0905 !important;
        }
        [data-theme="light"] .modal-window p {
            color: #7a2c16 !important;
        }
        [data-theme="light"] .auth-tab-row {
            background: #fbf5f1;
            border: 1px solid rgba(255, 106, 0, 0.22);
            padding: 4px;
        }
        [data-theme="light"] .auth-tab-btn {
            color: #7a2c16;
            font-weight: 700;
        }
        [data-theme="light"] .auth-tab-btn:hover {
            color: var(--flame-orange);
        }
        [data-theme="light"] .auth-tab-btn.active {
            background: var(--gradient-flame);
            color: #ffffff !important;
            box-shadow: 0 4px 14px rgba(255, 80, 20, 0.3);
        }
        [data-theme="light"] .auth-label {
            color: #5c1e0e;
            font-weight: 800;
        }
        [data-theme="light"] .auth-input-elem {
            background: #ffffff !important;
            border: 1.5px solid rgba(255, 106, 0, 0.28) !important;
            color: #1e0905 !important;
            box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.04);
        }
        [data-theme="light"] .auth-input-elem::placeholder {
            color: #b86b53;
            opacity: 0.8;
        }
        [data-theme="light"] .auth-input-elem:focus {
            border-color: var(--flame-orange) !important;
            box-shadow: 0 0 0 3px rgba(255, 106, 0, 0.22) !important;
            background: #ffffff !important;
        }
        [data-theme="light"] .auth-submit-btn {
            background: var(--gradient-flame);
            color: #ffffff !important;
            box-shadow: 0 4px 18px rgba(255, 80, 20, 0.35);
        }
        [data-theme="light"] .auth-submit-btn:hover {
            box-shadow: 0 6px 26px rgba(255, 80, 20, 0.5);
            transform: translateY(-2px);
        }
        [data-theme="light"] .modal-close-btn {
            background: #fbf5f1;
            border: 1px solid rgba(255, 106, 0, 0.25);
            color: #7a2c16;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.06);
        }
        [data-theme="light"] .modal-close-btn:hover {
            background: rgba(255, 106, 0, 0.15);
            color: var(--flame-orange);
        }
        [data-theme="light"] .remed-tab-row .remed-tab-btn {
            background: #ffffff;
            border: 1px solid rgba(255, 106, 0, 0.2);
            color: #7a2c16;
        }
        [data-theme="light"] .remed-tab-row .remed-tab-btn.active {
            background: var(--gradient-flame);
            color: #ffffff;
            border-color: var(--flame-orange);
        }
        [data-theme="light"] .code-box {
            background: #fdf8f5;
            border-color: rgba(255, 106, 0, 0.22);
            color: #9a3412;
        }
        [data-theme="light"] .code-copy-btn {
            background: #ffffff;
            border-color: rgba(255, 106, 0, 0.3);
            color: #7a2c16;
        }

        /* Light Theme Audit Results & Cards Refinements */
        [data-theme="light"] .meta-pill {
            background: #ffffff;
            border: 1px solid rgba(255, 106, 0, 0.25);
            color: #6c2a18;
            box-shadow: 0 2px 8px rgba(180, 50, 10, 0.05);
        }
        [data-theme="light"] .meta-pill:hover {
            background: #fff8f5;
            border-color: var(--flame-orange);
        }
        [data-theme="light"] .meta-pill svg {
            stroke: var(--flame-orange);
        }
        [data-theme="light"] .meta-pill span {
            color: #6c2a18;
        }

        [data-theme="light"] .info-tile {
            background: #ffffff;
            border: 1px solid rgba(255, 106, 0, 0.18);
            box-shadow: 0 2px 10px rgba(180, 60, 20, 0.05);
        }
        [data-theme="light"] .info-tile:hover {
            background: #fdfaf8;
            border-color: rgba(255, 106, 0, 0.38);
            transform: translateY(-2px);
            box-shadow: 0 4px 16px rgba(180, 60, 20, 0.09);
        }
        [data-theme="light"] .info-tile-label {
            color: #9a3412;
        }
        [data-theme="light"] .info-tile-value {
            color: #1e0905;
        }

        [data-theme="light"] .header-item-row {
            background: #ffffff;
            border: 1px solid rgba(255, 106, 0, 0.18);
            box-shadow: 0 2px 8px rgba(180, 50, 10, 0.04);
        }
        [data-theme="light"] .header-item-row:hover {
            background: #fdfaf8;
            border-color: rgba(255, 106, 0, 0.35);
            transform: translateX(4px);
        }
        [data-theme="light"] .header-item-name {
            color: #1e0905;
        }
        [data-theme="light"] .header-item-desc {
            color: #7a2c16;
        }
        [data-theme="light"] .header-item-val {
            background: rgba(255, 106, 0, 0.09);
            color: #c2410c;
            border: 1px solid rgba(255, 106, 0, 0.2);
        }

        [data-theme="light"] .action-btn {
            background: #ffffff;
            border: 1px solid rgba(255, 106, 0, 0.25);
            color: #6c2a18;
            box-shadow: 0 2px 8px rgba(180, 50, 10, 0.06);
        }
        [data-theme="light"] .action-btn:hover {
            border-color: var(--flame-orange);
            color: var(--flame-orange);
            box-shadow: 0 4px 14px rgba(255, 106, 0, 0.22);
        }

        [data-theme="light"] .status-badge.badge-secure {
            background: rgba(255, 106, 0, 0.1);
            color: #c2410c;
            border-color: rgba(255, 106, 0, 0.35);
            box-shadow: none;
        }
        [data-theme="light"] .status-badge.badge-warning {
            background: rgba(217, 119, 6, 0.12);
            color: #b45309;
            border-color: rgba(217, 119, 6, 0.35);
            box-shadow: none;
        }
        [data-theme="light"] .status-badge.badge-danger {
            background: rgba(220, 38, 38, 0.12);
            color: #b91c1c;
            border-color: rgba(220, 38, 38, 0.35);
            box-shadow: none;
        }

        [data-theme="light"] .fix-btn {
            background: linear-gradient(135deg, #ff4500 0%, #ff6a00 55%, #ff8800 100%);
            border: 1px solid rgba(255, 69, 0, 0.25);
            color: #ffffff;
            box-shadow: 0 3px 12px rgba(255, 80, 20, 0.28);
        }
        [data-theme="light"] .fix-btn svg {
            stroke: #ffffff;
        }
        [data-theme="light"] .fix-btn:hover {
            background: linear-gradient(135deg, #e63900 0%, #ff5500 50%, #ff6a00 100%);
            color: #ffffff;
            box-shadow: 0 6px 20px rgba(255, 80, 20, 0.45);
            transform: translateY(-2px);
        }

        /* Resets */
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        html { scroll-behavior: smooth; }
        body {
            font-family: var(--font-body);
            background-color: var(--bg-base);
            color: var(--text-primary);
            min-height: 100vh;
            overflow-x: hidden;
            transition: background-color 0.4s ease, color 0.4s ease;
        }

        /* ═══════════════════════════════════════════════════════════════
           PLAYFUL ICON ANIMATIONS
           ═══════════════════════════════════════════════════════════════ */
        @keyframes playfulWiggle {
            0%, 100% { transform: rotate(0deg); }
            20% { transform: rotate(-9deg) scale(1.08); }
            40% { transform: rotate(9deg) scale(1.08); }
            60% { transform: rotate(-5deg) scale(1.04); }
            80% { transform: rotate(5deg) scale(1.04); }
        }
        @keyframes playfulBounce {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-5px) scale(1.05); }
        }
        @keyframes rocketBoost {
            0%, 100% { transform: translate(0, 0) rotate(0deg); }
            25% { transform: translate(3px, -4px) rotate(12deg) scale(1.18); }
            50% { transform: translate(-2px, 1px) rotate(-8deg) scale(1.1); }
            75% { transform: translate(2px, -2px) rotate(6deg) scale(1.15); }
        }
        @keyframes flameBreathe {
            0%, 100% { filter: drop-shadow(0 0 10px rgba(255, 106, 0, 0.45)); transform: scale(1); }
            50% { filter: drop-shadow(0 0 22px rgba(255, 34, 63, 0.8)); transform: scale(1.04); }
        }
        @keyframes spinSlow {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
        @keyframes clockTick {
            0%, 100% { transform: rotate(0deg); }
            25% { transform: rotate(45deg); }
            50% { transform: rotate(90deg); }
            75% { transform: rotate(180deg); }
        }
        @keyframes flip360 {
            0% { transform: rotate(0deg) scale(1); }
            50% { transform: rotate(180deg) scale(1.25); }
            100% { transform: rotate(360deg) scale(1); }
        }
        @keyframes cookieWiggle {
            0%, 100% { transform: rotate(0deg) scale(1); }
            30% { transform: rotate(-14deg) scale(1.15); }
            70% { transform: rotate(14deg) scale(1.15); }
        }
        @keyframes pulseDot {
            0%, 100% { transform: scale(1); opacity: 1; }
            50% { transform: scale(0.7); opacity: 0.35; }
        }
        @keyframes fluidBorderRotate {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        @keyframes fluidGlowPulse {
            0%, 100% {
                box-shadow: 0 0 16px rgba(255, 110, 0, 0.45), 0 0 28px rgba(0, 210, 255, 0.25);
            }
            50% {
                box-shadow: 0 0 24px rgba(255, 0, 85, 0.55), 0 0 38px rgba(79, 172, 254, 0.4);
            }
        }

        /* ═══════════════════════════════════════════════════════════════
           AMBIENT CANVAS & MAGMA ORBS
           ═══════════════════════════════════════════════════════════════ */
        .ambient-canvas {
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            pointer-events: none; z-index: 0; overflow: hidden;
        }
        .gradient-flow {
            position: absolute; top: 0; left: 0; width: 300%; height: 300%;
            background: linear-gradient(-45deg, var(--bg-base) 0%, rgba(255, 34, 63, 0.08) 25%, var(--bg-base) 50%, rgba(255, 106, 0, 0.09) 75%, var(--bg-base) 100%);
            background-size: 400% 400%;
            animation: gradientFlow 16s ease infinite;
        }
        [data-theme="light"] .gradient-flow {
            background: linear-gradient(-45deg, #fbf5f1 0%, #fae0d5 25%, #ffffff 50%, #fde7df 75%, #fbf5f1 100%);
            background-size: 400% 400%;
        }
        @keyframes gradientFlow {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
        .cyber-grid {
            position: absolute; top: 0; left: 0; width: 100%; height: 100%;
            opacity: 0.05;
            background-image:
                linear-gradient(rgba(255, 106, 0, 0.3) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255, 106, 0, 0.3) 1px, transparent 1px);
            background-size: 60px 60px;
            animation: gridDrift 20s linear infinite;
        }
        @keyframes gridDrift {
            0% { transform: translate(0, 0); }
            100% { transform: translate(60px, 60px); }
        }
        .pulse-orb {
            position: absolute; border-radius: 50%; filter: blur(120px);
            animation: orbPulse 8s ease-in-out infinite alternate;
        }
        .pulse-orb-1 { width: 550px; height: 550px; top: -10%; left: -10%; background: rgba(255, 34, 63, 0.16); }
        .pulse-orb-2 { width: 620px; height: 480px; top: 25%; right: -12%; background: rgba(255, 106, 0, 0.14); animation-delay: 2.5s; }
        .pulse-orb-3 { width: 440px; height: 440px; bottom: -10%; left: 35%; background: rgba(255, 170, 0, 0.1); animation-delay: 5s; }
        @keyframes orbPulse {
            0% { transform: scale(1) translate(0, 0); opacity: 0.45; }
            50% { transform: scale(1.15) translate(20px, -15px); opacity: 0.8; }
            100% { transform: scale(1.05) translate(-15px, 20px); opacity: 0.55; }
        }

        /* Cursor Glow & Particles */
        .cursor-glow {
            position: fixed; pointer-events: none; z-index: 9999;
            width: 140px; height: 140px; border-radius: 50%;
            background: radial-gradient(circle, rgba(255, 106, 0, 0.25) 0%, transparent 68%);
            transform: translate(-50%, -50%); opacity: 0; transition: opacity 0.3s;
            mix-blend-mode: screen;
        }
        [data-theme="light"] .cursor-glow { mix-blend-mode: multiply; }
        .cursor-dot {
            position: fixed; pointer-events: none; z-index: 10000;
            width: 7px; height: 7px; border-radius: 50%;
            background: var(--flame-orange);
            transform: translate(-50%, -50%);
            box-shadow: 0 0 12px var(--flame-orange), 0 0 24px var(--flame-glow);
            transition: width 0.15s, height 0.15s;
        }

        /* ═══════════════════════════════════════════════════════════════
           IMAGE 1: EMBER BLOOM PILL CARD DESIGN
           ═══════════════════════════════════════════════════════════════ */
        .ember-card {
            background: var(--ember-card-surface);
            border: 1px solid var(--ember-card-border);
            border-radius: 26px;
            box-shadow: var(--ember-card-shadow);
            position: relative;
            overflow: hidden;
            transition: transform 0.25s cubic-bezier(0.16, 1, 0.3, 1), border-color 0.25s ease, box-shadow 0.25s ease;
        }
        .ember-card:hover {
            border-color: rgba(255, 115, 30, 0.55);
            box-shadow: inset 0 1.5px 2px rgba(255, 170, 80, 0.75), inset 0 0 22px rgba(255, 70, 20, 0.22), 0 20px 48px rgba(0, 0, 0, 0.85);
        }

        /* ═══════════════════════════════════════════════════════════════
           IMAGE 2: CHROMATIC PRISMATIC BUTTON & CAPSULE DESIGN
           ═══════════════════════════════════════════════════════════════ */
        .chromatic-capsule {
            display: inline-flex;
            align-items: center;
            background: rgba(16, 7, 9, 0.88);
            border: 1px solid rgba(255, 80, 30, 0.2);
            box-shadow: inset 0 1px 1.5px rgba(255, 255, 255, 0.1), 0 8px 24px rgba(0, 0, 0, 0.6);
            border-radius: 999px;
            padding: 4px;
            position: relative;
            transition: border-color 0.25s ease;
        }
        .chromatic-capsule:hover {
            border-color: rgba(255, 115, 30, 0.45);
        }
        .chromatic-circle-btn {
            width: 44px; height: 44px;
            border-radius: 50%;
            background: transparent;
            padding: 2.2px;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: var(--chromatic-glow);
            cursor: pointer;
            border: none;
            outline: none;
            transition: transform 0.25s cubic-bezier(0.16, 1, 0.3, 1), box-shadow 0.25s ease;
            position: relative;
            overflow: hidden;
            animation: fluidGlowPulse 4s ease-in-out infinite;
        }
        .chromatic-circle-btn::before {
            content: '';
            position: absolute;
            top: -50%; left: -50%;
            width: 200%; height: 200%;
            background: conic-gradient(from 0deg, #ff8800 0%, #ff0055 22%, #9900ff 40%, #00f2fe 60%, #4facfe 75%, #ffe600 90%, #ff8800 100%);
            animation: fluidBorderRotate 3.5s linear infinite;
            z-index: 0;
            pointer-events: none;
        }
        .chromatic-circle-btn:hover::before {
            animation-duration: 1.8s;
        }
        .chromatic-circle-btn:hover {
            transform: scale(1.08) rotate(6deg);
            box-shadow: 0 0 28px rgba(255, 120, 0, 0.7), 0 0 40px rgba(0, 210, 255, 0.5);
        }
        .chromatic-circle-inner {
            position: relative;
            z-index: 1;
            width: 100%; height: 100%;
            border-radius: 50%;
            background: radial-gradient(circle at 35% 30%, #2a1315 0%, #15080a 70%, #0a0304 100%);
            box-shadow: inset 0 1px 1px rgba(255, 255, 255, 0.3), inset 0 -2px 4px rgba(0, 0, 0, 0.6);
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .chromatic-circle-inner svg {
            width: 20px; height: 20px;
            color: #f4f4f5;
            filter: drop-shadow(0 2px 3px rgba(0, 0, 0, 0.7));
            transition: transform 0.2s ease;
        }
        .chromatic-circle-btn:hover .chromatic-circle-inner svg {
            animation: playfulBounce 0.4s ease;
        }

        /* ═══════════════════════════════════════════════════════════════
           NAVBAR (HEADER SECTION)
           ═══════════════════════════════════════════════════════════════ */
        .nav-bar {
            position: fixed; top: 0; left: 0; right: 0; z-index: 1000;
            height: var(--nav-height);
            background: linear-gradient(180deg, rgba(6, 3, 4, 0.75) 0%, rgba(6, 3, 4, 0.35) 65%, transparent 100%);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border-bottom: none;
            box-shadow: none;
            transition: all 0.3s ease;
        }
        .nav-inner {
            max-width: 1240px; margin: 0 auto; height: 100%;
            display: flex; align-items: center; justify-content: space-between;
            padding: 0 1.75rem;
        }
        .nav-brand {
            display: flex; align-items: center; gap: 12px;
            text-decoration: none; color: var(--text-primary);
        }
        .brand-logo-mark {
            position: relative;
            width: 36px; height: 36px;
            display: flex; align-items: center; justify-content: center;
            flex-shrink: 0;
        }
        .logo-mark-glow {
            position: absolute; inset: -3px; border-radius: 12px;
            background: radial-gradient(circle, rgba(255, 115, 29, 0.45) 0%, transparent 70%);
            filter: blur(6px); opacity: 0.6;
            transition: all 0.25s ease;
        }
        .logo-mark-frame {
            position: relative; width: 100%; height: 100%;
            border-radius: 10px;
            background: linear-gradient(135deg, rgba(32, 14, 18, 0.95), rgba(14, 6, 8, 0.95));
            border: 1px solid rgba(255, 115, 29, 0.4);
            display: flex; align-items: center; justify-content: center;
            box-shadow: inset 0 1px 2px rgba(255, 255, 255, 0.2), 0 4px 12px rgba(0, 0, 0, 0.5);
            transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
        }
        .nav-brand:hover .logo-mark-frame {
            transform: scale(1.08) rotate(4deg);
            border-color: rgba(255, 140, 50, 0.85);
            box-shadow: inset 0 1px 3px rgba(255, 200, 150, 0.4), 0 0 20px rgba(255, 115, 29, 0.5);
        }
        .nav-brand:hover .logo-mark-glow {
            opacity: 1; transform: scale(1.25);
        }
        .logo-mark-frame svg {
            width: 22px; height: 22px;
        }
        .brand-text-wrapper { display: flex; flex-direction: column; }
        .nav-brand-text {
            font-family: var(--font-display);
            font-size: 1.3rem; font-weight: 700; letter-spacing: 0.06em;
            background: var(--gradient-flame);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
            line-height: 1.1;
            transition: filter 0.25s ease;
        }
        .nav-brand:hover .nav-brand-text {
            filter: drop-shadow(0 0 12px rgba(255, 115, 29, 0.6));
        }
        .nav-brand-sub {
            font-size: 0.64rem; font-family: var(--font-mono); color: var(--text-muted);
            letter-spacing: 0.1em; text-transform: uppercase;
        }
        .cyber-status-pill {
            display: inline-flex; align-items: center; gap: 6px;
            padding: 3px 10px; border-radius: 999px;
            background: rgba(34, 197, 94, 0.08);
            border: 1px solid rgba(34, 197, 94, 0.35);
            box-shadow: 0 0 12px rgba(34, 197, 94, 0.12);
            font-size: 0.65rem; font-weight: 700; font-family: var(--font-mono);
            color: #4ade80; letter-spacing: 0.08em; text-transform: uppercase;
            transition: all 0.25s ease;
            margin-left: 2px;
        }
        .cyber-status-pill:hover {
            background: rgba(34, 197, 94, 0.16);
            border-color: rgba(34, 197, 94, 0.6);
            box-shadow: 0 0 18px rgba(34, 197, 94, 0.35);
            transform: translateY(-1px);
        }
        .cyber-status-dot {
            width: 6px; height: 6px; border-radius: 50%;
            background: #22c55e;
            box-shadow: 0 0 8px #22c55e, 0 0 14px rgba(34, 197, 94, 0.8);
            animation: pulseStatus 2s infinite ease-in-out;
        }
        @keyframes pulseStatus {
            0%, 100% { transform: scale(1); opacity: 1; box-shadow: 0 0 8px #22c55e, 0 0 14px rgba(34, 197, 94, 0.8); }
            50% { transform: scale(1.3); opacity: 0.75; box-shadow: 0 0 14px #22c55e, 0 0 22px rgba(34, 197, 94, 0.95); }
        }

        .nav-actions { display: flex; align-items: center; gap: 10px; }

        /* Secondary actions wrapped in chromatic capsules */
        .history-count-badge {
            position: absolute; top: -3px; right: -3px;
            background: var(--gradient-flame); color: #070303;
            font-size: 0.62rem; font-weight: 800; font-family: var(--font-mono);
            width: 18px; height: 18px; border-radius: 50%;
            display: flex; align-items: center; justify-content: center;
            box-shadow: 0 0 10px var(--flame-glow);
        }

        /* Image 1 Styled Pill Button for Auth */
        .auth-pill-btn {
            background: var(--ember-card-surface);
            border: 1px solid var(--ember-card-border);
            box-shadow: var(--ember-card-shadow);
            color: var(--text-primary); font-weight: 800; font-size: 0.88rem;
            padding: 10px 22px; border-radius: 999px;
            cursor: pointer; display: flex; align-items: center; gap: 8px;
            transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
            font-family: var(--font-heading);
        }
        .auth-pill-btn:hover {
            transform: translateY(-2px) scale(1.03);
            border-color: rgba(255, 120, 30, 0.6);
            box-shadow: inset 0 1.5px 2px rgba(255, 170, 80, 0.75), 0 8px 25px rgba(255, 100, 20, 0.35);
        }
        .auth-pill-btn svg { width: 17px; height: 17px; stroke: var(--flame-orange); }

        /* Profile Hub */
        .profile-hub { position: relative; }
        .online-dot {
            position: absolute; bottom: 0; right: 0;
            width: 12px; height: 12px; border-radius: 50%;
            background: var(--flame-orange); border: 2px solid var(--bg-base);
            box-shadow: 0 0 8px var(--flame-orange);
            animation: pulseDot 2s infinite ease-in-out;
        }
        .profile-dropdown {
            position: absolute; top: calc(100% + 12px); right: 0;
            width: 270px;
            background: var(--ember-card-surface);
            border: 1px solid var(--ember-card-border); border-radius: 20px;
            padding: 8px; box-shadow: var(--ember-card-shadow), 0 20px 50px rgba(0, 0, 0, 0.7);
            opacity: 0; visibility: hidden; transform: translateY(-10px) scale(0.96);
            transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1); z-index: 2000;
        }
        .profile-dropdown.open { opacity: 1; visibility: visible; transform: translateY(0) scale(1); }
        .profile-dropdown-header {
            padding: 14px 12px; border-bottom: 1px solid rgba(255, 80, 30, 0.15);
            display: flex; align-items: center; gap: 12px; margin-bottom: 4px;
        }
        .profile-dropdown-avatar {
            width: 40px; height: 40px; border-radius: 50%;
            background: var(--gradient-flame); display: flex; align-items: center; justify-content: center;
            font-weight: 800; color: #070303; font-size: 0.9rem;
        }
        .profile-dropdown-info h4 { font-size: 0.9rem; font-weight: 700; color: var(--text-primary); }
        .profile-dropdown-info .role-badge {
            display: inline-block; font-size: 0.65rem; font-weight: 700;
            padding: 2px 7px; border-radius: 4px; margin-top: 3px;
            background: rgba(255, 106, 0, 0.14); color: var(--flame-orange);
            border: 1px solid rgba(255, 106, 0, 0.35);
        }
        .profile-dropdown-item {
            display: flex; align-items: center; gap: 10px;
            padding: 10px 12px; border-radius: 10px; cursor: pointer;
            transition: background 0.15s ease; color: var(--text-secondary);
            font-size: 0.85rem; font-weight: 600; border: none;
            background: transparent; width: 100%; text-align: left;
            font-family: var(--font-body);
        }
        .profile-dropdown-item:hover { background: rgba(255, 106, 0, 0.1); color: var(--text-primary); }
        .profile-dropdown-item:hover svg { animation: playfulBounce 0.4s ease; }
        .profile-dropdown-item svg { width: 17px; height: 17px; }
        .profile-dropdown-item.danger { color: var(--danger); }
        .profile-dropdown-item.danger:hover { background: rgba(255, 34, 63, 0.15); }
        .profile-dropdown-divider { height: 1px; background: rgba(255, 80, 30, 0.15); margin: 5px 0; }

        /* ═══════════════════════════════════════════════════════════════
           MAIN HERO SECTION
           ═══════════════════════════════════════════════════════════════ */
        .main-content {
            position: relative; z-index: 1;
            padding: calc(var(--nav-height) + 3.8rem) 1.5rem 4rem;
            max-width: 1200px; margin: 0 auto;
        }
        .hero {
            text-align: center; margin-bottom: 2.8rem;
            animation: fadeInDown 0.6s cubic-bezier(0.16, 1, 0.3, 1);
        }
        @keyframes fadeInDown {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .hero-pill-badge {
            display: inline-flex; align-items: center; gap: 6px;
            padding: 4px 14px; border-radius: 999px;
            background: var(--ember-card-surface);
            border: 1px solid var(--ember-card-border);
            box-shadow: var(--ember-card-shadow);
            font-size: 0.70rem; font-weight: 700; color: var(--flame-orange);
            margin-bottom: 1.15rem; letter-spacing: 0.05em; text-transform: uppercase;
            font-family: var(--font-heading);
            transition: transform 0.2s ease;
        }
        .hero-pill-badge:hover { transform: scale(1.04); }
        .badge-text-mobile { display: none; }
        .live-dot {
            width: 6px; height: 6px; border-radius: 50%;
            background: var(--flame-red); box-shadow: 0 0 6px var(--flame-red);
            animation: pulseDot 1.8s infinite ease-in-out;
            flex-shrink: 0;
        }

        .hero-title {
            font-family: var(--font-display);
            font-size: 4rem; font-weight: 700; letter-spacing: 0.04em;
            background: var(--gradient-flame);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
            margin-bottom: 0.9rem; line-height: 1.15;
            filter: drop-shadow(0 2px 20px var(--flame-red-glow));
        }
        .hero-desc {
            color: var(--text-secondary); font-size: 1.18rem; max-width: 660px;
            margin: 0 auto 1.45rem; line-height: 1.6; font-family: var(--font-body);
        }
        .hero-desc strong { color: var(--text-primary); }
        .hero-kbd-hint {
            display: inline-flex; align-items: center; gap: 8px;
            font-size: 0.82rem; color: var(--text-muted);
            padding: 6px 18px; border-radius: 999px;
            background: var(--bg-surface); border: 1px solid rgba(255, 80, 20, 0.2);
            font-family: var(--font-mono);
        }
        .hero-kbd-hint kbd {
            padding: 3px 8px; border-radius: 6px;
            background: var(--bg-elevated); border: 1px solid rgba(255, 80, 20, 0.25);
            font-size: 0.74rem; color: var(--text-primary);
        }

        /* ═══════════════════════════════════════════════════════════════
           SEARCH COCKPIT (EXACT IMAGE 1 EMBER BLOOM CARD)
           ═══════════════════════════════════════════════════════════════ */
        .search-cockpit {
            padding: 2rem 2.2rem;
            margin-bottom: 2.5rem;
        }
        .search-input-group { display: flex; gap: 14px; flex-wrap: wrap; }
        .search-wrapper { position: relative; flex: 1; min-width: 280px; }
        .search-wrapper svg {
            position: absolute; left: 20px; top: 50%; transform: translateY(-50%);
            width: 22px; height: 22px; color: var(--text-muted); pointer-events: none;
            transition: color 0.2s ease;
        }
        .target-input:focus ~ svg, .search-wrapper:hover svg { color: var(--flame-orange); animation: playfulBounce 0.4s ease; }
        .target-input {
            width: 100%; padding: 18px 20px 18px 56px;
            background: linear-gradient(180deg, rgba(16, 7, 10, 0.92) 0%, rgba(10, 4, 6, 0.96) 100%);
            border: 1px solid rgba(255, 106, 0, 0.3);
            border-radius: 18px; color: var(--text-primary);
            font-size: 1.05rem; font-family: var(--font-body); outline: none;
            transition: all 0.25s ease;
            box-shadow: inset 0 2px 5px rgba(0, 0, 0, 0.65), 0 4px 16px rgba(0, 0, 0, 0.4);
        }
        .target-input:focus {
            border-color: var(--flame-orange);
            box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.3), 0 0 0 3px rgba(255, 106, 0, 0.25), 0 0 25px rgba(255, 106, 0, 0.2);
        }
        .target-input::placeholder { color: rgba(255, 171, 150, 0.4); }

        /* Audit Target Button (Chromatic Pill Button) */
        .audit-btn {
            background: transparent;
            padding: 2.5px;
            border-radius: 18px;
            border: none;
            cursor: pointer;
            box-shadow: var(--chromatic-glow);
            transition: transform 0.25s cubic-bezier(0.16, 1, 0.3, 1), box-shadow 0.25s ease;
            display: inline-flex;
            position: relative;
            overflow: hidden;
            animation: fluidGlowPulse 4s ease-in-out infinite;
        }
        .audit-btn::before {
            content: '';
            position: absolute;
            width: 300%;
            height: 300%;
            top: -100%;
            left: -100%;
            background: conic-gradient(from 0deg, #ff8800 0%, #ff0055 22%, #9900ff 40%, #00f2fe 60%, #4facfe 75%, #ffe600 90%, #ff8800 100%);
            animation: fluidBorderRotate 4.5s linear infinite;
            z-index: 0;
            pointer-events: none;
        }
        .audit-btn:hover::before {
            animation-duration: 2s;
        }
        .audit-btn:hover {
            transform: translateY(-2px) scale(1.03);
            box-shadow: 0 0 32px rgba(255, 120, 0, 0.7), 0 0 50px rgba(0, 210, 255, 0.5);
        }
        .audit-btn:hover svg { animation: rocketBoost 0.7s ease infinite; }
        .audit-btn:active { transform: translateY(0) scale(0.98); }
        .audit-btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
        .audit-btn-inner {
            position: relative;
            z-index: 1;
            background: radial-gradient(circle at 35% 30%, #2f1216 0%, #16070a 70%, #0a0304 100%);
            box-shadow: inset 0 1px 2px rgba(255, 255, 255, 0.3), inset 0 -2px 4px rgba(0, 0, 0, 0.6);
            border-radius: 16px;
            padding: 16px 36px;
            display: flex;
            align-items: center;
            gap: 10px;
            color: #fff2ef;
            font-weight: 800;
            font-size: 1.05rem;
            font-family: var(--font-heading);
        }
        .audit-btn-inner svg { width: 20px; height: 20px; stroke: var(--flame-orange); }

        .quick-targets-row {
            display: flex; gap: 10px; margin-top: 16px; flex-wrap: wrap; align-items: center;
        }
        .quick-targets-label { font-size: 0.8rem; color: var(--text-muted); font-weight: 700; text-transform: uppercase; font-family: var(--font-heading); }
        .quick-chip {
            padding: 8px 16px; border-radius: 999px; font-size: 0.82rem;
            font-weight: 600; font-family: var(--font-mono);
            background: var(--ember-card-surface);
            border: 1px solid var(--ember-card-border);
            color: var(--text-secondary); cursor: pointer;
            transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
            box-shadow: inset 0 1px 1px rgba(255, 255, 255, 0.1);
        }
        .quick-chip:hover {
            background: rgba(255, 106, 0, 0.18); border-color: var(--flame-orange);
            color: var(--flame-orange); transform: translateY(-2px) scale(1.05);
        }

        /* ═══════════════════════════════════════════════════════════════
           LIVE CYBER SCANNER TERMINAL
           ═══════════════════════════════════════════════════════════════ */
        .terminal-container {
            display: none;
            background: rgba(10, 4, 5, 0.94);
            border: 1px solid rgba(255, 80, 30, 0.35);
            border-radius: 24px; overflow: hidden;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.85), 0 0 50px rgba(255, 106, 0, 0.2);
            margin-bottom: 2.5rem;
            animation: terminalPop 0.4s cubic-bezier(0.16, 1, 0.3, 1);
        }
        @keyframes terminalPop {
            from { opacity: 0; transform: scale(0.97) translateY(10px); }
            to { opacity: 1; transform: scale(1) translateY(0); }
        }
        .terminal-topbar {
            background: rgba(18, 7, 9, 0.88);
            border-bottom: 1px solid rgba(255, 80, 30, 0.18);
            padding: 13px 20px; display: flex; align-items: center; justify-content: space-between;
        }
        .terminal-dots { display: flex; gap: 8px; }
        .terminal-dot { width: 11px; height: 11px; border-radius: 50%; }
        .dot-red { background: #ff453a; }
        .dot-yellow { background: #ff9f0a; }
        .dot-green { background: #32d74b; }
        .terminal-title {
            font-family: var(--font-mono); font-size: 0.78rem; font-weight: 700;
            color: var(--flame-orange); letter-spacing: 0.05em;
            display: flex; align-items: center; gap: 8px;
        }
        .terminal-title svg { animation: spinSlow 8s linear infinite; }
        .terminal-body {
            padding: 1.35rem 1.6rem; font-family: var(--font-mono); font-size: 0.85rem;
            color: var(--text-secondary); line-height: 1.85; max-height: 240px;
            overflow-y: auto;
        }
        .terminal-line { display: flex; gap: 12px; }
        .term-ts { color: var(--text-muted); }
        .term-tag { color: var(--flame-orange); font-weight: 700; }
        .term-msg { color: var(--text-primary); }
        .cursor-blink {
            display: inline-block; width: 8px; height: 14px;
            background: var(--flame-orange); vertical-align: middle;
            animation: cursorBlink 0.8s infinite;
        }
        @keyframes cursorBlink { 0%, 100% { opacity: 1; } 50% { opacity: 0; } }

        /* Error Alert */
        .error-alert {
            display: none;
            background: rgba(255, 34, 63, 0.1);
            border: 1px solid rgba(255, 34, 63, 0.45);
            border-radius: 20px; padding: 1.35rem 1.6rem;
            color: var(--danger); margin-bottom: 2rem;
            box-shadow: 0 8px 30px rgba(255, 34, 63, 0.25);
        }
        .error-alert h4 { font-weight: 800; font-size: 1rem; margin-bottom: 4px; display: flex; align-items: center; gap: 8px; font-family: var(--font-heading); }
        .error-alert svg { animation: playfulWiggle 0.6s ease; }

        /* ═══════════════════════════════════════════════════════════════
           AUDIT RESULTS SECTION (EXACT IMAGE 1 EMBER STYLING)
           ═══════════════════════════════════════════════════════════════ */
        .results-wrapper { display: none; flex-direction: column; gap: 2rem; }

        /* Score Executive Banner */
        .score-banner {
            padding: 2.2rem 2.4rem;
            display: flex; align-items: center; justify-content: space-between;
            flex-wrap: wrap; gap: 2rem;
        }
        .target-header-col { flex: 1; min-width: 280px; }
        .target-header-col h2 {
            font-size: 2.3rem; font-weight: 800; letter-spacing: -0.02em;
            color: var(--text-primary); word-break: break-all; margin-bottom: 6px;
            font-family: var(--font-heading);
        }
        .target-meta-row { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; margin-top: 12px; }
        .meta-pill {
            display: inline-flex; align-items: center; gap: 6px;
            font-size: 0.8rem; font-family: var(--font-mono);
            padding: 5px 12px; border-radius: 999px;
            background: rgba(10, 4, 5, 0.85); border: 1px solid rgba(255, 80, 20, 0.22);
            color: var(--text-secondary); transition: transform 0.2s ease;
        }
        .meta-pill:hover { transform: translateY(-2px); border-color: var(--flame-orange); }
        .meta-pill:hover svg { animation: playfulBounce 0.4s ease; }
        .meta-pill svg { width: 15px; height: 15px; stroke: var(--flame-orange); }

        .score-display-group {
            display: flex; align-items: center; gap: 2.4rem;
        }
        .gauge-wrapper {
            position: relative; width: 124px; height: 124px;
        }
        .gauge-svg { width: 124px; height: 124px; transform: rotate(-90deg); }
        .gauge-bg { fill: none; stroke: rgba(255, 80, 20, 0.12); stroke-width: 8; }
        .gauge-fg {
            fill: none; stroke-width: 8; stroke-linecap: round;
            stroke-dasharray: 377; stroke-dashoffset: 377;
            transition: stroke-dashoffset 1.4s cubic-bezier(0.16, 1, 0.3, 1), stroke 0.4s;
        }
        .gauge-inner-text {
            position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);
            text-align: center;
        }
        .gauge-number { font-size: 2.2rem; font-weight: 800; font-family: var(--font-mono); line-height: 1; }
        .gauge-label { font-size: 0.65rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-muted); margin-top: 4px; font-family: var(--font-heading); }

        .grade-gemstone {
            width: 88px; height: 88px; border-radius: 24px;
            display: flex; flex-direction: column; align-items: center; justify-content: center;
            background: var(--gradient-flame); color: #070303;
            box-shadow: inset 0 2px 5px rgba(255, 255, 255, 0.5), 0 15px 35px var(--flame-glow);
            border: 2px solid rgba(255, 255, 255, 0.4);
            transition: transform 0.3s cubic-bezier(0.16, 1, 0.3, 1);
            cursor: pointer;
        }
        .grade-gemstone:hover { transform: scale(1.1) rotate(-4deg); animation: flameBreathe 2s infinite ease-in-out; }
        .grade-char { font-size: 2.6rem; font-weight: 900; line-height: 1; font-family: var(--font-display); }
        .grade-subtext { font-size: 0.62rem; font-weight: 800; text-transform: uppercase; letter-spacing: 0.06em; opacity: 0.88; font-family: var(--font-heading); }

        /* Fast Metrics Bar */
        .fast-metrics-bar {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1.1rem;
        }
        .metric-tile {
            padding: 1.25rem 1.35rem;
        }
        .metric-label { font-size: 0.76rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 6px; font-family: var(--font-heading); }
        .metric-value { font-size: 1.2rem; font-weight: 700; color: var(--text-primary); font-family: var(--font-mono); }

        /* Detailed Audit Cards */
        .audit-card {
            padding: 1.9rem 2.2rem;
        }
        .audit-card-header {
            display: flex; align-items: center; justify-content: space-between;
            flex-wrap: wrap; gap: 12px; margin-bottom: 1.6rem;
            padding-bottom: 1.15rem; border-bottom: 1px solid rgba(255, 80, 30, 0.16);
        }
        .audit-card-title {
            display: flex; align-items: center; gap: 12px;
            font-size: 1.3rem; font-weight: 800; color: var(--text-primary);
            font-family: var(--font-heading);
        }
        .audit-card:hover .audit-card-title svg { animation: playfulWiggle 0.5s ease; }
        .audit-card-title svg { width: 23px; height: 23px; stroke: var(--flame-orange); }

        /* Badges */
        .status-badge {
            display: inline-flex; align-items: center; gap: 6px;
            padding: 6px 14px; border-radius: 999px;
            font-size: 0.74rem; font-weight: 800; text-transform: uppercase;
            letter-spacing: 0.05em; font-family: var(--font-mono);
        }
        .badge-secure {
            background: rgba(255, 106, 0, 0.16); color: var(--flame-orange);
            border: 1px solid rgba(255, 106, 0, 0.4); box-shadow: 0 0 14px var(--flame-glow);
        }
        .badge-warning {
            background: rgba(255, 170, 0, 0.16); color: var(--warning);
            border: 1px solid rgba(255, 170, 0, 0.4); box-shadow: 0 0 14px rgba(255, 170, 0, 0.2);
        }
        .badge-danger {
            background: rgba(255, 34, 63, 0.18); color: var(--danger);
            border: 1px solid rgba(255, 34, 63, 0.45); box-shadow: 0 0 14px rgba(255, 34, 63, 0.25);
        }

        /* 2-Column Info Grid */
        .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 1.1rem; }
        .info-tile {
            background: rgba(10, 4, 5, 0.85);
            border: 1px solid rgba(255, 80, 20, 0.18);
            border-radius: 18px; padding: 1.15rem 1.3rem;
            box-shadow: inset 0 1px 1px rgba(255, 255, 255, 0.1);
            transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
        }
        .info-tile:hover {
            background: rgba(20, 8, 10, 0.95); border-color: rgba(255, 110, 30, 0.45);
            transform: translateY(-2px);
        }
        .info-tile-label {
            font-size: 0.74rem; font-weight: 700; color: var(--text-muted);
            text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 6px;
            font-family: var(--font-heading);
        }
        .info-tile-value { font-size: 1rem; font-weight: 600; color: var(--text-primary); word-break: break-all; }

        /* Header Rows & Remediation */
        .header-list { display: flex; flex-direction: column; gap: 10px; }
        .header-item-row {
            display: flex; align-items: center; justify-content: space-between;
            background: rgba(10, 4, 5, 0.85);
            border: 1px solid rgba(255, 80, 20, 0.18);
            border-radius: 18px; padding: 15px 20px;
            gap: 14px; transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
            box-shadow: inset 0 1px 1px rgba(255, 255, 255, 0.1);
            flex-wrap: wrap;
        }
        .header-item-row:hover {
            background: rgba(20, 8, 10, 0.95); border-color: rgba(255, 110, 30, 0.45);
            transform: translateX(4px);
        }
        .header-item-left { display: flex; flex-direction: column; gap: 4px; flex: 1; min-width: 240px; }
        .header-item-name { font-family: var(--font-mono); font-size: 0.92rem; font-weight: 700; color: var(--text-primary); }
        .header-item-desc { font-size: 0.82rem; color: var(--text-muted); line-height: 1.4; font-family: var(--font-body); }
        .header-item-actions { display: flex; align-items: center; gap: 10px; }
        .header-item-val {
            font-family: var(--font-mono); font-size: 0.82rem; color: var(--flame-orange);
            background: rgba(255, 106, 0, 0.1); padding: 5px 12px; border-radius: 8px;
            max-width: 480px; word-break: break-all;
        }

        /* Fix Button (Sleek High-Contrast Capsule) */
        .fix-btn {
            background: linear-gradient(135deg, rgba(255, 69, 0, 0.16) 0%, rgba(255, 106, 0, 0.24) 100%);
            border: 1.5px solid rgba(255, 106, 0, 0.45);
            color: #ff9838; padding: 7px 18px;
            border-radius: 999px; font-size: 0.82rem; font-weight: 700;
            cursor: pointer; display: inline-flex; align-items: center; gap: 7px;
            transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1); font-family: var(--font-heading);
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.25);
        }
        .fix-btn:hover {
            background: var(--gradient-flame); color: #ffffff;
            border-color: transparent;
            box-shadow: 0 4px 18px var(--flame-glow); transform: translateY(-2px);
        }
        .fix-btn:hover svg { animation: playfulWiggle 0.4s ease; stroke: #ffffff; }
        .fix-btn:active { transform: translateY(0) scale(0.98); }
        .fix-btn svg { width: 15px; height: 15px; stroke: currentColor; stroke-width: 2.2; }

        /* JSON Code Terminal */
        .json-terminal {
            background: #080304;
            border: 1px solid rgba(255, 80, 20, 0.25);
            border-radius: 18px; padding: 1.6rem;
            font-family: var(--font-mono); font-size: 0.85rem;
            color: #ff9800; max-height: 380px;
            overflow-y: auto; white-space: pre-wrap; word-break: break-all;
            box-shadow: inset 0 1px 4px rgba(0, 0, 0, 0.6);
        }
        [data-theme="light"] .json-terminal {
            background: #fdf6f2; color: #c2410c;
        }

        .action-btn-row { display: flex; gap: 12px; flex-wrap: wrap; margin-top: 1.2rem; }
        .action-btn {
            background: var(--ember-card-surface);
            border: 1px solid var(--ember-card-border);
            color: var(--text-secondary); padding: 12px 22px;
            border-radius: 999px; font-size: 0.85rem; font-weight: 700;
            cursor: pointer; display: inline-flex; align-items: center; gap: 8px;
            transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1); font-family: var(--font-heading);
            box-shadow: var(--ember-card-shadow);
        }
        .action-btn:hover {
            border-color: var(--flame-orange); color: var(--flame-orange);
            transform: translateY(-2px) scale(1.03);
            box-shadow: 0 6px 20px rgba(255, 106, 0, 0.3);
        }
        .action-btn:hover svg { animation: playfulBounce 0.4s ease; }
        .action-btn svg { width: 17px; height: 17px; stroke: currentColor; }

        /* ═══════════════════════════════════════════════════════════════
           MODALS (AUTH, REMEDIATION, HISTORY)
           ═══════════════════════════════════════════════════════════════ */
        .modal-backdrop {
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0, 0, 0, 0.78); backdrop-filter: blur(14px);
            -webkit-backdrop-filter: blur(14px);
            z-index: 5000; display: flex; align-items: center; justify-content: center;
            opacity: 0; visibility: hidden; transition: all 0.25s ease;
        }
        .modal-backdrop.open { opacity: 1; visibility: visible; }
        .modal-window {
            width: 100%; max-width: 540px; margin: 1rem;
            padding: 2.2rem 2.4rem;
            position: relative; max-height: 90vh; overflow-y: auto;
            transform: translateY(20px) scale(0.96);
            transition: transform 0.3s cubic-bezier(0.16, 1, 0.3, 1);
            background: linear-gradient(160deg, rgba(22, 10, 13, 0.98) 0%, rgba(12, 5, 7, 0.98) 100%);
            border: 1px solid rgba(255, 106, 0, 0.32);
            box-shadow: inset 0 1px 1.5px rgba(255, 200, 160, 0.25), 0 25px 60px rgba(0, 0, 0, 0.85);
        }
        .modal-backdrop.open .modal-window { transform: translateY(0) scale(1); }
        .modal-close-btn {
            position: absolute; top: 18px; right: 18px;
            width: 38px; height: 38px; border-radius: 50%;
            background: rgba(10, 4, 5, 0.85); border: 1px solid rgba(255, 80, 20, 0.3);
            cursor: pointer; display: flex; align-items: center; justify-content: center;
            color: var(--text-muted); transition: all 0.2s ease;
            z-index: 10;
        }
        .modal-close-btn:hover { background: rgba(255, 106, 0, 0.2); color: var(--flame-orange); transform: rotate(90deg); }
        .modal-close-btn svg { width: 19px; height: 19px; }

        /* Slide-over Drawer for History */
        .drawer-backdrop {
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0, 0, 0, 0.68); backdrop-filter: blur(8px);
            z-index: 5000; opacity: 0; visibility: hidden; transition: all 0.3s ease;
        }
        .drawer-backdrop.open { opacity: 1; visibility: visible; }
        .drawer-panel {
            position: fixed; top: 0; right: 0; width: 100%; max-width: 440px; height: 100%;
            background: var(--bg-surface);
            border-left: 1px solid rgba(255, 80, 20, 0.25);
            box-shadow: -10px 0 50px rgba(0, 0, 0, 0.85);
            z-index: 5001; padding: 2rem 1.85rem;
            display: flex; flex-direction: column;
            transform: translateX(100%); transition: transform 0.35s cubic-bezier(0.16, 1, 0.3, 1);
        }
        .drawer-backdrop.open .drawer-panel { transform: translateX(0); }
        .drawer-header {
            display: flex; align-items: center; justify-content: space-between;
            margin-bottom: 1.5rem; padding-bottom: 1rem; border-bottom: 1px solid rgba(255, 80, 20, 0.18);
        }
        .drawer-list { flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 10px; }
        .drawer-item {
            background: var(--ember-card-surface);
            border: 1px solid var(--ember-card-border);
            border-radius: 18px; padding: 14px 18px; cursor: pointer;
            display: flex; align-items: center; justify-content: space-between;
            transition: all 0.2s ease;
        }
        .drawer-item:hover { border-color: var(--flame-orange); transform: translateX(-4px); }

        /* Auth Tabs & Inputs */
        .auth-tab-row {
            display: flex; gap: 6px; background: rgba(255, 106, 0, 0.08);
            border: 1px solid rgba(255, 80, 20, 0.25); border-radius: 999px; padding: 4px;
            margin: 1.25rem 0 1.5rem;
        }
        .auth-tab-btn {
            flex: 1; padding: 10px; border: none; border-radius: 999px;
            background: transparent; color: var(--text-muted); font-weight: 700;
            font-size: 0.86rem; cursor: pointer; transition: all 0.2s ease;
            font-family: var(--font-heading);
        }
        .auth-tab-btn.active {
            background: var(--gradient-flame); color: #ffffff;
            font-weight: 800; text-shadow: 0 1px 2px rgba(0, 0, 0, 0.35);
            box-shadow: 0 4px 14px rgba(255, 80, 20, 0.35);
        }
        .auth-field { margin-bottom: 1.15rem; }
        .auth-label { display: block; font-size: 0.78rem; font-weight: 700; color: var(--text-secondary); margin-bottom: 6px; text-transform: uppercase; font-family: var(--font-heading); }
        .auth-input-elem {
            width: 100%; padding: 13px 16px;
            background: linear-gradient(180deg, rgba(16, 7, 9, 0.95) 0%, rgba(11, 4, 6, 0.98) 100%);
            border: 1px solid rgba(255, 106, 0, 0.28);
            border-radius: 14px; color: var(--text-primary); font-size: 0.95rem;
            outline: none; font-family: var(--font-body);
            box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.6);
            transition: all 0.2s ease;
        }
        .auth-input-elem:focus {
            border-color: var(--flame-orange);
            box-shadow: inset 0 1px 2px rgba(0, 0, 0, 0.3), 0 0 0 3px rgba(255, 106, 0, 0.25), 0 0 20px rgba(255, 106, 0, 0.2);
        }
        .auth-submit-btn {
            width: 100%; padding: 14px; border: none; border-radius: 999px;
            background: var(--gradient-flame); color: #ffffff; font-weight: 800;
            font-size: 1rem; cursor: pointer; transition: all 0.2s ease;
            box-shadow: 0 4px 20px rgba(255, 80, 20, 0.4); margin-top: 0.5rem;
            font-family: var(--font-heading);
            text-shadow: 0 1px 2px rgba(0, 0, 0, 0.35);
        }
        .auth-submit-btn:hover { transform: translateY(-2px); box-shadow: 0 8px 30px rgba(255, 80, 20, 0.6); }

        /* Remediation Modal Code Snippets */
        .remed-tab-row { display: flex; gap: 8px; margin-bottom: 1rem; flex-wrap: wrap; }
        .remed-tab-btn {
            padding: 8px 16px; border-radius: 999px; border: 1px solid var(--ember-card-border);
            background: var(--ember-card-surface); color: var(--text-secondary);
            font-size: 0.82rem; font-weight: 700; cursor: pointer; transition: all 0.2s ease;
            font-family: var(--font-heading);
        }
        .remed-tab-btn.active { background: var(--gradient-flame); color: #070303; border-color: var(--flame-orange); }
        .code-box {
            position: relative; background: #080304; border: 1px solid rgba(255, 80, 20, 0.28);
            border-radius: 16px; padding: 1.35rem; font-family: var(--font-mono);
            font-size: 0.86rem; color: #ffb74d; overflow-x: auto;
        }
        .code-copy-btn {
            position: absolute; top: 10px; right: 10px;
            background: rgba(255, 255, 255, 0.12); border: 1px solid rgba(255, 255, 255, 0.24);
            color: #fff; padding: 5px 12px; border-radius: 6px; font-size: 0.74rem;
            cursor: pointer; font-weight: 700; font-family: var(--font-heading);
        }
        .code-copy-btn:hover { background: var(--flame-orange); color: #070303; }

        /* Footer */
        .site-footer {
            text-align: center;
            padding: 2.5rem 1.5rem 1.8rem;
            margin-top: 4.5rem;
            color: var(--text-muted);
            font-size: 0.82rem;
            line-height: 1.6;
            border-top: 1px solid rgba(255, 80, 20, 0.12);
        }
        .site-footer strong { color: var(--flame-orange); letter-spacing: 0.04em; }
        .site-footer a { color: var(--text-secondary); text-decoration: none; font-weight: 600; }
        .site-footer a:hover { color: var(--flame-orange); }

        /* Print Media Styles */
        @media print {
            body { background: #fff !important; color: #000 !important; }
            .ambient-canvas, .cursor-glow, .cursor-dot, .nav-bar, .search-cockpit, .terminal-container, .site-footer, .action-btn-row, .fix-btn { display: none !important; }
            .main-content { padding: 0 !important; max-width: 100% !important; }
            .ember-card {
                background: #fff !important; border: 1px solid #ccc !important;
                box-shadow: none !important; color: #000 !important; break-inside: avoid;
            }
            .target-header-col h2, .audit-card-title { color: #000 !important; }
        }

        /* ═══════════════════════════════════════════════════════════════
           COMPREHENSIVE MOBILE & TABLET RESPONSIVE SYSTEM (100/100)
           ═══════════════════════════════════════════════════════════════ */

        /* Touch & Coarse Pointer Optimizations */
        @media (hover: none) and (pointer: coarse) {
            .cursor-glow, .cursor-dot { display: none !important; }
            * { -webkit-tap-highlight-color: transparent; }
            .chromatic-circle-btn:hover { transform: none; box-shadow: var(--chromatic-glow); }
            .auth-pill-btn:hover { transform: none; }
            .audit-btn:hover { transform: none; }
            .quick-chip:hover { transform: none; }
            .ember-card:hover { transform: none; }
            .action-btn:hover { transform: none; }
            .fix-btn:hover { transform: none; }
        }

        /* Tablet Breakpoint (max-width: 900px) */
        @media (max-width: 900px) {
            .main-content {
                padding: calc(var(--nav-height) + 2rem) 1.25rem 3.5rem;
            }
            .hero-title {
                font-size: clamp(2.5rem, 7vw, 3.5rem);
            }
            .score-banner {
                padding: 1.8rem 1.6rem;
                gap: 1.5rem;
            }
            .fast-metrics-bar {
                grid-template-columns: repeat(2, 1fr);
            }
            .search-cockpit {
                padding: 1.6rem 1.5rem;
            }
            .audit-card {
                padding: 1.6rem 1.5rem;
            }
        }

        /* Mobile Breakpoint (max-width: 640px) */
        @media (max-width: 640px) {
            :root {
                --nav-height: 60px;
            }

            /* Container & Body Overflow Shield */
            html, body {
                width: 100%;
                max-width: 100vw;
                overflow-x: hidden;
            }

            .main-content {
                padding: calc(var(--nav-height) + 1.25rem) 0.85rem 3rem;
                max-width: 100%;
            }

            /* Navbar Layout */
            .nav-bar {
                padding-top: env(safe-area-inset-top);
                height: auto;
                min-height: var(--nav-height);
            }
            .nav-inner {
                padding: 0 0.75rem;
                height: var(--nav-height);
                gap: 6px;
            }
            .nav-brand {
                gap: 6px;
                min-width: 0;
                flex-shrink: 1;
            }
            .brand-logo-mark {
                width: 30px;
                height: 30px;
            }
            .brand-logo-mark svg {
                width: 18px;
                height: 18px;
            }
            .brand-text-wrapper {
                min-width: 0;
            }
            .nav-brand-text {
                font-size: 0.95rem;
                letter-spacing: 0.03em;
                line-height: 1;
            }
            .nav-brand-sub,
            .cyber-status-pill {
                display: none !important;
            }

            .nav-actions {
                gap: 4px;
                flex-shrink: 0;
            }
            .chromatic-capsule {
                padding: 2px;
            }
            .chromatic-circle-btn {
                width: 34px;
                height: 34px;
            }
            .chromatic-circle-inner svg {
                width: 15px;
                height: 15px;
            }
            .history-count-badge {
                width: 14px;
                height: 14px;
                font-size: 0.52rem;
                top: -2px;
                right: -2px;
            }

            /* Turn Login button into sleek icon circle button on mobile */
            .auth-pill-btn {
                padding: 0;
                width: 34px;
                height: 34px;
                border-radius: 50%;
                justify-content: center;
                gap: 0;
            }
            .auth-pill-btn span {
                display: none !important;
            }
            .auth-pill-btn svg {
                width: 15px;
                height: 15px;
            }

            /* Hero Section */
            .hero {
                margin-bottom: 1.6rem;
            }
            .badge-text-desktop {
                display: none !important;
            }
            .badge-text-mobile {
                display: inline-block !important;
                white-space: nowrap;
            }
            .hero-pill-badge {
                padding: 4px 12px;
                font-size: 0.65rem;
                letter-spacing: 0.04em;
                margin-bottom: 0.85rem;
                max-width: 95%;
                white-space: nowrap;
                justify-content: center;
                gap: 6px;
            }
            .live-dot {
                width: 5px;
                height: 5px;
                flex-shrink: 0;
            }
            .hero-title {
                font-size: clamp(1.9rem, 8.8vw, 2.6rem);
                letter-spacing: 0.01em;
                margin-bottom: 0.55rem;
                line-height: 1.1;
                word-break: break-word;
            }
            .hero-desc {
                font-size: 0.88rem;
                line-height: 1.55;
                max-width: 320px;
                margin: 0 auto 0.95rem;
                padding: 0 4px;
            }
            /* Keyboard hints are desktop-only */
            .hero-kbd-hint {
                display: none !important;
            }

            /* Search Cockpit */
            .search-cockpit {
                padding: 1.25rem 1.1rem;
                border-radius: 22px;
                margin-bottom: 1.5rem;
            }
            .search-input-group {
                flex-direction: column;
                gap: 10px;
                width: 100%;
            }
            .search-wrapper {
                width: 100%;
                min-width: 0;
            }
            .search-wrapper svg {
                left: 14px;
                width: 17px;
                height: 17px;
            }
            .target-input {
                padding: 13px 14px 13px 40px;
                font-size: 0.88rem;
                border-radius: 14px;
            }
            .target-input::placeholder {
                font-size: 0.82rem;
            }
            .audit-btn {
                width: 100%;
                display: flex;
                border-radius: 16px;
            }
            .audit-btn-inner {
                width: 100%;
                justify-content: center;
                padding: 13px 20px;
                font-size: 0.96rem;
                border-radius: 14px;
            }

            /* Preset Chips */
            .quick-targets-row {
                gap: 6px;
                margin-top: 13px;
                justify-content: center;
            }
            .quick-targets-label {
                width: 100%;
                text-align: center;
                font-size: 0.68rem;
                letter-spacing: 0.08em;
                margin-bottom: 3px;
            }
            .quick-chip {
                padding: 5px 12px;
                font-size: 0.72rem;
                border-radius: 999px;
            }

            /* Terminal Container */
            .terminal-container {
                border-radius: 18px;
                margin-bottom: 1.5rem;
            }
            .terminal-topbar {
                padding: 9px 13px;
            }
            .terminal-title {
                font-size: 0.65rem;
                max-width: 180px;
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
            }
            .terminal-body {
                padding: 0.9rem 1rem;
                font-size: 0.75rem;
                max-height: 180px;
                line-height: 1.6;
            }
            .terminal-line {
                gap: 6px;
                font-size: 0.72rem;
            }

            /* Results Section */
            .results-wrapper {
                gap: 1.25rem;
            }

            /* Score Banner */
            .score-banner {
                padding: 1.35rem 1rem;
                border-radius: 20px;
                flex-direction: column;
                align-items: center;
                text-align: center;
                gap: 1.25rem;
            }
            .target-header-col {
                min-width: 0;
                width: 100%;
                text-align: center;
            }
            .target-header-col h2 {
                font-size: 1.4rem;
                word-break: break-all;
                margin-bottom: 4px;
            }
            .target-header-col p#resVerdict {
                font-size: 0.88rem;
            }
            .target-meta-row {
                justify-content: center;
                gap: 6px;
                margin-top: 10px;
            }
            .meta-pill {
                font-size: 0.7rem;
                padding: 4px 9px;
                gap: 4px;
            }
            .meta-pill svg {
                width: 13px;
                height: 13px;
            }

            .score-display-group {
                width: 100%;
                justify-content: center;
                gap: 1.25rem;
            }
            .gauge-wrapper {
                width: 102px;
                height: 102px;
            }
            .gauge-svg {
                width: 102px;
                height: 102px;
            }
            .gauge-number {
                font-size: 1.8rem;
            }
            .gauge-label {
                font-size: 0.58rem;
            }
            .grade-gemstone {
                width: 74px;
                height: 74px;
                border-radius: 18px;
            }
            .grade-char {
                font-size: 2rem;
            }
            .grade-subtext {
                font-size: 0.56rem;
            }

            /* Fast Metrics: Clean 2x2 Grid */
            .fast-metrics-bar {
                grid-template-columns: repeat(2, 1fr);
                gap: 8px;
            }
            .metric-tile {
                padding: 0.85rem 0.95rem;
                border-radius: 16px;
            }
            .metric-label {
                font-size: 0.65rem;
                margin-bottom: 3px;
            }
            .metric-value {
                font-size: 0.98rem;
            }

            /* Detailed Audit Cards */
            .audit-card {
                padding: 1.2rem 1rem;
                border-radius: 20px;
            }
            .audit-card-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 8px;
                margin-bottom: 1rem;
                padding-bottom: 0.75rem;
            }
            .audit-card-title {
                font-size: 1.05rem;
                gap: 8px;
            }
            .audit-card-title svg {
                width: 19px;
                height: 19px;
                flex-shrink: 0;
            }
            .status-badge {
                font-size: 0.65rem;
                padding: 4px 10px;
                align-self: flex-start;
            }

            /* Single column info grid */
            .info-grid {
                grid-template-columns: 1fr;
                gap: 8px;
            }
            .info-tile {
                padding: 0.85rem 1rem;
                border-radius: 14px;
            }
            .info-tile-label {
                font-size: 0.68rem;
                margin-bottom: 3px;
            }
            .info-tile-value {
                font-size: 0.86rem;
            }

            /* Security Headers Rows */
            .header-item-row {
                padding: 11px 12px;
                border-radius: 14px;
                flex-direction: column;
                align-items: flex-start;
                gap: 8px;
            }
            .header-item-left {
                min-width: 0;
                width: 100%;
            }
            .header-item-name {
                font-size: 0.84rem;
                word-break: break-all;
            }
            .header-item-desc {
                font-size: 0.75rem;
            }
            .header-item-actions {
                width: 100%;
                flex-direction: column;
                align-items: stretch;
                gap: 6px;
            }
            .header-item-val {
                max-width: 100%;
                width: 100%;
                font-size: 0.75rem;
                word-break: break-all;
                padding: 4px 8px;
            }
            .fix-btn {
                width: 100%;
                justify-content: center;
                padding: 8px 14px;
                font-size: 0.76rem;
            }

            /* Export Suite */
            .json-terminal {
                padding: 0.95rem;
                font-size: 0.74rem;
                max-height: 200px;
                border-radius: 14px;
            }
            .action-btn-row {
                flex-direction: column;
                width: 100%;
                gap: 8px;
            }
            .action-btn {
                width: 100%;
                justify-content: center;
                padding: 10px 16px;
                font-size: 0.82rem;
            }

            /* Modals */
            .modal-backdrop {
                padding: 10px;
            }
            .modal-window {
                padding: 1.4rem 1.1rem;
                border-radius: 20px;
                max-height: 88vh;
            }
            .modal-close-btn {
                top: 10px;
                right: 10px;
                width: 32px;
                height: 32px;
            }
            .modal-window h3 {
                font-size: 1.15rem !important;
            }
            .remed-tab-row {
                gap: 5px;
            }
            .remed-tab-btn {
                padding: 5px 10px;
                font-size: 0.72rem;
            }
            .code-box {
                padding: 0.9rem;
                font-size: 0.74rem;
                border-radius: 12px;
            }
            .code-copy-btn {
                top: 6px;
                right: 6px;
                padding: 3px 8px;
                font-size: 0.65rem;
            }
            .auth-tab-row {
                margin: 0.85rem 0 1.15rem;
            }
            .auth-tab-btn {
                padding: 7px;
                font-size: 0.78rem;
            }
            .auth-input-elem {
                padding: 10px 12px;
                font-size: 0.88rem;
            }
            .auth-submit-btn {
                padding: 11px;
                font-size: 0.9rem;
            }

            /* History Drawer on Mobile */
            .drawer-panel {
                max-width: 100%;
                width: 100%;
                padding: 1.35rem 1rem;
            }
            .drawer-header h3 {
                font-size: 1.15rem;
            }
            .drawer-item {
                padding: 10px 12px;
                font-size: 0.8rem;
            }

            /* Profile Dropdown on Mobile */
            .profile-dropdown {
                width: calc(100vw - 24px);
                max-width: 280px;
                right: 0;
            }

            /* Footer */
            .site-footer {
                padding: 1.4rem 0.9rem;
                margin-top: 2.2rem;
                font-size: 0.74rem;
                border-radius: 18px;
            }
        }

        /* Extra Small Screens (<= 380px e.g. iPhone SE, Galaxy Z Flip cover, small Android) */
        @media (max-width: 380px) {
            .nav-inner {
                padding: 0 0.5rem;
            }
            .nav-brand-text {
                font-size: 0.92rem;
            }
            .brand-logo-mark {
                width: 28px;
                height: 28px;
            }
            .chromatic-circle-btn,
            .auth-pill-btn {
                width: 32px;
                height: 32px;
            }
            .chromatic-circle-inner svg,
            .auth-pill-btn svg {
                width: 14px;
                height: 14px;
            }
            .hero-title {
                font-size: 1.85rem;
            }
            .hero-pill-badge {
                font-size: 0.62rem;
                padding: 4px 8px;
            }
            .fast-metrics-bar {
                grid-template-columns: 1fr;
            }
            .score-display-group {
                flex-direction: column;
                gap: 1rem;
            }
        }
    </style>
</head>
<body>
    <!-- ═══════════ AMBIENT CANVAS & CURSOR ═══════════ -->
    <div class="ambient-canvas" aria-hidden="true">
        <div class="gradient-flow"></div>
        <div class="cyber-grid"></div>
        <div class="pulse-orb pulse-orb-1"></div>
        <div class="pulse-orb pulse-orb-2"></div>
        <div class="pulse-orb pulse-orb-3"></div>
    </div>
    <div class="cursor-glow" id="cursorGlow"></div>
    <div class="cursor-dot" id="cursorDot"></div>
    <canvas id="particleCanvas" style="position:fixed;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:9998;"></canvas>

    <!-- ═══════════ NAVIGATION BAR ═══════════ -->
    <nav class="nav-bar">
        <div class="nav-inner">
            <a href="#" class="nav-brand" onclick="window.scrollTo({top:0, behavior:'smooth'}); return false;">
                <!-- Creative Compact Cyber Shield Logo Mark -->
                <div class="brand-logo-mark">
                    <div class="logo-mark-glow"></div>
                    <div class="logo-mark-frame">
                        <svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M16 3L6 7V15C6 21.5 10.3 27.5 16 29C21.7 27.5 26 21.5 26 15V7L16 3Z" stroke="url(#navShieldGrad)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                            <path d="M16 8L10 11V15C10 19.5 12.6 23.6 16 24.8C19.4 23.6 22 19.5 22 15V11L16 8Z" fill="url(#navShieldInnerGrad)" opacity="0.45"/>
                            <circle cx="16" cy="16" r="3" fill="#ff731d"/>
                            <line x1="16" y1="11" x2="16" y2="13" stroke="#ff731d" stroke-width="1.8" stroke-linecap="round"/>
                            <line x1="16" y1="19" x2="16" y2="21" stroke="#ff731d" stroke-width="1.8" stroke-linecap="round"/>
                            <line x1="11" y1="16" x2="13" y2="16" stroke="#ff731d" stroke-width="1.8" stroke-linecap="round"/>
                            <line x1="19" y1="16" x2="21" y2="16" stroke="#ff731d" stroke-width="1.8" stroke-linecap="round"/>
                            <defs>
                                <linearGradient id="navShieldGrad" x1="6" y1="3" x2="26" y2="29" gradientUnits="userSpaceOnUse">
                                    <stop stop-color="#ff3b30"/>
                                    <stop offset="0.5" stop-color="#ff731d"/>
                                    <stop offset="1" stop-color="#ffb300"/>
                                </linearGradient>
                                <linearGradient id="navShieldInnerGrad" x1="10" y1="8" x2="22" y2="24.8" gradientUnits="userSpaceOnUse">
                                    <stop stop-color="#ff731d"/>
                                    <stop offset="1" stop-color="#ff3b30" stop-opacity="0"/>
                                </linearGradient>
                            </defs>
                        </svg>
                    </div>
                </div>
                <div class="brand-text-wrapper">
                    <span class="nav-brand-text">CYBERSHIELD</span>
                    <span class="nav-brand-sub">Threat Intelligence</span>
                </div>
            </a>

            <div class="nav-actions">
                <!-- Sound Toggle (Image 2 Chromatic Style) -->
                <div class="chromatic-capsule">
                    <button class="chromatic-circle-btn" id="audioToggleBtn" title="Toggle Sound FX" aria-label="Toggle sound">
                        <div class="chromatic-circle-inner">
                            <svg id="audioIconOn" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                                <polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/>
                                <path d="M15.54 8.46a5 5 0 0 1 0 7.07"/>
                                <path d="M19.07 4.93a10 10 0 0 1 0 14.14"/>
                            </svg>
                            <svg id="audioIconOff" style="display:none;" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                                <polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/>
                                <line x1="23" y1="9" x2="17" y2="15"/><line x1="17" y1="9" x2="23" y2="15"/>
                            </svg>
                        </div>
                    </button>
                </div>

                <!-- History Drawer Trigger (Image 2 Chromatic Style) -->
                <div class="chromatic-capsule" style="position:relative;">
                    <button class="chromatic-circle-btn" id="historyDrawerBtn" title="View Audit History [H]" aria-label="Scan history">
                        <div class="chromatic-circle-inner">
                            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                                <circle cx="12" cy="12" r="10"/>
                                <polyline points="12 6 12 12 16 14"/>
                            </svg>
                        </div>
                    </button>
                    <span class="history-count-badge" id="historyCounter">0</span>
                </div>

                <!-- Theme Switcher (Image 2 Chromatic Style) -->
                <div class="chromatic-capsule">
                    <button class="chromatic-circle-btn" id="themeToggleBtn" title="Toggle Theme" aria-label="Toggle theme">
                        <div class="chromatic-circle-inner">
                            <svg class="theme-icon-moon" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
                            </svg>
                            <svg class="theme-icon-sun" style="display:none;" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                                <circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
                            </svg>
                        </div>
                    </button>
                </div>

                <!-- Exact Image 1 Style Pill Button for Login -->
                <button class="auth-pill-btn" id="openAuthBtn">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                        <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                    </svg>
                    <span>SecOps Login</span>
                </button>

                <!-- Profile Hub (When logged in) -->
                <div class="profile-hub" id="profileHub" style="display:none;">
                    <div class="chromatic-capsule">
                        <button class="chromatic-circle-btn" id="profileMenuBtn">
                            <div class="chromatic-circle-inner" style="font-weight:800; font-family:var(--font-mono); font-size:0.85rem;" id="userInitials">
                                SO
                            </div>
                        </button>
                        <span class="online-dot"></span>
                    </div>
                    <div class="profile-dropdown ember-card" id="profileDropdown">
                        <div class="profile-dropdown-header">
                            <div class="profile-dropdown-avatar" id="dropdownAvatar">SO</div>
                            <div class="profile-dropdown-info">
                                <h4 id="dropdownUserName">SecOps Specialist</h4>
                                <span class="role-badge">Lead Analyst</span>
                            </div>
                        </div>
                        <button class="profile-dropdown-item" onclick="openHistoryDrawer(); closeProfileMenu();">
                            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                            Audit History
                        </button>
                        <button class="profile-dropdown-item" onclick="alert('API Integration Key: CS-SEC-' + Math.random().toString(36).substring(2, 10).toUpperCase())">
                            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path d="M15 7a2 2 0 0 1 2 2m4 0a6 6 0 0 1-7.743 5.743L11 17H9v2H7v2H4a1 1 0 0 1-1-1v-2.586a1 1 0 0 1 .293-.707l5.964-5.964A6 6 0 1 1 21 9z"/></svg>
                            API Credentials
                        </button>
                        <div class="profile-dropdown-divider"></div>
                        <button class="profile-dropdown-item danger" id="signOutBtn">
                            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 0 1-3 3H6a3 3 0 0 1-3-3V7a3 3 0 0 1 3-3h4a3 3 0 0 1 3 3v1"/></svg>
                            Sign Out
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </nav>

    <!-- ═══════════ MAIN CONTENT ═══════════ -->
    <main class="main-content">
        <!-- Hero Section -->
        <section class="hero">
            <div>
                <div class="hero-pill-badge">
                    <span class="live-dot"></span>
                    <span class="badge-text-desktop">Real-Time Threat Intelligence &bull; TLS 1.3 &bull; Cryptographic Assurance</span>
                    <span class="badge-text-mobile">Real-Time Threat Intel &bull; TLS 1.3</span>
                </div>
            </div>

            <h1 class="hero-title">CYBERSHIELD</h1>
            <p class="hero-desc">Automated <strong>TLS Cryptography Audit</strong> &bull; <strong>HTTP Security Headers</strong> &bull; <strong>Cookie Hygiene</strong> &mdash; Comprehensive threat defense for cloud infrastructure.</p>
            <div class="hero-kbd-hint">
                <kbd>Enter</kbd> to launch audit &middot; <kbd>Ctrl</kbd>+<kbd>K</kbd> to focus target &middot; <kbd>H</kbd> for history
            </div>
        </section>

        <!-- Search Cockpit (Image 1 Style Ember Bloom Card) -->
        <section class="ember-card search-cockpit">
            <div class="search-input-group">
                <div class="search-wrapper">
                    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                        <circle cx="11" cy="11" r="8"/>
                        <line x1="21" y1="21" x2="16.65" y2="16.65"/>
                    </svg>
                    <input type="text" id="targetInput" class="target-input" placeholder="Enter domain or URL (e.g. github.com)" autocomplete="off" spellcheck="false">
                </div>

                <!-- Chromatic Audit Button -->
                <button id="scanBtn" class="audit-btn">
                    <div class="audit-btn-inner">
                        <span>Audit Target</span>
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09z"/>
                            <path d="M12 15l-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.35 22.35 0 0 1-4 2z"/>
                            <path d="M9 12H4s.55-3.03 2-4c1.62-1.08 5 0 5 0"/>
                            <path d="M12 15v5s3.03-.55 4-2c1.08-1.62 0-5 0-5"/>
                        </svg>
                    </div>
                </button>
            </div>

            <div class="quick-targets-row">
                <span class="quick-targets-label">Preset Targets:</span>
                <button class="quick-chip" onclick="setQuickTarget('github.com')">github.com</button>
                <button class="quick-chip" onclick="setQuickTarget('google.com')">google.com</button>
                <button class="quick-chip" onclick="setQuickTarget('stripe.com')">stripe.com</button>
                <button class="quick-chip" onclick="setQuickTarget('cloudflare.com')">cloudflare.com</button>
                <button class="quick-chip" onclick="setQuickTarget('e-commerce-zeta-virid-84.vercel.app')">vercel-demo.app</button>
            </div>
        </section>

        <!-- Error Card -->
        <div id="errorAlert" class="error-alert">
            <h4>
                <svg width="22" height="22" fill="none" stroke="currentColor" stroke-width="2.2" viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
                </svg>
                Audit Execution Error
            </h4>
            <p id="errorMessage">Unable to establish connection to the target host.</p>
        </div>

        <!-- Live Hacker Terminal -->
        <div id="liveTerminal" class="terminal-container">
            <div class="terminal-topbar">
                <div class="terminal-dots">
                    <span class="terminal-dot dot-red"></span>
                    <span class="terminal-dot dot-yellow"></span>
                    <span class="terminal-dot dot-green"></span>
                </div>
                <div class="terminal-title">
                    <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
                    CYBERSHIELD_AGENT // THREAT_TELEMETRY_ENGINE
                </div>
                <div style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--text-muted);" id="termStatus">ACTIVE</div>
            </div>
            <div class="terminal-body" id="terminalLogs"></div>
        </div>

        <!-- Audit Results Container -->
        <section id="resultsSection" class="results-wrapper">

            <!-- Executive Score Banner (Image 1 Ember Card) -->
            <div class="ember-card score-banner">
                <div class="target-header-col">
                    <h2 id="resTarget">example.com</h2>
                    <p style="color: var(--text-secondary); font-size: 0.95rem;" id="resVerdict">Analyzing posture...</p>
                    <div class="target-meta-row">
                        <span class="meta-pill" id="metaIp">
                            <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
                            </svg>
                            <span id="resIp">0.0.0.0</span>
                        </span>
                        <span class="meta-pill" id="metaLatency">
                            <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
                            </svg>
                            <span id="resLatency">0ms</span>
                        </span>
                        <span class="meta-pill" id="metaInfra">
                            <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/>
                            </svg>
                            <span id="resInfra">Direct</span>
                        </span>
                        <span class="meta-pill" id="metaTimestamp">Audited just now</span>
                    </div>
                </div>

                <div class="score-display-group">
                    <div class="gauge-wrapper">
                        <svg class="gauge-svg" viewBox="0 0 130 130">
                            <circle class="gauge-bg" cx="65" cy="65" r="60"/>
                            <circle class="gauge-fg" id="gaugeFg" cx="65" cy="65" r="60"/>
                        </svg>
                        <div class="gauge-inner-text">
                            <div class="gauge-number" id="resScoreNum" style="color: var(--flame-orange);">0</div>
                            <div class="gauge-label">Threat Score</div>
                        </div>
                    </div>
                    <div class="grade-gemstone" id="gradeGemstone">
                        <span class="grade-char" id="resGradeChar">A+</span>
                        <span class="grade-subtext">GRADE</span>
                    </div>
                </div>
            </div>

            <!-- Fast Metrics Bar (Image 1 Ember Cards) -->
            <div class="fast-metrics-bar">
                <div class="ember-card metric-tile">
                    <div class="metric-label">TLS Protocol</div>
                    <div class="metric-value" id="fastTlsVer">TLSv1.3</div>
                </div>
                <div class="ember-card metric-tile">
                    <div class="metric-label">Cert Validity</div>
                    <div class="metric-value" id="fastCertDays">0 Days</div>
                </div>
                <div class="ember-card metric-tile">
                    <div class="metric-label">HTTPS Redirect</div>
                    <div class="metric-value" id="fastRedirect">Enforced</div>
                </div>
                <div class="ember-card metric-tile">
                    <div class="metric-label">HTTP Status</div>
                    <div class="metric-value" id="fastHttpStatus">200 OK</div>
                </div>
            </div>

            <!-- TLS / Cryptographic Status Card -->
            <div class="ember-card audit-card">
                <div class="audit-card-header">
                    <div class="audit-card-title">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                            <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                            <circle cx="12" cy="16" r="1"/>
                        </svg>
                        Cryptographic Architecture &amp; TLS Chain
                    </div>
                    <div id="tlsBadge" class="status-badge badge-secure">VALID CERTIFICATE</div>
                </div>

                <div class="info-grid">
                    <div class="info-tile">
                        <div class="info-tile-label">Negotiated Protocol</div>
                        <div class="info-tile-value" id="tlsVersionVal" style="font-family: var(--font-mono); color: var(--flame-orange);">TLSv1.3</div>
                    </div>
                    <div class="info-tile">
                        <div class="info-tile-label">Active Cipher Suite</div>
                        <div class="info-tile-value" id="tlsCipherVal" style="font-family: var(--font-mono); font-size: 0.84rem;">TLS_AES_128_GCM_SHA256</div>
                    </div>
                    <div class="info-tile">
                        <div class="info-tile-label">Certificate Authority (Issuer)</div>
                        <div class="info-tile-value" id="tlsIssuerVal">Google Trust Services</div>
                    </div>
                    <div class="info-tile">
                        <div class="info-tile-label">Expiration Countdown</div>
                        <div class="info-tile-value" id="tlsExpiryVal">68 Days Remaining</div>
                    </div>
                    <div class="info-tile">
                        <div class="info-tile-label">Subject Alternative Names (SANs)</div>
                        <div class="info-tile-value" id="tlsSansVal" style="font-family: var(--font-mono); font-size: 0.85rem;">12 Domains Covered</div>
                    </div>
                    <div class="info-tile">
                        <div class="info-tile-label">SHA-256 Fingerprint</div>
                        <div class="info-tile-value" id="tlsFingerprintVal" style="font-family: var(--font-mono); font-size: 0.74rem; cursor: pointer;" title="Click to copy">Loading...</div>
                    </div>
                </div>
            </div>

            <!-- HTTP Security Headers Matrix -->
            <div class="ember-card audit-card">
                <div class="audit-card-header">
                    <div class="audit-card-title">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                            <polyline points="9 12 11 14 15 10"/>
                        </svg>
                        HTTP Security Headers Defense Matrix
                    </div>
                </div>

                <!-- Missing Headers (Vulnerabilities) -->
                <div style="margin-bottom: 2rem;">
                    <div class="info-tile-label" style="margin-bottom: 10px; color: var(--danger); display: flex; align-items: center; gap: 8px;">
                        <svg width="17" height="17" fill="none" stroke="currentColor" stroke-width="2.2" viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round">
                            <polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/>
                            <line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
                        </svg>
                        Missing Critical Policies (Action Required)
                    </div>
                    <div class="header-list" id="missingHeadersList"></div>
                </div>

                <!-- Enforced Headers -->
                <div>
                    <div class="info-tile-label" style="margin-bottom: 10px; color: var(--flame-orange); display: flex; align-items: center; gap: 8px;">
                        <svg width="17" height="17" fill="none" stroke="currentColor" stroke-width="2.2" viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round">
                            <polyline points="20 6 9 17 4 12"/>
                        </svg>
                        Enforced Security Policies
                    </div>
                    <div class="header-list" id="presentHeadersList"></div>
                </div>
            </div>

            <!-- Server Information Leakage Card -->
            <div class="ember-card audit-card" id="leakageCard" style="display:none;">
                <div class="audit-card-header">
                    <div class="audit-card-title">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                            <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
                        </svg>
                        Information Disclosure &amp; Server Banners
                    </div>
                    <span class="status-badge badge-warning">BANNER EXPOSED</span>
                </div>
                <div class="header-list" id="leakageList"></div>
            </div>

            <!-- Cookie Security Audit Card -->
            <div class="ember-card audit-card" id="cookieCard" style="display:none;">
                <div class="audit-card-header">
                    <div class="audit-card-title">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M12 2a10 10 0 1 0 10 10 4 4 0 0 1-5-5 4 4 0 0 1-5-5z"/>
                            <circle cx="8.5" cy="8.5" r="1.5" fill="currentColor"/>
                            <circle cx="15.5" cy="15.5" r="1.5" fill="currentColor"/>
                            <circle cx="8.5" cy="15.5" r="1.5" fill="currentColor"/>
                        </svg>
                        Cookie Security &amp; Isolation Audit
                    </div>
                </div>
                <div class="header-list" id="cookieList"></div>
            </div>

            <!-- Export & Raw Intelligence Terminal -->
            <div class="ember-card audit-card">
                <div class="audit-card-header">
                    <div class="audit-card-title">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                            <polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>
                        </svg>
                        Threat Intelligence Export Suite
                    </div>
                </div>
                <pre class="json-terminal" id="rawJsonOutput"></pre>
                <div class="action-btn-row">
                    <button class="action-btn" id="copyJsonBtn">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
                        Copy JSON Report
                    </button>
                    <button class="action-btn" id="downloadJsonBtn">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                        Download JSON
                    </button>
                    <button class="action-btn" id="copyMarkdownBtn">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
                        Copy Executive Markdown
                    </button>
                    <button class="action-btn" onclick="window.print()">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 01-2-2v-5a2 2 0 012-2h16a2 2 0 012 2v5a2 2 0 01-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>
                        Print / PDF Report
                    </button>
                </div>
            </div>

        </section>

        <!-- Footer -->
        <footer class="site-footer">
            <p><strong>CYBERSHIELD</strong> v3.0 &mdash; Elite Web Threat Intelligence &amp; Cryptographic Assurance Platform &middot; Developed for <a href="#" onclick="return false;">SecOps &amp; Infrastructure Architects</a></p>
        </footer>
    </main>

    <!-- ═══════════ REMEDIATION GUIDE MODAL ═══════════ -->
    <div class="modal-backdrop" id="remedModal">
        <div class="modal-window ember-card">
            <button class="modal-close-btn" onclick="closeRemedModal()">
                <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            </button>
            <h3 id="remedHeaderName" style="font-size:1.4rem; font-weight:800; margin-bottom:6px; color:var(--text-primary); font-family:var(--font-heading);">Header Remediation</h3>
            <p id="remedHeaderDesc" style="color:var(--text-muted); font-size:0.88rem; margin-bottom:1.35rem; line-height:1.5;">Configuration snippets for production web servers.</p>
            
            <div class="remed-tab-row">
                <button class="remed-tab-btn active" onclick="switchRemedTab('nginx')">Nginx</button>
                <button class="remed-tab-btn" onclick="switchRemedTab('apache')">Apache</button>
                <button class="remed-tab-btn" onclick="switchRemedTab('cloudflare')">Cloudflare</button>
                <button class="remed-tab-btn" onclick="switchRemedTab('nextjs')">Next.js / Vercel</button>
                <button class="remed-tab-btn" onclick="switchRemedTab('caddy')">Caddy</button>
            </div>

            <div class="code-box">
                <button class="code-copy-btn" id="remedCopyBtn" onclick="copyRemedCode()">Copy</button>
                <code id="remedCodeContent">Loading snippet...</code>
            </div>
        </div>
    </div>

    <!-- ═══════════ SCAN HISTORY DRAWER ═══════════ -->
    <div class="drawer-backdrop" id="historyDrawer">
        <div class="drawer-panel">
            <div class="drawer-header">
                <div>
                    <h3 style="font-size:1.3rem; font-weight:800; color:var(--text-primary); font-family:var(--font-heading);">Audit History</h3>
                    <p style="font-size:0.8rem; color:var(--text-muted);">Stored locally on this workstation</p>
                </div>
                <button class="modal-close-btn" onclick="closeHistoryDrawer()" style="position:static;">
                    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                </button>
            </div>
            <div class="drawer-list" id="historyList"></div>
            <div style="margin-top: 1.5rem; display: flex; justify-content: flex-end;">
                <button class="action-btn" onclick="clearHistory()" style="color:var(--danger); border-color:rgba(255,34,63,0.35);">
                    Clear History
                </button>
            </div>
        </div>
    </div>

    <!-- ═══════════ AUTH MODAL ═══════════ -->
    <div class="modal-backdrop" id="authModal">
        <div class="modal-window ember-card">
            <button class="modal-close-btn" onclick="closeAuthModal()">
                <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            </button>
            <div style="text-align: center; margin-bottom: 1rem;">
                <h3 style="font-size: 1.5rem; font-weight: 800; color: var(--text-primary); font-family: var(--font-heading);">SecOps Analyst Portal</h3>
                <p style="color: var(--text-muted); font-size: 0.88rem;">Authenticate for elevated telemetry features</p>
            </div>

            <div class="auth-tab-row">
                <button class="auth-tab-btn active" id="tabSignIn" onclick="setAuthTab('signin')">Sign In</button>
                <button class="auth-tab-btn" id="tabSignUp" onclick="setAuthTab('signup')">Create Account</button>
            </div>

            <form id="authForm" onsubmit="handleAuthSubmit(event)">
                <div class="auth-field" id="nameFieldGroup" style="display:none;">
                    <label class="auth-label">Full Name</label>
                    <input type="text" id="authName" class="auth-input-elem" placeholder="Alex Morgan">
                </div>
                <div class="auth-field">
                    <label class="auth-label">SecOps Email</label>
                    <input type="email" id="authEmail" class="auth-input-elem" placeholder="analyst@cybershield.internal" required>
                </div>
                <div class="auth-field">
                    <label class="auth-label">Password</label>
                    <input type="password" id="authPassword" class="auth-input-elem" placeholder="••••••••••••" required>
                </div>
                <button type="submit" class="auth-submit-btn" id="authSubmitText">Access CyberShield Terminal</button>
            </form>
        </div>
    </div>

    <!-- ═══════════════════════════════════════════════════════════════
         APPLICATION JAVASCRIPT & AUDIO ENGINE
         ═══════════════════════════════════════════════════════════════ -->
    <script>
    (function() {
        'use strict';

        // Audio Engine
        let audioCtx = null;
        let isAudioMuted = localStorage.getItem('cybershield-audio-muted') === 'true';

        function initAudio() {
            if (!audioCtx) {
                const AudioContext = window.AudioContext || window.webkitAudioContext;
                if (AudioContext) audioCtx = new AudioContext();
            }
            if (audioCtx && audioCtx.state === 'suspended') {
                audioCtx.resume();
            }
        }

        function playSound(type) {
            if (isAudioMuted) return;
            try {
                initAudio();
                if (!audioCtx) return;
                const now = audioCtx.currentTime;

                if (type === 'click') {
                    const osc = audioCtx.createOscillator();
                    const gain = audioCtx.createGain();
                    osc.type = 'sine';
                    osc.frequency.setValueAtTime(800, now);
                    osc.frequency.exponentialRampToValueAtTime(400, now + 0.04);
                    gain.gain.setValueAtTime(0.04, now);
                    gain.gain.linearRampToValueAtTime(0.001, now + 0.04);
                    osc.connect(gain);
                    gain.connect(audioCtx.destination);
                    osc.start(now);
                    osc.stop(now + 0.04);
                } else if (type === 'scanStart') {
                    const osc = audioCtx.createOscillator();
                    const gain = audioCtx.createGain();
                    osc.type = 'triangle';
                    osc.frequency.setValueAtTime(220, now);
                    osc.frequency.exponentialRampToValueAtTime(880, now + 0.18);
                    gain.gain.setValueAtTime(0.05, now);
                    gain.gain.linearRampToValueAtTime(0.001, now + 0.2);
                    osc.connect(gain);
                    gain.connect(audioCtx.destination);
                    osc.start(now);
                    osc.stop(now + 0.2);
                } else if (type === 'success') {
                    [523.25, 659.25, 783.99].forEach((freq, idx) => {
                        const osc = audioCtx.createOscillator();
                        const gain = audioCtx.createGain();
                        osc.type = 'sine';
                        osc.frequency.setValueAtTime(freq, now + idx * 0.06);
                        gain.gain.setValueAtTime(0.06, now + idx * 0.06);
                        gain.gain.exponentialRampToValueAtTime(0.001, now + idx * 0.06 + 0.35);
                        osc.connect(gain);
                        gain.connect(audioCtx.destination);
                        osc.start(now + idx * 0.06);
                        osc.stop(now + idx * 0.06 + 0.35);
                    });
                } else if (type === 'error') {
                    const osc = audioCtx.createOscillator();
                    const gain = audioCtx.createGain();
                    osc.type = 'sawtooth';
                    osc.frequency.setValueAtTime(180, now);
                    osc.frequency.linearRampToValueAtTime(110, now + 0.22);
                    gain.gain.setValueAtTime(0.08, now);
                    gain.gain.linearRampToValueAtTime(0.001, now + 0.22);
                    osc.connect(gain);
                    gain.connect(audioCtx.destination);
                    osc.start(now);
                    osc.stop(now + 0.22);
                }
            } catch(e) {}
        }

        const audioToggleBtn = document.getElementById('audioToggleBtn');
        const audioIconOn = document.getElementById('audioIconOn');
        const audioIconOff = document.getElementById('audioIconOff');

        function updateAudioUI() {
            audioIconOn.style.display = isAudioMuted ? 'none' : 'block';
            audioIconOff.style.display = isAudioMuted ? 'block' : 'none';
        }
        updateAudioUI();

        audioToggleBtn.addEventListener('click', () => {
            isAudioMuted = !isAudioMuted;
            localStorage.setItem('cybershield-audio-muted', isAudioMuted);
            updateAudioUI();
            if (!isAudioMuted) playSound('click');
        });

        // Theme Switcher
        const html = document.documentElement;
        const themeToggleBtn = document.getElementById('themeToggleBtn');
        const sunIcon = document.querySelector('.theme-icon-sun');
        const moonIcon = document.querySelector('.theme-icon-moon');

        const savedTheme = localStorage.getItem('cybershield-theme') || 'dark';
        applyTheme(savedTheme);

        function applyTheme(t) {
            html.setAttribute('data-theme', t);
            if (t === 'light') {
                sunIcon.style.display = 'block';
                moonIcon.style.display = 'none';
            } else {
                sunIcon.style.display = 'none';
                moonIcon.style.display = 'block';
            }
        }

        themeToggleBtn.addEventListener('click', () => {
            playSound('click');
            const current = html.getAttribute('data-theme');
            const next = current === 'dark' ? 'light' : 'dark';
            applyTheme(next);
            localStorage.setItem('cybershield-theme', next);
        });

        // Particle Canvas & Cursor
        const cursorGlow = document.getElementById('cursorGlow');
        const cursorDot = document.getElementById('cursorDot');
        const pCanvas = document.getElementById('particleCanvas');
        const pCtx = pCanvas.getContext('2d');
        let mouseX = -300, mouseY = -300;
        let smoothX = -300, smoothY = -300;
        let sparks = [];

        function resizePCanvas() {
            pCanvas.width = window.innerWidth;
            pCanvas.height = window.innerHeight;
        }
        resizePCanvas();
        window.addEventListener('resize', resizePCanvas);

        document.addEventListener('mousemove', (e) => {
            mouseX = e.clientX;
            mouseY = e.clientY;
            cursorGlow.style.opacity = '0.35';
            cursorDot.style.left = mouseX + 'px';
            cursorDot.style.top = mouseY + 'px';

            for (let i = 0; i < 2; i++) {
                sparks.push({
                    x: mouseX,
                    y: mouseY,
                    vx: (Math.random() - 0.5) * 2,
                    vy: (Math.random() - 0.5) * 2,
                    radius: Math.random() * 2.8 + 1,
                    alpha: 1,
                    decay: Math.random() * 0.025 + 0.015
                });
            }
        });

        document.addEventListener('mouseleave', () => { cursorGlow.style.opacity = '0'; });

        function animateSparks() {
            smoothX += (mouseX - smoothX) * 0.14;
            smoothY += (mouseY - smoothY) * 0.14;
            cursorGlow.style.left = smoothX + 'px';
            cursorGlow.style.top = smoothY + 'px';

            pCtx.clearRect(0, 0, pCanvas.width, pCanvas.height);
            const isDark = html.getAttribute('data-theme') !== 'light';
            const colorRgb = isDark ? '255, 106, 0' : '234, 88, 12';

            for (let i = sparks.length - 1; i >= 0; i--) {
                const s = sparks[i];
                s.x += s.vx;
                s.y += s.vy;
                s.alpha -= s.decay;
                s.radius *= 0.97;

                if (s.alpha <= 0 || s.radius <= 0.2) {
                    sparks.splice(i, 1);
                    continue;
                }

                pCtx.beginPath();
                pCtx.arc(s.x, s.y, s.radius, 0, Math.PI * 2);
                pCtx.fillStyle = `rgba(${colorRgb}, ${s.alpha * 0.7})`;
                pCtx.fill();
            }

            requestAnimationFrame(animateSparks);
        }
        animateSparks();

        // Scanner Engine & Telemetry
        const targetInput = document.getElementById('targetInput');
        const scanBtn = document.getElementById('scanBtn');
        const liveTerminal = document.getElementById('liveTerminal');
        const terminalLogs = document.getElementById('terminalLogs');
        const termStatus = document.getElementById('termStatus');
        const errorAlert = document.getElementById('errorAlert');
        const errorMessage = document.getElementById('errorMessage');
        const resultsSection = document.getElementById('resultsSection');

        let activeAuditData = null;

        window.setQuickTarget = function(domain) {
            playSound('click');
            targetInput.value = domain;
            targetInput.focus();
        };

        function addTerminalLog(tag, msg) {
            const now = new Date();
            const ts = now.toISOString().substring(14, 23);
            const line = document.createElement('div');
            line.className = 'terminal-line';
            line.innerHTML = `<span class="term-ts">[${ts}]</span><span class="term-tag">${tag}</span><span class="term-msg">${msg}</span>`;
            terminalLogs.appendChild(line);
            terminalLogs.scrollTop = terminalLogs.scrollHeight;
        }

        async function triggerAudit() {
            const rawTarget = targetInput.value.trim();
            if (!rawTarget) {
                showError("Please enter a valid website hostname or URL (e.g. github.com)");
                return;
            }

            playSound('scanStart');
            errorAlert.style.display = 'none';
            resultsSection.style.display = 'none';
            liveTerminal.style.display = 'block';
            terminalLogs.innerHTML = '';
            termStatus.textContent = 'RUNNING';
            termStatus.style.color = 'var(--flame-orange)';
            scanBtn.disabled = true;

            addTerminalLog('INIT', `Auditing target: ${rawTarget}`);
            addTerminalLog('DNS_LOOKUP', 'Resolving DNS record & socket connection...');

            const startTime = Date.now();
            let simulatedTelemetry = [
                { delay: 180, tag: 'SOCKET_TCP', msg: 'Connected to remote port 443 with TLS ALPN...' },
                { delay: 350, tag: 'TLS_NEGOTIATE', msg: 'Negotiating cipher suite & checking TLS 1.3 compliance...' },
                { delay: 550, tag: 'X509_CHAIN', msg: 'Extracting Certificate Authority, validity period & SANs...' },
                { delay: 750, tag: 'HTTP_AUDIT', msg: 'Scanning HSTS, CSP, Clickjacking & Referrer headers...' },
                { delay: 900, tag: 'COOKIE_SEC', msg: 'Auditing cookie security flags (Secure, HttpOnly, SameSite)...' }
            ];

            simulatedTelemetry.forEach(item => {
                setTimeout(() => {
                    if (termStatus.textContent === 'RUNNING') {
                        addTerminalLog(item.tag, item.msg);
                    }
                }, item.delay);
            });

            try {
                const response = await fetch('/api/audit', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: rawTarget })
                });
                const data = await response.json();

                if (!response.ok || data.error) {
                    throw new Error(data.error || 'Failed to complete security audit.');
                }

                addTerminalLog('SUCCESS', `Audit completed in ${Date.now() - startTime}ms. Threat Score: ${data.score}/100 [Grade ${data.grade}]`);
                termStatus.textContent = 'FINISHED';
                termStatus.style.color = 'var(--flame-orange)';
                playSound('success');

                setTimeout(() => {
                    renderAuditReport(data);
                    saveToHistory(data);
                    scanBtn.disabled = false;
                }, 500);

            } catch (err) {
                termStatus.textContent = 'FAILED';
                termStatus.style.color = 'var(--danger)';
                addTerminalLog('ERROR', err.message);
                playSound('error');
                showError(err.message);
                scanBtn.disabled = false;
            }
        }

        function showError(msg) {
            errorMessage.textContent = msg;
            errorAlert.style.display = 'block';
            window.scrollTo({ top: errorAlert.offsetTop - 100, behavior: 'smooth' });
        }

        scanBtn.addEventListener('click', triggerAudit);
        targetInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') triggerAudit(); });

        function renderAuditReport(data) {
            activeAuditData = data;

            document.getElementById('resTarget').textContent = data.target;
            document.getElementById('resVerdict').textContent = `${data.verdict} — ${data.deductions.length ? data.deductions.length + ' vulnerabilities detected' : 'Zero critical flaws'}`;
            document.getElementById('resIp').textContent = data.network.ip || 'Unknown';
            document.getElementById('resLatency').textContent = `${data.network.latency_ms}ms ping`;
            document.getElementById('resInfra').textContent = data.http.infrastructure || 'Direct';
            document.getElementById('metaTimestamp').textContent = `Audited ${data.timestamp}`;

            const gaugeFg = document.getElementById('gaugeFg');
            const circumference = 2 * Math.PI * 60;
            const offset = circumference - (data.score / 100) * circumference;
            gaugeFg.style.strokeDashoffset = offset;
            gaugeFg.style.stroke = data.grade_color;

            const scoreNum = document.getElementById('resScoreNum');
            let curr = 0;
            const inc = Math.ceil(data.score / 25);
            const timer = setInterval(() => {
                curr += inc;
                if (curr >= data.score) { curr = data.score; clearInterval(timer); }
                scoreNum.textContent = curr;
            }, 30);
            scoreNum.style.color = data.grade_color;

            const gradeGem = document.getElementById('gradeGemstone');
            document.getElementById('resGradeChar').textContent = data.grade;
            gradeGem.style.background = data.grade_color;

            document.getElementById('fastTlsVer').textContent = data.tls.tls_version || 'N/A';
            document.getElementById('fastCertDays').textContent = `${data.tls.cert_expires_in_days} Days`;
            document.getElementById('fastRedirect').textContent = data.http.redirect_secure ? 'Enforced' : 'None';
            document.getElementById('fastHttpStatus').textContent = `${data.http.status_code || 200} OK`;

            document.getElementById('tlsVersionVal').textContent = data.tls.tls_version || 'N/A';
            document.getElementById('tlsCipherVal').textContent = data.tls.cipher_suite || 'N/A';
            document.getElementById('tlsIssuerVal').textContent = data.tls.issuer_org || 'Unknown CA';
            document.getElementById('tlsExpiryVal').textContent = `${data.tls.cert_expires_in_days} Days Left (${data.tls.expires_at || ''})`;
            document.getElementById('tlsSansVal').textContent = `${data.tls.sans_count} Domains (${data.tls.sans_sample ? data.tls.sans_sample.slice(0, 3).join(', ') : ''}...)`;
            
            const fpVal = document.getElementById('tlsFingerprintVal');
            fpVal.textContent = data.tls.fingerprint_sha256 || 'N/A';
            fpVal.onclick = () => {
                navigator.clipboard.writeText(data.tls.fingerprint_sha256);
                alert('Fingerprint copied to clipboard!');
            };

            const tlsBadge = document.getElementById('tlsBadge');
            if (data.tls.cert_valid && data.tls.protocol_secure) {
                tlsBadge.textContent = "STRONG CRYPTOGRAPHY";
                tlsBadge.className = "status-badge badge-secure";
            } else if (data.tls.cert_valid) {
                tlsBadge.textContent = "LEGACY PROTOCOL";
                tlsBadge.className = "status-badge badge-warning";
            } else {
                tlsBadge.textContent = "INSECURE / EXPIRED";
                tlsBadge.className = "status-badge badge-danger";
            }

            const missingList = document.getElementById('missingHeadersList');
            missingList.innerHTML = '';
            if (data.http.missing_headers && data.http.missing_headers.length > 0) {
                data.http.missing_headers.forEach(item => {
                    const row = document.createElement('div');
                    row.className = 'header-item-row';
                    const sevClass = item.severity === 'Critical' ? 'badge-danger' : (item.severity === 'High' ? 'badge-warning' : 'badge-secure');
                    row.innerHTML = `
                        <div class="header-item-left">
                            <div style="display:flex; align-items:center; gap:8px;">
                                <span class="header-item-name" style="color:var(--danger);">${item.name}</span>
                                <span class="status-badge ${sevClass}">${item.severity}</span>
                            </div>
                            <span class="header-item-desc">${item.description}</span>
                        </div>
                        <div class="header-item-actions">
                            <button class="fix-btn" onclick="openRemedModal('${item.name}')">
                                <svg fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/></svg>
                                Fix Snippet
                            </button>
                        </div>
                    `;
                    missingList.appendChild(row);
                });
            } else {
                missingList.innerHTML = `<div class="header-item-row"><span style="color:var(--flame-orange);">All recommended enterprise security headers are enforced! 🎉</span></div>`;
            }

            const presentList = document.getElementById('presentHeadersList');
            presentList.innerHTML = '';
            const pKeys = Object.keys(data.http.present_headers || {});
            if (pKeys.length > 0) {
                pKeys.forEach(k => {
                    const row = document.createElement('div');
                    row.className = 'header-item-row';
                    row.innerHTML = `
                        <div class="header-item-left">
                            <span class="header-item-name">${k}</span>
                        </div>
                        <div class="header-item-actions">
                            <span class="header-item-val">${escapeHtml(data.http.present_headers[k])}</span>
                            <span class="status-badge badge-secure">PASSED</span>
                        </div>
                    `;
                    presentList.appendChild(row);
                });
            } else {
                presentList.innerHTML = `<div class="header-item-row"><span style="color:var(--text-muted);">No standard security headers detected.</span></div>`;
            }

            const leakageCard = document.getElementById('leakageCard');
            const leakageList = document.getElementById('leakageList');
            leakageList.innerHTML = '';
            if (data.http.leakage && data.http.leakage.length > 0) {
                leakageCard.style.display = 'block';
                data.http.leakage.forEach(leak => {
                    const row = document.createElement('div');
                    row.className = 'header-item-row';
                    row.innerHTML = `
                        <div class="header-item-left">
                            <span class="header-item-name" style="color:var(--warning);">${leak.header}: ${escapeHtml(leak.value)}</span>
                            <span class="header-item-desc">${leak.risk}</span>
                        </div>
                        <div class="header-item-actions">
                            <span class="status-badge badge-warning">DISCLOSED</span>
                        </div>
                    `;
                    leakageList.appendChild(row);
                });
            } else {
                leakageCard.style.display = 'none';
            }

            const cookieCard = document.getElementById('cookieCard');
            const cookieList = document.getElementById('cookieList');
            cookieList.innerHTML = '';
            if (data.http.cookies && data.http.cookies.length > 0) {
                cookieCard.style.display = 'block';
                data.http.cookies.forEach(c => {
                    const row = document.createElement('div');
                    row.className = 'header-item-row';
                    const secBadge = c.secure ? '<span class="status-badge badge-secure">Secure</span>' : '<span class="status-badge badge-danger">Insecure</span>';
                    const httpBadge = c.httponly ? '<span class="status-badge badge-secure">HttpOnly</span>' : '<span class="status-badge badge-warning">No HttpOnly</span>';
                    const sameBadge = `<span class="status-badge badge-secure">SameSite=${c.samesite}</span>`;
                    row.innerHTML = `
                        <div class="header-item-left">
                            <span class="header-item-name">${escapeHtml(c.name)}</span>
                            <span class="header-item-desc">Scope: ${escapeHtml(c.domain || 'Domain')} ${escapeHtml(c.path || '/')}</span>
                        </div>
                        <div class="header-item-actions">
                            ${secBadge} ${httpBadge} ${sameBadge}
                        </div>
                    `;
                    cookieList.appendChild(row);
                });
            } else {
                cookieCard.style.display = 'none';
            }

            document.getElementById('rawJsonOutput').textContent = JSON.stringify(data, null, 2);
            resultsSection.style.display = 'flex';
            window.scrollTo({ top: resultsSection.offsetTop - 80, behavior: 'smooth' });
        }

        function escapeHtml(str) {
            if (!str) return '';
            return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
        }

        // Remediation Snippet Database
        const remediationDb = {
            "Strict-Transport-Security": {
                name: "Strict-Transport-Security (HSTS)",
                desc: "Enforces browsers to exclusively access the domain over HTTPS for 1 year, including subdomains.",
                nginx: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
                apache: 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
                cloudflare: '// In Cloudflare Dashboard -> SSL/TLS -> Edge Certificates -> Enable HSTS\n// Max-Age: 12 months, Include Subdomains: ON, Preload: ON',
                nextjs: '// next.config.js\nmodule.exports = {\n  async headers() {\n    return [{\n      source: "/:path*",\n      headers: [{ key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains; preload" }]\n    }];\n  }\n};',
                caddy: 'header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"'
            },
            "Content-Security-Policy": {
                name: "Content-Security-Policy (CSP)",
                desc: "Mitigates Cross-Site Scripting (XSS) and data injection by declaring approved content sources.",
                nginx: 'add_header Content-Security-Policy "default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\' https://fonts.googleapis.com; font-src \'self\' https://fonts.gstatic.com;" always;',
                apache: 'Header always set Content-Security-Policy "default-src \'self\'; script-src \'self\'; style-src \'self\'; font-src \'self\';"',
                cloudflare: '// Add Transform Rule -> Modify Response Header\n// Header: Content-Security-Policy\n// Value: default-src \'self\'; script-src \'self\';',
                nextjs: '// next.config.js\nheaders: [{ key: "Content-Security-Policy", value: "default-src \'self\'; script-src \'self\';" }]',
                caddy: 'header Content-Security-Policy "default-src \'self\'; script-src \'self\';"'
            },
            "X-Frame-Options": {
                name: "X-Frame-Options",
                desc: "Defends against clickjacking by refusing iframe embedding across external origins.",
                nginx: 'add_header X-Frame-Options "SAMEORIGIN" always;',
                apache: 'Header always set X-Frame-Options "SAMEORIGIN"',
                cloudflare: '// Cloudflare Transform Rule -> Set X-Frame-Options to SAMEORIGIN',
                nextjs: 'headers: [{ key: "X-Frame-Options", value: "SAMEORIGIN" }]',
                caddy: 'header X-Frame-Options "SAMEORIGIN"'
            },
            "X-Content-Type-Options": {
                name: "X-Content-Type-Options",
                desc: "Prevents browser MIME-type sniffing vulnerabilities by enforcing declared MIME types.",
                nginx: 'add_header X-Content-Type-Options "nosniff" always;',
                apache: 'Header always set X-Content-Type-Options "nosniff"',
                cloudflare: '// Cloudflare Transform Rule -> Set X-Content-Type-Options to nosniff',
                nextjs: 'headers: [{ key: "X-Content-Type-Options", value: "nosniff" }]',
                caddy: 'header X-Content-Type-Options "nosniff"'
            },
            "Referrer-Policy": {
                name: "Referrer-Policy",
                desc: "Restricts referral info sent when following outbound hyperlinks, preventing sensitive URL leaks.",
                nginx: 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
                apache: 'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
                cloudflare: '// Cloudflare Transform Rule -> Set Referrer-Policy to strict-origin-when-cross-origin',
                nextjs: 'headers: [{ key: "Referrer-Policy", value: "strict-origin-when-cross-origin" }]',
                caddy: 'header Referrer-Policy "strict-origin-when-cross-origin"'
            },
            "Permissions-Policy": {
                name: "Permissions-Policy",
                desc: "Restricts browser feature APIs such as camera, microphone, geolocation, and payment requests.",
                nginx: 'add_header Permissions-Policy "geolocation=(), camera=(), microphone=()" always;',
                apache: 'Header always set Permissions-Policy "geolocation=(), camera=(), microphone=()"',
                cloudflare: '// Cloudflare Transform Rule -> Set Permissions-Policy to geolocation=(), camera=(), microphone=()',
                nextjs: 'headers: [{ key: "Permissions-Policy", value: "geolocation=(), camera=(), microphone=()" }]',
                caddy: 'header Permissions-Policy "geolocation=(), camera=(), microphone=()"'
            }
        };

        let currentRemedHeader = "Strict-Transport-Security";
        let currentRemedTab = "nginx";

        window.openRemedModal = function(headerName) {
            playSound('click');
            currentRemedHeader = headerName;
            const item = remediationDb[headerName] || {
                name: headerName,
                desc: "Security header enforcement directive.",
                nginx: `add_header ${headerName} "1; mode=block" always;`,
                apache: `Header always set ${headerName} "1; mode=block"`,
                cloudflare: `// Cloudflare Transform Rule -> Set ${headerName}`,
                nextjs: `headers: [{ key: "${headerName}", value: "1" }]`,
                caddy: `header ${headerName} "1"`
            };

            document.getElementById('remedHeaderName').textContent = item.name;
            document.getElementById('remedHeaderDesc').textContent = item.desc;
            switchRemedTab('nginx');
            document.getElementById('remedModal').classList.add('open');
        };

        window.closeRemedModal = function() {
            playSound('click');
            document.getElementById('remedModal').classList.remove('open');
        };

        window.switchRemedTab = function(tab) {
            currentRemedTab = tab;
            document.querySelectorAll('.remed-tab-btn').forEach(btn => {
                btn.classList.toggle('active', btn.textContent.toLowerCase().includes(tab.toLowerCase()));
            });
            const item = remediationDb[currentRemedHeader] || {};
            document.getElementById('remedCodeContent').textContent = item[tab] || `// Configuration for ${tab}`;
        };

        window.copyRemedCode = function() {
            playSound('click');
            const code = document.getElementById('remedCodeContent').textContent;
            navigator.clipboard.writeText(code);
            const btn = document.getElementById('remedCopyBtn');
            btn.textContent = 'Copied!';
            setTimeout(() => btn.textContent = 'Copy', 2000);
        };

        // Scan History
        const historyDrawer = document.getElementById('historyDrawer');
        const historyList = document.getElementById('historyList');
        const historyCounter = document.getElementById('historyCounter');

        function getHistory() {
            try { return JSON.parse(localStorage.getItem('cybershield-history') || '[]'); } catch(e) { return []; }
        }

        function saveToHistory(report) {
            let hist = getHistory();
            hist = hist.filter(h => h.target !== report.target);
            hist.unshift({
                target: report.target,
                score: report.score,
                grade: report.grade,
                grade_color: report.grade_color,
                timestamp: report.timestamp,
                data: report
            });
            if (hist.length > 25) hist.pop();
            localStorage.setItem('cybershield-history', JSON.stringify(hist));
            updateHistoryUI();
        }

        function updateHistoryUI() {
            const hist = getHistory();
            historyCounter.textContent = hist.length;
            historyList.innerHTML = '';
            if (hist.length === 0) {
                historyList.innerHTML = `<div style="text-align:center; padding:2rem 0; color:var(--text-muted);">No scan history yet.</div>`;
                return;
            }
            hist.forEach(item => {
                const row = document.createElement('div');
                row.className = 'drawer-item';
                row.onclick = () => {
                    closeHistoryDrawer();
                    renderAuditReport(item.data);
                };
                row.innerHTML = `
                    <div>
                        <div style="font-weight:700; color:var(--text-primary); font-size:0.95rem; font-family:var(--font-heading);">${item.target}</div>
                        <div style="font-size:0.75rem; color:var(--text-muted); font-family:var(--font-mono);">${item.timestamp}</div>
                    </div>
                    <div style="display:flex; align-items:center; gap:8px;">
                        <span style="font-family:var(--font-mono); font-weight:800; font-size:1.1rem; color:${item.grade_color};">${item.score}</span>
                        <span class="status-badge" style="background:${item.grade_color}; color:#070303; padding:3px 8px;">${item.grade}</span>
                    </div>
                `;
                historyList.appendChild(row);
            });
        }
        updateHistoryUI();

        window.openHistoryDrawer = function() {
            playSound('click');
            updateHistoryUI();
            historyDrawer.classList.add('open');
        };

        window.closeHistoryDrawer = function() {
            playSound('click');
            historyDrawer.classList.remove('open');
        };

        window.clearHistory = function() {
            playSound('click');
            if (confirm('Clear all local audit history?')) {
                localStorage.removeItem('cybershield-history');
                updateHistoryUI();
            }
        };

        document.getElementById('historyDrawerBtn').addEventListener('click', openHistoryDrawer);
        historyDrawer.addEventListener('click', (e) => { if (e.target === historyDrawer) closeHistoryDrawer(); });

        // Export Actions
        document.getElementById('copyJsonBtn').addEventListener('click', () => {
            playSound('click');
            if (!activeAuditData) return;
            navigator.clipboard.writeText(JSON.stringify(activeAuditData, null, 2));
            const btn = document.getElementById('copyJsonBtn');
            btn.textContent = 'Copied!';
            setTimeout(() => btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg> Copy JSON Report`, 2000);
        });

        document.getElementById('downloadJsonBtn').addEventListener('click', () => {
            playSound('click');
            if (!activeAuditData) return;
            const blob = new Blob([JSON.stringify(activeAuditData, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `cybershield-${activeAuditData.target}-${Date.now()}.json`;
            a.click();
            URL.revokeObjectURL(url);
        });

        document.getElementById('copyMarkdownBtn').addEventListener('click', () => {
            playSound('click');
            if (!activeAuditData) return;
            const d = activeAuditData;
            const md = `# CyberShield Security Audit Report: ${d.target}
**Timestamp:** ${d.timestamp}
**Threat Intelligence Score:** ${d.score}/100 (Grade: ${d.grade})
**Posture Verdict:** ${d.verdict}

## Cryptographic Status
- **TLS Version:** ${d.tls.tls_version}
- **Cipher Suite:** ${d.tls.cipher_suite}
- **Certificate Issuer:** ${d.tls.issuer_org}
- **Cert Expiry:** ${d.tls.cert_expires_in_days} Days Remaining (${d.tls.expires_at})
- **HTTPS Redirect:** ${d.http.redirect_secure ? 'Enforced' : 'Missing'}
- **SHA-256 Fingerprint:** \`${d.tls.fingerprint_sha256}\`

## Missing Security Headers (Vulnerabilities)
${d.http.missing_headers.map(h => `- [ ] **${h.name}** (${h.severity}): ${h.description}`).join('\n') || 'None - All headers enforced!'}

## Enforced Headers
${Object.keys(d.http.present_headers || {}).map(k => `- [x] **${k}**: \`${d.http.present_headers[k]}\``).join('\n')}

*Generated by CyberShield v3.0 Threat Intelligence Platform*`;

            navigator.clipboard.writeText(md);
            const btn = document.getElementById('copyMarkdownBtn');
            btn.textContent = 'Copied Markdown!';
            setTimeout(() => btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg> Copy Executive Markdown`, 2000);
        });

        // Auth & Profile
        const authModal = document.getElementById('authModal');
        const openAuthBtn = document.getElementById('openAuthBtn');
        const profileHub = document.getElementById('profileHub');
        const profileMenuBtn = document.getElementById('profileMenuBtn');
        const profileDropdown = document.getElementById('profileDropdown');

        window.openAuthModal = function() { playSound('click'); authModal.classList.add('open'); };
        window.closeAuthModal = function() { playSound('click'); authModal.classList.remove('open'); };

        openAuthBtn.addEventListener('click', openAuthModal);
        authModal.addEventListener('click', (e) => { if (e.target === authModal) closeAuthModal(); });

        let authMode = 'signin';
        window.setAuthTab = function(mode) {
            playSound('click');
            authMode = mode;
            document.getElementById('tabSignIn').classList.toggle('active', mode === 'signin');
            document.getElementById('tabSignUp').classList.toggle('active', mode === 'signup');
            document.getElementById('nameFieldGroup').style.display = mode === 'signup' ? 'block' : 'none';
            document.getElementById('authSubmitText').textContent = mode === 'signup' ? 'Register SecOps Account' : 'Access CyberShield Terminal';
        };

        window.handleAuthSubmit = function(e) {
            e.preventDefault();
            playSound('success');
            const email = document.getElementById('authEmail').value;
            const name = document.getElementById('authName').value || email.split('@')[0];
            const initials = name.slice(0, 2).toUpperCase();

            document.getElementById('userInitials').textContent = initials;
            document.getElementById('dropdownAvatar').textContent = initials;
            document.getElementById('dropdownUserName').textContent = name;

            openAuthBtn.style.display = 'none';
            profileHub.style.display = 'block';
            closeAuthModal();
        };

        window.closeProfileMenu = function() { profileDropdown.classList.remove('open'); };

        profileMenuBtn.addEventListener('click', (e) => {
            playSound('click');
            e.stopPropagation();
            profileDropdown.classList.toggle('open');
        });
        document.addEventListener('click', (e) => {
            if (!profileDropdown.contains(e.target) && e.target !== profileMenuBtn) closeProfileMenu();
        });

        document.getElementById('signOutBtn').addEventListener('click', () => {
            playSound('click');
            profileHub.style.display = 'none';
            openAuthBtn.style.display = 'flex';
            closeProfileMenu();
        });

        // Keyboard Shortcuts
        document.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
                e.preventDefault();
                targetInput.focus();
            } else if (e.key.toLowerCase() === 'h' && document.activeElement !== targetInput && document.activeElement.tagName !== 'INPUT') {
                e.preventDefault();
                openHistoryDrawer();
            } else if (e.key === 'Escape') {
                closeAuthModal();
                closeRemedModal();
                closeHistoryDrawer();
                closeProfileMenu();
            }
        });

    })();
    </script>
</body>
</html>"""

class VercelPathRewriteMiddleware:
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        matched_path = environ.get('HTTP_X_MATCHED_PATH')
        if matched_path:
            environ['PATH_INFO'] = matched_path
        return self.wsgi_app(environ, start_response)

app.wsgi_app = VercelPathRewriteMiddleware(app.wsgi_app)

@app.route("/fonts/<path:filename>")
@app.route("/api/fonts/<path:filename>")
def serve_font(filename):
    """Serves custom font files (Kapiler, Zeta Drive, Escape Artist, etc.) from the fonts directory."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(base_dir, 'fonts'),
        os.path.join(base_dir, '..', 'fonts'),
        os.path.join(base_dir, 'public', 'fonts'),
        os.path.join(base_dir, '..', 'public', 'fonts')
    ]
    fonts_dir = next((c for c in candidates if os.path.exists(c)), candidates[0])
    font_map = {
        'texas-tango.otf': 'TEXAT BOLD PERSONAL USE___.otf',
        'texas-tango.ttf': 'TEXAT BOLD PERSONAL USE___.otf'
    }
    actual_file = font_map.get(filename, filename)
    mimetype = 'font/otf' if actual_file.lower().endswith('.otf') else 'font/ttf'
    return send_from_directory(fonts_dir, actual_file, mimetype=mimetype)

@app.route("/")
@app.route("/api")
@app.route("/api/index")
@app.route("/index")
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route("/api/audit", methods=["POST"])
@app.route("/audit", methods=["POST"])
def api_audit():
    data = request.get_json() or {}
    url_input = data.get("url", "").strip()
    if not url_input:
        return jsonify({"error": "Please specify a target domain or website URL."}), 400
    try:
        report = run_audit(url_input)
        return jsonify(report)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.errorhandler(404)
def not_found(e):
    # If client attempted to POST to any audit route
    if request.path.endswith('/audit') and request.method == 'POST':
        return api_audit()
    # Otherwise render the dashboard (SPA fallback)
    return render_template_string(HTML_TEMPLATE)

def open_browser(port):
    webbrowser.open(f"http://127.0.0.1:{port}")

if __name__ == "__main__":
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        domain = sys.argv[1]
        report = run_audit(domain)
        print("\n" + "="*50)
        print(f" CYBERSHIELD AUDIT: {report['target']}")
        print("="*50)
        print(f"  Threat Score: {report['score']}/100 [Grade {report['grade']}]")
        print(f"  Verdict:      {report['verdict']}")
        print(f"  Target IP:    {report['network']['ip']} ({report['network']['latency_ms']}ms)")
        print(f"  TLS Protocol: {report['tls']['tls_version']}")
        print(f"  Cipher Suite: {report['tls']['cipher_suite']}")
        print(f"  Certificate:  {report['tls']['issuer_org']} ({report['tls']['cert_expires_in_days']} days left)")
        print(f"  Fingerprint:  {report['tls']['fingerprint_sha256']}")
        print(f"  Redirect:     {'Enforced' if report['http']['redirect_secure'] else 'Missing'}")
        print("\n  Missing Headers:")
        for m in report['http']['missing_headers']:
            print(f"   [-] {m['name']} ({m['severity']}): {m['description']}")
        print("\n  Enforced Headers:")
        for k, v in report['http']['present_headers'].items():
            print(f"   [+] {k}: {v[:60]}")
        print("="*50 + "\n")
    else:
        port = 5000
        print(f"[*] Starting CyberShield v3.0 Command Center at http://127.0.0.1:{port} ...")
        # Only open browser once (prevents duplicate tabs when debug reloader restarts)
        if os.environ.get("WERKZEUG_RUN_MAIN") != "true":
            threading.Timer(1.2, open_browser, args=[port]).start()
        app.run(host="127.0.0.1", port=port, debug=True)