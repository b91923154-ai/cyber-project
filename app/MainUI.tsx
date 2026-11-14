import { useState, useRef } from "react";

export default function MainUI() {
// Input and audit states
  const inputRef = useRef<HTMLInputElement>(null);
  const terminalEndRef = useRef<HTMLDivElement>(null);

  const [targetInput, setTargetInput] = useState("");
  const [isAuditing, setIsAuditing] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");
  const [isTerminalVisible, setIsTerminalVisible] = useState(false);

  // Terminal states
  const [terminalLogs, setTerminalLogs] = useState<any[]>([]);
  const [termStatus, setTermStatus] = useState("IDLE");

  // Audit result states
  const [auditData, setAuditData] = useState<any>(null);
  const [animatedScore, setAnimatedScore] = useState(0);

  // Export button states
  const [copyJsonText, setCopyJsonText] = useState("Copy JSON");
  const [copyMdText, setCopyMdText] = useState("Copy Markdown");

  // Gauge calculation
  const gaugeOffset = auditData
    ? 377 - (auditData.score / 100) * 377
    : 377;

  // Function placeholders: connect your original implementations here
  const handleAudit = () => {};
  const handleQuickPreset = (target: string) => {
    setTargetInput(target);
  };
  const copyJson = () => {};
  const downloadJson = () => {};
  const copyMarkdown = () => {};
  const openRemediation = (header: string) => {};


return(
          <main className="main-content">
        <section className="hero">
          <div>
            <div className="hero-pill-badge">
              <span className="live-dot" />
              <span className="badge-text-desktop">Real-Time Threat Intelligence &bull; TLS 1.3 &bull; Cryptographic Assurance</span>
              <span className="badge-text-mobile">Real-Time Threat Intel &bull; TLS 1.3</span>
            </div>
          </div>

          <h1 className="hero-title">CYBERSHIELD</h1>
          <p className="hero-desc">
            Automated <strong>TLS Cryptography Audit</strong> &bull;{" "}
            <strong>HTTP Security Headers</strong> &bull; <strong>Cookie Hygiene</strong> &mdash; Comprehensive threat defense for cloud infrastructure.
          </p>
          <div className="hero-kbd-hint">
            <kbd>Enter</kbd> to launch audit &middot; <kbd>Ctrl</kbd>+<kbd>K</kbd> to focus target &middot; <kbd>H</kbd> for history
          </div>
        </section>

        {/* Search Cockpit (Image 1 Style Ember Bloom Card) */}
        <section className="ember-card search-cockpit">
          <div className="search-input-group">
            <div className="search-wrapper">
              <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="11" cy="11" r="8" />
                <line x1="21" y1="21" x2="16.65" y2="16.65" />
              </svg>
              <input
                ref={inputRef}
                type="text"
                id="targetInput"
                className="target-input"
                placeholder="Enter domain or URL (e.g. github.com)"
                value={targetInput}
                onChange={(e) => setTargetInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleAudit();
                }}
                autoComplete="off"
                spellCheck="false"
              />
            </div>

            {/* Chromatic Audit Button */}
            <button
              id="scanBtn"
              className="audit-btn"
              disabled={isAuditing}
              onClick={() => handleAudit()}
            >
              <div className="audit-btn-inner">
                <span>{isAuditing ? "Auditing..." : "Audit Target"}</span>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09z" />
                  <path d="M12 15l-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.35 22.35 0 0 1-4 2z" />
                  <path d="M9 12H4s.55-3.03 2-4c1.62-1.08 5 0 5 0" />
                  <path d="M12 15v5s3.03-.55 4-2c1.08-1.62 0-5 0-5" />
                </svg>
              </div>
            </button>
          </div>

          <div className="quick-targets-row">
            <span className="quick-targets-label">Preset Targets:</span>
            <button className="quick-chip" onClick={() => handleQuickPreset("github.com")}>
              github.com
            </button>
            <button className="quick-chip" onClick={() => handleQuickPreset("google.com")}>
              google.com
            </button>
            <button className="quick-chip" onClick={() => handleQuickPreset("stripe.com")}>
              stripe.com
            </button>
            <button className="quick-chip" onClick={() => handleQuickPreset("cloudflare.com")}>
              cloudflare.com
            </button>
            <button className="quick-chip" onClick={() => handleQuickPreset("e-commerce-zeta-virid-84.vercel.app")}>
              vercel-demo.app
            </button>
          </div>
        </section>

        {/* Error Alert Card */}
        {errorMsg && (
          <div id="errorAlert" className="error-alert" style={{ display: "block" }}>
            <h4>
              <svg width="22" height="22" fill="none" stroke="currentColor" strokeWidth="2.2" viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="10" />
                <line x1="12" y1="8" x2="12" y2="12" />
                <line x1="12" y1="16" x2="12.01" y2="16" />
              </svg>
              Audit Execution Error
            </h4>
            <p id="errorMessage">{errorMsg}</p>
          </div>
        )}

        {/* Live Hacker Terminal */}
        {isTerminalVisible && (
          <div id="liveTerminal" className="terminal-container" style={{ display: "block" }}>
            <div className="terminal-topbar">
              <div className="terminal-dots">
                <span className="terminal-dot dot-red" />
                <span className="terminal-dot dot-yellow" />
                <span className="terminal-dot dot-green" />
              </div>
              <div className="terminal-title">
                <svg width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                  <polyline points="4 17 10 11 4 5" />
                  <line x1="12" y1="19" x2="20" y2="19" />
                </svg>
                CYBERSHIELD_AGENT // THREAT_TELEMETRY_ENGINE
              </div>
              <div
                id="termStatus"
                style={{
                  fontFamily: "var(--font-mono)",
                  fontSize: "0.72rem",
                  color:
                    termStatus === "RUNNING"
                      ? "var(--flame-orange)"
                      : termStatus === "FAILED"
                      ? "var(--danger)"
                      : "var(--success)",
                }}
              >
                {termStatus}
              </div>
            </div>
            <div className="terminal-body" id="terminalLogs">
              {terminalLogs.map((log) => (
                <div key={log.id} className="terminal-line">
                  <span className="term-ts">[{log.ts}]</span>
                  <span className="term-tag">{log.tag}</span>
                  <span className="term-msg">{log.msg}</span>
                </div>
              ))}
              <div ref={terminalEndRef} />
            </div>
          </div>
        )}

        {/* Audit Results Container */}
        {auditData && (
          <section id="resultsSection" className="results-wrapper" style={{ display: "flex" }}>
            {/* Executive Score Banner (Image 1 Ember Card) */}
            <div className="ember-card score-banner">
              <div className="target-header-col">
                <h2 id="resTarget">{auditData.target}</h2>
                <p id="resVerdict" style={{ color: "var(--text-secondary)", fontSize: "0.95rem" }}>
                  {auditData.verdict} &mdash;{" "}
                  {auditData.deductions.length > 0
                    ? `${auditData.deductions.length} vulnerabilities detected`
                    : "Zero critical flaws"}
                </p>
                <div className="target-meta-row">
                  <span className="meta-pill" id="metaIp">
                    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <circle cx="12" cy="12" r="10" />
                      <line x1="2" y1="12" x2="22" y2="12" />
                      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
                    </svg>
                    <span id="resIp">{auditData.network.ip}</span>
                  </span>
                  <span className="meta-pill" id="metaLatency">
                    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
                    </svg>
                    <span id="resLatency">{auditData.network.latency_ms}ms ping</span>
                  </span>
                  <span className="meta-pill" id="metaInfra">
                    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z" />
                    </svg>
                    <span id="resInfra">{auditData.http.infrastructure}</span>
                  </span>
                  <span className="meta-pill" id="metaTimestamp">Audited {auditData.timestamp}</span>
                </div>
              </div>

              <div className="score-display-group">
                <div className="gauge-wrapper">
                  <svg className="gauge-svg" viewBox="0 0 130 130">
                    <circle className="gauge-bg" cx="65" cy="65" r="60" />
                    <circle
                      className="gauge-fg"
                      id="gaugeFg"
                      cx="65"
                      cy="65"
                      r="60"
                      style={{
                        strokeDashoffset: gaugeOffset,
                        stroke: auditData.grade_color,
                      }}
                    />
                  </svg>
                  <div className="gauge-inner-text">
                    <div
                      className="gauge-number"
                      id="resScoreNum"
                      style={{ color: auditData.grade_color }}
                    >
                      {animatedScore}
                    </div>
                    <div className="gauge-label">Threat Score</div>
                  </div>
                </div>

                <div
                  className="grade-gemstone"
                  id="gradeGemstone"
                  style={{ background: auditData.grade_color }}
                >
                  <span className="grade-char" id="resGradeChar">{auditData.grade}</span>
                  <span className="grade-subtext">GRADE</span>
                </div>
              </div>
            </div>

            {/* Fast Metrics Bar (Image 1 Ember Cards) */}
            <div className="fast-metrics-bar">
              <div className="ember-card metric-tile">
                <div className="metric-label">TLS Protocol</div>
                <div className="metric-value" id="fastTlsVer">{auditData.tls.tls_version || "N/A"}</div>
              </div>
              <div className="ember-card metric-tile">
                <div className="metric-label">Cert Validity</div>
                <div className="metric-value" id="fastCertDays">{auditData.tls.cert_expires_in_days} Days</div>
              </div>
              <div className="ember-card metric-tile">
                <div className="metric-label">HTTPS Redirect</div>
                <div className="metric-value" id="fastRedirect">
                  {auditData.http.redirect_secure ? "Enforced" : "None"}
                </div>
              </div>
              <div className="ember-card metric-tile">
                <div className="metric-label">HTTP Status</div>
                <div className="metric-value" id="fastHttpStatus">{auditData.http.status_code || 200} OK</div>
              </div>
            </div>

            {/* TLS / Cryptographic Status Card */}
            <div className="ember-card audit-card">
              <div className="audit-card-header">
                <div className="audit-card-title">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                    <circle cx="12" cy="16" r="1" />
                  </svg>
                  Cryptographic Architecture &amp; TLS Chain
                </div>
                <div
                  id="tlsBadge"
                  className={`status-badge ${
                    auditData.tls.cert_valid && auditData.tls.protocol_secure
                      ? "badge-secure"
                      : auditData.tls.cert_valid
                      ? "badge-warning"
                      : "badge-danger"
                  }`}
                >
                  {auditData.tls.cert_valid && auditData.tls.protocol_secure
                    ? "STRONG CRYPTOGRAPHY"
                    : auditData.tls.cert_valid
                    ? "LEGACY PROTOCOL"
                    : "INSECURE / EXPIRED"}
                </div>
              </div>

              <div className="info-grid">
                <div className="info-tile">
                  <div className="info-tile-label">Negotiated Protocol</div>
                  <div
                    className="info-tile-value"
                    id="tlsVersionVal"
                    style={{ fontFamily: "var(--font-mono)", color: "var(--flame-orange)" }}
                  >
                    {auditData.tls.tls_version || "N/A"}
                  </div>
                </div>
                <div className="info-tile">
                  <div className="info-tile-label">Active Cipher Suite</div>
                  <div
                    className="info-tile-value"
                    id="tlsCipherVal"
                    style={{ fontFamily: "var(--font-mono)", fontSize: "0.84rem" }}
                  >
                    {auditData.tls.cipher_suite || "Unknown"}
                  </div>
                </div>
                <div className="info-tile">
                  <div className="info-tile-label">Certificate Authority (Issuer)</div>
                  <div className="info-tile-value" id="tlsIssuerVal">{auditData.tls.issuer_org || "Unknown CA"}</div>
                </div>
                <div className="info-tile">
                  <div className="info-tile-label">Expiration Countdown</div>
                  <div className="info-tile-value" id="tlsExpiryVal">
                    {auditData.tls.cert_expires_in_days} Days Remaining ({auditData.tls.expires_at})
                  </div>
                </div>
                <div className="info-tile">
                  <div className="info-tile-label">Subject Alternative Names (SANs)</div>
                  <div
                    className="info-tile-value"
                    id="tlsSansVal"
                    style={{ fontFamily: "var(--font-mono)", fontSize: "0.85rem" }}
                  >
                    {auditData.tls.sans_count} Domains (
                    {auditData.tls.sans_sample ? auditData.tls.sans_sample.slice(0, 3).join(", ") : ""}
                    ...)
                  </div>
                </div>
                <div className="info-tile">
                  <div className="info-tile-label">SHA-256 Fingerprint</div>
                  <div
                    className="info-tile-value"
                    id="tlsFingerprintVal"
                    style={{ fontFamily: "var(--font-mono)", fontSize: "0.74rem", cursor: "pointer" }}
                    title="Click to copy"
                    onClick={() => {
                      navigator.clipboard.writeText(auditData.tls.fingerprint_sha256);
                      alert("Fingerprint copied to clipboard!");
                    }}
                  >
                    {auditData.tls.fingerprint_sha256 || "N/A"}
                  </div>
                </div>
              </div>
            </div>

            {/* HTTP Security Headers Matrix */}
            <div className="ember-card audit-card">
              <div className="audit-card-header">
                <div className="audit-card-title">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                    <polyline points="9 12 11 14 15 10" />
                  </svg>
                  HTTP Security Headers Defense Matrix
                </div>
              </div>

              {/* Missing Headers (Vulnerabilities) */}
              <div style={{ marginBottom: "2rem" }}>
                <div
                  className="info-tile-label"
                  style={{
                    marginBottom: "10px",
                    color: "var(--danger)",
                    display: "flex",
                    alignItems: "center",
                    gap: "8px",
                  }}
                >
                  <svg width="17" height="17" fill="none" stroke="currentColor" strokeWidth="2.2" viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round">
                    <polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2" />
                    <line x1="12" y1="8" x2="12" y2="12" />
                    <line x1="12" y1="16" x2="12.01" y2="16" />
                  </svg>
                  Missing Critical Policies (Action Required)
                </div>
                <div className="header-list" id="missingHeadersList">
                  {auditData.http.missing_headers && auditData.http.missing_headers.length > 0 ? (
                  auditData.http.missing_headers.map((item: any) => {
                      const sevClass =
                        item.severity === "Critical"
                          ? "badge-danger"
                          : item.severity === "High"
                          ? "badge-warning"
                          : "badge-secure";
                      return (
                        <div key={item.name} className="header-item-row">
                          <div className="header-item-left">
                            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                              <span className="header-item-name" style={{ color: "var(--danger)" }}>
                                {item.name}
                              </span>
                              <span className={`status-badge ${sevClass}`}>{item.severity}</span>
                            </div>
                            <span className="header-item-desc">{item.description}</span>
                          </div>
                          <div className="header-item-actions">
                            <button
                              className="fix-btn"
                              onClick={() => openRemediation(item.name)}
                            >
                              <svg fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
                              </svg>
                              Fix Snippet
                            </button>
                          </div>
                        </div>
                      );
                    })
                  ) : (
                    <div className="header-item-row">
                      <span style={{ color: "var(--flame-orange)" }}>
                        All recommended enterprise security headers are enforced! 🎉
                      </span>
                    </div>
                  )}
                </div>
              </div>

              {/* Enforced Headers */}
              <div>
                <div
                  className="info-tile-label"
                  style={{
                    marginBottom: "10px",
                    color: "var(--flame-orange)",
                    display: "flex",
                    alignItems: "center",
                    gap: "8px",
                  }}
                >
                  <svg width="17" height="17" fill="none" stroke="currentColor" strokeWidth="2.2" viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                  Enforced Security Policies
                </div>
                <div className="header-list" id="presentHeadersList">
                  {Object.keys(auditData.http.present_headers || {}).length > 0 ? (
Object.entries(auditData.http.present_headers).map(([k, val]: [string, any]) => (
<div key={k} className="header-item-row">
                        <div className="header-item-left">
                          <span className="header-item-name">{k}</span>
                        </div>
                        <div className="header-item-actions">
                          <span className="header-item-val">{val}</span>
                          <span className="status-badge badge-secure">PASSED</span>
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="header-item-row">
                      <span style={{ color: "var(--text-muted)" }}>
                        No standard security headers detected.
                      </span>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Server Information Leakage Card */}
            {auditData.http.leakage && auditData.http.leakage.length > 0 && (
              <div className="ember-card audit-card" id="leakageCard" style={{ display: "block" }}>
                <div className="audit-card-header">
                  <div className="audit-card-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                      <line x1="12" y1="9" x2="12" y2="13" />
                      <line x1="12" y1="17" x2="12.01" y2="17" />
                    </svg>
                    Information Disclosure &amp; Server Banners
                  </div>
                  <span className="status-badge badge-warning">BANNER EXPOSED</span>
                </div>
                <div className="header-list" id="leakageList">

                  {auditData.http.leakage.map((leak: any, idx: number) => (
                    
                    <div key={idx} className="header-item-row">
                      <div className="header-item-left">
                        <span className="header-item-name" style={{ color: "var(--warning)" }}>
                          {leak.header}: {leak.value}
                        </span>
                        <span className="header-item-desc">{leak.risk}</span>
                      </div>
                      <div className="header-item-actions">
                        <span className="status-badge badge-warning">DISCLOSED</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Cookie Security Audit Card */}
            {auditData.http.cookies && auditData.http.cookies.length > 0 && (
              <div className="ember-card audit-card" id="cookieCard" style={{ display: "block" }}>
                <div className="audit-card-header">
                  <div className="audit-card-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M12 2a10 10 0 1 0 10 10 4 4 0 0 1-5-5 4 4 0 0 1-5-5z" />
                      <circle cx="8.5" cy="8.5" r="1.5" fill="currentColor" />
                      <circle cx="15.5" cy="15.5" r="1.5" fill="currentColor" />
                      <circle cx="8.5" cy="15.5" r="1.5" fill="currentColor" />
                    </svg>
                    Cookie Security &amp; Isolation Audit
                  </div>
                </div>
                <div className="header-list" id="cookieList">
               {auditData.http.cookies.map((c: any, idx: number) => (
                    <div key={idx} className="header-item-row">
                      <div className="header-item-left">
                        <span className="header-item-name">{c.name}</span>
                        <span className="header-item-desc">
                          Scope: {c.domain || "Domain"} {c.path || "/"}
                        </span>
                      </div>
                      <div className="header-item-actions">
                        {c.secure ? (
                          <span className="status-badge badge-secure">Secure</span>
                        ) : (
                          <span className="status-badge badge-danger">Insecure</span>
                        )}
                        {c.httponly ? (
                          <span className="status-badge badge-secure">HttpOnly</span>
                        ) : (
                          <span className="status-badge badge-warning">No HttpOnly</span>
                        )}
                        <span className="status-badge badge-secure">SameSite={c.samesite}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Threat Intelligence Export Suite */}
            <div className="ember-card audit-card">
              <div className="audit-card-header">
                <div className="audit-card-title">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="16 18 22 12 16 6" />
                    <polyline points="8 6 2 12 8 18" />
                  </svg>
                  Threat Intelligence Export Suite
                </div>
              </div>
              <pre className="json-terminal" id="rawJsonOutput">{JSON.stringify(auditData, null, 2)}</pre>
              <div className="action-btn-row">
                <button className="action-btn" id="copyJsonBtn" onClick={copyJson}>
                  <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                    <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" />
                  </svg>
                  {copyJsonText}
                </button>
                <button className="action-btn" id="downloadJsonBtn" onClick={downloadJson}>
                  <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                    <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
                    <polyline points="7 10 12 15 17 10" />
                    <line x1="12" y1="15" x2="12" y2="3" />
                  </svg>
                  Download JSON
                </button>
                <button className="action-btn" id="copyMarkdownBtn" onClick={copyMarkdown}>
                  <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                    <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
                    <polyline points="14 2 14 8 20 8" />
                    <line x1="16" y1="13" x2="8" y2="13" />
                    <line x1="16" y1="17" x2="8" y2="17" />
                  </svg>
                  {copyMdText}
                </button>
                <button className="action-btn" onClick={() => window.print()}>
                  <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                    <polyline points="6 9 6 2 18 2 18 9" />
                    <path d="M6 18H4a2 2 0 01-2-2v-5a2 2 0 012-2h16a2 2 0 012 2v5a2 2 0 01-2 2h-2" />
                    <rect x="6" y="14" width="12" height="8" />
                  </svg>
                  Print / PDF Report
                </button>
              </div>
            </div>
          </section>
        )}

        {/* Footer */}
        <footer className="site-footer">
          <p>
            <strong>CYBERSHIELD</strong> v3.0 &mdash; Elite Web Threat Intelligence &amp; Cryptographic Assurance Platform &middot; Developed for{" "}
            <a href="#" onClick={(e) => e.preventDefault()}>
              SecOps &amp; Infrastructure Architects
            </a>
          </p>
        </footer>
      </main>
);
}