"use client";
import React, { useState } from "react";
import type { Finding, ManualCheck } from "@/lib/findings";

export interface Challenge {
  hostname: string;
  token: string;
  dns: { type: string; name: string; value: string };
  file: { url: string; content: string };
}

const sevColor: Record<string, string> = {
  Critical: "var(--danger)", High: "var(--danger)", Medium: "#ffb703", Low: "var(--text-secondary)", Info: "var(--text-secondary)",
};
const confLabel: Record<string, string> = { confirmed: "Confirmed", likely: "Likely", manual: "Needs manual verification" };
const mono: React.CSSProperties = { fontFamily: "'JetBrains Mono', monospace", fontSize: "0.8rem", wordBreak: "break-all" };

/** Shown when a deep scan is refused because domain ownership is not yet proven. */
export function VerifyPanel({ challenge, onVerified }: { challenge: Challenge; onVerified: () => void }) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const check = async () => {
    setBusy(true); setMsg(null);
    try {
      const res = await fetch("/api/verify", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain: challenge.hostname, check: true }) });
      const d = await res.json();
      if (d.verified) { setMsg("Verified. You can run the deep scan now."); onVerified(); }
      else setMsg(d.error || d.detail || "Not verified yet. DNS changes can take a few minutes.");
    } catch { setMsg("Verification request failed."); }
    setBusy(false);
  };
  return (
    <div className="ember-card audit-card" style={{ padding: 20, marginTop: 16 }}>
      <strong>Deep testing requires proof that you control {challenge.hostname}</strong>
      <p style={{ color: "var(--text-secondary)", margin: "8px 0" }}>
        Active tests are only run against systems their owner has authorised. Publish <em>one</em> of these, then re-check:
      </p>
      <p><b>Option 1 — DNS TXT (preferred)</b><br /><span style={mono}>{challenge.dns.name}</span><br /><span style={mono}>{challenge.dns.value}</span></p>
      <p><b>Option 2 — File</b><br /><span style={mono}>{challenge.file.url}</span><br />containing exactly: <span style={mono}>{challenge.file.content}</span></p>
      <button className="action-btn" onClick={check} disabled={busy}>{busy ? "Checking…" : "Check verification"}</button>
      {msg && <p style={{ marginTop: 8 }}>{msg}</p>}
    </div>
  );
}

/** Findings with confidence levels + guided manual checks. Tolerates old saved reports. */
export function FindingsPanel({ findings, manual, tier, verified, limitations }: {
  findings?: Finding[]; manual?: ManualCheck[]; tier?: string; verified?: boolean; limitations?: string[];
}) {
  if (!findings) return null;
  return (
    <div className="ember-card audit-card" style={{ padding: 20 }}>
      <div style={{ display: "flex", justifyContent: "space-between", flexWrap: "wrap", gap: 8 }}>
        <strong>Findings ({findings.length}) — {tier === "deep" ? "Deep scan" : "Basic scan"}</strong>
        <span style={{ color: "var(--text-secondary)", fontSize: "0.85rem" }}>{verified ? "Ownership verified" : "Passive checks only"}</span>
      </div>
      {findings.length === 0 && <p style={{ color: "var(--text-secondary)" }}>No findings from automated checks.</p>}
      {findings.map((f) => (
        <details key={f.id} style={{ borderTop: "1px solid rgba(255,255,255,0.08)", padding: "10px 0" }}>
          <summary style={{ cursor: "pointer" }}>
            <b style={{ color: sevColor[f.severity] }}>{f.severity}</b> · {f.title}
            <span style={{ color: "var(--text-secondary)", fontSize: "0.8rem" }}> · {confLabel[f.confidence]}</span>
          </summary>
          <div style={{ padding: "8px 0 0 12px", fontSize: "0.88rem" }}>
            <p><b>Evidence:</b> {f.evidence}</p>
            <p><b>Fix:</b> {f.remediation}</p>
            <p style={{ color: "var(--text-secondary)" }}>{f.cwe} · {f.owasp} · {f.wstg}</p>
          </div>
        </details>
      ))}
      {manual && manual.length > 0 && (
        <>
          <strong style={{ display: "block", marginTop: 18 }}>Guided manual checks ({manual.length})</strong>
          <p style={{ color: "var(--text-secondary)", fontSize: "0.85rem" }}>Automation cannot judge these. A tester should work through them on systems they are authorised to test.</p>
          {manual.map((m) => (
            <details key={m.id} style={{ borderTop: "1px solid rgba(255,255,255,0.08)", padding: "10px 0" }}>
              <summary style={{ cursor: "pointer" }}>{m.title} <span style={{ color: "var(--text-secondary)", fontSize: "0.8rem" }}>· {m.wstg}</span></summary>
              <div style={{ padding: "8px 0 0 12px", fontSize: "0.88rem" }}>
                <p><b>Why flagged:</b> {m.why}</p>
                <p><b>Needs:</b> {m.needs.join(", ")}</p>
                <ol style={{ paddingLeft: 18 }}>{m.steps.map((s, i) => <li key={i}>{s}</li>)}</ol>
              </div>
            </details>
          ))}
        </>
      )}
      {limitations && <ul style={{ color: "var(--text-secondary)", fontSize: "0.8rem", marginTop: 14, paddingLeft: 18 }}>{limitations.map((l, i) => <li key={i}>{l}</li>)}</ul>}
    </div>
  );
}
