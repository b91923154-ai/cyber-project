"use client";

import { useState } from "react";
import { useAuth } from "./context/AuthContext";

interface RemediationGuideModalProps {
  playSound: (type: "click" | "scanStart" | "success" | "error") => void;
}
const REMEDIATION_DB: Record<
  string,
  {
    name: string;
    desc: string;
    nginx: string;
    apache: string;
    cloudflare: string;
    nextjs: string;
    caddy: string;
  }
> = {
  "Strict-Transport-Security": {
    name: "Strict-Transport-Security (HSTS)",
    desc: "Enforces browsers to exclusively access the domain over HTTPS for 1 year, including subdomains.",
    nginx: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
    apache: 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
    cloudflare:
      "// In Cloudflare Dashboard -> SSL/TLS -> Edge Certificates -> Enable HSTS\n// Max-Age: 12 months, Include Subdomains: ON, Preload: ON",
    nextjs:
      '// next.config.js\nmodule.exports = {\n  async headers() {\n    return [{\n      source: "/:path*",\n      headers: [{ key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains; preload" }]\n    }];\n  }\n};',
    caddy: 'header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
  },

  "Content-Security-Policy": {
    name: "Content-Security-Policy (CSP)",
    desc: "Mitigates Cross-Site Scripting (XSS) and data injection by declaring approved content sources.",
    nginx:
      "add_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com;\" always;",
    apache:
      "Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self';\"",
    cloudflare:
      "// Add Transform Rule -> Modify Response Header\n// Header: Content-Security-Policy\n// Value: default-src 'self'; script-src 'self';",
    nextjs:
      '// next.config.js\nheaders: [{ key: "Content-Security-Policy", value: "default-src \'self\'; script-src \'self\';" }]',
    caddy: 'header Content-Security-Policy "default-src \'self\'; script-src \'self\';"',
  },

  "X-Frame-Options": {
    name: "X-Frame-Options",
    desc: "Defends against clickjacking by refusing iframe embedding across external origins.",
    nginx: 'add_header X-Frame-Options "SAMEORIGIN" always;',
    apache: 'Header always set X-Frame-Options "SAMEORIGIN"',
    cloudflare: "// Cloudflare Transform Rule -> Set X-Frame-Options to SAMEORIGIN",
    nextjs: 'headers: [{ key: "X-Frame-Options", value: "SAMEORIGIN" }]',
    caddy: 'header X-Frame-Options "SAMEORIGIN"',
  },

  "X-Content-Type-Options": {
    name: "X-Content-Type-Options",
    desc: "Prevents browser MIME-type sniffing vulnerabilities by enforcing declared MIME types.",
    nginx: 'add_header X-Content-Type-Options "nosniff" always;',
    apache: 'Header always set X-Content-Type-Options "nosniff"',
    cloudflare: "// Cloudflare Transform Rule -> Set X-Content-Type-Options to nosniff",
    nextjs: 'headers: [{ key: "X-Content-Type-Options", value: "nosniff" }]',
    caddy: 'header X-Content-Type-Options "nosniff"',
  },

  "Referrer-Policy": {
    name: "Referrer-Policy",
    desc: "Restricts referral info sent when following outbound hyperlinks, preventing sensitive URL leaks.",
    nginx: 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
    apache: 'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
    cloudflare:
      "// Cloudflare Transform Rule -> Set Referrer-Policy to strict-origin-when-cross-origin",
    nextjs:
      'headers: [{ key: "Referrer-Policy", value: "strict-origin-when-cross-origin" }]',
    caddy: 'header Referrer-Policy "strict-origin-when-cross-origin"',
  },

  "Permissions-Policy": {
    name: "Permissions-Policy",
    desc: "Restricts browser feature APIs such as camera, microphone, geolocation, and payment requests.",
    nginx:
      'add_header Permissions-Policy "geolocation=(), camera=(), microphone=()" always;',
    apache:
      'Header always set Permissions-Policy "geolocation=(), camera=(), microphone=()"',
    cloudflare:
      "// Cloudflare Transform Rule -> Set Permissions-Policy to geolocation=(), camera=(), microphone=()",
    nextjs:
      'headers: [{ key: "Permissions-Policy", value: "geolocation=(), camera=(), microphone=()" }]',
    caddy:
      'header Permissions-Policy "geolocation=(), camera=(), microphone=()"',
  },
};


export default function RemediationGuideModal({
  playSound,
}: RemediationGuideModalProps) {
  const { remedModal, setRemedModal } = useAuth();
  const [remedCopied, setRemedCopied] = useState(false);


}
