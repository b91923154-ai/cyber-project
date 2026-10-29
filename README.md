# CYBERSHIELD — Threat Intelligence & Cryptographic Assurance Platform

CyberShield is an enterprise-grade security auditing platform that analyzes DNS resolution, TLS certificates, HTTP security headers, cookie flags, and threat attack surfaces.

Now rebuilt as a modern fullstack **React 19 + Tailwind CSS + Next.js** application with identical aesthetics, rich glassmorphism, dynamic animations, Web Audio SFX, and high-performance serverless telemetry auditing.

---

## 💻 Running Locally

### 1. Install Dependencies
```bash
npm install
```

### 2. Start the Development Server
```bash
npm run dev
```

Visit [http://localhost:3000](http://localhost:3000) in your web browser.

### 3. Production Build & Start
```bash
npm run build
npm start
```

---

## 🚀 Deploying to Vercel

### Method 1: GitHub Deployment (Recommended)
1. Push this project to your GitHub repository.
2. In your [Vercel Dashboard](https://vercel.com), click **Add New** > **Project** and import your repo.
3. Vercel automatically detects Next.js, React, and Tailwind CSS.
4. Click **Deploy**.

### Method 2: Vercel CLI
```bash
npm i -g vercel
vercel
```

---

## 🛡️ Key Features & Architecture

- **React + Tailwind CSS Architecture**: Fully componentized in `app/page.tsx`, `app/layout.tsx`, and `app/globals.css`.
- **Node.js Telemetry API**: Native DNS lookup, TLS socket handshake inspection, redirect verification, and header security audits located in `app/api/audit/route.ts`.
- **Visual Excellence**:
  - Tactical Carbon Obsidian + Luminous Amber Glass (`--ember-card-surface`)
  - Prismatic chromatic dispersion conic borders and micro-animations
  - Ambient gradient flow and interactive cursor sparks canvas
  - Animated SVG threat score gauge and dynamic grade gemstone (`A+`, `A`, `B`, `C`, `D`, `F`)
  - Live hacker terminal telemetry stream
- **Interactive Modals & Drawers**:
  - Remediation Guide with multi-server configuration snippets (Nginx, Apache, Cloudflare, Next.js, Caddy)
  - Slide-over Scan History drawer persisted in `localStorage`
  - SecOps Analyst Portal with custom session state
- **Audio Engine**: Synthesizes tactile clicks, scanning sweeps, success chords, and error tones using the Web Audio API with an instant mute toggle.
- **Export Capabilities**: Raw JSON terminal, Copy JSON, Download `.json` report file, Copy Executive Markdown report, and Print/PDF layout.
