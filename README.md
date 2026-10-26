# CyberShield v3.0 - Security Intelligence Platform

CyberShield is a full-featured security auditing platform that analyzes DNS, TLS certificates, HTTP security headers, open ports, cookie flags, and threat surfaces.

## 🚀 Deploying to Vercel

### Method 1: Vercel Drop (Drag & Drop)
1. Go to [vercel.com/drop](https://vercel.com/drop).
2. Drag and drop the `cybershield-vercel.zip` file onto the page.
3. Sign in to your Vercel account and click **Deploy**.

### Method 2: Vercel CLI
If you have Node.js and the Vercel CLI installed:
```bash
npm i -g vercel
vercel deploy
```

### Method 3: GitHub Deployment
1. Push this project to a GitHub repository.
2. In your Vercel Dashboard, click **Add New** > **Project** and import your GitHub repo.
3. Vercel will automatically detect Python, `vercel.json`, and `requirements.txt`.
4. Click **Deploy**.

---

## 💻 Running Locally

```bash
# Install dependencies
pip install -r requirements.txt

# Run the app
python index.py
```
Visit `http://127.0.0.1:5000` in your web browser.
