# VulnVision AI

**GitHub + Website Security Auditor with AI-Powered Fix Recommendations**

A lightweight vulnerability scanner dashboard. Enter a website URL and/or GitHub
repo link — the backend checks for missing security headers, basic XSS surface
area, and outdated/vulnerable dependencies, then uses an LLM (via OpenRouter)
to explain each finding in plain English, generate fixes, simulate an attack
chain, and write an executive summary. Download the whole thing as a PDF report.

## Stack

- **Backend**: Node.js + Express
- **Frontend**: React + Vite
- **AI**: OpenRouter API (free-tier-friendly; explanations, fixes, attack simulation, executive summary)
- **Vulnerability data**: OSV.dev (Open Source Vulnerabilities database)
- **PDF**: pdf-lib
- **Diagrams**: Mermaid.js (attack simulation sequence diagrams)

## Project Structure

```
vulnvision/
├── backend/
│   ├── src/
│   │   ├── server.js              # Express entry point
│   │   ├── routes/scan.js         # /api/scan and /api/report/:id
│   │   ├── services/
│   │   │   ├── websiteScanner.js  # security headers + XSS surface heuristics
│   │   │   ├── githubScanner.js   # dependency check via GitHub API + OSV.dev
│   │   │   ├── aiService.js       # OpenRouter LLM: explanations, fixes, attack sim, summary
│   │   │   └── reportService.js   # PDF generation (pdf-lib)
│   │   └── utils/riskScore.js     # risk score calculation
│   ├── .env.example
│   └── package.json
└── frontend/
    ├── src/
    │   ├── App.jsx                 # main dashboard
    │   ├── index.css               # design tokens + styles
    │   └── components/
    │       ├── RiskGauge.jsx       # risk score gauge (signature visual)
    │       ├── FindingCard.jsx     # individual vulnerability card
    │       └── AttackSimulation.jsx # narrative + Mermaid diagram
    └── package.json
```

## Setup

### 1. Backend

```bash
cd backend
npm install
cp .env.example .env
```

Edit `.env`:

```
PORT=5000
OPENROUTER_API_KEY=sk-or-...                            # required for AI features (explanations, fixes, attack sim, summary)
OPENROUTER_MODEL=meta-llama/llama-3.1-8b-instruct:free  # any model from https://openrouter.ai/models?max_price=0
GITHUB_TOKEN=ghp_...                                    # optional, raises GitHub API rate limits
```

Start the backend:

```bash
npm start
```

Backend runs on `http://localhost:5000`.

> **Note**: Without `OPENROUTER_API_KEY`, the scanner still works — header
> checks, XSS heuristics, and dependency vulnerability lookups all run fine.
> You just won't get plain-English explanations, fix suggestions, attack
> simulations, or the executive summary. The UI shows a banner when AI
> features are disabled.
>
> **Free OpenRouter models**: sign up at https://openrouter.ai (no credit
> card required for free models), generate an API key at
> https://openrouter.ai/keys, and pick any model tagged `:free` from
> https://openrouter.ai/models?max_price=0. Note that free models have lower
> rate limits and may occasionally return malformed JSON for the
> explanation/fix step — the code handles this gracefully by falling back to
> generic text if parsing fails.

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend runs on `http://localhost:3000` and proxies `/api/*` requests to the
backend on port 5000.

## How It Works

1. **Website scan** (`websiteScanner.js`): fetches the target URL, checks
   response headers against a checklist (CSP, HSTS, X-Frame-Options,
   X-Content-Type-Options, Referrer-Policy, Permissions-Policy), and does
   lightweight HTML analysis for form/input surface area, inline scripts, and
   reflected query parameters (heuristic XSS signal — not a full scanner).

2. **Repo scan** (`githubScanner.js`): pulls `package.json` and/or
   `requirements.txt` from the repo's default branch via the GitHub API, then
   batch-queries OSV.dev for known CVEs affecting those exact dependency
   versions.

3. **Risk score** (`riskScore.js`): combines weighted findings from both scans
   into a 0–100 score with Low/Medium/High/Critical bands, using a soft-cap
   exponential curve so a few critical issues push the score high quickly.

4. **AI layer** (`aiService.js`): sends all findings to an LLM via OpenRouter
   in one batch to get plain-English explanations + concrete fixes per
   finding, generates an attack simulation (narrative + Mermaid sequence
   diagram) from the top findings, and writes a 3–4 sentence executive
   summary.

5. **PDF report** (`reportService.js`): assembles everything — risk score,
   summary, findings with explanations/fixes, attack narrative — into a
   downloadable PDF.

## Demo Tips

- Use a deliberately misconfigured site/repo for predictable demo results
  (e.g. a test repo with an old `lodash` or `express` version in
  `package.json`, or any site missing CSP/HSTS headers — most sites are
  missing at least one).
- If GitHub API rate limits hit during the demo, add a `GITHUB_TOKEN` (a
  plain personal access token with no scopes works for public repo reads).
- The Mermaid attack diagram and AI explanations require
  `OPENROUTER_API_KEY` — make sure it's set before the demo for the full
  "AI-powered" experience. Free models can occasionally return malformed
  JSON; if explanations look generic ("Could not generate explanation"),
  try a different `:free` model or re-run the scan.

## Extending Further

- Swap the in-memory `lastScans` map in `routes/scan.js` for Redis/a database
  to support multiple concurrent users / scan history.
- Add authenticated scanning (private repos) by passing a user-supplied
  `GITHUB_TOKEN` per request instead of a global env var.
- Expand `websiteScanner.js` with more checks (cookie flags, CORS
  misconfiguration, TLS version/cipher checks via a TLS library).
- Add a real crawler (Puppeteer) for multi-page scans instead of single-page.
