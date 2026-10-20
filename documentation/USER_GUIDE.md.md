\# CORSHeaderForge Pro \- User Guide & DevSecOps Integration Manual

\#\# 1\. Web Studio Quickstart

1\. Open \`source-code/index.html\` in any modern web browser.  
2\. Select an industry preset from the top dropdown:  
   \- \*\*Enterprise Zero-Trust Banking API (A+)\*\*: Exact allowed origins with credentials, HSTS Preload (1 year), CSP Level 3 with nonces, frame-ancestors 'none', COOP same-origin.  
   \- \*\*Production SaaS CDN & Static SPA (A+)\*\*: Hardened static asset delivery with same-origin embedding and HSTS.  
   \- \*\*Hazardous Wildcard CORS & XSS Exposure (F)\*\*: Demonstrates the fatal wildcard credentials bug and unconstrained CSP.  
3\. Review the \*\*10-Point Zero-Trust Web Security Scorecard\*\* to inspect compliance and security health.  
4\. Toggle security controls (Allow Credentials, HSTS Preload, nosniff, Clickjacking Block, CSP Level 3, Cross-Origin Isolation).  
5\. Switch between server synthesizer tabs:  
   \- \*\*Nginx (\`nginx.conf\`)\*\*: Copy directly into your server block.  
   \- \*\*Apache (\`.htaccess\`)\*\*: Drop into your document root.  
   \- \*\*Cloudflare Workers\*\*: Deploy to Cloudflare edge serverless workers.  
   \- \*\*Caddy (\`Caddyfile\`)\*\*: Add to your Caddy configuration.  
   \- \*\*AWS CloudFront Function\*\*: Deploy as a Viewer Response function.  
   \- \*\*Next.js (\`next.config.js\`)\*\*: Add to your Next.js application root.

\---

\#\# 2\. DevSecOps CLI Tool (\`corsheaderforge-cli.py\`)

The standalone Python CLI tool requires zero external dependencies and runs on Python 3.8+.

\#\#\# 2.1 Linting CORS Profiles for Structural Bugs  
\`\`\`bash  
python3 build/corsheaderforge-cli.py lint \--preset presets/enterprise-zero-trust-banking-api.json  
\`\`\`  
Output:  
\`\`\`  
\[LINT PASSED\] CORS configuration is structurally secure (0 warnings).  
\`\`\`

\#\#\# 2.2 Running CI/CD Pipeline Security Audits  
\`\`\`bash  
\# Clean production profile \-\> Exits code 0  
python3 build/corsheaderforge-cli.py audit \--preset presets/enterprise-zero-trust-banking-api.json \--strict

\# Insecure profile \-\> Exits code 1 (Pipeline Fails)  
python3 build/corsheaderforge-cli.py audit \--preset presets/hazardous-wildcard-cors-xss.json \--strict  
\`\`\`

\#\#\# 2.3 Synthesizing Caddyfile or JSON Configurations  
\`\`\`bash  
python3 build/corsheaderforge-cli.py synthesize \--preset presets/enterprise-zero-trust-banking-api.json \-f caddy  
\`\`\`

\---

\#\# 3\. GitHub Actions CI/CD Pipeline Template

Add this workflow to your infrastructure or backend repository (\`.github/workflows/security-headers-gate.yml\`) to automatically validate CORS profiles and security headers before merging pull requests:

\`\`\`yaml  
name: Web Security Headers & CORS CI/CD Gate

on:  
  pull\_request:  
    paths:  
      \- 'configs/security/\*\*'  
      \- 'nginx/\*\*'  
      \- 'next.config.js'

jobs:  
  cors-audit:  
    runs-on: ubuntu-latest  
    steps:  
      \- name: Checkout Code  
        uses: actions/checkout@v4

      \- name: Set up Python  
        uses: actions/setup-python@v5  
        with:  
          python-version: '3.11'

      \- name: Lint CORS & Origin Integrity  
        run: |  
          python3 build/corsheaderforge-cli.py lint \--preset presets/enterprise-zero-trust-banking-api.json

      \- name: Audit Zero-Trust Web Security (Strict Gate)  
        run: |  
          python3 build/corsheaderforge-cli.py audit \--preset presets/enterprise-zero-trust-banking-api.json \--strict  
\`\`\`  
