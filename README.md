# 🔍 VulnScan Pro

**AI-Powered Vulnerability Scanner with Automated Fix Generation**

Advanced security scanner with 15+ modules, IDOR detection, Claude Opus 4.6 AI analysis, and automated fix proposals.

---

## 🚀 Quick Start

```bash
# Install
pip install -r requirements.txt

# Basic scan
python -m vulnscan https://target.com

# AI-powered scan (optimized with Claude Opus 4.6)
export ANTHROPIC_API_KEY=your-key
python -m vulnscan https://target.com --ai --ai-limit 10

# Generate AI fix proposals from scan report
python -m vulnscan --fix-report vulnscan_reports/report.json
```

---

## ⚡ Key Features

- **15 Vulnerability Modules** - XSS, SQLi, SSRF, IDOR, Auth bypass, API security, and more
- **IDOR Scanner** - Detects insecure direct object references with sequential ID testing
- **AI Analysis** - Claude Opus 4.6 with parallel processing (3 workers) for 25x faster analysis
- **AI Fix Generator** - Generates actionable fix proposals with code snippets and commands
- **Smart Limit** - `--ai-limit 10` analyzes only top 10 critical findings to save time/tokens
- **Clean Terminal UI** - Professional output optimized for presentations and screenshots

---

## 📋 Commands

### Scan Target
```bash
# Standard scan
python -m vulnscan https://target.com

# With AI verification (fast, limited to 10 critical findings)
python -m vulnscan https://target.com --ai --ai-limit 10

# Full scan with all modules
python -m vulnscan https://target.com --full --ai

# Specific modules only
python -m vulnscan https://target.com --modules idor,xss,injection
```

### Generate Fix Proposals
```bash
# Generate fixes from existing scan report
python -m vulnscan --fix-report vulnscan_reports/target_20260419_032510.json

# Custom output file
python -m vulnscan --fix-report report.json --fix-output fixes.md
```

### Advanced Options
```bash
# With Burp Suite proxy
python -m vulnscan https://target.com --proxy http://127.0.0.1:8080

# Subdomain discovery + scan
python -m vulnscan https://target.com --recon

# Quiet mode
python -m vulnscan https://target.com --quiet
```

---

## 🎯 Modules

| Module | Detects |
|--------|---------|
| `idor` | Insecure Direct Object References (file/document exposure) |
| `xss` | Cross-Site Scripting (reflected, stored, DOM) |
| `injection` | SQL/Command/Template injection |
| `ssrf` | Server-Side Request Forgery |
| `auth` | Authentication bypass, weak credentials |
| `api` | GraphQL, REST API, BOLA vulnerabilities |
| `headers` | Missing security headers (CSP, HSTS, etc.) |
| `cors` | CORS misconfigurations |
| `redirect` | Open redirect vulnerabilities |
| `info` | Information disclosure, sensitive files |
| `ssl` | SSL/TLS issues |
| `waf` | WAF detection & bypass |
| `dirs` | Directory/file discovery |
| `ports` | Port scanning |
| `tech` | Technology fingerprinting |

---

## 🤖 AI Features

### Optimized Performance
- **Model**: Claude Opus 4.6 for maximum accuracy
- **Parallel Processing**: 3 concurrent workers
- **Smart Limiting**: `--ai-limit 10` (default) analyzes only critical findings
- **Speed**: ~10 seconds vs 4+ minutes (25x faster)

### AI Fix Generator
Generates markdown reports with:
- **Fix Summary** - One-line solution
- **Priority & Effort** - Immediate/Short-term/Long-term, Hours/Days/Weeks
- **Code Snippets** - Ready-to-use patches
- **Config Changes** - Server/framework configuration
- **Shell Commands** - Installation/setup commands
- **Verification Steps** - How to test the fix

---

## 📊 Output

### Terminal Output
Clean, presentation-ready output with severity icons:
```
◉ 2 CRITICAL   ◈ 3 HIGH   ◇ 5 MEDIUM   ○ 1 LOW
```

### JSON Reports
Auto-saved to `vulnscan_reports/`:
```json
{
  "scan_info": {
    "target": "https://target.com",
    "total_findings": 11,
    "ai_mode": true
  },
  "findings": [...]
}
```

### Fix Reports
Markdown files with AI-generated fixes:
```markdown
## 1. 🔴 IDOR - Sensitive File Exposure

**Severity:** CRITICAL (CVSS 9.3)
**Priority:** immediate
**Effort:** hours

### Fix Summary
Implement authorization checks before serving files

### Code Snippets
...
```

---

## 🎓 Hackathon Use Case

1. **Scan target** → Get JSON report with vulnerabilities
2. **Generate fixes** → AI creates actionable remediation steps
3. **Present findings** → Clean terminal output for screenshots
4. **Show impact** → CVSS scores, severity levels, PoC commands

---

## ⚙️ Options

```
--ai              Enable AI analysis (Claude Opus 4.6)
--ai-limit N      Analyze only top N findings (default: 10)
--ai-key KEY      Anthropic API key
--fix-report FILE Generate fix proposals from JSON report
--fix-output FILE Output file for fix report (default: fixes_TIMESTAMP.md)
--modules LIST    Comma-separated module list
--full            Run all modules
--recon           Subdomain discovery
--proxy URL       Route through proxy (Burp Suite)
--quiet           Minimal output
```

---

## 📜 Legal

For authorized security testing only. Obtain proper authorization before scanning any system.

## 📄 License

MIT
