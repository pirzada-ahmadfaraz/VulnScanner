# VulnScan Pro

**Adaptive Vulnerability Scanner with AI-Powered Analysis**

A professional-grade security scanning tool with 14+ vulnerability modules, subdomain enumeration, and Claude AI integration for intelligent vulnerability verification and discovery.

## Features

- **14 Vulnerability Scanning Modules** - Comprehensive coverage of OWASP Top 10 and beyond
- **AI-Powered Analysis** - Uses Claude API to verify findings and discover additional vulnerabilities
- **Subdomain Enumeration** - Discovers attack surface via crt.sh, HackerTarget, and DNS brute force
- **Burp Suite Integration** - Route all traffic through proxy for traffic mapping
- **Real-time Terminal UI** - Professional hacker-style output with live activity
- **Auto-save Reports** - JSON reports with full details saved automatically

## Installation

```bash
# Install dependencies
pip install requests anthropic beautifulsoup4

# Or using requirements.txt
pip install -r requirements.txt
```

## Usage

### Basic Scan
```bash
# From the cloned repo root
python -m vulnscan https://target.com

# Direct script entry also works
python scanner.py https://target.com
```

### With Burp Suite Proxy
```bash
python -m vulnscan https://target.com --proxy http://127.0.0.1:8080
```

### Subdomain Discovery + Scan
```bash
python -m vulnscan https://target.com --recon
```

### Full Scan (All Modules)
```bash
python -m vulnscan https://target.com --full
```

### AI-Powered Verification
```bash
# Set API key as environment variable
export ANTHROPIC_API_KEY=your-api-key

# Run with AI verification
python -m vulnscan https://target.com --ai

# Or pass key directly
python -m vulnscan https://target.com --ai --ai-key your-api-key
```

### Specific Modules Only
```bash
python -m vulnscan https://target.com --modules tech,xss,injection,ssrf
```

## Available Modules (14)

| Module | Description |
|--------|-------------|
| `tech` | Technology fingerprinting & CVE detection |
| `headers` | Security headers analysis |
| `info` | Information disclosure & sensitive files |
| `auth` | Authentication security testing |
| `injection` | SQL/Command/Template injection |
| `xss` | Cross-site scripting detection |
| `ssrf` | Server-side request forgery |
| `redirect` | Open redirect vulnerabilities |
| `ssl` | SSL/TLS certificate & protocol analysis |
| `cors` | CORS misconfiguration detection |
| `waf` | WAF detection & bypass testing |
| `api` | API security (GraphQL, REST, BOLA) |
| `dirs` | Directory & file discovery |
| `ports` | Port scanning & service detection |

## AI Security Engine

When `--ai` flag is enabled, the scanner uses Claude API to:

1. **Verify Findings** - Re-tests each vulnerability and uses AI to determine if it's a true positive or false positive
2. **Discover Vulnerabilities** - Analyzes response data to find additional issues that automated scanners miss
3. **Business Logic Analysis** - Identifies IDOR, race conditions, and workflow bypasses
4. **Generate Payloads** - Creates context-aware payloads based on detected tech stack and WAF

### AI Analysis Output

```
═══════════════════════════════════════════════════════════════════════════════
   █████╗ ██╗    ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗
  ██╔══██╗██║    ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝
  ███████║██║    ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝
  ██╔══██║██║    ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝
  ██║  ██║██║    ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║
  ╚═╝  ╚═╝╚═╝    ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝
═══════════════════════════════════════════════════════════════════════════════

  AI ANALYSIS COMPLETE
────────────────────────────────────────────────────────────────────────────────
  ✓ Verified: 8 findings
  + Discovered: 3 new issues
  ✗ Rejected: 5 false positives
────────────────────────────────────────────────────────────────────────────────
```

## Report Format

Reports are auto-saved to `vulnscan_reports/` directory in JSON format:

```json
{
  "scan_info": {
    "target": "https://example.com",
    "scan_date": "2024-01-15T10:30:00",
    "total_findings": 12,
    "ai_mode": true
  },
  "ai_analysis": {
    "verified_count": 8,
    "discovered_count": 3,
    "rejected_count": 5,
    "rejected_findings": [...]
  },
  "findings": [
    {
      "vuln_class": "SQL Injection",
      "severity": "CRITICAL",
      "cvss": 9.8,
      "url": "https://example.com/api/users",
      "parameter": "id",
      "description": "...",
      "evidence": {...},
      "remediation": [...]
    }
  ]
}
```

## Command Line Options

```
usage: vulnscan [-h] [--proxy PROXY] [--modules MODULES] [--timeout TIMEOUT]
                [--output OUTPUT] [--quiet] [--recon] [--full] [--ai]
                [--ai-key AI_KEY]
                target

Options:
  target                Target URL to scan
  --proxy, -p           Proxy URL (e.g., http://127.0.0.1:8080)
  --modules, -m         Comma-separated list of modules
  --timeout, -t         Request timeout in seconds (default: 15)
  --output, -o          Output file for JSON report
  --quiet, -q           Quiet mode (minimal output)
  --recon, -r           Discover subdomains before scanning
  --full, -f            Run all modules including heavy scans
  --ai, -a              Enable AI-powered verification
  --ai-key              Anthropic API key
```

## Exit Codes

- `0` - No critical or high findings
- `1` - High severity findings detected
- `2` - Critical severity findings detected
- `130` - Scan interrupted by user

## Legal Disclaimer

This tool is intended for authorized security testing only. Always obtain proper authorization before scanning any system. The authors are not responsible for any misuse or damage caused by this tool.

## License

MIT License
