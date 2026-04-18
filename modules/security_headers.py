"""
Module: Security Headers Analyzer
Analyzes HTTP headers for security issues
- Missing security headers
- Misconfigured headers
- Insecure cookie flags
- Version disclosure
"""

import re
from typing import List, Dict, Optional
from urllib.parse import urlparse

from ..core.finding import Finding
from ..core.http_client import AdaptiveHTTPClient


class SecurityHeadersScanner:
    """Analyze response headers for security issues"""

    def __init__(self, client: AdaptiveHTTPClient):
        self.client = client
        self.findings: List[Finding] = []

    def _analyze_csp(self, csp: str, url: str) -> List[Finding]:
        """Analyze Content-Security-Policy for weaknesses"""
        findings = []
        csp_lower = csp.lower()

        # Dangerous CSP directives
        issues = []

        if "'unsafe-inline'" in csp_lower:
            issues.append(("unsafe-inline allows inline scripts, defeating XSS protection", "HIGH"))
        if "'unsafe-eval'" in csp_lower:
            issues.append(("unsafe-eval allows eval(), enabling script injection", "HIGH"))
        if "data:" in csp_lower and "script-src" in csp_lower:
            issues.append(("data: URIs in script-src can bypass CSP", "MEDIUM"))
        if "*" in csp:
            issues.append(("Wildcard (*) in CSP allows any source", "MEDIUM"))
        if "http:" in csp_lower:
            issues.append(("CSP allows HTTP sources, enabling MITM attacks", "MEDIUM"))

        # Check for missing directives
        important_directives = ['default-src', 'script-src', 'object-src', 'base-uri']
        missing = [d for d in important_directives if d not in csp_lower]
        if missing:
            issues.append((f"Missing important CSP directives: {', '.join(missing)}", "LOW"))

        for issue, severity in issues:
            findings.append(Finding(
                vuln_class="Weak Content-Security-Policy",
                severity=severity,
                url=url,
                description=f"CSP vulnerability: {issue}",
                evidence=csp[:200],
                remediation=[
                    "Remove 'unsafe-inline' and 'unsafe-eval'",
                    "Use nonces or hashes for inline scripts",
                    "Avoid wildcards in CSP",
                    "Ensure all directives are explicitly set",
                ],
                tags=["headers", "csp"],
            ))

        return findings

    def _analyze_cors(self, headers: Dict, url: str) -> List[Finding]:
        """Analyze CORS headers for misconfigurations"""
        findings = []

        acao = headers.get('Access-Control-Allow-Origin', '')
        acac = headers.get('Access-Control-Allow-Credentials', '').lower()

        if acao == '*':
            if acac == 'true':
                findings.append(Finding(
                    vuln_class="CORS Misconfiguration",
                    severity="CRITICAL",
                    cvss=9.0,
                    url=url,
                    description="CORS allows any origin (*) with credentials. Complete auth bypass possible.",
                    evidence=f"Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {acac}",
                    remediation=[
                        "Never use '*' with credentials",
                        "Whitelist specific trusted origins",
                        "Validate Origin header server-side",
                    ],
                    tags=["cors", "authentication"],
                ))
            else:
                findings.append(Finding(
                    vuln_class="Permissive CORS",
                    severity="LOW",
                    url=url,
                    description="CORS allows any origin. May expose public data to any site.",
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    remediation=[
                        "Restrict to specific trusted origins if sensitive data is returned",
                    ],
                    tags=["cors"],
                ))

        # Check if origin is reflected (common misconfiguration)
        # This would need to be tested with actual origin injection

        return findings

    def _check_missing_headers(self, headers: Dict, url: str, is_https: bool) -> List[Finding]:
        """Check for missing security headers"""
        findings = []

        # Define expected headers and their properties
        expected = {
            'X-Content-Type-Options': {
                'description': 'Prevents MIME type sniffing',
                'severity': 'MEDIUM',
                'cvss': 5.0,
                'expected': 'nosniff',
            },
            'X-Frame-Options': {
                'description': 'Prevents clickjacking',
                'severity': 'MEDIUM',
                'cvss': 5.5,
                'expected': 'DENY or SAMEORIGIN',
            },
            'Strict-Transport-Security': {
                'description': 'Enforces HTTPS connections',
                'severity': 'HIGH' if is_https else 'LOW',
                'cvss': 7.0 if is_https else 3.0,
                'expected': 'max-age=31536000; includeSubDomains',
                'https_only': True,
            },
            'Content-Security-Policy': {
                'description': 'Prevents XSS and data injection',
                'severity': 'MEDIUM',
                'cvss': 6.0,
                'expected': "default-src 'self'",
            },
            'Referrer-Policy': {
                'description': 'Controls referrer information leakage',
                'severity': 'LOW',
                'cvss': 3.0,
                'expected': 'strict-origin-when-cross-origin',
            },
            'Permissions-Policy': {
                'description': 'Disables unused browser features',
                'severity': 'LOW',
                'cvss': 2.0,
                'expected': 'geolocation=(), microphone=()',
            },
            'X-XSS-Protection': {
                'description': 'Legacy XSS filter (deprecated but still useful)',
                'severity': 'INFO',
                'cvss': 1.0,
                'expected': '1; mode=block',
            },
        }

        headers_lower = {k.lower(): v for k, v in headers.items()}
        missing = []

        for header, props in expected.items():
            h_lower = header.lower()

            # Skip HSTS for HTTP sites
            if props.get('https_only') and not is_https:
                continue

            # Skip low-severity headers to reduce noise
            if props['severity'] in ['LOW', 'INFO']:
                continue

            if h_lower not in headers_lower:
                missing.append({
                    'header': header,
                    'description': props['description'],
                    'severity': props['severity'],
                    'cvss': props['cvss'],
                    'expected': props['expected'],
                })

        if missing:
            # Only report if we have HIGH severity missing headers
            high_missing = [m for m in missing if m['severity'] == 'HIGH']
            medium_missing = [m for m in missing if m['severity'] == 'MEDIUM']

            # Only report if we have at least one HIGH or MEDIUM header missing
            if high_missing or medium_missing:
                findings.append(Finding(
                    vuln_class="Missing Security Headers",
                    severity="HIGH" if high_missing else "MEDIUM",
                    cvss=max(m['cvss'] for m in missing),
                    url=url,
                    description=f"{len(missing)} important security header(s) missing: {', '.join([m['header'] for m in missing])}",
                    evidence={"missing_headers": [m['header'] for m in missing]},
                    remediation=[f"Add {m['header']}: {m['expected']}" for m in missing[:5]],
                    extra={"missing_details": missing},
                    tags=["headers", "misconfiguration"],
                ))

        return findings

    def _check_cookie_security(self, headers: Dict, url: str, is_https: bool) -> List[Finding]:
        """Check for insecure cookie configurations"""
        findings = []

        set_cookies = headers.get('Set-Cookie', '')
        if isinstance(set_cookies, list):
            cookies = set_cookies
        else:
            cookies = [set_cookies] if set_cookies else []

        for cookie in cookies:
            if not cookie:
                continue

            cookie_lower = cookie.lower()
            name = cookie.split('=')[0].strip()
            issues = []

            # Check for sensitive session cookies
            is_session = any(x in name.lower() for x in ['session', 'auth', 'token', 'jwt', 'sid', 'user'])

            if is_session or len(cookie) > 50:  # Likely contains meaningful data
                if 'httponly' not in cookie_lower:
                    issues.append(("Missing HttpOnly flag", "Accessible via JavaScript, XSS risk"))
                if is_https and 'secure' not in cookie_lower:
                    issues.append(("Missing Secure flag", "Can be sent over HTTP, MITM risk"))
                if 'samesite' not in cookie_lower:
                    issues.append(("Missing SameSite attribute", "CSRF vulnerability"))
                elif 'samesite=none' in cookie_lower and 'secure' not in cookie_lower:
                    issues.append(("SameSite=None without Secure", "Invalid configuration"))

            if issues:
                findings.append(Finding(
                    vuln_class="Insecure Cookie Configuration",
                    severity="MEDIUM" if is_session else "LOW",
                    cvss=5.5 if is_session else 3.0,
                    url=url,
                    description=f"Cookie '{name}' has security issues: {'; '.join([i[0] for i in issues])}",
                    evidence=cookie[:100],
                    remediation=[
                        "Set HttpOnly flag on session cookies",
                        "Set Secure flag on all cookies for HTTPS sites",
                        "Set SameSite=Strict or Lax for CSRF protection",
                    ],
                    tags=["cookies", "session"],
                ))

        return findings

    def _check_version_disclosure(self, headers: Dict, url: str) -> List[Finding]:
        """Check for version information in headers - only report HIGH value disclosures"""
        findings = []

        # Only check headers that reveal meaningful version info
        disclosure_headers = ['X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']

        for header in disclosure_headers:
            value = headers.get(header, '')
            if value:
                # Check if it contains version info
                has_version = bool(re.search(r'\d+\.\d+', value))

                if has_version:
                    findings.append(Finding(
                        vuln_class="Server Version Disclosure",
                        severity="LOW",
                        cvss=3.5,
                        url=url,
                        description=f"Header '{header}' reveals software version: {value}",
                        evidence=f"{header}: {value}",
                        remediation=[
                            f"Remove or obfuscate {header} header",
                            "expose_php = Off (PHP)",
                        ],
                        tags=["information-disclosure", "fingerprinting"],
                    ))

        return findings

    def scan(self, url: str) -> List[Finding]:
        """Run full security headers scan"""
        self.findings = []

        parsed = urlparse(url)
        is_https = parsed.scheme == 'https'

        try:
            resp = self.client.get(url, timeout=10)
            headers = dict(resp.headers)

            # Check for missing headers
            self.findings.extend(self._check_missing_headers(headers, url, is_https))

            # Check CORS
            self.findings.extend(self._analyze_cors(headers, url))

            # Check CSP if present
            csp = headers.get('Content-Security-Policy', '')
            if csp:
                self.findings.extend(self._analyze_csp(csp, url))

            # Check cookies
            self.findings.extend(self._check_cookie_security(headers, url, is_https))

            # Check version disclosure
            self.findings.extend(self._check_version_disclosure(headers, url))

        except Exception as e:
            pass

        return self.findings
