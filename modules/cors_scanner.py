"""
CORS Misconfiguration Scanner
- Origin reflection detection
- Null origin bypass
- Subdomain wildcard issues
- Credential exposure
- Pre-flight bypass techniques
"""

from typing import List, Dict, Optional
from urllib.parse import urlparse

from ..core.finding import Finding
from ..core.http_client import AdaptiveHTTPClient


class CORSScanner:
    """CORS misconfiguration detection"""

    def __init__(self, client: AdaptiveHTTPClient):
        self.client = client
        self.findings: List[Finding] = []

    def scan(self, base_url: str, callback=None) -> List[Finding]:
        """
        Scan for CORS misconfigurations

        Args:
            base_url: Target URL
            callback: Progress callback

        Returns:
            List of findings
        """
        self.findings = []
        parsed = urlparse(base_url)
        target_domain = parsed.netloc

        if callback:
            callback("info", f"Testing CORS configuration on {target_domain}")

        # Test various CORS attack vectors
        self._test_origin_reflection(base_url, target_domain, callback)
        self._test_null_origin(base_url, callback)
        self._test_subdomain_bypass(base_url, target_domain, callback)
        self._test_prefix_suffix_bypass(base_url, target_domain, callback)
        self._test_special_chars_bypass(base_url, target_domain, callback)

        return self.findings

    def _test_origin_reflection(self, base_url: str, target_domain: str, callback=None):
        """Test if arbitrary origins are reflected"""
        if callback:
            callback("probe", "Testing origin reflection")

        evil_origins = [
            "https://evil.com",
            "https://attacker.com",
            f"https://{target_domain}.evil.com",
            f"https://evil.{target_domain}",
        ]

        for origin in evil_origins:
            try:
                headers = {"Origin": origin}
                resp = self.client.get(base_url, headers=headers, timeout=10)

                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

                if acao == origin:
                    severity = "HIGH" if acac == "true" else "MEDIUM"
                    cvss = 8.0 if acac == "true" else 5.5

                    self.findings.append(Finding(
                        vuln_class="CORS Origin Reflection",
                        severity=severity,
                        cvss=cvss,
                        url=base_url,
                        description=f"Server reflects arbitrary origin in ACAO header. "
                                   f"Tested origin: {origin}" +
                                   (" WITH credentials allowed!" if acac == "true" else ""),
                        evidence={
                            "tested_origin": origin,
                            "acao_header": acao,
                            "acac_header": acac,
                        },
                        request=f"GET {base_url}\nOrigin: {origin}",
                        response=f"Access-Control-Allow-Origin: {acao}\n"
                                f"Access-Control-Allow-Credentials: {acac}",
                        remediation=[
                            "Implement strict origin whitelist",
                            "Never reflect arbitrary origins",
                            "Be cautious with Access-Control-Allow-Credentials",
                            "Use specific origins instead of wildcards",
                        ],
                        tags=["cors", "misconfiguration"],
                    ))
                    return  # Found one, no need to test more

            except Exception:
                continue

    def _test_null_origin(self, base_url: str, callback=None):
        """Test if null origin is accepted"""
        if callback:
            callback("probe", "Testing null origin")

        try:
            headers = {"Origin": "null"}
            resp = self.client.get(base_url, headers=headers, timeout=10)

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

            if acao == "null":
                severity = "HIGH" if acac == "true" else "MEDIUM"
                self.findings.append(Finding(
                    vuln_class="CORS Null Origin Accepted",
                    severity=severity,
                    cvss=7.5 if acac == "true" else 5.0,
                    url=base_url,
                    description="Server accepts 'null' origin which can be exploited via "
                               "sandboxed iframes or local file requests." +
                               (" WITH credentials allowed!" if acac == "true" else ""),
                    evidence={
                        "acao_header": acao,
                        "acac_header": acac,
                    },
                    request=f"GET {base_url}\nOrigin: null",
                    response=f"Access-Control-Allow-Origin: {acao}",
                    remediation=[
                        "Do not accept 'null' as a valid origin",
                        "Implement strict origin validation",
                    ],
                    tags=["cors", "null-origin"],
                ))

        except Exception:
            pass

    def _test_subdomain_bypass(self, base_url: str, target_domain: str, callback=None):
        """Test subdomain-based CORS bypass - only report EVIL subdomains"""
        if callback:
            callback("probe", "Testing subdomain bypass")

        # Only test attacker-controlled subdomain patterns
        bypass_origins = [
            f"https://evil.{target_domain}",
            f"https://attacker.{target_domain}",
        ]

        for origin in bypass_origins:
            try:
                headers = {"Origin": origin}
                resp = self.client.get(base_url, headers=headers, timeout=10)

                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

                # Only report if it accepts attacker-controlled subdomain AND has credentials
                if acao == origin and acac == "true":
                    self.findings.append(Finding(
                        vuln_class="CORS Subdomain Wildcard",
                        severity="HIGH",
                        cvss=7.5,
                        url=base_url,
                        description=f"Server accepts ANY subdomains as valid origins WITH credentials. "
                                   f"If attacker controls any subdomain via XSS or subdomain takeover, they can steal user data.",
                        evidence={
                            "tested_origin": origin,
                            "acao_header": acao,
                            "acac_header": acac,
                        },
                        remediation=[
                            "Explicitly whitelist trusted subdomains only",
                            "Do not use wildcard subdomain matching with credentials",
                            "Audit all subdomains for security",
                        ],
                        tags=["cors", "subdomain"],
                    ))
                    return

            except Exception:
                continue

    def _test_prefix_suffix_bypass(self, base_url: str, target_domain: str, callback=None):
        """Test prefix/suffix bypass techniques"""
        if callback:
            callback("probe", "Testing prefix/suffix bypass")

        # Extract base domain parts
        parts = target_domain.split(".")
        base_name = parts[0] if len(parts) > 0 else target_domain

        bypass_origins = [
            f"https://{target_domain}.evil.com",  # Suffix
            f"https://evil{target_domain}",  # Prefix without dot
            f"https://{base_name}evil.com",  # Similar domain
            f"https://evil-{target_domain}",  # Hyphen prefix
        ]

        for origin in bypass_origins:
            try:
                headers = {"Origin": origin}
                resp = self.client.get(base_url, headers=headers, timeout=10)

                acao = resp.headers.get("Access-Control-Allow-Origin", "")

                if acao == origin:
                    self.findings.append(Finding(
                        vuln_class="CORS Origin Validation Bypass",
                        severity="HIGH",
                        cvss=7.0,
                        url=base_url,
                        description=f"Server origin validation can be bypassed using "
                                   f"prefix/suffix techniques. Origin {origin} was accepted.",
                        evidence={
                            "bypass_origin": origin,
                            "acao_header": acao,
                        },
                        remediation=[
                            "Use exact string matching for origins",
                            "Parse origins properly before comparison",
                            "Avoid regex-based origin validation",
                        ],
                        tags=["cors", "bypass"],
                    ))
                    return

            except Exception:
                continue

    def _test_special_chars_bypass(self, base_url: str, target_domain: str, callback=None):
        """Test special character bypass"""
        if callback:
            callback("probe", "Testing special character bypass")

        special_origins = [
            f"https://{target_domain}%60.evil.com",  # Backtick
            f"https://{target_domain}`.evil.com",
            f"https://{target_domain}%00.evil.com",  # Null byte
            f"https://{target_domain}/.evil.com",  # Path separator
        ]

        for origin in special_origins:
            try:
                headers = {"Origin": origin}
                resp = self.client.get(base_url, headers=headers, timeout=10)

                acao = resp.headers.get("Access-Control-Allow-Origin", "")

                if acao and acao != "*" and target_domain in acao:
                    self.findings.append(Finding(
                        vuln_class="CORS Special Character Bypass",
                        severity="MEDIUM",
                        cvss=5.5,
                        url=base_url,
                        description=f"Origin validation may be vulnerable to special "
                                   f"character bypass techniques.",
                        evidence={
                            "tested_origin": origin,
                            "acao_header": acao,
                        },
                        remediation=[
                            "Sanitize and validate origin header properly",
                            "Use URL parsing libraries for validation",
                        ],
                        tags=["cors", "bypass", "special-chars"],
                    ))
                    return

            except Exception:
                continue
