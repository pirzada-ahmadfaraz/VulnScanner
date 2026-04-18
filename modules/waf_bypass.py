"""
WAF Bypass & Evasion Scanner
- Detects WAF presence
- Tests bypass techniques
- Encoding evasion
- HTTP method tricks
- Header manipulation
"""

import re
from typing import List, Dict, Optional
from urllib.parse import urljoin, quote

from ..core.finding import Finding
from ..core.http_client import AdaptiveHTTPClient


class WAFBypassScanner:
    """WAF detection and bypass testing"""

    # Common WAF signatures
    WAF_SIGNATURES = {
        "Cloudflare": [
            "cloudflare", "cf-ray", "__cfduid", "cf-cache-status",
            "cloudflare-nginx", "1020", "1015"
        ],
        "AWS WAF": [
            "awswaf", "x-amzn-requestid", "x-amz-cf-id"
        ],
        "Akamai": [
            "akamai", "akamaighost", "x-akamai", "ak_bmsc"
        ],
        "Imperva/Incapsula": [
            "incapsula", "imperva", "visid_incap", "incap_ses"
        ],
        "ModSecurity": [
            "mod_security", "modsecurity", "NOYB"
        ],
        "F5 BIG-IP": [
            "bigip", "f5", "TS[a-z0-9]{6}"
        ],
        "Sucuri": [
            "sucuri", "x-sucuri"
        ],
        "Barracuda": [
            "barracuda", "barra_counter_session"
        ],
        "FortiWeb": [
            "fortiweb", "fortigate"
        ],
    }

    # Encoding techniques for bypass
    ENCODING_TECHNIQUES = {
        "url_encode": lambda x: quote(x),
        "double_url": lambda x: quote(quote(x)),
        "unicode": lambda x: "".join(f"\\u{ord(c):04x}" for c in x),
        "hex": lambda x: "".join(f"\\x{ord(c):02x}" for c in x),
        "html_entity": lambda x: "".join(f"&#{ord(c)};" for c in x),
    }

    def __init__(self, client: AdaptiveHTTPClient):
        self.client = client
        self.findings: List[Finding] = []
        self.detected_waf: Optional[str] = None

    def scan(self, base_url: str, callback=None) -> List[Finding]:
        """
        Scan for WAF and test bypass techniques

        Args:
            base_url: Target URL
            callback: Progress callback

        Returns:
            List of findings
        """
        self.findings = []

        if callback:
            callback("info", "Detecting WAF presence")

        # Detect WAF
        self._detect_waf(base_url, callback)

        # Test various bypass techniques
        if callback:
            callback("probe", "Testing WAF bypass techniques")

        self._test_method_bypass(base_url, callback)
        self._test_encoding_bypass(base_url, callback)
        self._test_header_bypass(base_url, callback)
        self._test_case_variation(base_url, callback)
        self._test_path_normalization(base_url, callback)

        return self.findings

    def _detect_waf(self, base_url: str, callback=None):
        """Detect which WAF is in use"""
        if callback:
            callback("probe", "Fingerprinting WAF")

        try:
            # Normal request
            normal_resp = self.client.get(base_url, timeout=10)

            # Malicious request to trigger WAF
            malicious_url = f"{base_url}?test=<script>alert(1)</script>"
            try:
                malicious_resp = self.client.get(malicious_url, timeout=10)
            except Exception:
                malicious_resp = None

            # Check headers and cookies for WAF signatures
            all_headers = str(normal_resp.headers).lower()
            all_cookies = str(normal_resp.cookies).lower()
            combined = all_headers + all_cookies

            if malicious_resp:
                combined += str(malicious_resp.headers).lower()
                combined += malicious_resp.text[:2000].lower()

            for waf_name, signatures in self.WAF_SIGNATURES.items():
                for sig in signatures:
                    if re.search(sig.lower(), combined):
                        self.detected_waf = waf_name
                        self.findings.append(Finding(
                            vuln_class="WAF Detected",
                            severity="INFO",
                            url=base_url,
                            description=f"Web Application Firewall detected: {waf_name}",
                            evidence={"waf": waf_name, "signature": sig},
                            tags=["waf", "fingerprint"],
                        ))
                        if callback:
                            callback("info", f"WAF detected: {waf_name}")
                        return

            # Check for generic WAF behavior
            if malicious_resp:
                if malicious_resp.status_code in [403, 406, 429, 503]:
                    self.detected_waf = "Unknown WAF"
                    self.findings.append(Finding(
                        vuln_class="WAF Detected",
                        severity="INFO",
                        url=base_url,
                        description=f"Generic WAF behavior detected (blocked malicious request)",
                        evidence={"status_code": malicious_resp.status_code},
                        tags=["waf", "fingerprint"],
                    ))

        except Exception:
            pass

    def _test_method_bypass(self, base_url: str, callback=None):
        """Test HTTP method-based WAF bypass"""
        if callback:
            callback("probe", "Testing HTTP method bypass")

        test_payload = "' OR '1'='1"
        test_url = f"{base_url}?id={test_payload}"

        # Methods that might bypass WAF
        methods_to_test = [
            ("GET", None),
            ("POST", {"id": test_payload}),
            ("PUT", {"id": test_payload}),
            ("PATCH", {"id": test_payload}),
            ("OPTIONS", None),
            ("HEAD", None),
        ]

        blocked_methods = []
        allowed_methods = []

        for method, data in methods_to_test:
            try:
                if method == "GET":
                    resp = self.client.get(test_url, timeout=8)
                elif method == "HEAD":
                    resp = self.client.head(test_url, timeout=8)
                elif method == "OPTIONS":
                    resp = self.client.options(base_url, timeout=8)
                else:
                    resp = self.client.request(method, base_url, data=data, timeout=8)

                if resp.status_code in [200, 201, 204]:
                    allowed_methods.append(method)
                elif resp.status_code in [403, 406, 429]:
                    blocked_methods.append(method)

            except Exception:
                continue

        if blocked_methods and allowed_methods:
            self.findings.append(Finding(
                vuln_class="Inconsistent WAF Method Blocking",
                severity="LOW",
                cvss=3.5,
                url=base_url,
                description=f"WAF blocks some HTTP methods but not others. "
                           f"Blocked: {blocked_methods}, Allowed: {allowed_methods}",
                evidence={
                    "blocked_methods": blocked_methods,
                    "allowed_methods": allowed_methods,
                },
                remediation=[
                    "Ensure WAF rules apply to all HTTP methods",
                    "Test all methods during security configuration",
                ],
                tags=["waf", "bypass", "method"],
            ))

    def _test_encoding_bypass(self, base_url: str, callback=None):
        """Test encoding-based WAF bypass"""
        if callback:
            callback("probe", "Testing encoding bypass")

        original_payload = "<script>alert(1)</script>"
        test_param = "test"

        for encoding_name, encode_func in self.ENCODING_TECHNIQUES.items():
            try:
                encoded_payload = encode_func(original_payload)
                test_url = f"{base_url}?{test_param}={quote(encoded_payload)}"

                resp = self.client.get(test_url, timeout=8)

                # Check if payload passed through
                if resp.status_code == 200 and (
                    original_payload in resp.text or
                    encoded_payload in resp.text
                ):
                    self.findings.append(Finding(
                        vuln_class="WAF Encoding Bypass",
                        severity="MEDIUM",
                        cvss=5.5,
                        url=test_url,
                        description=f"WAF bypassed using {encoding_name} encoding",
                        evidence={
                            "encoding": encoding_name,
                            "original_payload": original_payload,
                            "encoded_payload": encoded_payload[:100],
                        },
                        remediation=[
                            "Decode all encodings before WAF inspection",
                            "Implement recursive decoding",
                            "Normalize input before security checks",
                        ],
                        tags=["waf", "bypass", "encoding"],
                    ))
                    return  # Found one bypass

            except Exception:
                continue

    def _test_header_bypass(self, base_url: str, callback=None):
        """Test header-based WAF bypass"""
        if callback:
            callback("probe", "Testing header bypass")

        # Headers that might confuse WAF
        bypass_headers = [
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Remote-Addr": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"Content-Type": "application/x-www-form-urlencoded; charset=ibm037"},
            {"Content-Type": "text/xml"},
            {"Transfer-Encoding": "chunked"},
        ]

        malicious_payload = "?test=<script>alert(1)</script>"

        for headers in bypass_headers:
            try:
                resp = self.client.get(
                    base_url + malicious_payload,
                    headers=headers,
                    timeout=8
                )

                if resp.status_code == 200:
                    # Check if payload reflected (potential bypass)
                    if "<script>" in resp.text:
                        header_name = list(headers.keys())[0]
                        self.findings.append(Finding(
                            vuln_class="WAF Header Bypass",
                            severity="MEDIUM",
                            cvss=5.5,
                            url=base_url,
                            description=f"WAF may be bypassed using {header_name} header",
                            evidence={
                                "bypass_header": headers,
                                "status_code": resp.status_code,
                            },
                            remediation=[
                                "Inspect requests regardless of header values",
                                "Do not trust client-provided headers",
                            ],
                            tags=["waf", "bypass", "header"],
                        ))
                        return

            except Exception:
                continue

    def _test_case_variation(self, base_url: str, callback=None):
        """Test case variation bypass"""
        if callback:
            callback("probe", "Testing case variation")

        case_payloads = [
            "<ScRiPt>alert(1)</ScRiPt>",
            "<SCRIPT>alert(1)</SCRIPT>",
            "<sCRIPT>alert(1)</sCRIPT>",
            "<script>ALERT(1)</script>",
        ]

        for payload in case_payloads:
            try:
                test_url = f"{base_url}?test={quote(payload)}"
                resp = self.client.get(test_url, timeout=8)

                if resp.status_code == 200 and payload.lower() in resp.text.lower():
                    self.findings.append(Finding(
                        vuln_class="WAF Case Sensitivity Bypass",
                        severity="MEDIUM",
                        cvss=5.0,
                        url=test_url,
                        description="WAF can be bypassed using case variations",
                        evidence={"payload": payload},
                        remediation=[
                            "Normalize case before WAF inspection",
                            "Use case-insensitive pattern matching",
                        ],
                        tags=["waf", "bypass", "case"],
                    ))
                    return

            except Exception:
                continue

    def _test_path_normalization(self, base_url: str, callback=None):
        """Test path normalization bypass"""
        if callback:
            callback("probe", "Testing path normalization")

        # Various path tricks
        path_bypasses = [
            "/./admin",
            "//admin",
            "/admin/.",
            "/admin/../admin",
            "/%2e/admin",
            "/admin%00",
            "/admin;.css",
            "/admin/.json",
        ]

        for path in path_bypasses:
            try:
                test_url = urljoin(base_url, path)
                resp = self.client.get(test_url, timeout=8, allow_redirects=False)

                # If we get something other than 403/404, might be bypass
                if resp.status_code in [200, 301, 302]:
                    self.findings.append(Finding(
                        vuln_class="Path Normalization Issue",
                        severity="LOW",
                        cvss=3.5,
                        url=test_url,
                        description=f"Server responds differently to path: {path}",
                        evidence={
                            "path": path,
                            "status_code": resp.status_code,
                        },
                        remediation=[
                            "Normalize paths before routing",
                            "Apply security checks after path normalization",
                        ],
                        tags=["waf", "path", "normalization"],
                    ))

            except Exception:
                continue
