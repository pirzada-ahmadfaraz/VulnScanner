"""
Module: Open Redirect Scanner
- URL parameter injection
- JavaScript redirect detection
- Meta refresh detection
- Header-based redirect
"""

import re
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote

from ..core.finding import Finding
from ..core.http_client import AdaptiveHTTPClient


class OpenRedirectScanner:
    """Open redirect vulnerability scanner"""

    def __init__(self, client: AdaptiveHTTPClient):
        self.client = client
        self.findings: List[Finding] = []

    def _generate_payloads(self, marker_domain: str = "evil.com") -> List[Dict]:
        """Generate open redirect payloads"""
        payloads = []

        # Direct URLs
        direct = [
            f"https://{marker_domain}",
            f"http://{marker_domain}",
            f"//{marker_domain}",
            f"///{marker_domain}",
        ]

        for p in direct:
            payloads.append({'payload': p, 'type': 'direct', 'expect_domain': marker_domain})

        # Protocol-relative bypass
        proto_bypass = [
            f"https://{marker_domain}%2f%2f",
            f"https://{marker_domain}//",
            f"/\\{marker_domain}",
            f"\\{marker_domain}",
        ]

        for p in proto_bypass:
            payloads.append({'payload': p, 'type': 'protocol_bypass', 'expect_domain': marker_domain})

        # Parser confusion
        parser_bypass = [
            f"https://legit.com@{marker_domain}",
            f"https://{marker_domain}%00legit.com",
            f"https://{marker_domain}%0d%0alegit.com",
            f"https://legit.com#{marker_domain}",
            f"https://legit.com?{marker_domain}",
            f"//google.com%00@{marker_domain}",
        ]

        for p in parser_bypass:
            payloads.append({'payload': p, 'type': 'parser_bypass', 'expect_domain': marker_domain})

        # JavaScript protocol
        js_payloads = [
            "javascript:alert(1)",
            "javascript://evil.com%0aalert(1)",
            "data:text/html,<script>alert(1)</script>",
        ]

        for p in js_payloads:
            payloads.append({'payload': p, 'type': 'javascript', 'expect_domain': None})

        return payloads

    def _find_redirect_parameters(self, url: str) -> List[str]:
        """Find parameters likely to accept redirect URLs"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        redirect_hints = [
            'redirect', 'url', 'next', 'return', 'returnto', 'goto',
            'dest', 'destination', 'redir', 'redirect_uri', 'return_url',
            'continue', 'forward', 'target', 'link', 'out', 'view', 'ref',
            'callback', 'jump', 'path', 'redirect_to', 'return_path',
        ]

        candidates = []
        for param in params.keys():
            param_lower = param.lower()
            if any(hint in param_lower for hint in redirect_hints):
                candidates.append(param)
            # Also check if value looks like a URL
            elif params[param] and params[param][0].startswith(('http', '/', '//')):
                candidates.append(param)

        return candidates

    def _check_redirect_in_response(self, response, payload_info: Dict) -> Optional[Dict]:
        """Check if redirect occurred to attacker domain"""

        # Check HTTP redirect (3xx status with Location header)
        if response.status_code in [301, 302, 303, 307, 308]:
            location = response.headers.get('Location', '')
            expect = payload_info.get('expect_domain')

            if expect and expect in location:
                return {
                    'type': 'http_redirect',
                    'location': location,
                    'status': response.status_code,
                }

            # JavaScript protocol in Location (rare but possible)
            if payload_info['type'] == 'javascript' and 'javascript:' in location.lower():
                return {
                    'type': 'javascript_redirect',
                    'location': location,
                }

        # Check meta refresh in body
        body = response.text
        meta_match = re.search(
            r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?[\d;]*url=([^"\'>\s]+)',
            body, re.I
        )
        if meta_match:
            redirect_url = meta_match.group(1)
            expect = payload_info.get('expect_domain')
            if expect and expect in redirect_url:
                return {
                    'type': 'meta_refresh',
                    'location': redirect_url,
                }

        # Check JavaScript redirect
        js_redirect_patterns = [
            r'window\.location\s*=\s*["\']([^"\']+)',
            r'location\.href\s*=\s*["\']([^"\']+)',
            r'location\.replace\s*\(["\']([^"\']+)',
        ]
        for pattern in js_redirect_patterns:
            match = re.search(pattern, body)
            if match:
                redirect_url = match.group(1)
                expect = payload_info.get('expect_domain')
                if expect and expect in redirect_url:
                    return {
                        'type': 'javascript_redirect',
                        'location': redirect_url,
                    }

        return None

    def _test_open_redirect(self, url: str, param: str) -> List[Finding]:
        """Test parameter for open redirect"""
        findings = []
        marker = "evil-redirect.test"

        payloads = self._generate_payloads(marker)

        for payload_info in payloads:
            payload = payload_info['payload']

            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param] = [payload]

                query_string = urlencode(params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"

                # Don't follow redirects to detect the redirect
                resp = self.client.get(test_url, timeout=10, allow_redirects=False)

                result = self._check_redirect_in_response(resp, payload_info)

                if result:
                    severity = "MEDIUM"
                    if payload_info['type'] == 'javascript':
                        severity = "HIGH"

                    findings.append(Finding(
                        vuln_class="Open Redirect",
                        severity=severity,
                        cvss=6.1,
                        url=test_url,
                        parameter=param,
                        description=(
                            f"Open redirect via {payload_info['type']}. "
                            f"User can be redirected to attacker-controlled site."
                        ),
                        evidence={
                            'payload': payload,
                            'redirect_type': result['type'],
                            'redirect_location': result.get('location', ''),
                        },
                        remediation=[
                            "Validate redirect URLs against a whitelist of allowed domains",
                            "Use relative URLs instead of absolute URLs",
                            "Add a confirmation page before external redirects",
                            "Check that redirect URL starts with expected path prefix",
                        ],
                        tags=["open-redirect", payload_info['type']],
                    ))

                    # One confirmed is enough
                    return findings

            except Exception:
                continue

        return findings

    def scan(self, base_url: str) -> List[Finding]:
        """Run open redirect scan"""
        self.findings = []

        # Find redirect parameters in current URL
        candidates = self._find_redirect_parameters(base_url)

        for param in candidates:
            self.findings.extend(self._test_open_redirect(base_url, param))

        # Also check common redirect endpoints - only report if ACTUALLY redirects to evil domain
        redirect_paths = [
            '/redirect?url=',
            '/redir?url=',
            '/goto?url=',
            '/out?url=',
            '/link?url=',
        ]

        for path in redirect_paths:
            test_url = urljoin(base_url, path + "https://evil.test")
            try:
                resp = self.client.get(test_url, timeout=5, allow_redirects=False)
                if resp.status_code in [301, 302, 303, 307, 308]:
                    location = resp.headers.get('Location', '')
                    # Must redirect to EXACTLY our evil domain, not just contain it
                    if location.startswith('https://evil.test') or location.startswith('http://evil.test'):
                        self.findings.append(Finding(
                            vuln_class="Open Redirect",
                            severity="MEDIUM",
                            cvss=6.1,
                            url=test_url,
                            description=f"Open redirect endpoint discovered at {path}",
                            evidence={
                                'path': path,
                                'redirect_location': location,
                            },
                            tags=["open-redirect", "discovery"],
                        ))
            except Exception:
                continue

        return self.findings
