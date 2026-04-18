"""
Module: XSS Scanner
- Reflected XSS detection
- DOM-based XSS patterns
- Stored XSS detection (limited)
- Context-aware payload generation
"""

import re
import html
from typing import List, Dict, Tuple, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

from ..core.finding import Finding
from ..core.http_client import AdaptiveHTTPClient


class XSSScanner:
    """Cross-Site Scripting vulnerability scanner"""

    def __init__(self, client: AdaptiveHTTPClient):
        self.client = client
        self.findings: List[Finding] = []

    def _generate_payloads(self, context: str = 'html') -> List[Tuple[str, str, str]]:
        """Generate context-aware XSS payloads"""

        # Unique identifier for reflection detection
        marker = "VuLnScAn"

        payloads = []

        # HTML context payloads
        if context in ['html', 'all']:
            payloads.extend([
                (f"<script>{marker}</script>", "script tag", "html"),
                (f"<img src=x onerror={marker}>", "img onerror", "html"),
                (f"<svg onload={marker}>", "svg onload", "html"),
                (f"<body onload={marker}>", "body onload", "html"),
                (f"<input onfocus={marker} autofocus>", "autofocus", "html"),
                (f"<marquee onstart={marker}>", "marquee", "html"),
                (f"<details open ontoggle={marker}>", "details", "html"),
                (f"<video><source onerror={marker}>", "video source", "html"),
                (f"<iframe src='javascript:{marker}'>", "iframe javascript", "html"),
            ])

        # Attribute context payloads
        if context in ['attribute', 'all']:
            payloads.extend([
                (f'" onmouseover="{marker}"', "attr double quote", "attribute"),
                (f"' onmouseover='{marker}'", "attr single quote", "attribute"),
                (f" onmouseover={marker} ", "attr no quote", "attribute"),
                (f'" onfocus="{marker}" autofocus="', "attr autofocus", "attribute"),
                (f"javascript:{marker}", "attr javascript", "attribute"),
            ])

        # JavaScript context payloads
        if context in ['javascript', 'all']:
            payloads.extend([
                (f"';{marker}//", "js single quote break", "javascript"),
                (f'";{marker}//', "js double quote break", "javascript"),
                (f"}};{marker}//", "js object break", "javascript"),
                (f"]];{marker}//", "js array break", "javascript"),
                (f"</script><script>{marker}</script>", "js script break", "javascript"),
            ])

        # URL context payloads
        if context in ['url', 'all']:
            payloads.extend([
                (f"javascript:{marker}", "url javascript", "url"),
                (f"data:text/html,<script>{marker}</script>", "url data", "url"),
            ])

        return payloads

    def _detect_context(self, response_text: str, marker: str) -> List[str]:
        """Detect where the marker appears in the response"""
        contexts = []

        # Check HTML context (marker appears as raw HTML)
        if f"<script>{marker}</script>" in response_text:
            contexts.append("html_script")
        if f"onerror={marker}" in response_text or f'onerror="{marker}"' in response_text:
            contexts.append("html_event")
        if f"onload={marker}" in response_text:
            contexts.append("html_event")

        # Check if marker is in attribute value
        if re.search(rf'(?:href|src|value|action)=["\'][^"\']*{marker}', response_text, re.I):
            contexts.append("attribute")

        # Check if marker is in JavaScript context
        if re.search(rf'<script[^>]*>[^<]*{marker}[^<]*</script>', response_text, re.I | re.S):
            contexts.append("javascript")

        return contexts

    def _test_reflected_xss(self, url: str, param: str, value: str,
                            method: str = 'GET', form_data: Dict = None) -> List[Finding]:
        """Test for reflected XSS"""
        findings = []
        marker = "X5Sm4rK3r"

        # First, test if parameter is reflected at all
        try:
            test_value = marker

            if method == 'POST' and form_data:
                test_data = {**form_data, param: test_value}
                resp = self.client.post(url, data=test_data, timeout=10)
            else:
                params = self._extract_parameters(url)
                params[param] = test_value
                parsed = urlparse(url)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params)}"
                resp = self.client.get(test_url, timeout=10)

            if marker not in resp.text:
                # Parameter not reflected, skip
                return findings

        except Exception:
            return findings

        # Test XSS payloads - only report if payload is FULLY reflected with executable context
        confirmed_xss = False
        for payload, payload_type, context in self._generate_payloads('all'):
            try:
                if method == 'POST' and form_data:
                    test_data = {**form_data, param: payload}
                    resp = self.client.post(url, data=test_data, timeout=10)
                else:
                    params = self._extract_parameters(url)
                    params[param] = payload
                    parsed = urlparse(url)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params)}"
                    resp = self.client.get(test_url, timeout=10)

                # Check if payload appears EXACTLY unencoded (full payload, not parts)
                if payload in resp.text:
                    # Verify it's in an executable context, not just reflected in a safe place
                    # Check if it's inside a script tag, event handler, or similar
                    body = resp.text
                    payload_idx = body.find(payload)
                    if payload_idx >= 0:
                        context_before = body[max(0, payload_idx-100):payload_idx]
                        context_after = body[payload_idx:min(len(body), payload_idx+len(payload)+100)]

                        # Check if it's in a dangerous context
                        dangerous_contexts = [
                            '<script',  # Inside script tag
                            'onerror=', 'onload=', 'onclick=', 'onmouseover=',  # Event handlers
                            'javascript:',  # JavaScript URI
                            'href="javascript', 'src="javascript',
                        ]

                        is_dangerous = any(ctx in context_before.lower() or ctx in context_after.lower()
                                          for ctx in dangerous_contexts)

                        # Also check if our script/event is actually in the response properly
                        if is_dangerous or '<script>' in payload.lower() and payload in body:
                            findings.append(Finding(
                                vuln_class="Reflected XSS",
                                severity="HIGH",
                                cvss=7.5,
                                url=url,
                                parameter=param,
                                description=f"Reflected XSS via {payload_type}. Payload appears unencoded in response.",
                                evidence={
                                    'payload': payload,
                                    'payload_type': payload_type,
                                    'context': context,
                                },
                                request=f"{method} {url}\n{param}={quote(payload)}",
                                remediation=[
                                    "Encode output based on context (HTML, JavaScript, URL)",
                                    "Use Content-Security-Policy to prevent inline scripts",
                                    "Validate and sanitize input",
                                    "Use HTTPOnly cookies to protect sessions",
                                ],
                                tags=["xss", "reflected"],
                            ))
                            confirmed_xss = True
                            return findings  # Found confirmed XSS, return

            except Exception:
                continue

        # Only report potential XSS if we haven't found confirmed XSS and reflection is significant
        # Don't report partial reflection as it creates too many false positives

        return findings

    def _extract_parameters(self, url: str) -> Dict[str, str]:
        """Extract URL parameters"""
        parsed = urlparse(url)
        return {k: v[0] for k, v in parse_qs(parsed.query).items()}

    def _extract_forms(self, html_content: str, base_url: str) -> List[Dict]:
        """Extract forms from HTML"""
        forms = []

        if not HAS_BS4:
            return self._extract_forms_regex(html_content, base_url)

        soup = BeautifulSoup(html_content, 'html.parser')

        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(base_url, form.get('action', '')),
                'method': (form.get('method', 'GET')).upper(),
                'params': {},
            }

            for inp in form.find_all(['input', 'textarea']):
                name = inp.get('name', '')
                if name and inp.get('type', '') not in ['submit', 'button', 'file']:
                    form_data['params'][name] = inp.get('value', '')

            if form_data['params']:
                forms.append(form_data)

        return forms

    def _extract_forms_regex(self, html_content: str, base_url: str) -> List[Dict]:
        """Fallback regex-based form extraction"""
        forms = []

        form_pattern = r'<form[^>]*>(.*?)</form>'
        for form_match in re.finditer(form_pattern, html_content, re.DOTALL | re.IGNORECASE):
            form_tag = form_match.group(0)
            form_content = form_match.group(1)

            action_match = re.search(r'action=["\']([^"\']*)["\']', form_tag, re.IGNORECASE)
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_tag, re.IGNORECASE)

            form_data = {
                'action': urljoin(base_url, action_match.group(1) if action_match else ''),
                'method': (method_match.group(1) if method_match else 'GET').upper(),
                'params': {},
            }

            input_pattern = r'<input[^>]*>'
            for inp_match in re.finditer(input_pattern, form_content, re.IGNORECASE):
                inp_tag = inp_match.group(0)

                name_match = re.search(r'name=["\']([^"\']*)["\']', inp_tag, re.IGNORECASE)
                type_match = re.search(r'type=["\']([^"\']*)["\']', inp_tag, re.IGNORECASE)
                value_match = re.search(r'value=["\']([^"\']*)["\']', inp_tag, re.IGNORECASE)

                if name_match:
                    field_type = type_match.group(1).lower() if type_match else 'text'
                    if field_type not in ['submit', 'button', 'file']:
                        form_data['params'][name_match.group(1)] = value_match.group(1) if value_match else ''

            if form_data['params']:
                forms.append(form_data)

        return forms

    def _check_dom_xss_sinks(self, html_content: str, url: str) -> List[Finding]:
        """Detect potential DOM-based XSS sinks in JavaScript"""
        findings = []

        # DOM XSS sinks
        sinks = [
            (r'document\.write\s*\(', 'document.write', 'HIGH'),
            (r'\.innerHTML\s*=', 'innerHTML', 'HIGH'),
            (r'\.outerHTML\s*=', 'outerHTML', 'HIGH'),
            (r'eval\s*\(', 'eval', 'CRITICAL'),
            (r'setTimeout\s*\([^,)]*[\'"]', 'setTimeout string', 'HIGH'),
            (r'setInterval\s*\([^,)]*[\'"]', 'setInterval string', 'HIGH'),
            (r'\.insertAdjacentHTML\s*\(', 'insertAdjacentHTML', 'HIGH'),
            (r'document\.location\s*=', 'document.location', 'MEDIUM'),
            (r'window\.location\s*=', 'window.location', 'MEDIUM'),
            (r'\.src\s*=\s*[^;]*(?:location|document\.URL)', 'src with location', 'MEDIUM'),
        ]

        # DOM XSS sources
        sources = [
            r'location\.(?:hash|search|href)',
            r'document\.(?:URL|documentURI|referrer)',
            r'window\.name',
            r'document\.cookie',
        ]

        # Find all script content
        scripts = []
        if HAS_BS4:
            soup = BeautifulSoup(html_content, 'html.parser')
            for script in soup.find_all('script'):
                if script.string:
                    scripts.append(script.string)
        else:
            # Fallback regex extraction
            script_pattern = r'<script[^>]*>(.*?)</script>'
            for match in re.finditer(script_pattern, html_content, re.DOTALL | re.IGNORECASE):
                scripts.append(match.group(1))

        combined_js = '\n'.join(scripts)

        for sink_pattern, sink_name, severity in sinks:
            matches = re.finditer(sink_pattern, combined_js, re.I)
            for match in matches:
                # Check if a source is nearby (within ~100 chars)
                context_start = max(0, match.start() - 100)
                context_end = min(len(combined_js), match.end() + 100)
                context = combined_js[context_start:context_end]

                has_source = any(re.search(source, context, re.I) for source in sources)

                if has_source:
                    findings.append(Finding(
                        vuln_class="DOM-based XSS",
                        severity=severity,
                        url=url,
                        description=f"Potential DOM XSS: {sink_name} sink with user-controlled source.",
                        evidence={
                            'sink': sink_name,
                            'context': context[:200],
                        },
                        remediation=[
                            "Avoid dangerous sinks like innerHTML, eval",
                            "Use textContent instead of innerHTML",
                            "Sanitize user input before using in DOM",
                            "Implement Content-Security-Policy",
                        ],
                        tags=["xss", "dom", "client-side"],
                    ))
                else:
                    # Sink found but no obvious source - lower severity
                    findings.append(Finding(
                        vuln_class="DOM XSS Sink Detected",
                        severity="LOW",
                        url=url,
                        description=f"JavaScript contains {sink_name} sink. Review for DOM XSS.",
                        evidence={
                            'sink': sink_name,
                            'context': context[:150],
                        },
                        tags=["xss", "dom", "review"],
                    ))

        return findings

    def scan(self, base_url: str) -> List[Finding]:
        """Run full XSS scan"""
        self.findings = []

        try:
            resp = self.client.get(base_url, timeout=15)
        except Exception:
            return self.findings

        # Test URL parameters
        url_params = self._extract_parameters(base_url)
        for param, value in url_params.items():
            self.findings.extend(self._test_reflected_xss(base_url, param, value))

        # Test form parameters
        forms = self._extract_forms(resp.text, base_url)
        for form in forms:
            for param, value in form['params'].items():
                self.findings.extend(self._test_reflected_xss(
                    form['action'], param, value, form['method'], form['params']
                ))

        # Check for DOM XSS patterns
        self.findings.extend(self._check_dom_xss_sinks(resp.text, base_url))

        return self.findings
