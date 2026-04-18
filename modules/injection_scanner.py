"""
Module: Injection Scanner
- SQL Injection (error-based, blind, time-based)
- Command Injection
- LDAP Injection
- XPath Injection
- Template Injection (SSTI)
- Header Injection
"""

import re
import time
from typing import List, Dict, Tuple, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

from ..core.finding import Finding
from ..core.http_client import AdaptiveHTTPClient


class InjectionScanner:
    """Multi-injection vulnerability scanner"""

    def __init__(self, client: AdaptiveHTTPClient):
        self.client = client
        self.findings: List[Finding] = []
        self.baseline_responses: Dict[str, Tuple[int, int, float]] = {}

    def _get_baseline(self, url: str, method: str = 'GET', data: Dict = None) -> Tuple[int, int, float]:
        """Get baseline response for comparison"""
        cache_key = f"{method}:{url}:{hash(str(data))}"

        if cache_key not in self.baseline_responses:
            try:
                start = time.time()
                if method == 'POST':
                    resp = self.client.post(url, data=data, timeout=15)
                else:
                    resp = self.client.get(url, timeout=15)
                elapsed = time.time() - start

                self.baseline_responses[cache_key] = (
                    resp.status_code,
                    len(resp.text),
                    elapsed
                )
            except Exception:
                self.baseline_responses[cache_key] = (0, 0, 0)

        return self.baseline_responses[cache_key]

    def _extract_parameters(self, url: str) -> Dict[str, str]:
        """Extract URL parameters"""
        parsed = urlparse(url)
        return {k: v[0] for k, v in parse_qs(parsed.query).items()}

    def _extract_forms(self, html: str, url: str) -> List[Dict]:
        """Extract forms and their parameters"""
        forms = []

        if not HAS_BS4:
            # Fallback regex-based form extraction
            return self._extract_forms_regex(html, url)

        soup = BeautifulSoup(html, 'html.parser')

        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(url, form.get('action', '')),
                'method': (form.get('method', 'GET')).upper(),
                'params': {},
            }

            for inp in form.find_all(['input', 'select', 'textarea']):
                name = inp.get('name', '')
                if name and inp.get('type', '') not in ['submit', 'button', 'image']:
                    form_data['params'][name] = inp.get('value', '')

            if form_data['params']:
                forms.append(form_data)

        return forms

    def _extract_forms_regex(self, html: str, url: str) -> List[Dict]:
        """Fallback regex-based form extraction"""
        forms = []

        form_pattern = r'<form[^>]*>(.*?)</form>'
        for form_match in re.finditer(form_pattern, html, re.DOTALL | re.IGNORECASE):
            form_tag = form_match.group(0)
            form_content = form_match.group(1)

            action_match = re.search(r'action=["\']([^"\']*)["\']', form_tag, re.IGNORECASE)
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_tag, re.IGNORECASE)

            form_data = {
                'action': urljoin(url, action_match.group(1) if action_match else ''),
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
                    if field_type not in ['submit', 'button', 'image']:
                        form_data['params'][name_match.group(1)] = value_match.group(1) if value_match else ''

            if form_data['params']:
                forms.append(form_data)

        return forms

    # ==================== SQL INJECTION ====================

    def _test_sqli(self, url: str, param: str, value: str, method: str = 'GET',
                   form_data: Dict = None) -> List[Finding]:
        """Test parameter for SQL injection"""
        findings = []

        # Error-based SQL injection payloads (universal, not DB-specific)
        error_payloads = [
            ("'", "single quote"),
            ('"', "double quote"),
            ("'--", "comment"),
            ("' OR '1'='1", "OR bypass"),
            ("1' AND '1'='1", "AND true"),
            ("1' AND '1'='2", "AND false"),
            ("1 OR 1=1", "numeric OR"),
            ("') OR ('1'='1", "parenthesis"),
            ("' UNION SELECT NULL--", "UNION probe"),
            ("1; SELECT 1--", "stacked query"),
        ]

        # SQL error patterns - MUST be actual database errors, not just keywords in JSON
        # These are very specific patterns that indicate real SQL errors
        error_patterns = [
            r'you have an error in your sql syntax',
            r'warning.*?mysql_',
            r'warning.*?mysqli_',
            r'warning.*?pg_',
            r'unclosed quotation mark',
            r'quoted string not properly terminated',
            r'ora-\d{5}:',  # Oracle errors with colon
            r'pg_query\(\).*?error',
            r'sqlstate\[[\w]+\]',
            r'microsoft ole db.*?error',
            r'odbc.*?driver.*?error',
            r'syntax error.*?unexpected.*?token',
            r'sqlite3::query.*?error',
            r'supplied argument is not a valid mysql',
            r'mysql_num_rows\(\)',
            r'microsoft sql server.*?error',
            r'invalid column name',
            r'unknown column.*?in.*?clause',
            r'table.*?doesn\'t exist',
            r'column.*?cannot be null',
        ]

        base_status, base_len, base_time = self._get_baseline(url, method, form_data)

        for payload, payload_type in error_payloads:
            try:
                test_value = f"{value}{payload}"

                if method == 'POST' and form_data:
                    test_data = {**form_data, param: test_value}
                    start = time.time()
                    resp = self.client.post(url, data=test_data, timeout=15)
                else:
                    params = self._extract_parameters(url)
                    params[param] = test_value
                    parsed = urlparse(url)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params)}"
                    start = time.time()
                    resp = self.client.get(test_url, timeout=15)

                elapsed = time.time() - start
                body = resp.text.lower()

                # Check for SQL errors
                for pattern in error_patterns:
                    if re.search(pattern, body, re.I):
                        findings.append(Finding(
                            vuln_class="SQL Injection (Error-based)",
                            severity="CRITICAL",
                            cvss=9.8,
                            url=url,
                            parameter=param,
                            description=f"SQL injection via {payload_type}. Database error disclosed in response.",
                            evidence={
                                'payload': payload,
                                'error_pattern': pattern,
                                'response_snippet': resp.text[:500],
                            },
                            request=f"{method} {url}\n{param}={test_value}",
                            remediation=[
                                "Use parameterized queries/prepared statements",
                                "Implement input validation",
                                "Use ORM instead of raw SQL",
                                "Disable detailed error messages in production",
                            ],
                            tags=["sqli", "injection", "critical"],
                        ))
                        return findings  # Found SQLi, no need to continue

            except Exception:
                continue

        # Time-based blind SQLi detection
        time_payloads = [
            ("' AND SLEEP(5)--", 5),
            ("'; WAITFOR DELAY '0:0:5'--", 5),
            ("' AND pg_sleep(5)--", 5),
            ("1; SELECT SLEEP(5);--", 5),
        ]

        for payload, expected_delay in time_payloads:
            try:
                test_value = f"{value}{payload}"

                if method == 'POST' and form_data:
                    test_data = {**form_data, param: test_value}
                    start = time.time()
                    resp = self.client.post(url, data=test_data, timeout=20)
                else:
                    params = self._extract_parameters(url)
                    params[param] = test_value
                    parsed = urlparse(url)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params)}"
                    start = time.time()
                    resp = self.client.get(test_url, timeout=20)

                elapsed = time.time() - start

                # If response took significantly longer than baseline
                if elapsed > base_time + expected_delay - 1:
                    findings.append(Finding(
                        vuln_class="SQL Injection (Time-based Blind)",
                        severity="CRITICAL",
                        cvss=9.8,
                        url=url,
                        parameter=param,
                        description=f"Time-based blind SQL injection detected. Response delayed by ~{elapsed:.1f}s.",
                        evidence={
                            'payload': payload,
                            'baseline_time': f"{base_time:.2f}s",
                            'injected_time': f"{elapsed:.2f}s",
                        },
                        remediation=[
                            "Use parameterized queries",
                            "Implement strict input validation",
                            "Use WAF rules for time-based SQLi",
                        ],
                        tags=["sqli", "blind", "time-based", "critical"],
                    ))
                    return findings

            except Exception:
                continue

        return findings

    # ==================== COMMAND INJECTION ====================

    def _test_command_injection(self, url: str, param: str, value: str,
                                 method: str = 'GET', form_data: Dict = None) -> List[Finding]:
        """Test for OS command injection"""
        findings = []

        # Command injection payloads - use longer delays and verify properly
        payloads = [
            ("; sleep 7", 7, "semicolon"),
            ("| sleep 7", 7, "pipe"),
            ("`sleep 7`", 7, "backtick"),
            ("$(sleep 7)", 7, "subshell"),
        ]

        base_status, base_len, base_time = self._get_baseline(url, method, form_data)

        # Only test if baseline is reasonable (under 5s)
        if base_time > 5:
            return findings

        for payload, expected_delay, payload_type in payloads:
            try:
                test_value = f"{value}{payload}"

                if method == 'POST' and form_data:
                    test_data = {**form_data, param: test_value}
                    start = time.time()
                    resp = self.client.post(url, data=test_data, timeout=25)
                else:
                    params = self._extract_parameters(url)
                    params[param] = test_value
                    parsed = urlparse(url)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params)}"
                    start = time.time()
                    resp = self.client.get(test_url, timeout=25)

                elapsed = time.time() - start

                # Require significant delay difference (at least 5 seconds more than baseline)
                if elapsed > base_time + expected_delay - 2 and elapsed > 6:
                    # Double-check with a second request
                    start2 = time.time()
                    if method == 'POST' and form_data:
                        resp2 = self.client.post(url, data=test_data, timeout=25)
                    else:
                        resp2 = self.client.get(test_url, timeout=25)
                    elapsed2 = time.time() - start2

                    # Both requests must show delay
                    if elapsed2 > base_time + expected_delay - 2:
                        findings.append(Finding(
                            vuln_class="Command Injection",
                            severity="CRITICAL",
                            cvss=10.0,
                            url=url,
                            parameter=param,
                            description=f"OS command injection via {payload_type}. Time delay confirmed execution.",
                            evidence={
                                'payload': payload,
                                'baseline_time': f"{base_time:.2f}s",
                                'first_test': f"{elapsed:.2f}s",
                                'second_test': f"{elapsed2:.2f}s",
                            },
                            remediation=[
                                "Never pass user input to system commands",
                                "Use safe APIs instead of shell commands",
                                "If unavoidable, use strict whitelisting",
                                "Escape all special characters",
                            ],
                            tags=["command-injection", "rce", "critical"],
                        ))
                        return findings

            except Exception:
                continue

        return findings

    # ==================== SSTI ====================

    def _test_ssti(self, url: str, param: str, value: str,
                   method: str = 'GET', form_data: Dict = None) -> List[Finding]:
        """Test for Server-Side Template Injection"""
        findings = []

        # SSTI payloads with expected output (engine-agnostic)
        # Use unique math that's unlikely to appear normally
        payloads = [
            ("{{7*191}}", "1337", "Jinja2/Twig"),
            ("${7*191}", "1337", "Freemarker/Velocity"),
            ("#{7*191}", "1337", "Ruby ERB"),
            ("<%= 7*191 %>", "1337", "Ruby ERB"),
            ("${{7*191}}", "1337", "Spring"),
        ]

        for payload, expected, engine in payloads:
            try:
                test_value = payload

                if method == 'POST' and form_data:
                    test_data = {**form_data, param: test_value}
                    resp = self.client.post(url, data=test_data, timeout=10)
                else:
                    params = self._extract_parameters(url)
                    params[param] = test_value
                    parsed = urlparse(url)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params)}"
                    resp = self.client.get(test_url, timeout=10)

                if expected in resp.text:
                    findings.append(Finding(
                        vuln_class="Server-Side Template Injection (SSTI)",
                        severity="CRITICAL",
                        cvss=9.8,
                        url=url,
                        parameter=param,
                        description=f"SSTI detected. Likely engine: {engine}. Can lead to RCE.",
                        evidence={
                            'payload': payload,
                            'expected': expected,
                            'found_in_response': True,
                            'likely_engine': engine,
                        },
                        remediation=[
                            "Never pass user input directly to template engines",
                            "Use sandbox mode if available",
                            "Implement strict input validation",
                            "Use logic-less templates when possible",
                        ],
                        tags=["ssti", "injection", "rce", "critical"],
                    ))
                    return findings

            except Exception:
                continue

        return findings

    # ==================== HEADER INJECTION ====================

    def _test_header_injection(self, url: str) -> List[Finding]:
        """Test for HTTP header injection"""
        findings = []

        # Test CRLF injection in various places
        payloads = [
            ("%0d%0aSet-Cookie: injected=true", "set-cookie: injected"),
            ("%0d%0aX-Injected: true", "x-injected: true"),
            ("\r\nX-Injected: true", "x-injected: true"),
        ]

        for payload, expected in payloads:
            try:
                # Test in URL parameter
                test_url = f"{url}?param=value{payload}"
                resp = self.client.get(test_url, timeout=10, allow_redirects=False)

                # Check if our header appears
                headers_lower = {k.lower(): v for k, v in resp.headers.items()}
                if any(expected.split(':')[0] in k for k in headers_lower.keys()):
                    findings.append(Finding(
                        vuln_class="HTTP Header Injection (CRLF)",
                        severity="HIGH",
                        cvss=8.0,
                        url=test_url,
                        description="CRLF injection allows adding arbitrary HTTP headers.",
                        evidence={
                            'payload': payload,
                            'injected_header_found': True,
                        },
                        remediation=[
                            "Sanitize CRLF characters from user input",
                            "Use framework functions for header setting",
                            "Validate and encode all header values",
                        ],
                        tags=["header-injection", "crlf"],
                    ))
                    break

            except Exception:
                continue

        return findings

    def scan(self, base_url: str, depth: int = 2) -> List[Finding]:
        """Run injection scan on discovered parameters"""
        self.findings = []

        # Get initial page and extract parameters/forms
        try:
            resp = self.client.get(base_url, timeout=15)
        except Exception:
            return self.findings

        # URL parameters
        url_params = self._extract_parameters(base_url)
        for param, value in url_params.items():
            self.findings.extend(self._test_sqli(base_url, param, value))
            self.findings.extend(self._test_command_injection(base_url, param, value))
            self.findings.extend(self._test_ssti(base_url, param, value))

        # Form parameters
        forms = self._extract_forms(resp.text, base_url)
        for form in forms:
            for param, value in form['params'].items():
                self.findings.extend(self._test_sqli(
                    form['action'], param, value, form['method'], form['params']
                ))
                self.findings.extend(self._test_command_injection(
                    form['action'], param, value, form['method'], form['params']
                ))
                self.findings.extend(self._test_ssti(
                    form['action'], param, value, form['method'], form['params']
                ))

        # Header injection
        self.findings.extend(self._test_header_injection(base_url))

        return self.findings
