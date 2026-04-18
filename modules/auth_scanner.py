"""
Module: Authentication Security Scanner
- User enumeration via response analysis
- Brute force protection detection
- Password policy analysis
- Session management issues
- JWT vulnerabilities
"""

import re
import time
import json
import base64
import hashlib
from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

from ..core.finding import Finding
from ..core.http_client import AdaptiveHTTPClient


class AuthScanner:
    """Authentication and session security scanner"""

    def __init__(self, client: AdaptiveHTTPClient):
        self.client = client
        self.findings: List[Finding] = []

    def _find_forms(self, html: str, url: str) -> List[Dict]:
        """Extract forms from HTML with field analysis"""
        forms = []

        if not HAS_BS4:
            # Fallback to regex-based form detection
            return self._find_forms_regex(html, url)

        soup = BeautifulSoup(html, 'html.parser')

        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': (form.get('method', 'GET')).upper(),
                'fields': [],
                'has_password': False,
                'has_username': False,
                'has_email': False,
                'has_csrf': False,
            }

            for inp in form.find_all(['input', 'select', 'textarea']):
                field = {
                    'name': inp.get('name', ''),
                    'type': inp.get('type', 'text'),
                    'id': inp.get('id', ''),
                    'value': inp.get('value', ''),
                }
                form_data['fields'].append(field)

                name_lower = (field['name'] or field['id'] or '').lower()
                type_lower = field['type'].lower()

                if type_lower == 'password' or 'pass' in name_lower:
                    form_data['has_password'] = True
                if any(x in name_lower for x in ['user', 'login', 'account', 'name']):
                    form_data['has_username'] = True
                if 'email' in name_lower or '@' in field.get('value', ''):
                    form_data['has_email'] = True
                if any(x in name_lower for x in ['csrf', 'token', '_token', 'nonce', 'authenticity']):
                    form_data['has_csrf'] = True

            # Only include authentication-related forms
            if form_data['has_password'] or form_data['has_username']:
                forms.append(form_data)

        return forms

    def _find_forms_regex(self, html: str, url: str) -> List[Dict]:
        """Fallback regex-based form detection when bs4 is not available"""
        forms = []

        # Find all forms
        form_pattern = r'<form[^>]*>(.*?)</form>'
        form_matches = re.findall(form_pattern, html, re.DOTALL | re.IGNORECASE)

        for i, form_html in enumerate(form_matches):
            # Extract action
            action_match = re.search(r'action=["\']([^"\']*)["\']', html, re.IGNORECASE)
            action = action_match.group(1) if action_match else ''

            # Extract method
            method_match = re.search(r'method=["\']([^"\']*)["\']', html, re.IGNORECASE)
            method = (method_match.group(1) if method_match else 'GET').upper()

            form_data = {
                'action': action,
                'method': method,
                'fields': [],
                'has_password': False,
                'has_username': False,
                'has_email': False,
                'has_csrf': False,
            }

            # Find inputs
            input_pattern = r'<input[^>]*>'
            for inp_match in re.finditer(input_pattern, form_html, re.IGNORECASE):
                inp_tag = inp_match.group(0)

                name_match = re.search(r'name=["\']([^"\']*)["\']', inp_tag, re.IGNORECASE)
                type_match = re.search(r'type=["\']([^"\']*)["\']', inp_tag, re.IGNORECASE)
                value_match = re.search(r'value=["\']([^"\']*)["\']', inp_tag, re.IGNORECASE)

                field = {
                    'name': name_match.group(1) if name_match else '',
                    'type': type_match.group(1) if type_match else 'text',
                    'id': '',
                    'value': value_match.group(1) if value_match else '',
                }

                name_lower = field['name'].lower()
                if field['type'] == 'password':
                    form_data['has_password'] = True
                if any(x in name_lower for x in ['user', 'login', 'account', 'name']):
                    form_data['has_username'] = True
                if 'email' in name_lower:
                    form_data['has_email'] = True
                if any(x in name_lower for x in ['csrf', 'token', '_token', 'authenticity']):
                    form_data['has_csrf'] = True

                form_data['fields'].append(field)

            if form_data['has_password']:
                forms.append(form_data)

        return forms

    def _detect_user_enumeration(self, url: str, form: Dict) -> List[Finding]:
        """Test for user enumeration via response differences"""
        findings = []

        # Find the username/email field
        user_field = None
        pass_field = None
        for f in form['fields']:
            name_lower = (f['name'] or '').lower()
            if any(x in name_lower for x in ['user', 'login', 'email', 'account']):
                user_field = f['name']
            if f['type'] == 'password' or 'pass' in name_lower:
                pass_field = f['name']

        if not user_field or not pass_field:
            return findings

        action = urljoin(url, form['action']) if form['action'] else url

        # Build test payloads
        fake_user = "vulnscan_nonexistent_user_xyz789@test.invalid"
        likely_user = "admin"
        test_pass = "VulnScanTestPass123!@#"

        # Prepare form data with any hidden fields
        base_data = {f['name']: f['value'] for f in form['fields']
                     if f['name'] and f['type'] == 'hidden'}

        try:
            # Test with fake user
            data_fake = {**base_data, user_field: fake_user, pass_field: test_pass}
            time1 = time.time()
            resp_fake = self.client.post(action, data=data_fake, allow_redirects=True, timeout=15)
            time_fake = time.time() - time1

            # Test with likely valid user
            data_real = {**base_data, user_field: likely_user, pass_field: test_pass}
            time2 = time.time()
            resp_real = self.client.post(action, data=data_real, allow_redirects=True, timeout=15)
            time_real = time.time() - time2

            # Analyze response differences
            text_fake = resp_fake.text.lower()
            text_real = resp_real.text.lower()

            # Content-based enumeration
            enumeration_indicators = {
                'fake': ['not found', 'does not exist', 'no user', 'invalid user',
                         'unknown user', 'user not', 'not registered', 'no account'],
                'real': ['wrong password', 'incorrect password', 'invalid password',
                         'password incorrect', 'check your password'],
            }

            found_fake = any(ind in text_fake for ind in enumeration_indicators['fake'])
            found_real = any(ind in text_real for ind in enumeration_indicators['real'])

            # Length difference analysis
            len_diff = abs(len(resp_fake.text) - len(resp_real.text))
            len_diff_pct = len_diff / max(len(resp_fake.text), 1) * 100

            # Timing difference analysis
            time_diff = abs(time_fake - time_real)

            is_enumerable = False
            evidence = {}

            if found_fake or found_real:
                is_enumerable = True
                evidence['content_difference'] = {
                    'fake_user_indicators': found_fake,
                    'real_user_indicators': found_real,
                }

            if len_diff_pct > 10:  # More than 10% difference
                is_enumerable = True
                evidence['length_difference'] = {
                    'fake_length': len(resp_fake.text),
                    'real_length': len(resp_real.text),
                    'difference_pct': f"{len_diff_pct:.1f}%",
                }

            if time_diff > 0.5:  # More than 500ms difference
                evidence['timing_difference'] = {
                    'fake_time': f"{time_fake:.3f}s",
                    'real_time': f"{time_real:.3f}s",
                    'difference': f"{time_diff:.3f}s",
                }
                # Timing alone is a lower confidence indicator
                if time_diff > 1.0:
                    is_enumerable = True

            if is_enumerable:
                findings.append(Finding(
                    vuln_class="User Enumeration",
                    severity="MEDIUM",
                    cvss=5.3,
                    url=action,
                    parameter=user_field,
                    description="Login form reveals whether usernames exist through different responses.",
                    evidence=evidence,
                    remediation=[
                        "Use generic error message: 'Invalid username or password'",
                        "Ensure consistent response time regardless of user validity",
                        "Implement rate limiting and account lockout",
                    ],
                    tags=["authentication", "enumeration"],
                ))

        except Exception as e:
            pass

        return findings

    def _check_bruteforce_protection(self, url: str, form: Dict) -> List[Finding]:
        """Check for brute force protection mechanisms"""
        findings = []

        user_field = None
        pass_field = None
        for f in form['fields']:
            name_lower = (f['name'] or '').lower()
            if any(x in name_lower for x in ['user', 'login', 'email']):
                user_field = f['name']
            if f['type'] == 'password' or 'pass' in name_lower:
                pass_field = f['name']

        if not user_field or not pass_field:
            return findings

        action = urljoin(url, form['action']) if form['action'] else url

        base_data = {f['name']: f['value'] for f in form['fields']
                     if f['name'] and f['type'] == 'hidden'}

        # Send multiple rapid requests
        test_user = "bruteforce_test_user"
        responses = []

        for i in range(6):
            try:
                data = {**base_data, user_field: test_user, pass_field: f"wrongpass{i}"}
                resp = self.client.post(action, data=data, allow_redirects=True, timeout=10)
                responses.append({
                    'status': resp.status_code,
                    'length': len(resp.text),
                    'has_captcha': any(x in resp.text.lower() for x in ['captcha', 'recaptcha', 'hcaptcha']),
                    'is_blocked': resp.status_code in [429, 403] or 'blocked' in resp.text.lower(),
                })
            except Exception:
                break

        if len(responses) >= 5:
            # Check if we got blocked or captcha appeared
            got_blocked = any(r['is_blocked'] for r in responses[3:])
            got_captcha = any(r['has_captcha'] for r in responses[3:])

            if not got_blocked and not got_captcha:
                findings.append(Finding(
                    vuln_class="No Brute Force Protection",
                    severity="MEDIUM",
                    cvss=5.5,
                    url=action,
                    description="Login form lacks rate limiting or account lockout after multiple failed attempts.",
                    evidence={
                        'requests_made': len(responses),
                        'all_succeeded': all(r['status'] == 200 for r in responses),
                        'no_captcha': not any(r['has_captcha'] for r in responses),
                    },
                    remediation=[
                        "Implement rate limiting (e.g., 5 attempts per minute)",
                        "Add account lockout after N failed attempts",
                        "Implement CAPTCHA after failed attempts",
                        "Use progressive delays between attempts",
                    ],
                    tags=["authentication", "brute-force"],
                ))

        return findings

    def _check_csrf_protection(self, url: str, form: Dict) -> List[Finding]:
        """Check for CSRF protection on authentication forms"""
        findings = []

        if form['method'] != 'POST':
            return findings

        if not form['has_csrf']:
            findings.append(Finding(
                vuln_class="Missing CSRF Protection",
                severity="MEDIUM",
                cvss=6.1,
                url=url,
                description="Authentication form lacks CSRF token. Login/logout CSRF attacks possible.",
                evidence={
                    'form_action': form['action'],
                    'fields': [f['name'] for f in form['fields'] if f['name']],
                },
                remediation=[
                    "Add CSRF token to all state-changing forms",
                    "Validate token server-side",
                    "Use SameSite cookie attribute",
                ],
                tags=["csrf", "authentication"],
            ))

        return findings

    def _analyze_jwt(self, token: str, url: str) -> List[Finding]:
        """Analyze JWT token for security issues"""
        findings = []

        try:
            parts = token.split('.')
            if len(parts) != 3:
                return findings

            # Decode header
            header_b64 = parts[0] + '=' * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))

            # Decode payload
            payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            alg = header.get('alg', '').upper()

            # Check for none algorithm
            if alg == 'NONE' or alg == '':
                findings.append(Finding(
                    vuln_class="JWT None Algorithm",
                    severity="CRITICAL",
                    cvss=9.8,
                    url=url,
                    description="JWT uses 'none' algorithm, allowing forged tokens without signature.",
                    evidence={'header': header},
                    remediation=[
                        "Never accept 'none' algorithm",
                        "Whitelist allowed algorithms",
                        "Validate algorithm matches expected",
                    ],
                    tags=["jwt", "authentication", "critical"],
                ))

            # Check for weak algorithms
            if alg in ['HS256', 'HS384', 'HS512']:
                findings.append(Finding(
                    vuln_class="JWT Symmetric Algorithm",
                    severity="LOW",
                    url=url,
                    description=f"JWT uses symmetric algorithm ({alg}). Secret key must be strong and protected.",
                    evidence={'algorithm': alg},
                    remediation=[
                        "Use asymmetric algorithms (RS256, ES256) for better security",
                        "If using symmetric, ensure key is at least 256 bits random",
                        "Protect key from exposure",
                    ],
                    tags=["jwt", "authentication"],
                ))

            # Check for sensitive data in payload
            sensitive_keys = ['password', 'secret', 'key', 'ssn', 'credit_card', 'cc_number']
            for key in payload:
                if any(s in key.lower() for s in sensitive_keys):
                    findings.append(Finding(
                        vuln_class="Sensitive Data in JWT",
                        severity="HIGH",
                        url=url,
                        description=f"JWT payload contains potentially sensitive field: {key}",
                        evidence={'field': key, 'value': '***REDACTED***'},
                        remediation=[
                            "Never store sensitive data in JWT payloads",
                            "JWT payloads are only base64 encoded, not encrypted",
                            "Store sensitive data server-side",
                        ],
                        tags=["jwt", "information-disclosure"],
                    ))

            # Check expiration
            if 'exp' not in payload:
                findings.append(Finding(
                    vuln_class="JWT Missing Expiration",
                    severity="MEDIUM",
                    url=url,
                    description="JWT has no expiration (exp) claim. Tokens are valid forever.",
                    evidence={'payload_keys': list(payload.keys())},
                    remediation=[
                        "Always set exp claim",
                        "Use reasonable expiration times",
                        "Implement token refresh mechanism",
                    ],
                    tags=["jwt", "authentication"],
                ))

        except Exception:
            pass

        return findings

    def _find_login_pages(self, base_url: str) -> List[str]:
        """Discover login pages"""
        paths = [
            '/login', '/signin', '/sign-in', '/auth', '/authenticate',
            '/admin', '/admin/login', '/user/login', '/account/login',
            '/wp-login.php', '/wp-admin', '/administrator',
            '/members', '/portal', '/sso', '/oauth',
        ]

        found = []
        for path in paths:
            url = urljoin(base_url, path)
            try:
                resp = self.client.get(url, timeout=5, allow_redirects=True)
                if resp.status_code == 200:
                    # Check if it looks like a login page
                    text_lower = resp.text.lower()
                    if any(x in text_lower for x in ['password', 'login', 'sign in', 'log in']):
                        found.append(url)
            except Exception:
                continue

        return found

    def scan(self, base_url: str, login_urls: List[str] = None) -> List[Finding]:
        """Run full authentication security scan"""
        self.findings = []

        # Discover login pages if not provided
        if login_urls is None:
            login_urls = self._find_login_pages(base_url)

        # Also check base URL
        if base_url not in login_urls:
            login_urls.insert(0, base_url)

        for url in login_urls:
            try:
                resp = self.client.get(url, timeout=10)
                forms = self._find_forms(resp.text, url)

                for form in forms:
                    if form['has_password']:
                        # Check for user enumeration
                        self.findings.extend(self._detect_user_enumeration(url, form))

                        # Check for brute force protection
                        self.findings.extend(self._check_bruteforce_protection(url, form))

                        # Check for CSRF protection
                        self.findings.extend(self._check_csrf_protection(url, form))

                # Check for JWT in response
                for cookie in resp.cookies:
                    if 'jwt' in cookie.name.lower() or 'token' in cookie.name.lower():
                        self.findings.extend(self._analyze_jwt(cookie.value, url))

                # Check Authorization header in response
                auth_header = resp.headers.get('Authorization', '')
                if auth_header.startswith('Bearer '):
                    token = auth_header.split(' ')[1]
                    self.findings.extend(self._analyze_jwt(token, url))

            except Exception:
                continue

        return self.findings
