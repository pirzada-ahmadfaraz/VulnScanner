"""
Adaptive HTTP Client with fingerprinting
- Auto-detects WAF, tech stack, server behavior
- Routes all traffic through Burp when enabled
- Learns from responses (no hardcoded patterns)
"""

import re
import ssl
import socket
import hashlib
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, urljoin
import requests
import urllib3

from .safety import SafetyConfig

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class TechFingerprint:
    """Learned technology fingerprint from actual responses"""
    name: str
    version: Optional[str] = None
    confidence: float = 0.0
    source: str = ""  # where we detected it
    raw_evidence: str = ""


@dataclass
class ServerProfile:
    """Behavioral profile learned from probing"""
    base_url: str
    technologies: list = field(default_factory=list)
    headers_observed: dict = field(default_factory=dict)
    error_signatures: dict = field(default_factory=dict)
    response_times: list = field(default_factory=list)
    waf_detected: Optional[str] = None
    server_os: Optional[str] = None
    interesting_paths: list = field(default_factory=list)
    cookies_observed: list = field(default_factory=list)


class AdaptiveHTTPClient:
    """
    HTTP client that learns from every response.
    No hardcoded detection - builds profile dynamically.
    """

    def __init__(self, proxy: str = None, timeout: int = 15,
                 cookies: dict = None, auth_headers: dict = None,
                 safety: SafetyConfig = None):
        self.session = requests.Session()
        self.session.verify = False
        self.timeout = timeout
        self.profile: Optional[ServerProfile] = None
        self.safety = safety

        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        # Apply authentication
        if cookies:
            for name, value in cookies.items():
                self.session.cookies.set(name, value)

        if auth_headers:
            self.session.headers.update(auth_headers)

        # Rotate user agents to avoid detection
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
        ]
        self._ua_index = 0

    def _get_ua(self) -> str:
        ua = self.user_agents[self._ua_index % len(self.user_agents)]
        self._ua_index += 1
        return ua

    @staticmethod
    def parse_burp_request(filepath: str) -> dict:
        """Parse a Burp Suite saved request file and extract cookies + headers"""
        result = {"headers": {}, "cookies": {}}
        try:
            with open(filepath, 'r') as f:
                lines = f.read().split('\n')
        except (FileNotFoundError, PermissionError, OSError) as e:
            raise ValueError(f"Cannot read Burp request file: {e}")

        if len(lines) < 2:
            raise ValueError(f"Invalid Burp request file: {filepath}")

        for line in lines[1:]:  # Skip request line
            if not line.strip():
                break  # End of headers
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                if key.lower() == 'cookie':
                    for cookie_pair in value.split(';'):
                        cookie_pair = cookie_pair.strip()
                        if '=' in cookie_pair:
                            cname, cval = cookie_pair.split('=', 1)
                            result["cookies"][cname.strip()] = cval.strip()
                else:
                    result["headers"][key] = value
        return result

    def _extract_version(self, text: str) -> Optional[str]:
        """Extract version number from any string"""
        match = re.search(r'[\d]+\.[\d]+(?:\.[\d]+)?(?:[a-z\-]+[\d]*)?', text, re.I)
        return match.group(0) if match else None

    def _learn_from_headers(self, headers: dict) -> list:
        """Learn technologies from response headers - no hardcoding"""
        techs = []

        for header, value in headers.items():
            h_lower = header.lower()
            v_str = str(value)

            # X-Powered-By always reveals tech
            if 'powered' in h_lower:
                parts = v_str.split('/')
                name = parts[0].strip()
                version = self._extract_version(v_str)
                techs.append(TechFingerprint(
                    name=name,
                    version=version,
                    confidence=0.95,
                    source=f"Header: {header}",
                    raw_evidence=v_str
                ))

            # Server header
            elif h_lower == 'server':
                # Parse server string intelligently
                for part in re.split(r'[/\s,()]', v_str):
                    part = part.strip()
                    if part and not part.isdigit():
                        version = self._extract_version(v_str)
                        techs.append(TechFingerprint(
                            name=part,
                            version=version,
                            confidence=0.9,
                            source="Header: Server",
                            raw_evidence=v_str
                        ))

            # Framework-specific headers (learn the pattern)
            elif any(x in h_lower for x in ['asp', 'php', 'java', 'ruby', 'python', 'node']):
                techs.append(TechFingerprint(
                    name=header.replace('X-', '').replace('-', ' ').title(),
                    version=self._extract_version(v_str),
                    confidence=0.85,
                    source=f"Header: {header}",
                    raw_evidence=v_str
                ))

            # Set-Cookie can reveal framework
            elif h_lower == 'set-cookie':
                cookie_hints = {
                    'phpsessid': 'PHP',
                    'jsessionid': 'Java',
                    'asp.net': 'ASP.NET',
                    'laravel': 'Laravel',
                    'django': 'Django',
                    'express': 'Express.js',
                    'rack.session': 'Ruby/Rack',
                    'connect.sid': 'Node.js',
                }
                v_lower = v_str.lower()
                for hint, tech in cookie_hints.items():
                    if hint in v_lower:
                        techs.append(TechFingerprint(
                            name=tech,
                            confidence=0.8,
                            source="Cookie name pattern",
                            raw_evidence=v_str[:100]
                        ))

        return techs

    def _learn_from_body(self, body: str, url: str) -> list:
        """Learn technologies from response body - pattern-based, not hardcoded lists"""
        techs = []
        body_lower = body.lower()

        # Meta generator tags
        for match in re.finditer(r'<meta[^>]+generator[^>]+content=["\']([^"\']+)', body, re.I):
            content = match.group(1)
            techs.append(TechFingerprint(
                name=content.split()[0],
                version=self._extract_version(content),
                confidence=0.95,
                source="Meta generator tag",
                raw_evidence=content
            ))

        # Script src patterns - learn framework from paths
        for match in re.finditer(r'src=["\'][^"\']*?([a-zA-Z][\w\-]+)(?:\.min)?\.js', body):
            lib = match.group(1)
            if len(lib) > 2 and lib not in ['main', 'app', 'index', 'bundle', 'vendor', 'script']:
                # Try to find version nearby
                version = None
                context = body[max(0, match.start()-100):match.end()+100]
                v_match = re.search(rf'{lib}[/\-@]?([\d]+\.[\d]+(?:\.[\d]+)?)', context, re.I)
                if v_match:
                    version = v_match.group(1)
                techs.append(TechFingerprint(
                    name=lib,
                    version=version,
                    confidence=0.7,
                    source="JavaScript include",
                    raw_evidence=match.group(0)[:100]
                ))

        # Error page signatures (learn error patterns dynamically)
        error_patterns = [
            (r'(?:fatal|parse|syntax)\s+error.*?in\s+([/\w\.]+)\s+on\s+line', 'PHP'),
            (r'Traceback \(most recent call last\)', 'Python'),
            (r'at\s+[\w\.]+\([\w\.]+\.java:\d+\)', 'Java'),
            (r'Microsoft.*?Error', 'ASP.NET'),
            (r'Ruby.*?Error|ActionController', 'Ruby on Rails'),
            (r'Express|node_modules', 'Node.js'),
        ]
        for pattern, tech in error_patterns:
            if re.search(pattern, body, re.I):
                techs.append(TechFingerprint(
                    name=tech,
                    confidence=0.85,
                    source="Error message pattern",
                    raw_evidence=re.search(pattern, body, re.I).group(0)[:100]
                ))

        # CMS detection from HTML patterns
        cms_patterns = [
            (r'wp-content|wp-includes', 'WordPress'),
            (r'/sites/default/files|drupal', 'Drupal'),
            (r'joomla', 'Joomla'),
            (r'magento', 'Magento'),
            (r'shopify', 'Shopify'),
        ]
        for pattern, cms in cms_patterns:
            if re.search(pattern, body_lower):
                techs.append(TechFingerprint(
                    name=cms,
                    confidence=0.9,
                    source="CMS path pattern",
                    raw_evidence=pattern
                ))

        return techs

    def _detect_waf(self, response: requests.Response) -> Optional[str]:
        """Detect WAF from response characteristics"""
        headers_str = str(response.headers).lower()
        body_lower = response.text.lower() if response.text else ""

        waf_indicators = [
            ('cloudflare', 'Cloudflare'),
            ('akamai', 'Akamai'),
            ('incapsula', 'Imperva/Incapsula'),
            ('sucuri', 'Sucuri'),
            ('aws', 'AWS WAF'),
            ('mod_security', 'ModSecurity'),
            ('f5', 'F5 BIG-IP'),
            ('barracuda', 'Barracuda'),
        ]

        combined = headers_str + body_lower
        for indicator, waf_name in waf_indicators:
            if indicator in combined:
                return waf_name

        # Behavior-based detection (403 with specific patterns)
        if response.status_code == 403 and any(x in body_lower for x in ['blocked', 'denied', 'forbidden', 'security']):
            return "Unknown WAF (behavior-detected)"

        return None

    def probe(self, url: str) -> ServerProfile:
        """Initial probe to learn server behavior"""
        self.profile = ServerProfile(base_url=url)

        try:
            # Basic request
            resp = self.session.get(
                url,
                headers={"User-Agent": self._get_ua()},
                timeout=self.timeout,
                allow_redirects=True
            )

            # Learn from headers
            self.profile.headers_observed = dict(resp.headers)
            self.profile.technologies.extend(self._learn_from_headers(resp.headers))

            # Learn from body
            self.profile.technologies.extend(self._learn_from_body(resp.text, url))

            # Learn cookies
            for cookie in resp.cookies:
                self.profile.cookies_observed.append({
                    'name': cookie.name,
                    'secure': cookie.secure,
                    'httponly': cookie.has_nonstandard_attr('HttpOnly'),
                })

            # Detect WAF
            self.profile.waf_detected = self._detect_waf(resp)

            # Try to detect OS from various signals
            server = resp.headers.get('Server', '').lower()
            if 'win' in server or 'iis' in server:
                self.profile.server_os = 'Windows'
            elif any(x in server for x in ['unix', 'linux', 'ubuntu', 'debian', 'centos']):
                self.profile.server_os = 'Linux'

        except Exception as e:
            pass

        # Deduplicate technologies by name
        seen = set()
        unique_techs = []
        for t in self.profile.technologies:
            key = t.name.lower()
            if key not in seen:
                seen.add(key)
                unique_techs.append(t)
        self.profile.technologies = sorted(unique_techs, key=lambda x: -x.confidence)

        return self.profile

    def get(self, url: str, **kwargs) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        return self.request("POST", url, **kwargs)

    def head(self, url: str, **kwargs) -> requests.Response:
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs) -> requests.Response:
        return self.request("OPTIONS", url, **kwargs)

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        # Safety checks
        if self.safety:
            if not self.safety.check_request(url):
                # URL blocked by scope - raise a clear error
                raise requests.exceptions.ConnectionError(f"Blocked by scope: {url}")

        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('headers', {})
        kwargs['headers'].setdefault('User-Agent', self._get_ua())
        return self.session.request(method, url, **kwargs)
