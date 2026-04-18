"""
Web Crawler Module
- Same-origin link following with configurable depth
- Form extraction with input discovery
- JavaScript endpoint detection (fetch, axios, XMLHttpRequest, /api/ patterns)
- Comment URL extraction
- robots.txt parsing
- Threaded parallel crawling
- URL normalization and deduplication
- Site graph construction
"""

import re
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Callable, Tuple
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs, urlencode, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser

from ..core.finding import Finding
from ..core.http_client import AdaptiveHTTPClient


# ---------------------------------------------------------------------------
# CrawlResult dataclass
# ---------------------------------------------------------------------------

@dataclass
class CrawlResult:
    """Result container for a web crawl session"""

    # Each page dict: url, status, content_type, title, links_found
    pages: List[Dict] = field(default_factory=list)

    # Each form dict: url, action, method, inputs (list of {name, type})
    forms: List[Dict] = field(default_factory=list)

    # Unique discovered page/API endpoints
    endpoints: List[str] = field(default_factory=list)

    # Endpoints discovered inside JavaScript source
    js_endpoints: List[str] = field(default_factory=list)

    # Adjacency list  page -> [linked pages]
    graph: Dict[str, List[str]] = field(default_factory=dict)

    # url -> list of parameter names found in query strings / form inputs
    parameters: Dict[str, List[str]] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Lightweight HTML link / form parser
# ---------------------------------------------------------------------------

class _LinkFormParser(HTMLParser):
    """Fast single-pass HTML parser that extracts links, forms, and title."""

    def __init__(self):
        super().__init__()
        self.links: List[str] = []
        self.forms: List[Dict] = []
        self.title: str = ""

        self._in_title = False
        self._title_parts: List[str] = []
        self._current_form: Optional[Dict] = None

    # ---- helpers ----

    def _attr(self, attrs, name):
        for k, v in attrs:
            if k.lower() == name:
                return v
        return None

    # ---- handlers ----

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()

        if tag == "a":
            href = self._attr(attrs, "href")
            if href:
                self.links.append(href)

        elif tag == "form":
            self._current_form = {
                "action": self._attr(attrs, "action") or "",
                "method": (self._attr(attrs, "method") or "GET").upper(),
                "inputs": [],
            }

        elif tag == "input" and self._current_form is not None:
            name = self._attr(attrs, "name")
            itype = self._attr(attrs, "type") or "text"
            if name:
                self._current_form["inputs"].append({"name": name, "type": itype})

        elif tag == "textarea" and self._current_form is not None:
            name = self._attr(attrs, "name")
            if name:
                self._current_form["inputs"].append({"name": name, "type": "textarea"})

        elif tag == "select" and self._current_form is not None:
            name = self._attr(attrs, "name")
            if name:
                self._current_form["inputs"].append({"name": name, "type": "select"})

        elif tag == "title":
            self._in_title = True

        # Also pick up <link>, <script src>, <img src>, <iframe src>
        if tag in ("link", "script", "img", "iframe", "source", "embed"):
            src = self._attr(attrs, "src") or self._attr(attrs, "href")
            if src:
                self.links.append(src)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "title":
            self._in_title = False
            self.title = "".join(self._title_parts).strip()

        elif tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def handle_data(self, data):
        if self._in_title:
            self._title_parts.append(data)


# ---------------------------------------------------------------------------
# Sensitive path patterns for finding generation
# ---------------------------------------------------------------------------

_SENSITIVE_PATHS = {
    "admin": ("Admin Panel Discovered", "MEDIUM",
              "An administrative interface was found during crawling."),
    "administrator": ("Admin Panel Discovered", "MEDIUM",
                      "An administrative interface was found during crawling."),
    "dashboard": ("Dashboard Discovered", "LOW",
                  "A dashboard page was found during crawling."),
    "phpmyadmin": ("phpMyAdmin Discovered", "HIGH",
                   "phpMyAdmin database management interface is publicly accessible."),
    "wp-admin": ("WordPress Admin", "LOW",
                 "WordPress admin panel was found."),
    "cpanel": ("cPanel Discovered", "MEDIUM",
               "cPanel control panel was found."),
    "swagger": ("API Documentation Exposed", "LOW",
                "Swagger/OpenAPI documentation is publicly accessible."),
    "graphql": ("GraphQL Endpoint Discovered", "LOW",
                "A GraphQL endpoint was found during crawling."),
    "api-docs": ("API Documentation Exposed", "LOW",
                 "API documentation is publicly accessible."),
    "debug": ("Debug Endpoint Discovered", "MEDIUM",
              "A debug endpoint was found, potentially leaking internal state."),
    "actuator": ("Spring Actuator Exposed", "HIGH",
                 "Spring Boot Actuator endpoints are publicly accessible."),
    "elmah": ("ELMAH Error Log Exposed", "MEDIUM",
              "ELMAH error logging interface is publicly accessible."),
    "server-status": ("Server Status Exposed", "MEDIUM",
                      "Apache server-status page is publicly accessible."),
    "server-info": ("Server Info Exposed", "MEDIUM",
                    "Apache server-info page is publicly accessible."),
    ".git": ("Git Repository Exposed", "HIGH",
             "Git repository metadata is publicly accessible."),
    ".env": ("Environment File Exposed", "CRITICAL",
             "Environment file with potential secrets is publicly accessible."),
    "backup": ("Backup File/Directory", "MEDIUM",
               "Backup files or directory discovered during crawling."),
}


# ---------------------------------------------------------------------------
# WebCrawler
# ---------------------------------------------------------------------------

class WebCrawler:
    """
    Threaded web crawler that discovers endpoints, forms, and JS routes.

    Compatible with the VulnScan Pro module system:
        crawler = WebCrawler(client)
        findings = crawler.scan(base_url)

    For richer results use crawl() directly:
        result = crawler.crawl(base_url)
    """

    # Regex patterns for extracting endpoints from JavaScript
    _JS_ENDPOINT_PATTERNS = [
        # fetch("url") / fetch('url')
        re.compile(r'''fetch\s*\(\s*['"]([^'"]+)['"]''', re.I),
        # axios.get / .post / .put / .delete / .patch("url")
        re.compile(r'''axios\.\w+\s*\(\s*['"]([^'"]+)['"]''', re.I),
        # XMLHttpRequest open
        re.compile(r'''\.open\s*\(\s*['"][A-Z]+['"]\s*,\s*['"]([^'"]+)['"]''', re.I),
        # $.ajax / $.get / $.post
        re.compile(r'''\$\.(?:ajax|get|post|put|delete)\s*\(\s*['"]([^'"]+)['"]''', re.I),
        # url: "..." inside config objects
        re.compile(r'''['"]?url['"]?\s*:\s*['"]([^'"]+)['"]''', re.I),
        # /api/ paths in strings
        re.compile(r'''['"](/api/[^'"]{2,})['"]'''),
        # /v1/ /v2/ /v3/ paths in strings
        re.compile(r'''['"](/v[1-3]/[^'"]{2,})['"]'''),
        # Generic REST-ish paths
        re.compile(r'''['"](/(?:rest|graphql|gql|query|webhook|callback)/[^'"]{2,})['"]'''),
    ]

    # Patterns for URLs inside HTML comments
    _COMMENT_URL_RE = re.compile(
        r'https?://[^\s<>"\']+|/[a-zA-Z0-9_\-/.]+(?:\?[^\s<>"\']*)?',
    )

    # File extensions we never want to follow
    _SKIP_EXTENSIONS = frozenset([
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
        ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv", ".webm",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".zip", ".tar", ".gz", ".rar", ".7z", ".bz2",
        ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".css",
    ])

    def __init__(self, client: AdaptiveHTTPClient, max_depth: int = 3,
                 max_pages: int = 100, threads: int = 10):
        self.client = client
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.threads = threads

        # Internal state (reset per crawl)
        self._visited: Set[str] = set()
        self._queued: Set[str] = set()
        self._forms: List[Dict] = []
        self._js_endpoints: Set[str] = set()
        self._graph: Dict[str, List[str]] = {}
        self._pages: List[Dict] = []
        self._parameters: Dict[str, List[str]] = {}
        self._base_origin: str = ""
        self._robots_disallowed: Set[str] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def crawl(self, base_url: str, callback: Callable = None) -> CrawlResult:
        """
        Crawl *base_url* following same-origin links up to *max_depth*.

        Args:
            base_url: Starting URL.
            callback: Optional  ``callback(msg_type, msg)`` where
                      *msg_type* is ``"info"``, ``"probe"``, or ``"success"``.

        Returns:
            A populated :class:`CrawlResult`.
        """
        # Reset state
        self._visited = set()
        self._queued = set()
        self._forms = []
        self._js_endpoints = set()
        self._graph = {}
        self._pages = []
        self._parameters = {}

        parsed = urlparse(base_url)
        self._base_origin = f"{parsed.scheme}://{parsed.netloc}"

        # Normalise the seed URL
        base_url = self._normalise(base_url)

        # Optionally fetch robots.txt
        self._parse_robots(callback)

        if callback:
            callback("info", f"Starting crawl from {base_url} (depth={self.max_depth}, max={self.max_pages})")

        # BFS with depth tracking
        # queue items: (url, depth)
        queue: List[Tuple[str, int]] = [(base_url, 0)]
        self._queued.add(base_url)

        while queue and len(self._visited) < self.max_pages:
            # Grab a batch of URLs at the same or similar depth
            batch = []
            while queue and len(batch) < self.threads:
                batch.append(queue.pop(0))

            # Process batch in parallel
            with ThreadPoolExecutor(max_workers=min(self.threads, len(batch))) as executor:
                future_to_item = {
                    executor.submit(self._fetch_page, url, depth, callback): (url, depth)
                    for url, depth in batch
                    if url not in self._visited
                }

                for future in as_completed(future_to_item):
                    url, depth = future_to_item[future]
                    try:
                        child_links = future.result()
                    except Exception:
                        child_links = []

                    # Enqueue children if within depth
                    if depth < self.max_depth:
                        for link in child_links:
                            if (link not in self._queued
                                    and link not in self._visited
                                    and len(self._queued) < self.max_pages):
                                self._queued.add(link)
                                queue.append((link, depth + 1))

        # Collect all discovered endpoints (visited pages + JS endpoints)
        all_endpoints = sorted(self._visited | self._js_endpoints)

        if callback:
            callback("success",
                     f"Crawl complete: {len(self._visited)} pages, "
                     f"{len(self._forms)} forms, "
                     f"{len(self._js_endpoints)} JS endpoints")

        return CrawlResult(
            pages=list(self._pages),
            forms=list(self._forms),
            endpoints=all_endpoints,
            js_endpoints=sorted(self._js_endpoints),
            graph=dict(self._graph),
            parameters=dict(self._parameters),
        )

    def scan(self, base_url: str, callback: Callable = None) -> List[Finding]:
        """
        Module-compatible scan interface.

        Runs :meth:`crawl` internally, then converts interesting discoveries
        into :class:`Finding` objects.
        """
        result = self.crawl(base_url, callback=callback)
        findings: List[Finding] = []

        # --- Sensitive paths ---
        for page in result.pages:
            page_url = page.get("url", "")
            path_lower = urlparse(page_url).path.lower().rstrip("/")
            last_segment = path_lower.rsplit("/", 1)[-1]

            for keyword, (vuln_class, severity, desc) in _SENSITIVE_PATHS.items():
                if keyword in last_segment or keyword in path_lower:
                    findings.append(Finding(
                        vuln_class=vuln_class,
                        severity=severity,
                        url=page_url,
                        description=desc,
                        evidence={"status": page.get("status"), "title": page.get("title")},
                        tags=["crawl", "discovery"],
                        remediation=[
                            "Restrict access to sensitive paths",
                            "Implement proper authentication and authorization",
                        ],
                    ))
                    break  # one finding per page

        # --- Forms without CSRF tokens ---
        csrf_names = {"csrf", "csrftoken", "csrf_token", "_csrf", "xsrf",
                      "xsrf_token", "_xsrf", "__requestverificationtoken",
                      "authenticity_token", "anticsrf", "token"}

        for form in result.forms:
            if form["method"] == "POST":
                input_names = {inp["name"].lower() for inp in form.get("inputs", [])}
                has_csrf = bool(input_names & csrf_names)

                # Also consider hidden inputs whose name looks like a token
                hidden_names = {inp["name"].lower() for inp in form.get("inputs", [])
                                if inp.get("type") == "hidden"}
                has_csrf = has_csrf or bool(hidden_names & csrf_names)

                if not has_csrf:
                    findings.append(Finding(
                        vuln_class="Form Missing CSRF Protection",
                        severity="MEDIUM",
                        url=form.get("url", base_url),
                        description=(
                            f"A POST form (action={form.get('action', '?')}) "
                            f"does not contain a CSRF token."
                        ),
                        evidence={
                            "form_action": form.get("action"),
                            "form_method": form["method"],
                            "inputs": [i["name"] for i in form.get("inputs", [])],
                        },
                        tags=["crawl", "csrf", "form"],
                        remediation=[
                            "Add a CSRF token to all state-changing forms",
                            "Use the SameSite cookie attribute as defense-in-depth",
                        ],
                    ))

        # --- JS endpoints that look like internal API routes ---
        for ep in result.js_endpoints:
            ep_lower = ep.lower()
            if any(kw in ep_lower for kw in ["/internal", "/debug", "/admin",
                                              "/private", "/secret", "/config"]):
                findings.append(Finding(
                    vuln_class="Sensitive JS Endpoint Discovered",
                    severity="LOW",
                    url=ep if ep.startswith("http") else urljoin(base_url, ep),
                    description=(
                        f"A potentially sensitive endpoint was referenced in JavaScript: {ep}"
                    ),
                    tags=["crawl", "javascript", "api"],
                    remediation=[
                        "Remove references to internal endpoints from client-side code",
                        "Implement proper authentication on sensitive routes",
                    ],
                ))

        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_robots(self, callback: Callable = None):
        """Try to parse robots.txt to learn disallowed paths (best effort)."""
        robots_url = f"{self._base_origin}/robots.txt"
        try:
            resp = self.client.get(robots_url, timeout=8)
            if resp.status_code == 200 and "text" in resp.headers.get("Content-Type", ""):
                if callback:
                    callback("info", "Parsed robots.txt")
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            self._robots_disallowed.add(path)
                            # Treat disallowed paths as interesting endpoints
                            full = urljoin(self._base_origin, path)
                            self._js_endpoints.add(full)
        except Exception:
            pass

    def _normalise(self, url: str) -> str:
        """Normalise a URL for deduplication purposes."""
        parsed = urlparse(url)
        # Remove fragment
        # Sort query parameters
        query = parse_qs(parsed.query, keep_blank_values=True)
        sorted_query = urlencode(sorted(query.items()), doseq=True)
        # Lowercase scheme and host
        normalised = urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path.rstrip("/") or "/",
            parsed.params,
            sorted_query,
            "",  # drop fragment
        ))
        return normalised

    def _is_same_origin(self, url: str) -> bool:
        """Check whether *url* belongs to the same origin as the crawl base."""
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        return origin.lower() == self._base_origin.lower()

    def _should_skip(self, url: str) -> bool:
        """Return True if *url* should not be fetched (binary, off-origin, etc)."""
        parsed = urlparse(url)
        path_lower = parsed.path.lower()

        # Skip known binary / static extensions
        for ext in self._SKIP_EXTENSIONS:
            if path_lower.endswith(ext):
                return True

        # Skip non-HTTP schemes
        if parsed.scheme not in ("http", "https"):
            return True

        # Skip off-origin
        if not self._is_same_origin(url):
            return True

        return False

    def _fetch_page(self, url: str, depth: int,
                    callback: Callable = None) -> List[str]:
        """
        Fetch a single page, parse it, record forms/JS endpoints,
        and return a list of same-origin child links.
        """
        if url in self._visited:
            return []

        self._visited.add(url)

        if callback:
            callback("probe", f"[depth={depth}] {url}")

        try:
            resp = self.client.get(url, timeout=12, allow_redirects=True)
        except Exception:
            return []

        status = resp.status_code
        content_type = resp.headers.get("Content-Type", "")
        body = resp.text if hasattr(resp, "text") else ""

        # Record query-string parameters
        parsed_url = urlparse(url)
        qs_params = list(parse_qs(parsed_url.query).keys())
        if qs_params:
            self._parameters.setdefault(url, []).extend(qs_params)

        # Only parse HTML responses for links/forms
        child_links: List[str] = []

        if "html" in content_type.lower():
            child_links = self._parse_html(url, body, callback)
        elif "javascript" in content_type.lower() or "application/json" in content_type.lower():
            self._extract_js_endpoints(body, url)

        # Record page info
        title = ""
        if "html" in content_type.lower():
            title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
            if title_match:
                title = title_match.group(1).strip()[:200]

        self._pages.append({
            "url": url,
            "status": status,
            "content_type": content_type,
            "title": title,
            "links_found": len(child_links),
        })

        return child_links

    def _parse_html(self, page_url: str, html: str,
                    callback: Callable = None) -> List[str]:
        """Parse HTML for links, forms, inline JS endpoints, and comments."""
        parser = _LinkFormParser()
        try:
            parser.feed(html)
        except Exception:
            pass

        # Resolve and filter links
        resolved: List[str] = []
        for raw in parser.links:
            raw = raw.strip()
            if not raw or raw.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
                continue
            full = urljoin(page_url, raw)
            normalised = self._normalise(full)
            if not self._should_skip(normalised):
                resolved.append(normalised)

        # Record graph edges
        unique_children = list(dict.fromkeys(resolved))  # preserve order, dedup
        self._graph[page_url] = unique_children

        # Record forms
        for form_data in parser.forms:
            action_url = urljoin(page_url, form_data["action"]) if form_data["action"] else page_url
            form_record = {
                "url": page_url,
                "action": action_url,
                "method": form_data["method"],
                "inputs": form_data["inputs"],
            }
            self._forms.append(form_record)

            # Record form input names as parameters
            param_names = [inp["name"] for inp in form_data["inputs"] if inp.get("name")]
            if param_names:
                self._parameters.setdefault(action_url, []).extend(param_names)

        # Extract JS endpoints from inline scripts
        inline_scripts = re.findall(
            r"<script[^>]*>(.*?)</script>", html, re.S | re.I,
        )
        for script_body in inline_scripts:
            self._extract_js_endpoints(script_body, page_url)

        # Extract URLs from HTML comments
        comments = re.findall(r"<!--(.*?)-->", html, re.S)
        for comment in comments:
            for match in self._COMMENT_URL_RE.findall(comment):
                match = match.strip()
                if match.startswith("http"):
                    normalised = self._normalise(match)
                    if self._is_same_origin(normalised):
                        self._js_endpoints.add(normalised)
                elif match.startswith("/"):
                    full = urljoin(self._base_origin, match)
                    self._js_endpoints.add(self._normalise(full))

        return unique_children

    def _extract_js_endpoints(self, js_text: str, source_url: str):
        """Pull API / fetch / axios endpoints out of JavaScript text."""
        for pattern in self._JS_ENDPOINT_PATTERNS:
            for match in pattern.finditer(js_text):
                raw = match.group(1).strip()
                if not raw or len(raw) < 2 or len(raw) > 500:
                    continue
                # Skip data-URIs, templates with unresolved vars, etc.
                if any(c in raw for c in ["{", "}", "$", "`"]):
                    continue

                if raw.startswith("http"):
                    normalised = self._normalise(raw)
                    if self._is_same_origin(normalised):
                        self._js_endpoints.add(normalised)
                elif raw.startswith("/"):
                    full = urljoin(self._base_origin, raw)
                    self._js_endpoints.add(self._normalise(full))
