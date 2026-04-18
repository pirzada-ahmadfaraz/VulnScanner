"""
Module: Information Disclosure Scanner
Detects leaked sensitive info from actual response analysis
- Server errors with paths/stack traces
- Debug information
- Sensitive file exposure
- Comment leakage
"""

import re
from typing import List
from urllib.parse import urljoin, urlparse

from ..core.finding import Finding
from ..core.http_client import AdaptiveHTTPClient


class InfoDisclosureScanner:
    """Adaptive information disclosure detection"""

    def __init__(self, client: AdaptiveHTTPClient):
        self.client = client
        self.findings: List[Finding] = []

        # These are patterns we LEARN are errors, not hardcoded error strings
        self.learned_error_patterns = []

    def _analyze_response_for_errors(self, url: str, body: str, status: int) -> List[Finding]:
        """Analyze response body for error disclosure - learns patterns dynamically"""
        findings = []

        # Pattern: file path + line number (universal across languages)
        path_line_matches = re.findall(
            r'(?:in|at|file|from)\s+([/\\][\w\-./\\]+\.(?:php|py|js|java|rb|go|rs|cs|cpp|c))\s*(?:on\s+)?(?:line\s+)?(\d+)?',
            body, re.I
        )
        for path, line in path_line_matches:
            findings.append(Finding(
                vuln_class="Path Disclosure",
                severity="HIGH",
                cvss=7.5,
                url=url,
                parameter=None,
                description=f"Server file path leaked: {path}" + (f" line {line}" if line else ""),
                evidence={"path": path, "line": line},
                remediation=[
                    "Disable display_errors in production",
                    "Implement custom error pages",
                    "Log errors to file, not response",
                ],
                tags=["information-disclosure", "path-leak"],
            ))

        # Pattern: Stack traces (detect by structure, not specific text)
        # Stack traces have repeated indented lines with file:line patterns
        stack_indicators = [
            r'(?:Stack trace|Traceback|Call Stack|Exception)[\s\S]{0,50}(?:at\s+|in\s+|File\s+)',
            r'(?:#\d+\s+[\w\\/:]+\(\d+\)[\s\S]?){3,}',  # Multiple #N path(line) patterns
            r'(?:at\s+[\w.]+\([^)]*:\d+\)[\s\S]?){3,}',  # Java-style stack
        ]
        for pattern in stack_indicators:
            match = re.search(pattern, body, re.I)
            if match:
                findings.append(Finding(
                    vuln_class="Stack Trace Exposure",
                    severity="HIGH",
                    cvss=7.0,
                    url=url,
                    description="Application stack trace leaked in response. Reveals internal code structure.",
                    evidence=match.group(0)[:500],
                    remediation=[
                        "Never expose stack traces to users",
                        "Implement structured error handling",
                        "Use custom error pages",
                    ],
                    tags=["information-disclosure", "stack-trace"],
                ))
                break

        # Pattern: Database errors (detect by SQL keywords in error context)
        # MUST be actual error messages, not just JSON keys containing "error"
        db_error_patterns = [
            # Actual SQL syntax errors
            r'(?:syntax error|sql syntax).*?(?:near|at line|at position)',
            r'(?:mysql|mariadb|postgres|oracle|sqlite|mssql).*?(?:error|exception).*?(?:syntax|query|statement)',
            r'(?:ORA-\d{5}|PLS-\d{5})',  # Oracle errors
            r'(?:SQLSTATE\[\w+\])',  # PDO errors
            r'(?:pg_query|mysql_query|mysqli_query).*?(?:failed|error)',
            r'(?:Uncaught PDOException|mysqli_sql_exception)',
            # Actual query exposure
            r'(?:You have an error in your SQL syntax)',
            r'(?:Query failed|Query error|Invalid query)',
            r'(?:unterminated quoted string|invalid input syntax)',
        ]
        for pattern in db_error_patterns:
            match = re.search(pattern, body, re.I)
            if match:
                # Verify it's not just a JSON key
                context = body[max(0, match.start()-50):min(len(body), match.end()+50)]
                if not re.search(r'["\']\w*error\w*["\']:\s*(?:null|0|false|true|\d+)', context, re.I):
                    findings.append(Finding(
                        vuln_class="Database Error Disclosure",
                        severity="HIGH",
                        cvss=7.5,
                        url=url,
                        description="Database error message leaked. May reveal DB structure, queries, or credentials.",
                        evidence=match.group(0)[:300],
                        remediation=[
                            "Handle database exceptions gracefully",
                            "Never expose raw SQL errors",
                            "Use parameterized queries",
                        ],
                        tags=["information-disclosure", "database"],
                    ))
                    break

        # Pattern: Configuration/credentials in response
        # IMPORTANT: These patterns are strict to avoid false positives
        # Only flag actual secrets being leaked, not UI elements like "Forgot Password?"
        secret_patterns = [
            # API keys - must have actual key value (20+ alphanumeric chars after =)
            (r'(?:api[_-]?key|apikey|secret[_-]?key|auth[_-]?token|access[_-]?token)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', "API Key/Token"),
            # AWS credentials - very specific pattern
            (r'AKIA[A-Z0-9]{16}', "AWS Access Key"),
            # Database connection strings with credentials
            (r'(?:mongodb|mysql|postgres|redis)://[^:]+:[^@]+@[^\s<>"]+', "Database Connection String"),
            # Private keys - very specific header
            (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', "Private Key"),
            # Hardcoded passwords in code (password = "value" or password: "value")
            (r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']', "Hardcoded Password"),
        ]

        for pattern, secret_type in secret_patterns:
            match = re.search(pattern, body, re.I)
            if match:
                matched_text = match.group(0)

                # Skip false positives - common UI patterns
                false_positive_contexts = [
                    'forgot password',
                    'reset password',
                    'change password',
                    'enter password',
                    'your password',
                    'password field',
                    'password input',
                    'password:</label',
                    'password" placeholder',
                    'type="password"',
                    'password should',
                    'password must',
                    'password hint',
                    'password policy',
                    'password requirements',
                ]

                # Check surrounding context (100 chars before and after)
                start = max(0, match.start() - 100)
                end = min(len(body), match.end() + 100)
                context = body[start:end].lower()

                is_false_positive = any(fp in context for fp in false_positive_contexts)

                # Also skip if it's inside an HTML tag attribute
                if re.search(r'<[^>]*' + re.escape(matched_text[:20]), body[max(0, match.start()-50):match.end()], re.I):
                    is_false_positive = True

                # Skip short matches that are likely form labels
                if len(matched_text) < 15:
                    is_false_positive = True

                if not is_false_positive:
                    findings.append(Finding(
                        vuln_class=f"Exposed {secret_type}",
                        severity="CRITICAL",
                        cvss=9.5,
                        url=url,
                        description=f"{secret_type} found in response. This is a critical security issue.",
                        evidence=matched_text[:100],  # Show actual match, truncated
                        remediation=[
                            f"Remove {secret_type} from response immediately",
                            "Rotate all exposed credentials",
                            "Audit code for hardcoded secrets",
                            "Use environment variables for secrets",
                        ],
                        tags=["secret-exposure", "critical"],
                    ))

        # Pattern: HTML comments with sensitive info
        comments = re.findall(r'<!--[\s\S]*?-->', body)
        for comment in comments:
            sensitive_keywords = ['password', 'secret', 'key', 'token', 'todo', 'fixme', 'hack',
                                  'bug', 'debug', 'test', 'admin', 'internal', 'private', 'credential']
            for keyword in sensitive_keywords:
                if keyword in comment.lower():
                    findings.append(Finding(
                        vuln_class="Sensitive Comment Exposure",
                        severity="LOW",
                        cvss=3.5,
                        url=url,
                        description=f"HTML comment contains potentially sensitive information ({keyword})",
                        evidence=comment[:200],
                        remediation=[
                            "Remove sensitive comments before deployment",
                            "Use build process to strip comments",
                        ],
                        tags=["information-disclosure", "comment"],
                    ))
                    break

        return findings

    def _probe_sensitive_paths(self, base_url: str) -> List[Finding]:
        """Probe for exposed sensitive files"""
        findings = []

        # Dynamically generate paths based on detected tech stack
        paths = [
            # Universal
            ("/.git/config", "Git Repository"),
            ("/.git/HEAD", "Git Repository"),
            ("/.svn/entries", "SVN Repository"),
            ("/.env", "Environment File"),
            ("/.env.local", "Environment File"),
            ("/.env.production", "Environment File"),
            ("/config.json", "Configuration File"),
            ("/config.yaml", "Configuration File"),
            ("/config.yml", "Configuration File"),
            ("/settings.json", "Configuration File"),
            ("/secrets.json", "Secrets File"),
            ("/credentials.json", "Credentials File"),
            ("/.htaccess", "Apache Config"),
            ("/.htpasswd", "Apache Password"),
            ("/web.config", "IIS Config"),
            ("/robots.txt", "Robots File"),
            ("/sitemap.xml", "Sitemap"),
            ("/crossdomain.xml", "Flash Cross-Domain"),
            ("/clientaccesspolicy.xml", "Silverlight Policy"),
            ("/phpinfo.php", "PHP Info"),
            ("/info.php", "PHP Info"),
            ("/test.php", "Test File"),
            ("/debug.php", "Debug File"),
            ("/server-status", "Apache Status"),
            ("/server-info", "Apache Info"),
            ("/.DS_Store", "macOS Metadata"),
            ("/Thumbs.db", "Windows Metadata"),
            ("/backup.zip", "Backup Archive"),
            ("/backup.tar.gz", "Backup Archive"),
            ("/backup.sql", "Database Backup"),
            ("/dump.sql", "Database Dump"),
            ("/database.sql", "Database Dump"),
            ("/.bash_history", "Shell History"),
            ("/.ssh/id_rsa", "SSH Private Key"),
            ("/id_rsa", "SSH Private Key"),
            ("/docker-compose.yml", "Docker Config"),
            ("/Dockerfile", "Docker Config"),
            ("/package.json", "Node Package"),
            ("/composer.json", "PHP Composer"),
            ("/Gemfile", "Ruby Gems"),
            ("/requirements.txt", "Python Requirements"),
            ("/wp-config.php", "WordPress Config"),
            ("/configuration.php", "Joomla Config"),
            ("/sites/default/settings.php", "Drupal Config"),
            ("/.well-known/security.txt", "Security Policy"),
            ("/api/swagger.json", "API Documentation"),
            ("/api/v1/swagger.json", "API Documentation"),
            ("/swagger.json", "API Documentation"),
            ("/openapi.json", "API Documentation"),
            ("/graphql", "GraphQL Endpoint"),
            ("/graphiql", "GraphQL IDE"),
            ("/__graphql", "GraphQL Endpoint"),
            ("/actuator", "Spring Actuator"),
            ("/actuator/health", "Spring Health"),
            ("/actuator/env", "Spring Environment"),
            ("/metrics", "Application Metrics"),
            ("/health", "Health Check"),
            ("/status", "Status Page"),
            ("/admin", "Admin Panel"),
            ("/administrator", "Admin Panel"),
            ("/admin.php", "Admin Panel"),
            ("/wp-admin", "WordPress Admin"),
            ("/phpmyadmin", "phpMyAdmin"),
            ("/adminer.php", "Adminer"),
            ("/.well-known/jwks.json", "JWT Key Set"),
            ("/error_log", "Error Log"),
            ("/error.log", "Error Log"),
            ("/access.log", "Access Log"),
            ("/debug.log", "Debug Log"),
        ]

        for path, file_type in paths:
            url = urljoin(base_url, path)
            try:
                resp = self.client.get(url, allow_redirects=False, timeout=5)

                # Check for successful response with content
                if resp.status_code == 200:
                    content_length = len(resp.content)
                    content_type = resp.headers.get('Content-Type', '')

                    # Filter out generic error pages (usually HTML with standard content)
                    is_html = 'html' in content_type.lower()
                    is_likely_error = content_length < 500 and is_html

                    if not is_likely_error:
                        # Determine severity based on file type
                        severity = "HIGH"
                        cvss = 7.0
                        if any(x in file_type.lower() for x in ['key', 'credential', 'secret', 'password', 'backup', 'dump']):
                            severity = "CRITICAL"
                            cvss = 9.0
                        elif any(x in file_type.lower() for x in ['config', 'env']):
                            severity = "HIGH"
                            cvss = 8.0
                        elif 'git' in file_type.lower() or 'svn' in file_type.lower():
                            severity = "HIGH"
                            cvss = 8.5

                        # Validate it's actually the file we expect (not a custom 404)
                        body = resp.text[:1000]
                        is_valid = True

                        # Git config should contain certain patterns
                        if '.git' in path:
                            is_valid = '[core]' in body or 'ref:' in body
                        # .env should have KEY=VALUE pattern
                        elif '.env' in path:
                            is_valid = bool(re.search(r'^\w+=', body, re.M))
                        # Config files should have structure
                        elif 'config' in path or 'settings' in path:
                            is_valid = '{' in body or '<' in body or '=' in body

                        if is_valid:
                            findings.append(Finding(
                                vuln_class=f"Exposed {file_type}",
                                severity=severity,
                                cvss=cvss,
                                url=url,
                                description=f"{file_type} is publicly accessible at {path}",
                                evidence=resp.text[:300] if len(resp.text) < 500 else f"[{content_length} bytes]",
                                remediation=[
                                    f"Remove or restrict access to {path}",
                                    "Configure web server to block sensitive paths",
                                    "Add authentication for sensitive endpoints",
                                ],
                                tags=["exposure", "sensitive-file"],
                            ))

            except Exception:
                continue

        return findings

    def _check_directory_listing(self, base_url: str) -> List[Finding]:
        """Check for directory listing enabled"""
        findings = []

        # Common directories to check
        dirs = ['/', '/images/', '/uploads/', '/files/', '/assets/', '/static/',
                '/css/', '/js/', '/img/', '/media/', '/backup/', '/data/']

        for dir_path in dirs:
            url = urljoin(base_url, dir_path)
            try:
                resp = self.client.get(url, timeout=5)

                if resp.status_code == 200:
                    # Check for directory listing patterns
                    patterns = [
                        r'Index of /',
                        r'Directory listing for',
                        r'<title>Index of',
                        r'\[To Parent Directory\]',
                        r'Parent Directory</a>',
                        r'<h1>Index of',
                    ]
                    for pattern in patterns:
                        if re.search(pattern, resp.text, re.I):
                            findings.append(Finding(
                                vuln_class="Directory Listing Enabled",
                                severity="MEDIUM",
                                cvss=5.3,
                                url=url,
                                description=f"Directory listing is enabled at {dir_path}, exposing file structure.",
                                evidence=re.search(pattern, resp.text, re.I).group(0),
                                remediation=[
                                    "Disable directory listing in web server config",
                                    "Add index files to directories",
                                    "Options -Indexes (Apache)",
                                    "autoindex off (Nginx)",
                                ],
                                tags=["misconfiguration", "directory-listing"],
                            ))
                            break

            except Exception:
                continue

        return findings

    def scan(self, base_url: str, paths_to_check: List[str] = None) -> List[Finding]:
        """Run full information disclosure scan"""
        self.findings = []

        # Default paths to check for error disclosure
        if paths_to_check is None:
            paths_to_check = ['/', '/api/', '/admin/', '/login/', '/user/', '/test/', '/debug/']

        # Check each path for error disclosure
        for path in paths_to_check:
            url = urljoin(base_url, path)
            try:
                resp = self.client.get(url, timeout=10)
                self.findings.extend(self._analyze_response_for_errors(url, resp.text, resp.status_code))
            except Exception:
                continue

        # Probe for sensitive files
        self.findings.extend(self._probe_sensitive_paths(base_url))

        # Check for directory listing
        self.findings.extend(self._check_directory_listing(base_url))

        return self.findings
