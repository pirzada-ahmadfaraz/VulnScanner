"""
Directory & File Bruteforce Scanner
- Common paths discovery
- Backup file detection
- Admin panel discovery
- API endpoint discovery
- Technology-specific paths
"""

import re
from typing import List, Dict, Optional, Set
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core.finding import Finding
from ..core.http_client import AdaptiveHTTPClient


class DirectoryScanner:
    """Directory and file bruteforce discovery"""

    # Common directories and files
    COMMON_PATHS = [
        # Admin panels
        "/admin", "/admin/", "/administrator", "/administrator/",
        "/admin/login", "/admin/index.php", "/admin/admin.php",
        "/admincp", "/admin_area", "/admin_panel", "/cpanel",
        "/wp-admin", "/wp-admin/", "/wp-login.php",
        "/manager", "/manager/", "/management",
        "/dashboard", "/dashboard/", "/console",
        "/backend", "/backend/", "/backoffice",
        "/moderator", "/webadmin", "/sysadmin",
        "/controlpanel", "/admincontrol", "/admin1",

        # API endpoints
        "/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
        "/rest", "/rest/", "/graphql", "/graphiql",
        "/api/users", "/api/user", "/api/admin",
        "/api/login", "/api/auth", "/api/token",
        "/api/config", "/api/settings", "/api/debug",
        "/swagger", "/swagger-ui", "/swagger.json",
        "/openapi.json", "/api-docs", "/redoc",

        # Config & sensitive files
        "/.env", "/.env.local", "/.env.production", "/.env.backup",
        "/config.php", "/config.inc.php", "/configuration.php",
        "/settings.php", "/settings.py", "/config.json",
        "/config.yaml", "/config.yml", "/application.yml",
        "/database.yml", "/secrets.yml", "/credentials.json",
        "/wp-config.php", "/wp-config.php.bak", "/wp-config.old",
        "/web.config", "/applicationHost.config",

        # Backup files
        "/backup", "/backup/", "/backups", "/backups/",
        "/backup.zip", "/backup.tar.gz", "/backup.sql",
        "/backup.tar", "/backup.rar", "/backup.7z",
        "/db_backup.sql", "/database.sql", "/dump.sql",
        "/site_backup.zip", "/www.zip", "/public_html.zip",
        "/old", "/old/", "/_old", "/archive", "/archives",
        "/temp", "/tmp", "/cache", "/.cache",

        # Version control
        "/.git", "/.git/", "/.git/config", "/.git/HEAD",
        "/.gitignore", "/.gitattributes",
        "/.svn", "/.svn/", "/.svn/entries",
        "/.hg", "/.hg/", "/.bzr", "/.bzr/",
        "/CVS", "/CVS/", "/.cvs",

        # CI/CD & DevOps
        "/.github", "/.gitlab-ci.yml", "/Jenkinsfile",
        "/.circleci", "/.travis.yml", "/azure-pipelines.yml",
        "/docker-compose.yml", "/docker-compose.yaml",
        "/Dockerfile", "/.dockerignore",
        "/kubernetes", "/k8s", "/helm",
        "/terraform", "/.terraform",
        "/ansible", "/playbook.yml",

        # Debug & development
        "/debug", "/debug/", "/test", "/test/",
        "/testing", "/dev", "/dev/", "/development",
        "/staging", "/stage", "/uat", "/qa",
        "/phpinfo.php", "/info.php", "/php_info.php",
        "/test.php", "/debug.php", "/info.html",
        "/server-status", "/server-info",
        "/_debug", "/__debug__", "/elmah.axd",

        # Logs
        "/logs", "/logs/", "/log", "/log/",
        "/error_log", "/error.log", "/errors.log",
        "/access.log", "/access_log", "/debug.log",
        "/application.log", "/app.log", "/system.log",
        "/php_errors.log", "/mysql_error.log",

        # User content
        "/uploads", "/uploads/", "/upload", "/upload/",
        "/files", "/files/", "/documents", "/docs",
        "/media", "/media/", "/images", "/img",
        "/assets", "/static", "/public",
        "/content", "/data", "/attachments",

        # CMS specific
        "/wp-content", "/wp-content/uploads",
        "/wp-content/plugins", "/wp-content/themes",
        "/wp-includes", "/xmlrpc.php",
        "/sites/default/files", "/node", "/user",
        "/modules", "/themes", "/libraries",
        "/components", "/plugins", "/extensions",
        "/storage", "/vendor", "/node_modules",

        # Authentication
        "/login", "/login/", "/signin", "/sign-in",
        "/logout", "/signout", "/sign-out",
        "/register", "/signup", "/sign-up",
        "/forgot-password", "/reset-password",
        "/auth", "/oauth", "/sso", "/saml",
        "/callback", "/authorize", "/token",

        # Status & health
        "/health", "/healthcheck", "/health-check",
        "/status", "/ping", "/ready", "/live",
        "/metrics", "/.well-known",

        # Common files
        "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
        "/humans.txt", "/security.txt", "/.well-known/security.txt",
        "/crossdomain.xml", "/clientaccesspolicy.xml",
        "/favicon.ico", "/apple-touch-icon.png",
        "/manifest.json", "/browserconfig.xml",
        "/package.json", "/composer.json", "/Gemfile",
        "/requirements.txt", "/Pipfile", "/yarn.lock",
        "/package-lock.json", "/composer.lock",
    ]

    # Extension variations to try for files
    BACKUP_EXTENSIONS = [
        ".bak", ".backup", ".old", ".orig", ".original",
        ".save", ".saved", ".copy", ".tmp", ".temp",
        ".swp", ".swo", "~", ".1", ".2",
        "_backup", "_old", "_copy", "_bak",
    ]

    def __init__(self, client: AdaptiveHTTPClient, threads: int = 15):
        self.client = client
        self.threads = threads
        self.findings: List[Finding] = []

    def _check_path(self, base_url: str, path: str) -> Optional[Dict]:
        """Check if a path exists and analyze response"""
        url = urljoin(base_url, path)

        try:
            resp = self.client.get(url, timeout=8, allow_redirects=False)

            # Interesting status codes
            if resp.status_code in [200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 405, 500]:
                result = {
                    "url": url,
                    "path": path,
                    "status": resp.status_code,
                    "length": len(resp.content),
                    "content_type": resp.headers.get("Content-Type", ""),
                    "server": resp.headers.get("Server", ""),
                    "redirect": resp.headers.get("Location", ""),
                }

                # Check for interesting content
                body = resp.text[:2000].lower()

                # Is it a login page?
                if any(x in body for x in ["password", "login", "sign in", "username"]):
                    result["type"] = "login"

                # Is it an admin panel?
                elif any(x in body for x in ["admin", "dashboard", "control panel", "management"]):
                    result["type"] = "admin"

                # Is it an API response?
                elif resp.headers.get("Content-Type", "").startswith("application/json"):
                    result["type"] = "api"

                # Is it directory listing?
                elif any(x in body for x in ["index of", "directory listing", "parent directory"]):
                    result["type"] = "directory"

                # Is it a config/sensitive file?
                elif any(x in path.lower() for x in [".env", "config", ".git", "backup", ".sql"]):
                    result["type"] = "sensitive"

                else:
                    result["type"] = "other"

                return result

        except Exception:
            pass

        return None

    def _generate_backup_paths(self, original_paths: List[str]) -> List[str]:
        """Generate backup file variations"""
        backup_paths = []

        for path in original_paths:
            if "." in path.split("/")[-1]:  # Has extension
                base = path.rsplit(".", 1)[0]
                ext = "." + path.rsplit(".", 1)[1]

                for backup_ext in self.BACKUP_EXTENSIONS:
                    backup_paths.append(f"{path}{backup_ext}")
                    backup_paths.append(f"{base}{backup_ext}{ext}")
                    backup_paths.append(f"{base}{backup_ext}")

        return backup_paths[:200]  # Limit to prevent too many requests

    def scan(self, base_url: str, paths: List[str] = None,
             include_backups: bool = True, callback=None) -> List[Finding]:
        """
        Scan for directories and files

        Args:
            base_url: Target URL
            paths: Custom path list (uses default if None)
            include_backups: Generate backup file variations
            callback: Progress callback function

        Returns:
            List of findings
        """
        self.findings = []

        # Use provided paths or default
        all_paths = list(paths) if paths else list(self.COMMON_PATHS)

        # Add backup variations
        if include_backups:
            all_paths.extend(self._generate_backup_paths(all_paths[:50]))

        # Remove duplicates
        all_paths = list(set(all_paths))

        if callback:
            callback("info", f"Scanning {len(all_paths)} paths")

        discovered = []
        checked = 0

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._check_path, base_url, path): path
                      for path in all_paths}

            for future in as_completed(futures):
                checked += 1
                if callback and checked % 50 == 0:
                    callback("probe", f"Checked {checked}/{len(all_paths)} paths")

                try:
                    result = future.result()
                    if result:
                        discovered.append(result)

                        # Create finding based on type
                        finding = self._create_finding(result)
                        if finding:
                            self.findings.append(finding)
                            if callback:
                                callback("success", f"Found: {result['path']} ({result['status']})")

                except Exception:
                    continue

        return self.findings

    def _create_finding(self, result: Dict) -> Optional[Finding]:
        """Create a finding from discovery result"""
        path = result["path"]
        status = result["status"]
        result_type = result.get("type", "other")

        # Determine severity based on what was found
        if result_type == "sensitive" or any(x in path.lower() for x in [".env", ".git", "backup", ".sql", "config"]):
            if status == 200:
                return Finding(
                    vuln_class="Sensitive File Exposure",
                    severity="HIGH" if ".sql" in path or "backup" in path else "MEDIUM",
                    cvss=8.0 if ".sql" in path else 6.5,
                    url=result["url"],
                    description=f"Sensitive file accessible: {path}",
                    evidence={
                        "status": status,
                        "content_length": result["length"],
                        "content_type": result["content_type"],
                    },
                    remediation=[
                        f"Remove or restrict access to {path}",
                        "Configure web server to block sensitive paths",
                        "Move sensitive files outside web root",
                    ],
                    tags=["discovery", "sensitive-file"],
                )

        elif result_type == "admin":
            if status in [200, 401, 403]:
                return Finding(
                    vuln_class="Admin Panel Discovered",
                    severity="LOW",
                    cvss=3.5,
                    url=result["url"],
                    description=f"Admin panel found at {path}",
                    evidence={
                        "status": status,
                        "protected": status in [401, 403],
                    },
                    remediation=[
                        "Ensure strong authentication",
                        "Implement IP whitelisting if possible",
                        "Use non-standard paths for admin panels",
                    ],
                    tags=["discovery", "admin"],
                )

        elif result_type == "directory":
            return Finding(
                vuln_class="Directory Listing",
                severity="MEDIUM",
                cvss=5.3,
                url=result["url"],
                description=f"Directory listing enabled at {path}",
                evidence={"status": status},
                remediation=[
                    "Disable directory listing",
                    "Add index files to directories",
                ],
                tags=["discovery", "directory-listing"],
            )

        elif result_type == "api":
            if status == 200:
                return Finding(
                    vuln_class="API Endpoint Discovered",
                    severity="INFO",
                    url=result["url"],
                    description=f"API endpoint found at {path}",
                    evidence={
                        "status": status,
                        "content_type": result["content_type"],
                    },
                    tags=["discovery", "api"],
                )

        elif status == 200 and result["length"] > 0:
            # Generic discovery
            return Finding(
                vuln_class="Path Discovered",
                severity="INFO",
                url=result["url"],
                description=f"Accessible path found: {path}",
                evidence={
                    "status": status,
                    "length": result["length"],
                },
                tags=["discovery"],
            )

        return None
