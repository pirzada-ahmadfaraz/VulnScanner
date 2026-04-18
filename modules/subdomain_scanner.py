"""
Subdomain Discovery & Asset Enumeration
- DNS enumeration
- Certificate transparency logs
- Brute force common subdomains
- Recursive discovery
"""

import re
import socket
import ssl
import json
from typing import List, Set, Dict, Optional
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core.http_client import AdaptiveHTTPClient


class SubdomainScanner:
    """Subdomain discovery and enumeration"""

    # Common subdomain wordlist (top 500)
    COMMON_SUBDOMAINS = [
        "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
        "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test", "portal",
        "ns", "ww1", "host", "support", "dev", "web", "bbs", "ww42", "mx",
        "email", "cloud", "1", "mail1", "2", "forum", "owa", "www2", "gw",
        "admin", "store", "mx1", "cdn", "api", "exchange", "app", "gov",
        "2tty", "vps", "govyty", "hgfgdf", "news", "1mail", "mx2", "sql",
        "demo", "ssl", "staging", "stage", "login", "dashboard", "panel",
        "cpanel", "webdisk", "autodiscover", "autoconfig", "imap", "pop",
        "pop3", "db", "mysql", "data", "backup", "testing", "prod", "production",
        "internal", "intranet", "extranet", "corp", "corporate", "office",
        "files", "download", "downloads", "upload", "uploads", "media",
        "images", "img", "static", "assets", "content", "video", "videos",
        "audio", "music", "games", "game", "mobile", "mobi", "wap", "beta",
        "alpha", "old", "new", "v1", "v2", "api1", "api2", "rest", "graphql",
        "docs", "doc", "documentation", "help", "wiki", "kb", "knowledge",
        "learn", "learning", "training", "edu", "education", "student",
        "students", "staff", "employee", "hr", "payroll", "finance", "billing",
        "pay", "payment", "payments", "checkout", "cart", "order", "orders",
        "account", "accounts", "my", "member", "members", "user", "users",
        "customer", "customers", "client", "clients", "partner", "partners",
        "vendor", "vendors", "supplier", "crm", "erp", "sap", "oracle",
        "salesforce", "jira", "confluence", "git", "gitlab", "github", "svn",
        "code", "repo", "repository", "jenkins", "ci", "cd", "build", "deploy",
        "monitor", "monitoring", "status", "health", "ping", "check", "nagios",
        "grafana", "kibana", "elastic", "elasticsearch", "logs", "log",
        "syslog", "splunk", "analytics", "stats", "statistics", "metrics",
        "tracking", "track", "pixel", "ads", "ad", "adserver", "marketing",
        "promo", "campaign", "newsletter", "mail3", "smtp2", "smtp1", "relay",
        "gateway", "proxy", "cache", "varnish", "nginx", "apache", "iis",
        "tomcat", "jboss", "websphere", "weblogic", "glassfish", "wildfly",
        "docker", "kubernetes", "k8s", "container", "aws", "azure", "gcp",
        "cloud1", "cloud2", "s3", "storage", "bucket", "archive", "vault",
        "secret", "secrets", "key", "keys", "cert", "certs", "certificate",
        "pki", "ca", "ldap", "ad", "directory", "dns", "dns1", "dns2", "ns3",
        "ns4", "ntp", "time", "radius", "tacacs", "sso", "saml", "oauth",
        "auth", "authentication", "identity", "idp", "iam", "2fa", "mfa",
        "otp", "token", "session", "security", "firewall", "waf", "ids",
        "ips", "siem", "soc", "pentest", "scan", "scanner", "vuln",
        "vulnerability", "audit", "compliance", "policy", "legal", "privacy",
        "terms", "about", "info", "information", "contact", "feedback",
        "survey", "form", "forms", "report", "reports", "reporting",
        "dashboard1", "dashboard2", "console", "management", "manage", "mgmt",
        "control", "controller", "master", "slave", "primary", "secondary",
        "failover", "dr", "disaster", "recovery", "backup1", "backup2",
        "replica", "mirror", "sync", "replication", "cluster", "node",
        "node1", "node2", "worker", "agent", "collector", "aggregator",
    ]

    def __init__(self, client: AdaptiveHTTPClient, threads: int = 20):
        self.client = client
        self.threads = threads
        self.discovered: Set[str] = set()

    def _resolve_dns(self, domain: str) -> Optional[str]:
        """Try to resolve domain to IP"""
        try:
            ip = socket.gethostbyname(domain)
            return ip
        except socket.gaierror:
            return None

    def _check_subdomain(self, subdomain: str, base_domain: str) -> Optional[Dict]:
        """Check if subdomain exists and is reachable"""
        full_domain = f"{subdomain}.{base_domain}"

        ip = self._resolve_dns(full_domain)
        if not ip:
            return None

        # Try to connect via HTTP/HTTPS
        result = {
            "subdomain": full_domain,
            "ip": ip,
            "http": False,
            "https": False,
            "title": None,
            "server": None,
            "status": None,
        }

        for scheme in ["https", "http"]:
            try:
                url = f"{scheme}://{full_domain}"
                resp = self.client.get(url, timeout=5, allow_redirects=True)
                result[scheme] = True
                result["status"] = resp.status_code
                result["server"] = resp.headers.get("Server", "")

                # Extract title
                title_match = re.search(r"<title[^>]*>([^<]+)</title>", resp.text, re.I)
                if title_match:
                    result["title"] = title_match.group(1).strip()[:100]

                break  # Got a response, no need to try other scheme
            except Exception:
                continue

        return result if (result["http"] or result["https"]) else {"subdomain": full_domain, "ip": ip, "dns_only": True}

    def _query_crtsh(self, domain: str) -> List[str]:
        """Query crt.sh for subdomains from certificate transparency"""
        subdomains = set()
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            resp = self.client.get(url, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for line in name.split("\n"):
                        line = line.strip().lower()
                        if line.endswith(domain) and "*" not in line:
                            subdomains.add(line)
        except Exception:
            pass
        return list(subdomains)

    def _query_hackertarget(self, domain: str) -> List[str]:
        """Query HackerTarget for subdomains"""
        subdomains = set()
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            resp = self.client.get(url, timeout=15)
            if resp.status_code == 200 and "error" not in resp.text.lower():
                for line in resp.text.split("\n"):
                    if "," in line:
                        subdomain = line.split(",")[0].strip().lower()
                        if subdomain.endswith(domain):
                            subdomains.add(subdomain)
        except Exception:
            pass
        return list(subdomains)

    def enumerate(self, domain: str, use_wordlist: bool = True,
                  use_crtsh: bool = True, callback=None) -> List[Dict]:
        """
        Enumerate subdomains for a domain

        Args:
            domain: Base domain to enumerate (e.g., example.com)
            use_wordlist: Brute force common subdomains
            use_crtsh: Query certificate transparency logs
            callback: Function to call for progress updates

        Returns:
            List of discovered subdomain info dicts
        """
        self.discovered = set()
        results = []

        # Extract base domain from URL if needed
        if domain.startswith("http"):
            parsed = urlparse(domain)
            domain = parsed.netloc

        # Remove www. prefix if present
        if domain.startswith("www."):
            domain = domain[4:]

        if callback:
            callback("info", f"Enumerating subdomains for {domain}")

        # Collect subdomain candidates
        candidates = set()

        # Add the base domain itself
        candidates.add(domain)
        candidates.add(f"www.{domain}")

        # Query certificate transparency
        if use_crtsh:
            if callback:
                callback("probe", "Querying certificate transparency logs")
            ct_subs = self._query_crtsh(domain)
            candidates.update(ct_subs)
            if callback:
                callback("info", f"Found {len(ct_subs)} from crt.sh")

            # Also try HackerTarget
            ht_subs = self._query_hackertarget(domain)
            candidates.update(ht_subs)
            if callback:
                callback("info", f"Found {len(ht_subs)} from HackerTarget")

        # Add wordlist candidates
        if use_wordlist:
            if callback:
                callback("probe", f"Adding {len(self.COMMON_SUBDOMAINS)} wordlist entries")
            for sub in self.COMMON_SUBDOMAINS:
                candidates.add(f"{sub}.{domain}")

        if callback:
            callback("info", f"Total candidates to check: {len(candidates)}")

        # Resolve and check each candidate
        checked = 0
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all tasks
            future_to_domain = {}
            for candidate in candidates:
                if candidate == domain or not candidate.startswith("."):
                    # It's a full domain
                    future = executor.submit(self._check_single_domain, candidate)
                else:
                    # It's a subdomain prefix
                    future = executor.submit(self._check_subdomain, candidate.split(".")[0], domain)
                future_to_domain[future] = candidate

            # Collect results
            for future in as_completed(future_to_domain):
                checked += 1
                if callback and checked % 50 == 0:
                    callback("probe", f"Checked {checked}/{len(candidates)} subdomains")

                try:
                    result = future.result()
                    if result:
                        subdomain = result.get("subdomain", future_to_domain[future])
                        if subdomain not in self.discovered:
                            self.discovered.add(subdomain)
                            results.append(result)
                            if callback and (result.get("http") or result.get("https")):
                                callback("success", f"Found: {subdomain}")
                except Exception:
                    continue

        if callback:
            callback("info", f"Enumeration complete: {len(results)} subdomains found")

        return sorted(results, key=lambda x: x.get("subdomain", ""))

    def _check_single_domain(self, domain: str) -> Optional[Dict]:
        """Check a single full domain"""
        ip = self._resolve_dns(domain)
        if not ip:
            return None

        result = {
            "subdomain": domain,
            "ip": ip,
            "http": False,
            "https": False,
            "title": None,
            "server": None,
            "status": None,
        }

        for scheme in ["https", "http"]:
            try:
                url = f"{scheme}://{domain}"
                resp = self.client.get(url, timeout=5, allow_redirects=True)
                result[scheme] = True
                result["status"] = resp.status_code
                result["server"] = resp.headers.get("Server", "")

                title_match = re.search(r"<title[^>]*>([^<]+)</title>", resp.text, re.I)
                if title_match:
                    result["title"] = title_match.group(1).strip()[:100]

                break
            except Exception:
                continue

        return result if (result["http"] or result["https"]) else {"subdomain": domain, "ip": ip, "dns_only": True}
