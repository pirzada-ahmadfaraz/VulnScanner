"""
Main Scanner Orchestrator with Real-Time Output
Runs all modules and shows live activity
Auto-saves detailed JSON reports after each scan
Supports subdomain enumeration for full attack surface discovery
AI-powered vulnerability verification and discovery
"""

import os
import sys
import time
import json
from typing import List, Optional, Dict
from datetime import datetime
from urllib.parse import urlparse

# Allow `python scanner.py` to run from the repository root by bootstrapping
# the package name before any relative imports are resolved.
if __package__ in {None, ""}:
    PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
    PARENT_DIR = os.path.dirname(PACKAGE_DIR)
    if PARENT_DIR not in sys.path:
        sys.path.insert(0, PARENT_DIR)
    __package__ = os.path.basename(PACKAGE_DIR)

from .core.http_client import AdaptiveHTTPClient
from .core.finding import Finding, sort_findings, deduplicate_findings
from .core.safety import SafetyConfig
from .ui.terminal import (
    ScanUI, ModuleProgress, Colors, print_scan_complete, BANNER
)

# Import all scanner modules (16 total)
from .modules.info_disclosure import InfoDisclosureScanner
from .modules.security_headers import SecurityHeadersScanner
from .modules.auth_scanner import AuthScanner
from .modules.injection_scanner import InjectionScanner
from .modules.xss_scanner import XSSScanner
from .modules.ssrf_scanner import SSRFScanner
from .modules.tech_scanner import TechScanner
from .modules.open_redirect import OpenRedirectScanner
from .modules.ssl_scanner import SSLScanner
from .modules.port_scanner import PortScanner
from .modules.directory_scanner import DirectoryScanner
from .modules.subdomain_scanner import SubdomainScanner
from .modules.cors_scanner import CORSScanner
from .modules.waf_bypass import WAFBypassScanner
from .modules.api_scanner import APIScanner
from .modules.crawler import WebCrawler
from .modules.ai_engine import AISecurityEngine


SCAN_PROFILES = {
    'quick': {
        'description': 'Fast scan - recon + headers + tech only',
        'modules': ['tech', 'headers', 'info', 'ssl'],
    },
    'web': {
        'description': 'Web vulnerability focus - skip infrastructure',
        'modules': ['tech', 'headers', 'info', 'auth', 'injection', 'xss',
                    'ssrf', 'redirect', 'cors', 'api', 'crawl'],
    },
    'full': {
        'description': 'All modules including heavy scans',
        'modules': ['tech', 'headers', 'info', 'auth', 'injection', 'xss',
                    'ssrf', 'redirect', 'ssl', 'cors', 'waf', 'api', 'crawl', 'dirs', 'ports'],
    },
    'stealth': {
        'description': 'Passive only - no active probes',
        'modules': ['tech', 'headers', 'ssl'],
    },
}


class VulnScanner:
    """Main vulnerability scanner orchestrator with real-time output"""

    def __init__(self, proxy: str = None, timeout: int = 15, ai_api_key: str = None,
                 cookies: dict = None, auth_headers: dict = None, safety: SafetyConfig = None):
        self.proxy = proxy
        self.timeout = timeout
        self.safety = safety
        self.safe_mode = safety.safe_mode if safety else False
        self.client = AdaptiveHTTPClient(proxy=proxy, timeout=timeout,
                                          cookies=cookies, auth_headers=auth_headers,
                                          safety=safety)
        self._auth_cookies = cookies or {}
        self._auth_headers = auth_headers or {}
        self.findings: List[Finding] = []
        self.ui = ScanUI()
        self.discovered_subdomains: List[Dict] = []
        self.ai_api_key = ai_api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.ai_engine = None
        self.ai_enabled = False
        self.ai_verified_findings: List[Finding] = []
        self.ai_discovered_findings: List[Finding] = []
        self.ai_rejected_findings: List[Dict] = []
        self.ai_chains: List[Dict] = []
        self.response_data: Dict = {}  # Collected data for AI analysis
        self._seen_endpoints = set()
        self._crawl_enabled = False
        self._crawl_depth = 3

    def recon(self, domain: str, callback=None) -> List[Dict]:
        """
        Run reconnaissance to discover subdomains

        Args:
            domain: Base domain to enumerate
            callback: Progress callback

        Returns:
            List of discovered subdomain info dicts
        """
        print(f"\n{Colors.CYAN}{'=' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}  \u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2557   \u2588\u2588\u2557{Colors.RESET}")
        print(f"{Colors.CYAN}  \u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d\u2588\u2588\u2554\u2550\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2551{Colors.RESET}")
        print(f"{Colors.CYAN}  \u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2551     \u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2554\u2588\u2588\u2557 \u2588\u2588\u2551{Colors.RESET}")
        print(f"{Colors.CYAN}  \u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2554\u2550\u2550\u255d  \u2588\u2588\u2551     \u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2551\u255a\u2588\u2588\u2557\u2588\u2588\u2551{Colors.RESET}")
        print(f"{Colors.CYAN}  \u2588\u2588\u2551  \u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2551 \u255a\u2588\u2588\u2588\u2588\u2551{Colors.RESET}")
        print(f"{Colors.CYAN}  \u255a\u2550\u255d  \u255a\u2550\u255d\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d \u255a\u2550\u2550\u2550\u2550\u2550\u255d \u255a\u2550\u2550\u2550\u2550\u2550\u255d \u255a\u2550\u255d  \u255a\u2550\u2550\u2550\u255d{Colors.RESET}")
        print(f"{Colors.CYAN}{'=' * 80}{Colors.RESET}")
        print(f"  {Colors.DIM}Subdomain Discovery & Asset Enumeration{Colors.RESET}")
        print(f"{Colors.CYAN}{'=' * 80}{Colors.RESET}\n")

        # Extract domain if URL provided
        if domain.startswith("http"):
            parsed = urlparse(domain)
            domain = parsed.netloc

        # Remove www prefix
        if domain.startswith("www."):
            domain = domain[4:]

        print(f"  {Colors.BOLD}Target Domain:{Colors.RESET} {Colors.GREEN}{domain}{Colors.RESET}\n")

        # Progress callback for terminal output
        def recon_callback(msg_type, msg):
            timestamp = time.strftime('%H:%M:%S')
            if msg_type == "info":
                print(f"  {Colors.DIM}[{timestamp}]{Colors.RESET} {Colors.CYAN}\u2139{Colors.RESET} {msg}")
            elif msg_type == "probe":
                print(f"  {Colors.DIM}[{timestamp}]{Colors.RESET} {Colors.YELLOW}\u27f3{Colors.RESET} {msg}")
            elif msg_type == "success":
                print(f"  {Colors.DIM}[{timestamp}]{Colors.RESET} {Colors.GREEN}\u2713{Colors.RESET} {Colors.GREEN}{msg}{Colors.RESET}")
            elif msg_type == "error":
                print(f"  {Colors.DIM}[{timestamp}]{Colors.RESET} {Colors.RED}\u2717{Colors.RESET} {msg}")

        # Run subdomain scanner
        subdomain_scanner = SubdomainScanner(self.client)
        self.discovered_subdomains = subdomain_scanner.enumerate(
            domain,
            use_wordlist=True,
            use_crtsh=True,
            callback=recon_callback
        )

        # Display results
        print(f"\n{Colors.CYAN}{'-' * 80}{Colors.RESET}")
        print(f"  {Colors.BOLD}DISCOVERED ASSETS{Colors.RESET}")
        print(f"{Colors.CYAN}{'-' * 80}{Colors.RESET}\n")

        live_hosts = [s for s in self.discovered_subdomains if s.get("http") or s.get("https")]
        dns_only = [s for s in self.discovered_subdomains if s.get("dns_only")]

        print(f"  {Colors.GREEN}Live Hosts ({len(live_hosts)}):{Colors.RESET}")
        for sub in live_hosts[:20]:  # Show first 20
            status = sub.get("status", "?")
            server = sub.get("server", "")[:30]
            title = sub.get("title", "")[:40]
            protocol = "https" if sub.get("https") else "http"
            print(f"    {Colors.GREEN}\u25cf{Colors.RESET} {sub['subdomain']}")
            print(f"      {Colors.DIM}[{status}] {protocol} | {server} | {title}{Colors.RESET}")

        if len(live_hosts) > 20:
            print(f"    {Colors.DIM}... and {len(live_hosts) - 20} more{Colors.RESET}")

        if dns_only:
            print(f"\n  {Colors.YELLOW}DNS Only ({len(dns_only)}):{Colors.RESET}")
            for sub in dns_only[:10]:
                print(f"    {Colors.YELLOW}\u25cb{Colors.RESET} {sub['subdomain']} \u2192 {sub.get('ip', 'N/A')}")

        print(f"\n{Colors.CYAN}{'-' * 80}{Colors.RESET}")
        print(f"  {Colors.BOLD}Total:{Colors.RESET} {len(self.discovered_subdomains)} subdomains "
              f"({Colors.GREEN}{len(live_hosts)} live{Colors.RESET}, "
              f"{Colors.YELLOW}{len(dns_only)} DNS-only{Colors.RESET})")
        print(f"{Colors.CYAN}{'-' * 80}{Colors.RESET}\n")

        return self.discovered_subdomains

    def scan(self, target: str, modules: List[str] = None, quiet: bool = False,
             recon_mode: bool = False, ai_mode: bool = False) -> List[Finding]:
        """
        Run full vulnerability scan against target with real-time output

        Args:
            target: URL to scan
            modules: List of module names to run (None = all)
            quiet: Suppress UI output
            recon_mode: Run subdomain discovery first
            ai_mode: Enable AI verification and discovery

        Returns:
            List of Finding objects
        """
        start_time = time.time()
        self.findings = []
        self.ai_engine = None
        self.ai_enabled = False
        self.ai_verified_findings = []
        self.ai_discovered_findings = []
        self.ai_rejected_findings = []
        self.ai_chains = []
        self.response_data = {"endpoints": [], "responses": [], "technologies": []}
        self._seen_endpoints = set()

        # Initialize AI engine if requested
        if ai_mode:
            candidate_ai_engine = AISecurityEngine(self.client, self.ai_api_key)
            if not candidate_ai_engine.is_available():
                if not quiet:
                    print(f"\n  {Colors.YELLOW}\u26a0 AI mode requested but ANTHROPIC_API_KEY not set{Colors.RESET}")
                    print(f"  {Colors.DIM}Set environment variable or pass --ai-key{Colors.RESET}\n")
                ai_mode = False
            else:
                self.ai_engine = candidate_ai_engine
                self.ai_enabled = True

        # Normalize URL
        parsed = urlparse(target)
        if not parsed.scheme:
            target = f"https://{target}"

        # Run recon if requested
        targets_to_scan = [target]
        if recon_mode:
            subdomains = self.recon(target)
            # Add live subdomains to scan list
            for sub in subdomains:
                if sub.get("https"):
                    targets_to_scan.append(f"https://{sub['subdomain']}")
                elif sub.get("http"):
                    targets_to_scan.append(f"http://{sub['subdomain']}")

            # Remove duplicates and the original
            targets_to_scan = list(set(targets_to_scan))

            if not quiet:
                print(f"\n  {Colors.BOLD}Scanning {len(targets_to_scan)} targets...{Colors.RESET}\n")

        available_modules = self._get_available_modules()

        # Select modules to run
        if modules is None:
            # Default modules (skip heavy ones like ports/dirs for speed)
            modules_to_run = ['tech', 'headers', 'info', 'auth', 'injection',
                              'xss', 'ssrf', 'redirect', 'ssl', 'cors', 'waf', 'api']
        else:
            modules_to_run = [m for m in modules if m in available_modules]

        # Scan each target
        profile = None
        for scan_target in targets_to_scan:
            # Probe target
            try:
                profile = self.client.probe(scan_target)
            except Exception as e:
                if not quiet:
                    print(f"  {Colors.RED}\u2717{Colors.RESET} {Colors.DIM}Connection failed: {str(e)[:50]}{Colors.RESET}")
                continue

            # Start UI
            self.ui.start(scan_target, profile)

            if not quiet:
                self.ui.print_header()

            # Crawl phase - discover endpoints before scanning
            crawled_urls = set()
            if hasattr(self, '_crawl_enabled') and self._crawl_enabled:
                if not quiet:
                    print(f"  {Colors.CYAN}\u27f3{Colors.RESET} {Colors.DIM}Crawling target for endpoints...{Colors.RESET}")
                crawler = WebCrawler(self.client, max_depth=getattr(self, '_crawl_depth', 3))
                crawl_result = crawler.crawl(scan_target)
                crawled_urls = set(crawl_result.endpoints)
                self.response_data['crawl_forms'] = crawl_result.forms
                self.response_data['crawl_endpoints'] = list(crawl_result.endpoints)
                self.response_data['crawl_js_endpoints'] = crawl_result.js_endpoints
                self.response_data['crawl_graph'] = crawl_result.graph
                self.response_data['crawl_parameters'] = crawl_result.parameters
                if not quiet:
                    print(f"  {Colors.GREEN}\u2713{Colors.RESET} {Colors.DIM}Discovered {len(crawled_urls)} endpoints, {len(crawl_result.forms)} forms{Colors.RESET}")
                    print()

            # Create scanning progress bar
            if not quiet:
                self.ui.create_scan_bar(len(modules_to_run))

            # Run each module
            for mod_key in modules_to_run:
                name, scanner_class, activities = available_modules[mod_key]
                progress = self.ui.add_module(name)

                module_findings = self._run_module_with_activity(
                    name, scanner_class, scan_target, progress, activities, quiet
                )

                # Convert Finding objects to dicts
                for f in module_findings:
                    if isinstance(f, Finding):
                        self.findings.append(f)
                        self.ui.add_finding(f.to_dict())
                        self._record_endpoint(f.url, source=name, metadata={"vuln_class": f.vuln_class})
                    elif isinstance(f, dict):
                        self.findings.append(Finding(**f) if 'vuln_class' in f else f)
                        self.ui.add_finding(f)
                        self._record_endpoint(f.get("url"), source=name, metadata={"vuln_class": f.get("vuln_class")})

            # Finish scanning progress bar and stop UI
            if not quiet and self.ui._scan_bar:
                self.ui._scan_bar.finish("Complete")

            self.ui.stop()

            # Collect response data for AI analysis
            try:
                resp = self.client.get(scan_target, timeout=10)
                self.response_data["responses"].append({
                    "url": scan_target,
                    "status": resp.status_code,
                    "headers": dict(resp.headers),
                    "body_preview": resp.text[:3000],
                    "cookies": dict(resp.cookies),
                })
                self._record_endpoint(
                    scan_target,
                    source="probe",
                    status=resp.status_code,
                    content_type=resp.headers.get("Content-Type", "")
                )
                if profile and profile.technologies:
                    self.response_data["technologies"] = [
                        {"name": t.name, "version": t.version}
                        for t in profile.technologies
                    ]
            except Exception:
                pass

        # AI Verification and Discovery Phase
        if ai_mode and self.ai_engine and self.ai_engine.is_available():
            if not quiet:
                print(f"\n  {Colors.PURPLE}{'─' * 76}{Colors.RESET}")
                print(f"  {Colors.PURPLE}{Colors.BOLD}AI VERIFICATION{Colors.RESET}  {Colors.DIM}Claude-powered analysis{Colors.RESET}")
                print(f"  {Colors.PURPLE}{'─' * 76}{Colors.RESET}")
                print()

            # Create verification progress bar
            total_verify_steps = len(self.findings) + 2  # findings + discovery + chains
            verify_bar = self.ui.create_verify_bar(total_verify_steps)

            sys.stdout.write(Colors.HIDE_CURSOR)
            sys.stdout.flush()

            def ai_callback(msg_type, msg):
                if msg_type == "probe":
                    verify_bar.update(msg[:28])
                elif msg_type == "success":
                    verify_bar.advance(msg[:28])
                elif msg_type == "info" and ("Rejected" in msg or "discovered" in msg):
                    verify_bar.advance(msg[:28])
                elif msg_type == "info":
                    verify_bar.update(msg[:28])
                elif msg_type == "error":
                    verify_bar.advance(msg[:28])

            # Run AI verification and discovery
            verified, discovered, chains = self.ai_engine.scan(
                target,
                existing_findings=self.findings,
                response_data=self.response_data,
                callback=ai_callback if not quiet else None
            )

            if not quiet:
                verify_bar.finish("Analysis complete")

            sys.stdout.write(Colors.SHOW_CURSOR)
            sys.stdout.flush()

            self.ai_verified_findings = verified
            self.ai_discovered_findings = discovered
            self.ai_rejected_findings = self.ai_engine.rejected_findings
            self.ai_chains = chains

            # Replace findings with AI-verified ones + new discoveries
            self.findings = verified + discovered

            if not quiet:
                parts = [
                    f"{Colors.GREEN}\u2713 {len(verified)} Verified{Colors.RESET}",
                    f"{Colors.CYAN}+ {len(discovered)} Discovered{Colors.RESET}",
                    f"{Colors.RED}\u2717 {len(self.ai_rejected_findings)} Rejected{Colors.RESET}",
                ]
                if chains:
                    parts.append(f"{Colors.ORANGE}\u26d3 {len(chains)} Chain(s){Colors.RESET}")
                print(f"\n  {Colors.PURPLE}{'─' * 76}{Colors.RESET}")
                print(f"  {Colors.BOLD}{Colors.WHITE}AI RESULTS{Colors.RESET}  {Colors.DIM}│{Colors.RESET}  {'  │  '.join(parts)}")
                print(f"  {Colors.PURPLE}{'─' * 76}{Colors.RESET}")

        # Deduplicate and sort all findings
        self.findings = deduplicate_findings(self.findings)
        self.findings = sort_findings(self.findings)

        elapsed = time.time() - start_time

        # Count severities
        critical = sum(1 for f in self.findings if f.severity == 'CRITICAL')
        high = sum(1 for f in self.findings if f.severity == 'HIGH')
        medium = sum(1 for f in self.findings if f.severity == 'MEDIUM')
        low = sum(1 for f in self.findings if f.severity == 'LOW')

        if not quiet:
            self.ui.render_findings_summary()
            self.ui.render_all_findings()
            print_scan_complete(elapsed, len(self.findings), critical, high)

        # Safety stats (minimal)
        if self.safety and not quiet:
            stats = self.safety.get_stats()
            parts = [f"{stats['total_requests']} requests"]
            if stats['blocked_by_scope']:
                parts.append(f"{stats['blocked_by_scope']} blocked")
            if stats['rate_limit_wait_total']:
                parts.append(f"{stats['rate_limit_wait_total']:.1f}s throttled")
            print(f"  {Colors.DIM}Safety: {' · '.join(parts)}{Colors.RESET}")

        # Auto-save detailed JSON report
        report_path = self._save_report(target, elapsed, profile)
        if not quiet and report_path:
            print(f"  {Colors.GREEN}Report auto-saved:{Colors.RESET} {report_path}\n")

        return self.findings

    def _save_report(self, target: str, elapsed: float, profile) -> str:
        """Auto-save detailed JSON report after scan"""
        # Create reports directory
        reports_dir = os.path.join(os.getcwd(), "vulnscan_reports")
        os.makedirs(reports_dir, exist_ok=True)

        # Generate filename from target and timestamp
        parsed = urlparse(target)
        domain = parsed.netloc.replace(":", "_").replace(".", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{domain}_{timestamp}.json"
        filepath = os.path.join(reports_dir, filename)

        # Count severities
        severity_counts = {
            "CRITICAL": sum(1 for f in self.findings if f.severity == 'CRITICAL'),
            "HIGH": sum(1 for f in self.findings if f.severity == 'HIGH'),
            "MEDIUM": sum(1 for f in self.findings if f.severity == 'MEDIUM'),
            "LOW": sum(1 for f in self.findings if f.severity == 'LOW'),
            "INFO": sum(1 for f in self.findings if f.severity == 'INFO'),
        }

        # Build comprehensive report
        report = {
            "scan_info": {
                "target": target,
                "scan_date": datetime.now().isoformat(),
                "scan_duration_seconds": round(elapsed, 2),
                "scanner_version": "2.0.0",
                "total_findings": len(self.findings),
                "severity_counts": severity_counts,
                "modules_available": 16,
                "ai_mode": self.ai_enabled,
            },
            "target_profile": {
                "technologies": [
                    {
                        "name": t.name,
                        "version": t.version,
                        "confidence": t.confidence,
                        "source": t.source,
                    }
                    for t in (profile.technologies if profile else [])
                ],
                "waf_detected": profile.waf_detected if profile else None,
                "server_os": profile.server_os if profile else None,
            },
            "subdomains_discovered": [
                {
                    "subdomain": s.get("subdomain"),
                    "ip": s.get("ip"),
                    "live": s.get("http") or s.get("https"),
                }
                for s in self.discovered_subdomains
            ] if self.discovered_subdomains else [],
            "ai_analysis": {
                "verified_count": len(self.ai_verified_findings),
                "discovered_count": len(self.ai_discovered_findings),
                "rejected_count": len(self.ai_rejected_findings),
                "rejected_findings": self.ai_rejected_findings,
                "chains": self.ai_chains,
            } if self.ai_engine else None,
            "findings": [],
        }

        # Add detailed findings
        for f in self.findings:
            finding_dict = f.to_dict() if isinstance(f, Finding) else f
            report["findings"].append({
                "id": finding_dict.get("fingerprint", ""),
                "vuln_class": finding_dict.get("vuln_class", ""),
                "severity": finding_dict.get("severity", ""),
                "cvss": finding_dict.get("cvss", 0),
                "url": finding_dict.get("url", ""),
                "parameter": finding_dict.get("parameter", ""),
                "description": finding_dict.get("description", ""),
                "evidence": finding_dict.get("evidence", ""),
                "request": finding_dict.get("request", ""),
                "response": finding_dict.get("response", ""),
                "remediation": finding_dict.get("remediation", []),
                "references": finding_dict.get("references", []),
                "tags": finding_dict.get("tags", []),
                "confidence": finding_dict.get("confidence", 1.0),
                "timestamp": finding_dict.get("timestamp", ""),
            })

        # Write report
        try:
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            return filepath
        except Exception as e:
            return None

    def _run_module_with_activity(self, name: str, scanner_class, base_url: str,
                                   progress: ModuleProgress, activities: List[tuple],
                                   quiet: bool) -> List[Finding]:
        """Run a scanner module with real-time activity logging"""
        progress.start()

        try:
            # Handle special scanner initialization
            if name in ['SSL/TLS Analysis', 'Port Scanner']:
                scanner = scanner_class()  # These don't need client
            else:
                scanner = scanner_class(self.client)

            # Log activities as we scan
            for i, (action, detail) in enumerate(activities):
                if not quiet:
                    progress.update(action, detail)

            # Actually run the scan
            findings = scanner.scan(base_url)

            # Log findings as they're discovered
            for f in findings:
                if isinstance(f, Finding):
                    sev = f.severity
                    vuln = f.vuln_class
                    detail = f.url[:40] if f.url else ""
                else:
                    sev = f.get('severity', 'INFO')
                    vuln = f.get('vuln_class', 'Unknown')
                    detail = (f.get('url', '') or '')[:40]

                if sev in ['CRITICAL', 'HIGH', 'MEDIUM']:
                    progress.found(vuln, sev, detail)

            progress.finish(len(findings))
            return findings

        except Exception as e:
            progress.error(str(e)[:50])
            return []

    def save_html_report(self, target: str, elapsed: float, profile, chains: list = None) -> str:
        """Generate HTML report from scan findings"""
        template_path = os.path.join(os.path.dirname(__file__), 'templates', 'report.html')
        if not os.path.exists(template_path):
            return None

        try:
            with open(template_path, 'r') as f:
                template_str = f.read()
        except Exception:
            return None

        # Simple Jinja2-style rendering without requiring jinja2 package
        # Build report data
        severity_counts = {}
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            severity_counts[sev] = sum(1 for f in self.findings if f.severity == sev)

        scan_info = {
            "target": target,
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scan_duration_seconds": round(elapsed, 2),
            "scanner_version": "2.0.0",
            "total_findings": len(self.findings),
            "severity_counts": severity_counts,
            "ai_mode": self.ai_enabled,
        }

        target_profile = {
            "technologies": [
                {"name": t.name, "version": t.version, "confidence": t.confidence}
                for t in (profile.technologies if profile else [])
            ],
            "waf_detected": profile.waf_detected if profile else None,
            "server_os": profile.server_os if profile else None,
        }

        findings_list = [f.to_dict() for f in self.findings]

        ai_analysis = None
        if self.ai_enabled:
            ai_analysis = {
                "verified_count": len(self.ai_verified_findings),
                "discovered_count": len(self.ai_discovered_findings),
                "rejected_count": len(self.ai_rejected_findings),
            }

        # Try Jinja2 first, fall back to string replacement
        try:
            from jinja2 import Template
            tmpl = Template(template_str)
            html = tmpl.render(
                scan_info=scan_info,
                target_profile=target_profile,
                findings=findings_list,
                ai_analysis=ai_analysis,
                chains=chains or [],
            )
        except ImportError:
            # Fallback: basic string replacement for key values
            html = template_str
            html = html.replace('{{ scan_info.target }}', str(scan_info['target']))
            html = html.replace('{{ scan_info.scan_date }}', str(scan_info['scan_date']))
            html = html.replace('{{ scan_info.total_findings }}', str(scan_info['total_findings']))
            html = html.replace('{{ scan_info.scanner_version }}', str(scan_info['scanner_version']))
            html = html.replace('{{ scan_info.scan_duration_seconds }}', str(scan_info['scan_duration_seconds']))

        # Save HTML report
        reports_dir = os.path.join(os.getcwd(), "vulnscan_reports")
        os.makedirs(reports_dir, exist_ok=True)
        parsed = urlparse(target)
        domain = parsed.netloc.replace(":", "_").replace(".", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(reports_dir, f"{domain}_{timestamp}.html")

        try:
            with open(filepath, 'w') as f:
                f.write(html)
            return filepath
        except Exception:
            return None

    def _record_endpoint(self, url: str, source: str, status: int = None,
                         content_type: str = "", metadata: Dict = None):
        """Track HTTP endpoints for AI post-analysis without duplicating entries."""
        if not url or not isinstance(url, str):
            return
        if not url.startswith(("http://", "https://")):
            return
        if url in self._seen_endpoints:
            return

        self._seen_endpoints.add(url)
        endpoint = {
            "url": url,
            "source": source,
        }
        if status is not None:
            endpoint["status"] = status
        if content_type:
            endpoint["content_type"] = content_type
        if metadata:
            endpoint.update(metadata)

        self.response_data["endpoints"].append(endpoint)

    @staticmethod
    def _get_available_modules() -> Dict:
        """Return the mapping of module key → (display_name, class, activities)."""
        return {
            'tech': ('Tech Fingerprint', TechScanner, [
                ("Detecting server software", "Analyzing response headers"),
                ("Checking X-Powered-By", "Version fingerprinting"),
                ("Analyzing JavaScript files", "Framework detection"),
                ("Checking meta tags", "CMS detection"),
                ("Querying CVE database", "Matching known vulnerabilities"),
            ]),
            'headers': ('Security Headers', SecurityHeadersScanner, [
                ("Checking CSP header", "Content-Security-Policy analysis"),
                ("Checking HSTS", "Strict-Transport-Security"),
                ("Checking X-Frame-Options", "Clickjacking protection"),
                ("Analyzing CORS policy", "Cross-origin configuration"),
                ("Checking cookie flags", "HttpOnly, Secure, SameSite"),
            ]),
            'info': ('Info Disclosure', InfoDisclosureScanner, [
                ("Probing /.git/config", "Git repository exposure"),
                ("Probing /.env", "Environment file check"),
                ("Checking /robots.txt", "Crawling restrictions"),
                ("Probing /error_log", "Error log exposure"),
                ("Checking /phpinfo.php", "PHP configuration leak"),
                ("Probing /backup.sql", "Database backup exposure"),
                ("Testing /api/swagger.json", "API documentation leak"),
                ("Checking directory listing", "Index exposure"),
            ]),
            'auth': ('Authentication', AuthScanner, [
                ("Finding login forms", "Endpoint discovery"),
                ("Testing user enumeration", "Response differential"),
                ("Checking brute force protection", "Rate limiting test"),
                ("Analyzing CSRF protection", "Token validation"),
                ("Checking JWT security", "Token analysis"),
            ]),
            'injection': ('Injection Tests', InjectionScanner, [
                ("Testing SQL injection", "Error-based SQLi"),
                ("Testing blind SQLi", "Time-based detection"),
                ("Testing command injection", "OS command execution"),
                ("Testing SSTI", "Template injection"),
                ("Testing CRLF injection", "Header injection"),
            ]),
            'xss': ('XSS Scanner', XSSScanner, [
                ("Testing reflected XSS", "Parameter injection"),
                ("Checking DOM sinks", "Client-side analysis"),
                ("Testing attribute context", "Event handler injection"),
                ("Testing JavaScript context", "Script breakout"),
            ]),
            'ssrf': ('SSRF Scanner', SSRFScanner, [
                ("Testing localhost bypass", "127.0.0.1 variants"),
                ("Testing cloud metadata", "AWS/GCP/Azure endpoints"),
                ("Testing internal networks", "RFC1918 ranges"),
                ("Testing protocol handlers", "file://, gopher://"),
            ]),
            'redirect': ('Open Redirect', OpenRedirectScanner, [
                ("Finding redirect params", "URL parameter analysis"),
                ("Testing direct URLs", "External redirect"),
                ("Testing parser confusion", "URL bypass techniques"),
                ("Testing JavaScript redirect", "Protocol handlers"),
            ]),
            'ssl': ('SSL/TLS Analysis', SSLScanner, [
                ("Retrieving certificate", "Certificate validation"),
                ("Checking expiration", "Certificate lifetime"),
                ("Testing TLS versions", "Protocol analysis"),
                ("Analyzing cipher suites", "Crypto strength"),
            ]),
            'cors': ('CORS Scanner', CORSScanner, [
                ("Testing origin reflection", "Arbitrary origin"),
                ("Testing null origin", "Sandboxed bypass"),
                ("Testing subdomain bypass", "Wildcard matching"),
                ("Testing special chars", "Parser confusion"),
            ]),
            'waf': ('WAF Detection', WAFBypassScanner, [
                ("Fingerprinting WAF", "Signature detection"),
                ("Testing method bypass", "HTTP verb tampering"),
                ("Testing encoding bypass", "Payload obfuscation"),
                ("Testing header bypass", "Request manipulation"),
            ]),
            'dirs': ('Directory Scanner', DirectoryScanner, [
                ("Scanning common paths", "Admin panels"),
                ("Checking backup files", "Sensitive data"),
                ("Testing API endpoints", "Swagger, GraphQL"),
                ("Checking git exposure", "Version control"),
            ]),
            'ports': ('Port Scanner', PortScanner, [
                ("Scanning common ports", "Service discovery"),
                ("Grabbing banners", "Version detection"),
                ("Checking dangerous services", "Exposed databases"),
                ("Identifying protocols", "Service fingerprint"),
            ]),
            'api': ('API Security', APIScanner, [
                ("Testing GraphQL", "Introspection check"),
                ("Checking API docs", "Swagger/OpenAPI exposure"),
                ("Testing rate limits", "Brute force protection"),
                ("Checking BOLA patterns", "IDOR susceptibility"),
            ]),
            'crawl': ('Web Crawler', WebCrawler, [
                ("Crawling pages", "Link extraction"),
                ("Parsing forms", "Input discovery"),
                ("Extracting JS endpoints", "API route detection"),
                ("Building endpoint graph", "Site mapping"),
            ]),
        }

    # ── Extensive scan mode ──────────────────────────────────────────────

    def extensive_scan(self, target: str) -> List[Finding]:
        """
        AI-guided full attack lifecycle: recon → surface mapping →
        full scanning → AI deep analysis → executive summary.

        Unlike --recon --full --ai, the AI actively PLANS the attack strategy.

        Args:
            target: Primary target URL

        Returns:
            List of Finding objects
        """
        start_time = time.time()
        self.findings = []
        self.ai_verified_findings = []
        self.ai_discovered_findings = []
        self.ai_rejected_findings = []
        self.ai_chains = []
        self.response_data = {"endpoints": [], "responses": [], "technologies": []}
        self._seen_endpoints = set()

        # Initialize AI engine (required for extensive mode)
        self.ai_engine = AISecurityEngine(self.client, self.ai_api_key)
        self.ai_enabled = True

        # Normalize target
        parsed = urlparse(target)
        if not parsed.scheme:
            target = f"https://{target}"
            parsed = urlparse(target)

        domain = parsed.netloc.split(":")[0]
        if domain.startswith("www."):
            domain = domain[4:]

        # Print banner + extensive mode header
        print(BANNER)
        w = self.ui.W
        print(f"  {Colors.RED}{'━' * w}{Colors.RESET}")
        print(
            f"  {Colors.RED}{Colors.BOLD}EXTENSIVE MODE{Colors.RESET}  "
            f"{Colors.DIM}│{Colors.RESET}  "
            f"{Colors.WHITE}AI-Guided Full Attack Lifecycle{Colors.RESET}"
        )
        print(f"  {Colors.RED}{'━' * w}{Colors.RESET}")
        print(f"  {Colors.BOLD}{Colors.WHITE}TARGET{Colors.RESET}   {Colors.WHITE}{target}{Colors.RESET}")
        print(f"  {Colors.BOLD}{Colors.WHITE}TIME{Colors.RESET}     {Colors.DIM}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
        print(f"  {Colors.DIM}{'─' * w}{Colors.RESET}")

        # ── Phase 1: RECONNAISSANCE ──────────────────────────────────

        self.ui.print_phase_header(1, "RECONNAISSANCE")

        # Subdomain enumeration
        subdomain_scanner = SubdomainScanner(self.client)
        recon_bar = self.ui.create_phase_bar(3, "Recon", Colors.CYAN)

        def recon_cb(msg_type, msg):
            recon_bar.update(msg[:28])

        recon_bar.update("Enumerating subdomains")
        self.discovered_subdomains = subdomain_scanner.enumerate(
            domain, use_wordlist=True, use_crtsh=True, callback=recon_cb
        )
        recon_bar.advance("Subdomains done")

        live_targets = []
        for sub in self.discovered_subdomains:
            if sub.get("https"):
                live_targets.append(f"https://{sub['subdomain']}")
            elif sub.get("http"):
                live_targets.append(f"http://{sub['subdomain']}")
        live_targets = list(set(live_targets))
        if target not in live_targets:
            live_targets.insert(0, target)

        # Port scan main target
        recon_bar.update("Port scanning")
        port_scanner = PortScanner()
        port_findings = port_scanner.scan(target)
        recon_bar.advance("Ports done")

        open_ports = [f.evidence.get("port") for f in port_findings
                      if isinstance(f, Finding) and f.evidence and f.evidence.get("port")]

        recon_bar.finish(f"{len(self.discovered_subdomains)} subdomains, {len(live_targets)} live")

        recon_data = {
            "subdomains": [s.get("subdomain") for s in self.discovered_subdomains],
            "live_targets": live_targets,
            "open_ports": open_ports,
        }
        self.ui.print_phase_stat("Subdomains", len(self.discovered_subdomains))
        self.ui.print_phase_stat("Live targets", len(live_targets))
        self.ui.print_phase_stat("Open ports", len(open_ports))
        self.ui.print_phase_footer()

        # ── Phase 2: SURFACE MAPPING ─────────────────────────────────

        self.ui.print_phase_header(2, "SURFACE MAPPING")

        all_endpoints = []
        all_forms = []
        all_params = set()
        tech_data = []

        map_bar = self.ui.create_phase_bar(len(live_targets), "Mapping", Colors.PURPLE)

        for lt in live_targets:
            map_bar.update(urlparse(lt).netloc[:28])

            # Crawl
            try:
                crawler = WebCrawler(self.client, max_depth=3)
                crawl_result = crawler.crawl(lt)
                all_endpoints.extend(crawl_result.endpoints)
                all_forms.extend(crawl_result.forms)
                all_params.update(crawl_result.parameters)
            except Exception:
                pass

            # Tech fingerprint
            try:
                tech_scanner = TechScanner(self.client)
                tech_findings = tech_scanner.scan(lt)
                tech_data.extend([f.to_dict() if isinstance(f, Finding) else f for f in tech_findings])
            except Exception:
                pass

            map_bar.advance()

        map_bar.finish(f"{len(all_endpoints)} endpoints, {len(all_forms)} forms")

        surface_data = {
            "endpoints": list(set(all_endpoints))[:200],
            "forms": all_forms[:50],
            "parameters": list(all_params)[:100],
            "technologies": tech_data[:30],
        }
        self.response_data["endpoints"] = [{"url": ep, "source": "crawl"} for ep in all_endpoints[:200]]
        self.response_data["technologies"] = tech_data[:30]

        self.ui.print_phase_stat("Endpoints", len(all_endpoints))
        self.ui.print_phase_stat("Forms", len(all_forms))
        self.ui.print_phase_stat("Parameters", len(all_params))
        self.ui.print_phase_footer()

        # ── Phase 3: VULNERABILITY SCANNING ──────────────────────────

        self.ui.print_phase_header(3, "VULNERABILITY SCANNING")

        available_modules = self._get_available_modules()
        all_mod_keys = list(available_modules.keys())
        scan_bar = self.ui.create_phase_bar(
            len(all_mod_keys) * len(live_targets), "Scanning", Colors.ORANGE
        )
        self.ui._scan_bar = scan_bar

        for lt in live_targets:
            # Probe target
            try:
                profile = self.client.probe(lt)
            except Exception:
                scan_bar.advance(f"Skip {urlparse(lt).netloc[:20]}")
                continue

            for mod_key in all_mod_keys:
                name, scanner_class, activities = available_modules[mod_key]
                progress = self.ui.add_module(name)
                progress._scan_bar = scan_bar  # wire to phase bar

                module_findings = self._run_module_with_activity(
                    name, scanner_class, lt, progress, activities, quiet=False
                )

                for f in module_findings:
                    if isinstance(f, Finding):
                        self.findings.append(f)
                        self.ui.add_finding(f.to_dict())
                    elif isinstance(f, dict) and 'vuln_class' in f:
                        self.findings.append(Finding(**f))
                        self.ui.add_finding(f)

        scan_bar.finish(f"{len(self.findings)} findings")
        self.ui._scan_bar = None

        self.ui.print_phase_stat("Raw findings", len(self.findings))
        self.ui.print_phase_footer()

        # ── Phase 4: AI DEEP ANALYSIS ────────────────────────────────

        self.ui.print_phase_header(4, "AI DEEP ANALYSIS")

        # Collect response data for primary target
        try:
            resp = self.client.get(target, timeout=10)
            self.response_data["responses"].append({
                "url": target,
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "body_preview": resp.text[:3000],
                "cookies": dict(resp.cookies),
            })
        except Exception:
            pass

        # Step 4a: AI verify existing findings
        total_ai_steps = len(self.findings) + 4  # verify + discover + plan + chain
        ai_bar = self.ui.create_phase_bar(total_ai_steps, "Analyzing", Colors.RED)

        def ai_cb(msg_type, msg):
            if msg_type in ("success", "error"):
                ai_bar.advance(msg[:28])
            elif msg_type == "info" and ("Rejected" in msg or "discovered" in msg):
                ai_bar.advance(msg[:28])
            else:
                ai_bar.update(msg[:28])

        ai_bar.update("Verifying findings")
        verified, discovered, chains = self.ai_engine.scan(
            target,
            existing_findings=self.findings,
            response_data=self.response_data,
            callback=ai_cb
        )

        self.ai_verified_findings = verified
        self.ai_discovered_findings = discovered
        self.ai_rejected_findings = self.ai_engine.rejected_findings
        self.ai_chains = chains

        # Step 4b: AI plan targeted attacks
        ai_bar.update("Planning attacks")
        attack_plans = self.ai_engine.plan_attack(target, recon_data, surface_data)
        ai_bar.advance(f"{len(attack_plans)} plans")

        # Step 4c: Execute attack plans
        plan_findings = []
        for plan in attack_plans:
            ai_bar.update(f"Testing {plan.get('test_type', '?')[:20]}")
            try:
                pf = self.ai_engine.deep_scan_endpoint(
                    url=plan.get("url", target),
                    method=plan.get("method", "GET"),
                    params=plan.get("params"),
                    callback=ai_cb,
                )
                plan_findings.extend(pf)
            except Exception:
                pass
        ai_bar.advance(f"{len(plan_findings)} from plans")

        discovered.extend(plan_findings)
        self.ai_discovered_findings = discovered

        # Step 4d: Chain detection on full set
        all_confirmed = verified + discovered
        if len(all_confirmed) >= 2:
            ai_bar.update("Detecting chains")
            chains = self.ai_engine.detect_chains(all_confirmed)
            self.ai_chains = chains
        ai_bar.advance("Chains done")

        ai_bar.finish("Analysis complete")

        self.ui.print_phase_stat("Verified", len(verified))
        self.ui.print_phase_stat("Discovered", len(discovered))
        self.ui.print_phase_stat("Rejected", len(self.ai_rejected_findings))
        self.ui.print_phase_stat("Attack plans", len(attack_plans))
        self.ui.print_phase_stat("Chains", len(self.ai_chains))
        self.ui.print_phase_footer()

        # Replace findings with AI-curated set
        self.findings = verified + discovered
        self.findings = deduplicate_findings(self.findings)
        self.findings = sort_findings(self.findings)

        # ── Phase 5: REPORTING ───────────────────────────────────────

        self.ui.print_phase_header(5, "REPORTING")

        elapsed = time.time() - start_time

        # Generate executive summary
        scan_info = {
            "target": target,
            "domain": domain,
            "scan_duration_seconds": round(elapsed, 2),
            "live_targets_scanned": len(live_targets),
            "subdomains_found": len(self.discovered_subdomains),
            "total_findings": len(self.findings),
            "modules_run": len(all_mod_keys),
        }

        summary_text = self.ai_engine.generate_summary(
            self.findings, self.ai_chains, scan_info
        )

        if summary_text:
            print(f"\n  {Colors.BOLD}{Colors.WHITE}EXECUTIVE SUMMARY{Colors.RESET}")
            print(f"  {Colors.DIM}{'─' * w}{Colors.RESET}")
            for line in summary_text.split("\n"):
                print(f"  {Colors.DIM}{line}{Colors.RESET}")
            print(f"  {Colors.DIM}{'─' * w}{Colors.RESET}")

        # Save reports
        report_path = self._save_extensive_report(
            target, elapsed, recon_data, surface_data,
            attack_plans, summary_text, profile=None
        )
        html_path = self.save_html_report(
            target, elapsed, profile=None, chains=self.ai_chains
        )

        self.ui.print_phase_stat("JSON report", report_path or "failed")
        self.ui.print_phase_stat("HTML report", html_path or "failed")
        self.ui.print_phase_footer()

        # Print findings
        self.ui.render_findings_summary()
        self.ui.render_all_findings()

        critical = sum(1 for f in self.findings if f.severity == 'CRITICAL')
        high = sum(1 for f in self.findings if f.severity == 'HIGH')
        print_scan_complete(elapsed, len(self.findings), critical, high)

        return self.findings

    def _save_extensive_report(self, target: str, elapsed: float,
                                recon_data: Dict, surface_data: Dict,
                                attack_plans: List[Dict], summary_text: str,
                                profile=None) -> Optional[str]:
        """Save comprehensive JSON report for extensive mode."""
        reports_dir = os.path.join(os.getcwd(), "vulnscan_reports")
        os.makedirs(reports_dir, exist_ok=True)

        parsed = urlparse(target)
        domain = parsed.netloc.replace(":", "_").replace(".", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(reports_dir, f"{domain}_extensive_{timestamp}.json")

        severity_counts = {}
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            severity_counts[sev] = sum(1 for f in self.findings if f.severity == sev)

        report = {
            "scan_info": {
                "target": target,
                "mode": "extensive",
                "scan_date": datetime.now().isoformat(),
                "scan_duration_seconds": round(elapsed, 2),
                "scanner_version": "2.0.0",
                "total_findings": len(self.findings),
                "severity_counts": severity_counts,
            },
            "recon": recon_data,
            "surface": {
                "endpoints_count": len(surface_data.get("endpoints", [])),
                "forms_count": len(surface_data.get("forms", [])),
                "parameters_count": len(surface_data.get("parameters", [])),
                "technologies": surface_data.get("technologies", []),
            },
            "ai_analysis": {
                "verified_count": len(self.ai_verified_findings),
                "discovered_count": len(self.ai_discovered_findings),
                "rejected_count": len(self.ai_rejected_findings),
                "rejected_findings": self.ai_rejected_findings,
                "attack_plans": attack_plans,
                "chains": self.ai_chains,
            },
            "executive_summary": summary_text,
            "findings": [
                f.to_dict() if isinstance(f, Finding) else f
                for f in self.findings
            ],
        }

        try:
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            return filepath
        except Exception:
            return None


def main():
    """CLI entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="VulnScan Pro - Adaptive Vulnerability Scanner with AI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.CYAN}Examples:{Colors.RESET}
  vulnscan https://target.com
  vulnscan https://target.com --proxy http://127.0.0.1:8080
  vulnscan https://target.com --modules tech,headers,xss
  vulnscan https://target.com --recon        # Discover subdomains first
  vulnscan https://target.com --profile quick  # Fast scan
  vulnscan https://target.com --profile web   # Web vulns only
  vulnscan https://target.com --full          # All modules including heavy scans
  vulnscan https://target.com --ai            # Enable AI verification
  vulnscan https://target.com --crawl          # Crawl target first
  vulnscan https://target.com --crawl --crawl-depth 5  # Deep crawl
  vulnscan https://target.com --rate-limit 5           # Max 5 requests/sec
  vulnscan https://target.com --safe-mode              # No destructive payloads
  vulnscan https://target.com --scope target.com,api.target.com
  vulnscan https://target.com --extensive --ai-key KEY  # AI-guided full lifecycle
  vulnscan https://target.com --report-html   # Generate HTML report
  vulnscan https://target.com --output report.json
  vulnscan https://target.com --cookie "session=abc123"
  vulnscan https://target.com --bearer eyJhbGciOiJIUzI1NiJ9...
  vulnscan https://target.com --header "X-API-Key: secret123"
  vulnscan https://target.com --burp-request saved_request.txt

{Colors.CYAN}Available Modules (15):{Colors.RESET}
  tech      - Technology fingerprinting & CVE detection
  headers   - Security headers analysis
  info      - Information disclosure & sensitive files
  auth      - Authentication security testing
  injection - SQL/Command/Template injection
  xss       - Cross-site scripting detection
  ssrf      - Server-side request forgery
  redirect  - Open redirect vulnerabilities
  ssl       - SSL/TLS certificate & protocol analysis
  cors      - CORS misconfiguration detection
  waf       - WAF detection & bypass testing
  api       - API security (GraphQL, REST, BOLA)
  crawl     - Web crawler & endpoint discovery
  dirs      - Directory & file discovery (slow)
  ports     - Port scanning & service detection (slow)

{Colors.CYAN}Scan Profiles:{Colors.RESET}
  --profile quick   - Fast scan (tech, headers, info, ssl)
  --profile web     - Web vulnerability focus (skip infrastructure)
  --profile full    - All modules including heavy scans
  --profile stealth - Passive only, no active probes

{Colors.CYAN}Scan Modes:{Colors.RESET}
  --recon       - Discover subdomains before scanning
  --crawl       - Crawl target to discover endpoints before scanning
  --full        - Include all modules (dirs, ports)
  --ai          - Enable AI-powered verification & discovery
  --extensive   - AI-guided full attack lifecycle (recon+scan+AI analysis)
  --report-html - Generate HTML report alongside JSON

{Colors.CYAN}Safety Controls:{Colors.RESET}
  --rate-limit N  - Max N requests per second (0 = unlimited)
  --safe-mode     - Disable destructive/noisy payloads
  --scope DOMAINS - Comma-separated allowed domains (restricts all requests)

{Colors.PURPLE}AI Features (--ai):{Colors.RESET}
  \u2022 Verifies findings to eliminate false positives
  \u2022 Discovers additional vulnerabilities through intelligent analysis
  \u2022 Analyzes business logic flaws
  \u2022 Generates context-aware payloads
  \u2022 Requires ANTHROPIC_API_KEY environment variable or --ai-key
        """
    )

    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('--proxy', '-p', help='Proxy URL (e.g., http://127.0.0.1:8080 for Burp)')
    parser.add_argument('--modules', '-m', help='Comma-separated list of modules to run')
    parser.add_argument('--timeout', '-t', type=int, default=15, help='Request timeout in seconds')
    parser.add_argument('--output', '-o', help='Output file for JSON report')
    parser.add_argument('--quiet', '-q', action='store_true', help='Quiet mode (minimal output)')
    parser.add_argument('--recon', '-r', action='store_true', help='Run subdomain discovery first')
    parser.add_argument('--profile', choices=['quick', 'web', 'full', 'stealth'],
                        help='Scan profile (quick/web/full/stealth)')
    parser.add_argument('--full', '-f', action='store_true', help='Run all modules including heavy scans')
    parser.add_argument('--ai', '-a', action='store_true', help='Enable AI-powered verification & discovery')
    parser.add_argument('--ai-key', help='Anthropic API key (or set ANTHROPIC_API_KEY env var)')
    parser.add_argument('--extensive', '-e', action='store_true',
                        help='AI-guided full attack lifecycle (recon → mapping → scanning → AI analysis → report)')
    parser.add_argument('--report-html', action='store_true', help='Generate HTML report')
    parser.add_argument('--crawl', action='store_true', help='Crawl target to discover endpoints before scanning')
    parser.add_argument('--crawl-depth', type=int, default=3, help='Maximum crawl depth (default: 3)')

    # Safety controls
    parser.add_argument('--rate-limit', type=float, default=0, help='Max requests per second (0 = unlimited)')
    parser.add_argument('--safe-mode', action='store_true', help='Disable destructive/noisy payloads')
    parser.add_argument('--scope', help='Comma-separated allowed domains (restricts all requests)')

    parser.add_argument('--cookie', help='Cookies as "name=value; name2=value2"')
    parser.add_argument('--header', action='append', help='Custom header "Name: Value" (can repeat)')
    parser.add_argument('--bearer', help='Bearer token for Authorization header')
    parser.add_argument('--burp-request', help='Path to Burp Suite saved request file')

    args = parser.parse_args()

    # Auto-enable AI mode if key is provided
    if args.ai_key:
        args.ai = True

    # Parse modules (profile > modules > full > default)
    modules = None
    if args.profile:
        modules = SCAN_PROFILES[args.profile]['modules']
        if not args.quiet:
            print(f"\n  {Colors.CYAN}Profile:{Colors.RESET} {args.profile} \u2014 {SCAN_PROFILES[args.profile]['description']}")
    elif args.modules:
        modules = [m.strip() for m in args.modules.split(',')]
    elif args.full:
        modules = SCAN_PROFILES['full']['modules']

    # Parse authentication
    cookies = {}
    auth_headers = {}

    if args.cookie:
        for pair in args.cookie.split(';'):
            pair = pair.strip()
            if '=' in pair:
                name, value = pair.split('=', 1)
                cookies[name.strip()] = value.strip()

    if args.header:
        for h in args.header:
            if ':' in h:
                name, value = h.split(':', 1)
                auth_headers[name.strip()] = value.strip()

    if args.bearer:
        auth_headers['Authorization'] = f'Bearer {args.bearer}'

    if args.burp_request:
        burp_data = AdaptiveHTTPClient.parse_burp_request(args.burp_request)
        cookies.update(burp_data.get('cookies', {}))
        auth_headers.update(burp_data.get('headers', {}))

    # Safety controls
    scope_domains = None
    if args.scope:
        scope_domains = set(d.strip() for d in args.scope.split(','))

    safety = None
    if args.rate_limit > 0 or scope_domains or args.safe_mode:
        safety = SafetyConfig(
            rate_limit=args.rate_limit,
            scope_domains=scope_domains,
            safe_mode=args.safe_mode,
        )

    # Run scan
    scanner = VulnScanner(proxy=args.proxy, timeout=args.timeout, ai_api_key=args.ai_key,
                          cookies=cookies if cookies else None,
                          auth_headers=auth_headers if auth_headers else None,
                          safety=safety)
    scanner._crawl_enabled = args.crawl
    scanner._crawl_depth = getattr(args, 'crawl_depth', 3)

    # ── Extensive mode ────────────────────────────────────────────────
    if args.extensive:
        # Extensive requires an AI key
        ai_key = args.ai_key or os.environ.get("ANTHROPIC_API_KEY")
        if not ai_key:
            print(f"\n  {Colors.RED}✗ --extensive requires an AI API key{Colors.RESET}")
            print(f"  {Colors.DIM}Pass --ai-key KEY or set ANTHROPIC_API_KEY{Colors.RESET}\n")
            sys.exit(1)
        scanner.ai_api_key = ai_key

        # Default rate limit for extensive mode safety
        if not safety:
            safety = SafetyConfig(rate_limit=10)
            scanner.client.safety = safety
            scanner.safety = safety

        try:
            findings = scanner.extensive_scan(args.target)
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Scan interrupted by user{Colors.RESET}")
            sys.exit(130)

        critical_count = sum(1 for f in findings if f.severity == 'CRITICAL')
        high_count = sum(1 for f in findings if f.severity == 'HIGH')
        if critical_count > 0:
            sys.exit(2)
        elif high_count > 0:
            sys.exit(1)
        else:
            sys.exit(0)

    scan_start = time.time()
    try:
        findings = scanner.scan(args.target, modules=modules, quiet=args.quiet,
                               recon_mode=args.recon, ai_mode=args.ai)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Scan interrupted by user{Colors.RESET}")
        sys.exit(130)
    scan_elapsed = time.time() - scan_start

    # Generate HTML report if requested
    if args.report_html:
        html_path = scanner.save_html_report(
            args.target,
            elapsed=scan_elapsed,
            profile=scanner.client.profile,
            chains=scanner.ai_chains,
        )
        if html_path:
            print(f"  {Colors.GREEN}HTML report saved:{Colors.RESET} {html_path}")

    # Output to file if requested
    if args.output:
        import json
        with open(args.output, 'w') as f:
            json.dump([f.to_dict() for f in findings], f, indent=2, default=str)
        print(f"\n{Colors.GREEN}Report saved to: {args.output}{Colors.RESET}")

    # Exit code based on findings
    critical_count = sum(1 for f in findings if f.severity == 'CRITICAL')
    high_count = sum(1 for f in findings if f.severity == 'HIGH')

    if critical_count > 0:
        sys.exit(2)
    elif high_count > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
