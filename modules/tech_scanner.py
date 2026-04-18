"""
Module: Technology & Version Fingerprinting
- Software version detection
- CVE matching
- EOL software detection
- Learns from responses dynamically
"""

import re
import json
from typing import List, Dict, Optional
from datetime import datetime
from urllib.parse import urljoin

from ..core.finding import Finding
from ..core.http_client import AdaptiveHTTPClient, TechFingerprint


class TechScanner:
    """Technology fingerprinting and version vulnerability scanner"""

    def __init__(self, client: AdaptiveHTTPClient):
        self.client = client
        self.findings: List[Finding] = []

        # EOL dates for common software (learned/updated over time)
        # This is a starting point; ideally fetched from external source
        self.eol_database = {
            'PHP': [
                {'version_prefix': '5.', 'eol': '2018-12-31', 'severity': 'CRITICAL'},
                {'version_prefix': '7.0', 'eol': '2019-01-10', 'severity': 'CRITICAL'},
                {'version_prefix': '7.1', 'eol': '2019-12-01', 'severity': 'CRITICAL'},
                {'version_prefix': '7.2', 'eol': '2020-11-30', 'severity': 'HIGH'},
                {'version_prefix': '7.3', 'eol': '2021-12-06', 'severity': 'HIGH'},
                {'version_prefix': '7.4', 'eol': '2022-11-28', 'severity': 'MEDIUM'},
                {'version_prefix': '8.0', 'eol': '2023-11-26', 'severity': 'MEDIUM'},
            ],
            'Apache': [
                {'version_prefix': '2.2', 'eol': '2018-01-01', 'severity': 'CRITICAL'},
                {'version_prefix': '2.4.49', 'eol': '2021-10-07', 'severity': 'CRITICAL', 'cve': 'CVE-2021-41773'},
                {'version_prefix': '2.4.50', 'eol': '2021-10-07', 'severity': 'CRITICAL', 'cve': 'CVE-2021-42013'},
            ],
            'nginx': [
                {'version_prefix': '1.0', 'eol': '2014-04-01', 'severity': 'CRITICAL'},
                {'version_prefix': '1.2', 'eol': '2014-04-01', 'severity': 'CRITICAL'},
                {'version_prefix': '1.4', 'eol': '2016-04-01', 'severity': 'HIGH'},
            ],
            'OpenSSL': [
                {'version_prefix': '0.', 'eol': '2010-01-01', 'severity': 'CRITICAL'},
                {'version_prefix': '1.0.1', 'eol': '2016-12-31', 'severity': 'CRITICAL', 'cve': 'CVE-2014-0160'},
                {'version_prefix': '1.0.2', 'eol': '2020-01-01', 'severity': 'HIGH'},
                {'version_prefix': '1.1.0', 'eol': '2019-09-11', 'severity': 'HIGH'},
            ],
            'jQuery': [
                {'version_prefix': '1.', 'eol': '2016-06-01', 'severity': 'MEDIUM', 'cve': 'CVE-2020-11022'},
                {'version_prefix': '2.', 'eol': '2016-06-01', 'severity': 'MEDIUM', 'cve': 'CVE-2020-11023'},
            ],
            'WordPress': [
                {'version_prefix': '4.', 'eol': '2020-01-01', 'severity': 'HIGH'},
                {'version_prefix': '5.0', 'eol': '2022-01-01', 'severity': 'MEDIUM'},
            ],
            'Node.js': [
                {'version_prefix': '8.', 'eol': '2019-12-31', 'severity': 'HIGH'},
                {'version_prefix': '10.', 'eol': '2021-04-30', 'severity': 'MEDIUM'},
                {'version_prefix': '12.', 'eol': '2022-04-30', 'severity': 'MEDIUM'},
                {'version_prefix': '14.', 'eol': '2023-04-30', 'severity': 'LOW'},
            ],
        }

    def _check_version_eol(self, tech: TechFingerprint) -> Optional[Finding]:
        """Check if detected technology version is EOL"""
        name = tech.name
        version = tech.version

        if not version:
            return None

        # Normalize name
        name_mapping = {
            'php': 'PHP',
            'apache': 'Apache',
            'nginx': 'nginx',
            'openssl': 'OpenSSL',
            'jquery': 'jQuery',
            'wordpress': 'WordPress',
            'node': 'Node.js',
            'nodejs': 'Node.js',
        }
        normalized_name = name_mapping.get(name.lower(), name)

        if normalized_name not in self.eol_database:
            return None

        for entry in self.eol_database[normalized_name]:
            if version.startswith(entry['version_prefix']):
                eol_date = datetime.strptime(entry['eol'], '%Y-%m-%d')
                is_eol = datetime.now() > eol_date

                if is_eol:
                    cve = entry.get('cve', '')
                    severity = entry['severity']

                    description = (
                        f"{normalized_name} {version} is End-of-Life (EOL since {entry['eol']}). "
                        f"No security patches available. "
                    )
                    if cve:
                        description += f"Known CVE: {cve}. "

                    return Finding(
                        vuln_class="End-of-Life Software",
                        severity=severity,
                        cvss=9.8 if severity == 'CRITICAL' else 7.5 if severity == 'HIGH' else 5.0,
                        url=tech.source,
                        description=description,
                        evidence={
                            'technology': normalized_name,
                            'version': version,
                            'eol_date': entry['eol'],
                            'detection_source': tech.source,
                            'raw_evidence': tech.raw_evidence,
                        },
                        remediation=[
                            f"Upgrade {normalized_name} to the latest supported version",
                            "Test in staging before production upgrade",
                            "Enable automatic security updates if available",
                        ],
                        references=[
                            f"https://endoflife.date/{normalized_name.lower().replace('.', '')}",
                        ] + ([f"https://nvd.nist.gov/vuln/detail/{cve}"] if cve else []),
                        tags=["eol", "outdated", normalized_name.lower()],
                    )

        return None

    def _fetch_known_vulns(self, tech: str, version: str) -> List[Dict]:
        """
        Fetch known vulnerabilities for a technology/version.
        In a real implementation, this would query NVD API or a vuln database.
        """
        # Simplified - would query https://services.nvd.nist.gov/rest/json/cves/2.0
        # For hackathon, we return hardcoded critical CVEs for demo
        known_vulns = {
            ('PHP', '5.6'): [
                {'id': 'CVE-2019-11043', 'cvss': 9.8, 'desc': 'RCE via PHP-FPM'},
                {'id': 'CVE-2018-19518', 'cvss': 9.8, 'desc': 'IMAP RCE'},
            ],
            ('Apache', '2.4.49'): [
                {'id': 'CVE-2021-41773', 'cvss': 9.8, 'desc': 'Path traversal + RCE'},
            ],
            ('Apache', '2.4.50'): [
                {'id': 'CVE-2021-42013', 'cvss': 9.8, 'desc': 'Path traversal bypass + RCE'},
            ],
            ('jQuery', '1.'): [
                {'id': 'CVE-2020-11022', 'cvss': 6.1, 'desc': 'XSS in .html()'},
                {'id': 'CVE-2019-11358', 'cvss': 6.1, 'desc': 'Prototype pollution'},
            ],
        }

        for (t, v), vulns in known_vulns.items():
            if tech.lower() == t.lower() and version.startswith(v):
                return vulns

        return []

    def _create_cve_finding(self, tech: TechFingerprint, vuln: Dict) -> Finding:
        """Create finding for known CVE"""
        return Finding(
            vuln_class="Known CVE",
            severity="CRITICAL" if vuln['cvss'] >= 9.0 else "HIGH" if vuln['cvss'] >= 7.0 else "MEDIUM",
            cvss=vuln['cvss'],
            url=tech.source,
            description=f"{vuln['id']}: {vuln['desc']} in {tech.name} {tech.version}",
            evidence={
                'technology': tech.name,
                'version': tech.version,
                'cve_id': vuln['id'],
                'cve_cvss': vuln['cvss'],
            },
            remediation=[
                f"Upgrade {tech.name} to a patched version",
                f"Apply vendor security patches for {vuln['id']}",
                "Implement WAF rules if immediate patching not possible",
            ],
            references=[
                f"https://nvd.nist.gov/vuln/detail/{vuln['id']}",
            ],
            tags=["cve", vuln['id'].lower(), tech.name.lower()],
        )

    def _probe_additional_info(self, base_url: str) -> List[TechFingerprint]:
        """Probe additional endpoints for technology info"""
        additional_techs = []

        probe_paths = [
            '/robots.txt',
            '/humans.txt',
            '/.well-known/security.txt',
            '/favicon.ico',
            '/sitemap.xml',
            '/package.json',  # Node.js
            '/composer.json',  # PHP
        ]

        for path in probe_paths:
            url = urljoin(base_url, path)
            try:
                resp = self.client.get(url, timeout=5)
                if resp.status_code == 200:
                    # Check package.json for dependencies
                    if 'package.json' in path:
                        try:
                            pkg = json.loads(resp.text)
                            deps = {**pkg.get('dependencies', {}), **pkg.get('devDependencies', {})}
                            for dep, ver in deps.items():
                                ver_clean = re.sub(r'^[\^~]', '', ver)
                                additional_techs.append(TechFingerprint(
                                    name=dep,
                                    version=ver_clean,
                                    confidence=0.95,
                                    source=url,
                                    raw_evidence=f"{dep}@{ver}",
                                ))
                        except json.JSONDecodeError:
                            pass

                    # Check generator meta from HTML
                    if resp.headers.get('Content-Type', '').startswith('text/html'):
                        match = re.search(r'<meta[^>]+generator[^>]+content=["\']([^"\']+)', resp.text, re.I)
                        if match:
                            content = match.group(1)
                            version = re.search(r'[\d.]+', content)
                            additional_techs.append(TechFingerprint(
                                name=content.split()[0],
                                version=version.group(0) if version else None,
                                confidence=0.9,
                                source=url,
                                raw_evidence=content,
                            ))

            except Exception:
                continue

        return additional_techs

    def scan(self, base_url: str) -> List[Finding]:
        """Run technology fingerprinting and vulnerability scan"""
        self.findings = []

        # Get technologies from profile (already gathered by HTTP client)
        profile = self.client.probe(base_url)

        # Probe additional endpoints
        additional = self._probe_additional_info(base_url)
        all_techs = profile.technologies + additional

        # Dedupe by name
        seen = set()
        unique_techs = []
        for t in all_techs:
            key = t.name.lower()
            if key not in seen:
                seen.add(key)
                unique_techs.append(t)

        # Check each technology
        for tech in unique_techs:
            # Check if EOL
            eol_finding = self._check_version_eol(tech)
            if eol_finding:
                self.findings.append(eol_finding)

            # Check for known CVEs
            if tech.version:
                vulns = self._fetch_known_vulns(tech.name, tech.version)
                for vuln in vulns:
                    self.findings.append(self._create_cve_finding(tech, vuln))

        # Report tech stack (informational)
        if unique_techs:
            tech_list = [f"{t.name}" + (f"/{t.version}" if t.version else "") for t in unique_techs[:10]]
            self.findings.append(Finding(
                vuln_class="Technology Stack Detected",
                severity="INFO",
                url=base_url,
                description=f"Detected technologies: {', '.join(tech_list)}",
                evidence={
                    'technologies': [
                        {'name': t.name, 'version': t.version, 'confidence': t.confidence}
                        for t in unique_techs
                    ]
                },
                remediation=[
                    "Remove version information from headers (ServerTokens, X-Powered-By)",
                    "Keep all software up to date",
                ],
                tags=["fingerprinting", "reconnaissance"],
            ))

        return self.findings
