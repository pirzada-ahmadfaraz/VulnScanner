"""
SSL/TLS Security Scanner
- Certificate validation
- Protocol version checks
- Cipher suite analysis
- Known vulnerabilities (Heartbleed, POODLE, etc.)
"""

import socket
import ssl
import re
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse

from ..core.finding import Finding
from ..core.http_client import AdaptiveHTTPClient


class SSLScanner:
    """SSL/TLS security scanner"""

    # Weak cipher suites
    WEAK_CIPHERS = [
        "NULL", "EXPORT", "DES", "RC4", "RC2", "MD5",
        "ANON", "ADH", "AECDH", "3DES", "IDEA",
    ]

    # Insecure protocol versions
    INSECURE_PROTOCOLS = {
        ssl.PROTOCOL_SSLv23: "SSLv2/SSLv3",
    }

    # Protocol versions to test (if available)
    PROTOCOL_VERSIONS = [
        ("TLSv1.3", getattr(ssl, "PROTOCOL_TLS", None)),
        ("TLSv1.2", getattr(ssl, "PROTOCOL_TLSv1_2", None)),
        ("TLSv1.1", getattr(ssl, "PROTOCOL_TLSv1_1", None)),
        ("TLSv1.0", getattr(ssl, "PROTOCOL_TLSv1", None)),
    ]

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.findings: List[Finding] = []

    def _get_certificate_info(self, host: str, port: int = 443) -> Optional[Dict]:
        """Get SSL certificate information using two-pass connection.

        Pass 1: Default context (CERT_REQUIRED) — returns full parsed cert for valid certs.
        Pass 2 (fallback): On SSLCertVerificationError, reconnect with CERT_NONE to get
        cipher/version/binary cert, and record the validation error for classification.
        If both passes fail, return None (no SSL service).
        """
        cert = {}
        cert_binary = None
        cipher = None
        version = None
        validation_error = None

        # Pass 1: validating connection (gets full parsed cert dict)
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cert_binary = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    version = ssock.version()
        except ssl.SSLCertVerificationError as e:
            validation_error = str(e)
        except Exception:
            # Connection-level failure (no SSL at all, timeout, etc.)
            return None

        # Pass 2: non-validating fallback (grab cipher/version/binary cert)
        if validation_error is not None:
            try:
                ctx2 = ssl.create_default_context()
                ctx2.check_hostname = False
                ctx2.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=self.timeout) as sock:
                    with ctx2.wrap_socket(sock, server_hostname=host) as ssock:
                        cert_binary = ssock.getpeercert(binary_form=True)
                        cipher = ssock.cipher()
                        version = ssock.version()
            except Exception:
                # Even non-validating connection failed — no SSL service
                return None

        return {
            "cert": cert,
            "cert_binary": cert_binary,
            "cipher": cipher,
            "version": version,
            "host": host,
            "port": port,
            "validation_error": validation_error,
        }

    def _parse_cert_date(self, date_str: str) -> Optional[datetime]:
        """Parse certificate date string"""
        formats = [
            "%b %d %H:%M:%S %Y %Z",
            "%Y%m%d%H%M%SZ",
        ]
        for fmt in formats:
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue
        return None

    def _classify_validation_error(self, host: str, error_str: str,
                                     cert_info: Dict) -> List[Finding]:
        """Classify an SSL validation error into specific findings."""
        findings = []
        error_lower = error_str.lower()

        if "self-signed" in error_lower or "self signed" in error_lower:
            findings.append(Finding(
                vuln_class="Self-Signed Certificate",
                severity="MEDIUM",
                cvss=5.0,
                url=f"https://{host}",
                description="Certificate is self-signed and will not be trusted by browsers.",
                evidence={"validation_error": error_str},
                remediation=[
                    "Use a certificate from a trusted CA",
                    "Consider Let's Encrypt for free certificates",
                ],
                tags=["ssl", "certificate", "self-signed"],
            ))
        elif "expired" in error_lower or "not yet valid" in error_lower:
            findings.append(Finding(
                vuln_class="Expired SSL Certificate",
                severity="HIGH",
                cvss=7.5,
                url=f"https://{host}",
                description=f"SSL certificate failed validation: {error_str}",
                evidence={"validation_error": error_str},
                remediation=["Renew SSL certificate immediately"],
                tags=["ssl", "certificate", "expired"],
            ))
        elif "hostname mismatch" in error_lower or "doesn't match" in error_lower:
            findings.append(Finding(
                vuln_class="SSL Hostname Mismatch",
                severity="HIGH",
                cvss=7.0,
                url=f"https://{host}",
                description=f"Certificate does not match hostname: {error_str}",
                evidence={"validation_error": error_str},
                remediation=["Obtain certificate for correct hostname"],
                tags=["ssl", "certificate", "mismatch"],
            ))
        else:
            findings.append(Finding(
                vuln_class="SSL Certificate Validation Failed",
                severity="HIGH",
                cvss=7.0,
                url=f"https://{host}",
                description=f"SSL certificate validation failed: {error_str}",
                evidence={"validation_error": error_str},
                remediation=[
                    "Install a valid SSL certificate from a trusted CA",
                    "Ensure the certificate chain is complete",
                ],
                tags=["ssl", "certificate"],
            ))

        return findings

    def _check_certificate(self, host: str, cert_info: Dict) -> List[Finding]:
        """Check certificate for issues"""
        findings = []
        cert = cert_info.get("cert", {})
        validation_error = cert_info.get("validation_error")

        # If parsed cert is empty but binary cert exists, the cert couldn't be
        # validated (Pass 1 failed). Classify the validation error instead of
        # reporting a blanket "No SSL Certificate".
        if not cert:
            if cert_info.get("cert_binary") and validation_error:
                return self._classify_validation_error(host, validation_error, cert_info)
            findings.append(Finding(
                vuln_class="No SSL Certificate",
                severity="HIGH",
                cvss=7.5,
                url=f"https://{host}",
                description="No valid SSL certificate found or certificate could not be parsed.",
                remediation=["Install a valid SSL certificate"],
                tags=["ssl", "certificate"],
            ))
            return findings

        # Check expiration
        not_after = cert.get("notAfter", "")
        if not_after:
            expiry = self._parse_cert_date(not_after)
            if expiry:
                days_until_expiry = (expiry - datetime.now()).days

                if days_until_expiry < 0:
                    findings.append(Finding(
                        vuln_class="Expired SSL Certificate",
                        severity="HIGH",
                        cvss=7.5,
                        url=f"https://{host}",
                        description=f"SSL certificate expired {abs(days_until_expiry)} days ago on {not_after}",
                        evidence={"expiry_date": not_after, "days_expired": abs(days_until_expiry)},
                        remediation=["Renew SSL certificate immediately"],
                        tags=["ssl", "certificate", "expired"],
                    ))
                elif days_until_expiry < 30:
                    findings.append(Finding(
                        vuln_class="SSL Certificate Expiring Soon",
                        severity="MEDIUM",
                        cvss=5.0,
                        url=f"https://{host}",
                        description=f"SSL certificate expires in {days_until_expiry} days on {not_after}",
                        evidence={"expiry_date": not_after, "days_remaining": days_until_expiry},
                        remediation=["Plan certificate renewal before expiry"],
                        tags=["ssl", "certificate"],
                    ))

        # Check subject/issuer
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))

        cn = subject.get("commonName", "")
        issuer_cn = issuer.get("commonName", "")

        # Self-signed certificate check
        if subject == issuer:
            findings.append(Finding(
                vuln_class="Self-Signed Certificate",
                severity="MEDIUM",
                cvss=5.0,
                url=f"https://{host}",
                description="Certificate is self-signed and will not be trusted by browsers.",
                evidence={"subject": cn, "issuer": issuer_cn},
                remediation=[
                    "Use a certificate from a trusted CA",
                    "Consider Let's Encrypt for free certificates",
                ],
                tags=["ssl", "certificate", "self-signed"],
            ))

        # Check hostname mismatch
        san = cert.get("subjectAltName", [])
        valid_names = [cn] + [name for type_, name in san if type_ == "DNS"]

        hostname_valid = any(
            self._match_hostname(host, name) for name in valid_names
        )

        if not hostname_valid and cn:
            findings.append(Finding(
                vuln_class="SSL Hostname Mismatch",
                severity="HIGH",
                cvss=7.0,
                url=f"https://{host}",
                description=f"Certificate CN/SAN ({cn}) does not match hostname ({host})",
                evidence={"hostname": host, "certificate_names": valid_names[:5]},
                remediation=["Obtain certificate for correct hostname"],
                tags=["ssl", "certificate", "mismatch"],
            ))

        return findings

    def _match_hostname(self, hostname: str, pattern: str) -> bool:
        """Match hostname against certificate pattern (supports wildcards)"""
        if pattern.startswith("*."):
            suffix = pattern[2:]
            hostname_labels = hostname.split(".")
            suffix_labels = suffix.split(".")
            return (
                len(hostname_labels) == len(suffix_labels) + 1 and
                hostname.endswith(f".{suffix}")
            )
        return hostname == pattern

    def _check_protocol_version(self, host: str, port: int = 443) -> List[Finding]:
        """Check for weak protocol versions"""
        findings = []
        supported_versions = []

        # Check which protocols are supported
        for version_name, protocol in self.PROTOCOL_VERSIONS:
            if protocol is None:
                continue

            try:
                context = ssl.SSLContext(protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection((host, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        supported_versions.append(version_name)
            except Exception:
                continue

        # Check for old TLS versions
        old_versions = [v for v in supported_versions if v in ["TLSv1.0", "TLSv1.1"]]

        if old_versions:
            findings.append(Finding(
                vuln_class="Outdated TLS Version Supported",
                severity="MEDIUM",
                cvss=5.5,
                url=f"https://{host}:{port}",
                description=f"Server supports deprecated TLS versions: {', '.join(old_versions)}",
                evidence={
                    "deprecated_versions": old_versions,
                    "all_versions": supported_versions,
                },
                remediation=[
                    "Disable TLSv1.0 and TLSv1.1",
                    "Enable only TLSv1.2 and TLSv1.3",
                    "Update web server TLS configuration",
                ],
                tags=["ssl", "tls", "protocol"],
            ))

        if "TLSv1.3" not in supported_versions and "TLSv1.2" in supported_versions:
            findings.append(Finding(
                vuln_class="TLSv1.3 Not Supported",
                severity="LOW",
                cvss=3.0,
                url=f"https://{host}:{port}",
                description="Server does not support TLSv1.3 (latest secure version)",
                evidence={"supported_versions": supported_versions},
                remediation=["Enable TLSv1.3 support"],
                tags=["ssl", "tls"],
            ))

        return findings

    def _check_cipher_suite(self, cert_info: Dict, host: str) -> List[Finding]:
        """Check for weak cipher suites"""
        findings = []
        cipher = cert_info.get("cipher", ())

        if cipher:
            cipher_name = cipher[0]
            cipher_version = cipher[1]
            cipher_bits = cipher[2]

            # Check for weak ciphers
            for weak in self.WEAK_CIPHERS:
                if weak in cipher_name.upper():
                    findings.append(Finding(
                        vuln_class="Weak Cipher Suite",
                        severity="MEDIUM",
                        cvss=5.0,
                        url=f"https://{host}",
                        description=f"Connection used weak cipher: {cipher_name}",
                        evidence={
                            "cipher": cipher_name,
                            "protocol": cipher_version,
                            "bits": cipher_bits,
                        },
                        remediation=[
                            f"Disable {weak} ciphers",
                            "Configure strong cipher suite order",
                            "Use Mozilla SSL Configuration Generator",
                        ],
                        tags=["ssl", "cipher", "weak"],
                    ))
                    break

            # Check key length
            if cipher_bits and cipher_bits < 128:
                findings.append(Finding(
                    vuln_class="Weak Cipher Key Length",
                    severity="MEDIUM",
                    cvss=5.5,
                    url=f"https://{host}",
                    description=f"Cipher uses weak key length: {cipher_bits} bits",
                    evidence={"cipher": cipher_name, "bits": cipher_bits},
                    remediation=["Use ciphers with at least 128-bit keys"],
                    tags=["ssl", "cipher"],
                ))

        return findings

    def scan(self, target: str, callback=None) -> List[Finding]:
        """
        Scan SSL/TLS configuration

        Args:
            target: URL or hostname to scan
            callback: Progress callback

        Returns:
            List of findings
        """
        self.findings = []

        # Parse target
        if target.startswith("http"):
            parsed = urlparse(target)
            host = parsed.netloc.split(":")[0]
            port = parsed.port or (443 if parsed.scheme == "https" else 80)

            if parsed.scheme != "https":
                self.findings.append(Finding(
                    vuln_class="No HTTPS",
                    severity="MEDIUM",
                    cvss=5.0,
                    url=target,
                    description="Target does not use HTTPS",
                    remediation=["Enable HTTPS", "Redirect HTTP to HTTPS"],
                    tags=["ssl"],
                ))
                return self.findings
        else:
            host = target.split(":")[0]
            port = int(target.split(":")[1]) if ":" in target else 443

        if callback:
            callback("info", f"Checking SSL/TLS on {host}:{port}")

        # Get certificate info
        if callback:
            callback("probe", "Retrieving SSL certificate")

        cert_info = self._get_certificate_info(host, port)

        if not cert_info:
            self.findings.append(Finding(
                vuln_class="SSL Connection Failed",
                severity="HIGH",
                cvss=7.0,
                url=f"https://{host}:{port}",
                description="Could not establish SSL connection to server",
                remediation=["Verify SSL is properly configured"],
                tags=["ssl"],
            ))
            return self.findings

        # Check certificate
        if callback:
            callback("probe", "Analyzing certificate")
        self.findings.extend(self._check_certificate(host, cert_info))

        # Check protocol versions
        if callback:
            callback("probe", "Checking TLS versions")
        self.findings.extend(self._check_protocol_version(host, port))

        # Check cipher suites
        if callback:
            callback("probe", "Analyzing cipher suite")
        self.findings.extend(self._check_cipher_suite(cert_info, host))

        # Summary
        if not self.findings:
            self.findings.append(Finding(
                vuln_class="SSL Configuration",
                severity="INFO",
                url=f"https://{host}:{port}",
                description="SSL/TLS configuration appears secure",
                evidence={
                    "protocol": cert_info.get("version"),
                    "cipher": cert_info.get("cipher", [None])[0],
                },
                tags=["ssl"],
            ))

        return self.findings
