"""
Port Scanner Module
- TCP port scanning
- Service detection
- Banner grabbing
- Common service identification
"""

import socket
import ssl
import re
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from ..core.finding import Finding
from ..core.http_client import AdaptiveHTTPClient


class PortScanner:
    """Network port scanner with service detection"""

    # Common ports with service names
    COMMON_PORTS = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        111: "RPC",
        135: "MSRPC",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        465: "SMTPS",
        587: "SMTP Submission",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "Oracle",
        2049: "NFS",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        5985: "WinRM HTTP",
        5986: "WinRM HTTPS",
        6379: "Redis",
        8000: "HTTP Alt",
        8080: "HTTP Proxy",
        8443: "HTTPS Alt",
        8888: "HTTP Alt",
        9000: "PHP-FPM",
        9200: "Elasticsearch",
        9300: "Elasticsearch",
        11211: "Memcached",
        27017: "MongoDB",
        27018: "MongoDB",
    }

    # Extended port list for thorough scans
    EXTENDED_PORTS = list(range(1, 1025)) + [
        1080, 1433, 1521, 2049, 2082, 2083, 2086, 2087, 2096,
        3000, 3128, 3306, 3389, 4443, 5000, 5432, 5900, 5985,
        6000, 6379, 6443, 7001, 7002, 8000, 8008, 8080, 8081,
        8088, 8443, 8888, 9000, 9090, 9200, 9300, 10000, 10443,
        11211, 27017, 27018, 28017, 50000, 50070,
    ]

    # Dangerous services that should be flagged
    DANGEROUS_SERVICES = {
        "Telnet": ("Insecure protocol - cleartext credentials", "HIGH"),
        "FTP": ("Often misconfigured, cleartext auth", "MEDIUM"),
        "RDP": ("Common attack target", "MEDIUM"),
        "SMB": ("Frequently exploited (EternalBlue)", "HIGH"),
        "NetBIOS": ("Information disclosure risk", "MEDIUM"),
        "VNC": ("Often weak authentication", "MEDIUM"),
        "Redis": ("Often unauthenticated", "HIGH"),
        "MongoDB": ("Default config is unauthenticated", "HIGH"),
        "Memcached": ("Often unauthenticated, DDoS amplification", "HIGH"),
        "Elasticsearch": ("Often unauthenticated", "HIGH"),
        "MySQL": ("Should not be internet-exposed", "MEDIUM"),
        "PostgreSQL": ("Should not be internet-exposed", "MEDIUM"),
        "MSSQL": ("Should not be internet-exposed", "MEDIUM"),
    }

    def __init__(self, timeout: float = 2.0, threads: int = 50):
        self.timeout = timeout
        self.threads = threads
        self.findings: List[Finding] = []

    def _scan_port(self, host: str, port: int) -> Optional[Dict]:
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))

            if result == 0:
                # Port is open
                port_info = {
                    "port": port,
                    "state": "open",
                    "service": self.COMMON_PORTS.get(port, "unknown"),
                    "banner": None,
                    "ssl": False,
                }

                # Try to grab banner
                try:
                    # For HTTP/HTTPS, send a simple request
                    if port in [80, 8080, 8000, 8888, 8008]:
                        sock.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                    elif port in [443, 8443]:
                        # Try SSL
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        ssl_sock = context.wrap_socket(sock, server_hostname=host)
                        ssl_sock.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                        banner = ssl_sock.recv(1024).decode('utf-8', errors='ignore')
                        port_info["banner"] = banner[:500]
                        port_info["ssl"] = True
                        ssl_sock.close()
                        return port_info
                    else:
                        # Generic banner grab
                        sock.send(b"\r\n")

                    sock.settimeout(2)
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    port_info["banner"] = banner[:500]

                    # Try to identify service from banner
                    port_info["service"] = self._identify_service(banner, port)

                except Exception:
                    pass

                sock.close()
                return port_info

        except Exception:
            pass

        return None

    def _identify_service(self, banner: str, port: int) -> str:
        """Identify service from banner"""
        banner_lower = banner.lower()

        service_patterns = [
            (r"ssh-\d", "SSH"),
            (r"openssh", "OpenSSH"),
            (r"apache", "Apache"),
            (r"nginx", "Nginx"),
            (r"microsoft-iis", "IIS"),
            (r"ftp", "FTP"),
            (r"220.*ftp", "FTP"),
            (r"mysql", "MySQL"),
            (r"postgresql", "PostgreSQL"),
            (r"redis", "Redis"),
            (r"mongodb", "MongoDB"),
            (r"elastic", "Elasticsearch"),
            (r"smtp", "SMTP"),
            (r"220.*mail", "SMTP"),
            (r"pop3", "POP3"),
            (r"imap", "IMAP"),
            (r"vnc", "VNC"),
            (r"rdp", "RDP"),
            (r"http/", "HTTP"),
        ]

        for pattern, service in service_patterns:
            if re.search(pattern, banner_lower):
                return service

        return self.COMMON_PORTS.get(port, "unknown")

    def scan(self, target: str, ports: List[int] = None,
             quick: bool = True, callback=None) -> List[Finding]:
        """
        Scan ports on target

        Args:
            target: Hostname or IP to scan
            ports: Custom port list (uses default if None)
            quick: Use common ports only (vs extended list)
            callback: Progress callback

        Returns:
            List of findings
        """
        self.findings = []

        # Extract hostname from URL if needed
        if target.startswith("http"):
            parsed = urlparse(target)
            host = parsed.netloc.split(":")[0]
        else:
            host = target.split(":")[0]

        # Resolve hostname to IP
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            if callback:
                callback("error", f"Could not resolve {host}")
            return []

        # Select ports to scan
        if ports:
            scan_ports = ports
        elif quick:
            scan_ports = list(self.COMMON_PORTS.keys())
        else:
            scan_ports = self.EXTENDED_PORTS

        if callback:
            callback("info", f"Scanning {len(scan_ports)} ports on {host} ({ip})")

        open_ports = []
        scanned = 0

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._scan_port, ip, port): port
                      for port in scan_ports}

            for future in as_completed(futures):
                scanned += 1
                if callback and scanned % 100 == 0:
                    callback("probe", f"Scanned {scanned}/{len(scan_ports)} ports")

                try:
                    result = future.result()
                    if result:
                        open_ports.append(result)
                        if callback:
                            callback("success", f"Port {result['port']}/{result['service']} open")
                except Exception:
                    continue

        # Create findings
        for port_info in open_ports:
            finding = self._create_finding(host, port_info)
            if finding:
                self.findings.append(finding)

        # Summary finding
        if open_ports:
            self.findings.append(Finding(
                vuln_class="Open Ports Summary",
                severity="INFO",
                url=f"tcp://{host}",
                description=f"Found {len(open_ports)} open port(s): " +
                           ", ".join(f"{p['port']}/{p['service']}" for p in open_ports[:10]),
                evidence={"open_ports": [{"port": p["port"], "service": p["service"]}
                                        for p in open_ports]},
                tags=["reconnaissance", "port-scan"],
            ))

        return self.findings

    def _create_finding(self, host: str, port_info: Dict) -> Optional[Finding]:
        """Create finding for open port"""
        port = port_info["port"]
        service = port_info["service"]
        banner = port_info.get("banner", "")

        # Check if it's a dangerous service
        if service in self.DANGEROUS_SERVICES:
            desc, severity = self.DANGEROUS_SERVICES[service]
            return Finding(
                vuln_class=f"Exposed {service} Service",
                severity=severity,
                cvss=7.5 if severity == "HIGH" else 5.5,
                url=f"tcp://{host}:{port}",
                description=f"{service} service exposed on port {port}. {desc}",
                evidence={
                    "port": port,
                    "service": service,
                    "banner": banner[:200] if banner else None,
                },
                remediation=[
                    f"Restrict access to port {port}",
                    "Use firewall to limit source IPs",
                    "Consider using VPN for access",
                    f"If {service} must be exposed, ensure strong authentication",
                ],
                tags=["network", "exposed-service"],
            )

        return None
