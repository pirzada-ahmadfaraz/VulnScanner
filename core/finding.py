"""
Finding model - standardized vulnerability finding format
"""

from dataclasses import dataclass, field
from typing import Optional, List, Any
from datetime import datetime
import hashlib
import json


@dataclass
class Finding:
    """Standardized vulnerability finding"""

    vuln_class: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    url: str
    description: str

    # Optional fields
    cvss: float = 0.0
    parameter: Optional[str] = None
    evidence: Any = None
    request: Optional[str] = None
    response: Optional[str] = None
    remediation: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    confidence: float = 1.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    # Extra data
    extra: dict = field(default_factory=dict)

    def __post_init__(self):
        # Normalize severity
        self.severity = self.severity.upper()
        if self.severity not in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            self.severity = "INFO"

        # Auto-assign CVSS if not set
        if self.cvss == 0.0:
            default_cvss = {
                "CRITICAL": 9.5,
                "HIGH": 7.5,
                "MEDIUM": 5.5,
                "LOW": 3.0,
                "INFO": 1.0,
            }
            self.cvss = default_cvss.get(self.severity, 1.0)

    @property
    def fingerprint(self) -> str:
        """Unique identifier for deduplication"""
        key = f"{self.vuln_class}:{self.url}:{self.parameter or ''}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def generate_poc(self) -> str:
        """Generate a curl command to reproduce this finding"""
        if not self.url:
            return ""

        parts = ["curl -sk"]  # silent, insecure (for self-signed certs)

        # Add method if we have request data suggesting non-GET
        if self.request and isinstance(self.request, str):
            if any(m in self.request.upper() for m in ['POST ', 'PUT ', 'DELETE ', 'PATCH ']):
                for method in ['POST', 'PUT', 'DELETE', 'PATCH']:
                    if method in self.request.upper():
                        parts.append(f"-X {method}")
                        break

        # Build the URL with parameter if applicable
        url = self.url
        if self.parameter and self.evidence:
            # Try to include the payload in the URL
            payload = ""
            if isinstance(self.evidence, dict):
                payload = self.evidence.get("payload", self.evidence.get("test_payload", ""))
            elif isinstance(self.evidence, str):
                payload = self.evidence[:100]

            if payload:
                sep = "&" if "?" in url else "?"
                url = f"{url}{sep}{self.parameter}={payload}"

        # Add common useful headers
        parts.append('-H "User-Agent: Mozilla/5.0"')

        # Extract any special headers from request
        if self.request and isinstance(self.request, str):
            for line in self.request.split('\n'):
                line = line.strip()
                if ':' in line and not line.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'PATCH ', 'HEAD ', 'OPTIONS ')):
                    header_name = line.split(':')[0].strip().lower()
                    if header_name in ['origin', 'referer', 'x-forwarded-for', 'x-custom-ip-authorization', 'content-type']:
                        # Escape single quotes in the value
                        safe_line = line.replace("'", "'\\''")
                        parts.append(f"-H '{safe_line}'")

        # Add the URL (quote it for safety)
        parts.append(f"'{url}'")

        return " \\\n  ".join(parts)

    def to_dict(self) -> dict:
        return {
            "vuln_class": self.vuln_class,
            "severity": self.severity,
            "cvss": self.cvss,
            "url": self.url,
            "parameter": self.parameter,
            "description": self.description,
            "evidence": self.evidence,
            "request": self.request,
            "response": self.response,
            "remediation": self.remediation,
            "references": self.references,
            "tags": self.tags,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "fingerprint": self.fingerprint,
            "poc_curl": self.generate_poc(),
            **self.extra,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)


# Severity ordering for sorting
SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


def sort_findings(findings: List[Finding]) -> List[Finding]:
    """Sort findings by severity (critical first)"""
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))


def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """Remove duplicate findings based on fingerprint"""
    seen = set()
    unique = []
    for f in findings:
        if f.fingerprint not in seen:
            seen.add(f.fingerprint)
            unique.append(f)
    return unique
