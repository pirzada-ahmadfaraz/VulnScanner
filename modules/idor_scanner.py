"""
Advanced IDOR (Insecure Direct Object Reference) Scanner
Detects unauthorized access to objects via ID manipulation
"""

import re
import random
from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

from ..core.finding import Finding
from ..core.http_client import AdaptiveHTTPClient


class IDORScanner:
    """Advanced IDOR vulnerability scanner"""

    # Common IDOR-prone URL patterns
    IDOR_PATTERNS = [
        # User/Profile endpoints
        r'/user[s]?/(\d+)',
        r'/profile[s]?/(\d+)',
        r'/account[s]?/(\d+)',
        r'/member[s]?/(\d+)',

        # Document/File endpoints
        r'/document[s]?/(\d+)',
        r'/file[s]?/(\d+)',
        r'/upload[s]?/(\d+)',
        r'/download[s]?/(\d+)',
        r'/attachment[s]?/(\d+)',
        r'/media/.*?/(\d+)',
        r'/img/.*?/(\d+)',

        # Order/Transaction endpoints
        r'/order[s]?/(\d+)',
        r'/invoice[s]?/(\d+)',
        r'/payment[s]?/(\d+)',
        r'/transaction[s]?/(\d+)',

        # API endpoints
        r'/api/.*?/(\d+)',
        r'/v\d+/.*?/(\d+)',
    ]

    # Sensitive file extensions that indicate IDOR risk
    SENSITIVE_EXTENSIONS = [
        '.pdf', '.doc', '.docx', '.xls', '.xlsx',
        '.jpg', '.jpeg', '.png', '.gif',
        '.zip', '.rar', '.tar', '.gz',
        '.sql', '.db', '.bak', '.backup',
        '.csv', '.xml', '.json'
    ]

    # Patterns indicating sensitive data in response
    SENSITIVE_DATA_PATTERNS = [
        r'aadhar|aadhaar|adhaar',
        r'pan\s*card|pan\s*number',
        r'passport',
        r'driving\s*license',
        r'voter\s*id',
        r'social\s*security',
        r'credit\s*card',
        r'bank\s*account',
        r'salary|income',
        r'medical|health',
        r'address.*\d{6}',  # Address with pincode
        r'phone.*\d{10}',   # Phone number
        r'email.*@',
        r'dob|date.*birth',
    ]

    def __init__(self, client: AdaptiveHTTPClient):
        self.client = client
        self.findings: List[Finding] = []

    def scan(self, base_url: str, callback=None) -> List[Finding]:
        """
        Scan for IDOR vulnerabilities

        Args:
            base_url: Target URL
            callback: Progress callback

        Returns:
            List of findings
        """
        self.findings = []

        if callback:
            callback("info", "Scanning for IDOR vulnerabilities")

        # Test known vulnerable patterns first (like AICTE)
        self._test_known_patterns(base_url, callback)

        # Test common IDOR patterns
        self._test_common_patterns(base_url, callback)

        # Test file/document IDOR
        self._test_file_idor(base_url, callback)

        # Test API endpoints for IDOR
        self._test_api_idor(base_url, callback)

        return self.findings

    def _test_known_patterns(self, base_url: str, callback=None):
        """Test known vulnerable patterns from real-world findings"""
        if callback:
            callback("probe", "Testing known IDOR patterns")

        # Extract domain and ensure HTTPS
        parsed = urlparse(base_url)
        domain = parsed.netloc

        # Try both HTTP and HTTPS
        base_urls = []
        if parsed.scheme == "http":
            base_urls.append(base_url)
            base_urls.append(base_url.replace("http://", "https://"))
        else:
            base_urls.append(base_url)

        # Known vulnerable patterns with specific IDs to test
        known_patterns = [
            # AICTE-style patterns
            {
                "path": "/jk_media/img/uploads/aadharCard/{id}_aadharCard.pdf",
                "test_ids": ["2025043698", "2025043697", "2025043696", "2025043695"],
                "file_type": "Aadhaar Card",
                "domains": ["aicte-jk-scholarship-gov.in", "aicte"],
            },
            {
                "path": "/jk_media/img/uploads/panCard/{id}_panCard.pdf",
                "test_ids": ["2025043698", "2025043697", "2025043696"],
                "file_type": "PAN Card",
                "domains": ["aicte-jk-scholarship-gov.in", "aicte"],
            },
            # Generic patterns
            {
                "path": "/media/img/uploads/aadharCard/{id}_aadharCard.pdf",
                "test_ids": ["2025043698", "2024012345", "1000001", "1000002"],
                "file_type": "Aadhaar Card",
                "domains": [],  # Test on all domains
            },
            {
                "path": "/uploads/documents/{id}_document.pdf",
                "test_ids": ["1", "2", "100", "101", "1000", "1001"],
                "file_type": "Document",
                "domains": [],
            },
        ]

        for pattern_info in known_patterns:
            # Check if pattern applies to this domain
            if pattern_info["domains"]:
                if not any(d in domain for d in pattern_info["domains"]):
                    continue

            path_template = pattern_info["path"]
            test_ids = pattern_info["test_ids"]
            file_type = pattern_info["file_type"]

            # Try each base URL (HTTP and HTTPS)
            for test_base_url in base_urls:
                # Test first ID
                first_id = test_ids[0]
                test_url = urljoin(test_base_url, path_template.replace("{id}", first_id))

                try:
                    resp1 = self.client.get(test_url, timeout=10, allow_redirects=True)

                    if resp1.status_code == 200 and len(resp1.content) > 1000:
                        # Found accessible file! Test with different IDs
                        for next_id in test_ids[1:3]:  # Test next 2 IDs
                            test_url2 = urljoin(test_base_url, path_template.replace("{id}", next_id))

                            try:
                                resp2 = self.client.get(test_url2, timeout=10, allow_redirects=True)

                                if resp2.status_code == 200 and len(resp2.content) > 1000:
                                    # Check if files are different
                                    if abs(len(resp1.content) - len(resp2.content)) > 100:
                                        # IDOR confirmed!
                                        self.findings.append(Finding(
                                            vuln_class="IDOR - Sensitive File Exposure",
                                            severity="CRITICAL",
                                            cvss=9.3,
                                            url=test_url,
                                            description=f"CRITICAL: Sensitive {file_type} files are accessible by "
                                                      f"manipulating ID parameters in the URL. By changing the ID "
                                                      f"from {first_id} to {next_id}, different users' sensitive "
                                                      f"documents can be accessed without authorization. "
                                                      f"This allows mass enumeration of user documents.",
                                            evidence={
                                                "original_url": test_url,
                                                "manipulated_url": test_url2,
                                                "original_id": first_id,
                                                "manipulated_id": next_id,
                                                "file_type": file_type,
                                                "both_accessible": True,
                                                "file_size_1": len(resp1.content),
                                                "file_size_2": len(resp2.content),
                                                "content_type": resp1.headers.get("Content-Type", ""),
                                            },
                                            request=f"GET {test_url}\nGET {test_url2}",
                                            remediation=[
                                                "IMMEDIATE: Implement authorization checks before serving files",
                                                "Verify that the authenticated user owns the requested file",
                                                "Use non-guessable file identifiers (UUIDs or secure tokens)",
                                                "Store files outside web root with access control",
                                                "Implement session-based file access tokens",
                                                "Log all file access attempts for audit",
                                                "Add rate limiting to prevent mass enumeration",
                                                "Consider encrypting sensitive files at rest",
                                            ],
                                            references=[
                                                "https://owasp.org/www-project-api-security/",
                                                "https://cwe.mitre.org/data/definitions/639.html",
                                            ],
                                            tags=["idor", "critical", "file-exposure", "pii"],
                                        ))

                                        if callback:
                                            callback("success", "IDOR vulnerability detected")

                                        return  # Found critical IDOR, stop testing

                            except Exception:
                                continue

                except Exception:
                    continue


    def _test_common_patterns(self, base_url: str, callback=None):
        """Test common IDOR-prone URL patterns"""
        if callback:
            callback("probe", "Testing common IDOR patterns")

        # Common endpoints to test
        test_endpoints = [
            "/user/1", "/users/1", "/profile/1", "/account/1",
            "/api/user/1", "/api/users/1", "/api/profile/1",
            "/document/1", "/file/1", "/download/1",
            "/order/1", "/invoice/1", "/payment/1",
        ]

        for endpoint in test_endpoints:
            url = urljoin(base_url, endpoint)

            try:
                # Test with ID 1
                resp1 = self.client.get(url, timeout=8)

                if resp1.status_code == 200:
                    # Test with different ID
                    url2 = url.replace("/1", "/2")
                    resp2 = self.client.get(url2, timeout=8)

                    if resp2.status_code == 200:
                        # Check if responses are different (indicating different objects)
                        if self._responses_differ(resp1, resp2):
                            # Check for sensitive data
                            has_sensitive = self._contains_sensitive_data(resp1.text) or \
                                          self._contains_sensitive_data(resp2.text)

                            severity = "HIGH" if has_sensitive else "MEDIUM"
                            cvss = 8.5 if has_sensitive else 6.5

                            self.findings.append(Finding(
                                vuln_class="IDOR - Insecure Direct Object Reference",
                                severity=severity,
                                cvss=cvss,
                                url=url,
                                description=f"Sequential ID enumeration possible. Accessing {url} and "
                                          f"{url2} returns different user/object data without proper "
                                          f"authorization checks." +
                                          (" Sensitive data exposed." if has_sensitive else ""),
                                evidence={
                                    "test_id_1": "1",
                                    "test_id_2": "2",
                                    "both_accessible": True,
                                    "responses_differ": True,
                                    "sensitive_data": has_sensitive,
                                },
                                request=f"GET {url}",
                                remediation=[
                                    "Implement proper authorization checks before returning object data",
                                    "Verify that the authenticated user owns/has access to the requested object",
                                    "Use UUIDs instead of sequential IDs",
                                    "Log and monitor access to sensitive objects",
                                    "Implement rate limiting to prevent mass enumeration",
                                ],
                                references=[
                                    "https://owasp.org/www-project-api-security/",
                                    "https://portswigger.net/web-security/access-control/idor",
                                ],
                                tags=["idor", "authorization", "api"],
                            ))

                            if callback:
                                callback("success", "IDOR vulnerability detected")

                            return  # Found IDOR, no need to test more

            except Exception:
                continue

    def _test_file_idor(self, base_url: str, callback=None):
        """
        Test for file/document IDOR vulnerabilities
        """
        if callback:
            callback("probe", "Testing file/document IDOR")

        # Common file upload/media paths
        file_paths = [
            "/uploads/", "/media/", "/files/", "/documents/",
            "/img/uploads/", "/images/uploads/", "/assets/uploads/",
            "/static/uploads/", "/public/uploads/", "/storage/",
            "/user_files/", "/attachments/", "/download/",
        ]

        # Common sensitive file patterns
        file_patterns = [
            r'(\d{10,})_.*?\.(pdf|jpg|jpeg|png|doc|docx)',  # ID_filename.ext
            r'(\d{4,}).*?\.(pdf|jpg|jpeg|png|doc|docx)',     # Year/ID based
            r'user_(\d+)_.*?\.(pdf|jpg|jpeg|png)',           # user_ID_file.ext
            r'document_(\d+)\.(pdf|doc|docx)',               # document_ID.ext
            r'aadhar.*?(\d+).*?\.(pdf|jpg|jpeg|png)',        # Aadhaar cards
            r'pan.*?(\d+).*?\.(pdf|jpg|jpeg|png)',           # PAN cards
            r'passport.*?(\d+).*?\.(pdf|jpg|jpeg|png)',      # Passports
        ]

        parsed = urlparse(base_url)

        # Try to find file URLs in the page
        try:
            resp = self.client.get(base_url, timeout=10)
            if resp.status_code == 200:
                # Extract file URLs from HTML
                file_urls = self._extract_file_urls(resp.text, base_url)

                for file_url in file_urls:
                    # Check if URL matches IDOR pattern
                    for pattern in file_patterns:
                        match = re.search(pattern, file_url, re.IGNORECASE)
                        if match:
                            # Found a file with ID pattern
                            original_id = match.group(1)

                            # Test with modified ID
                            idor_result = self._test_file_id_manipulation(
                                file_url, original_id, callback
                            )

                            if idor_result:
                                self.findings.append(idor_result)
                                return  # Found IDOR

        except Exception:
            pass

        # Also test common patterns directly
        self._test_direct_file_patterns(base_url, callback)

    def _test_direct_file_patterns(self, base_url: str, callback=None):
        """Test direct file access patterns"""

        # Common file access patterns
        test_patterns = [
            "/media/img/uploads/aadharCard/{id}_aadharCard.pdf",
            "/media/img/uploads/panCard/{id}_panCard.pdf",
            "/media/img/uploads/passport/{id}_passport.pdf",
            "/uploads/documents/{id}_document.pdf",
            "/uploads/files/{id}_file.pdf",
            "/files/user/{id}/document.pdf",
            "/documents/{id}.pdf",
            "/attachments/{id}.pdf",
        ]

        # Test with realistic ID patterns
        test_ids = [
            "2025043698",  # Year + ID pattern
            "2024012345",
            "2025000001",
            "1000001",     # Sequential
            "1000002",
            "100001",
            "100002",
        ]

        for pattern in test_patterns:
            for test_id in test_ids[:2]:  # Test first 2 IDs per pattern
                url = urljoin(base_url, pattern.replace("{id}", test_id))

                try:
                    resp = self.client.get(url, timeout=8)

                    if resp.status_code == 200 and len(resp.content) > 1000:
                        # Found accessible file, test with different ID
                        next_id = str(int(test_id) + 1)
                        url2 = urljoin(base_url, pattern.replace("{id}", next_id))

                        resp2 = self.client.get(url2, timeout=8)

                        if resp2.status_code == 200 and len(resp2.content) > 1000:
                            # Both files accessible - IDOR confirmed!

                            # Determine file type
                            file_type = "Unknown"
                            if "aadhar" in url.lower():
                                file_type = "Aadhaar Card"
                            elif "pan" in url.lower():
                                file_type = "PAN Card"
                            elif "passport" in url.lower():
                                file_type = "Passport"
                            elif "document" in url.lower():
                                file_type = "Document"

                            self.findings.append(Finding(
                                vuln_class="IDOR - Sensitive File Exposure",
                                severity="CRITICAL",
                                cvss=9.3,
                                url=url,
                                description=f"CRITICAL: Sensitive {file_type} files are accessible by "
                                          f"manipulating ID parameters in the URL. By changing the ID "
                                          f"from {test_id} to {next_id}, different users' sensitive "
                                          f"documents can be accessed without authorization.",
                                evidence={
                                    "original_url": url,
                                    "manipulated_url": url2,
                                    "original_id": test_id,
                                    "manipulated_id": next_id,
                                    "file_type": file_type,
                                    "both_accessible": True,
                                    "file_size_1": len(resp.content),
                                    "file_size_2": len(resp2.content),
                                    "content_type": resp.headers.get("Content-Type", ""),
                                },
                                request=f"GET {url}\nGET {url2}",
                                remediation=[
                                    "IMMEDIATE: Implement authorization checks before serving files",
                                    "Verify that the authenticated user owns the requested file",
                                    "Use non-guessable file identifiers (UUIDs or secure tokens)",
                                    "Store files outside web root with access control",
                                    "Implement session-based file access tokens",
                                    "Log all file access attempts for audit",
                                    "Add rate limiting to prevent mass enumeration",
                                    "Consider encrypting sensitive files at rest",
                                ],
                                references=[
                                    "https://owasp.org/www-project-api-security/",
                                    "https://cwe.mitre.org/data/definitions/639.html",
                                ],
                                tags=["idor", "critical", "file-exposure", "pii"],
                            ))

                            if callback:
                                callback("success", "IDOR vulnerability detected")

                            return  # Found critical IDOR

                except Exception:
                    continue

    def _test_file_id_manipulation(self, file_url: str, original_id: str,
                                   callback=None) -> Optional[Finding]:
        """Test if file ID can be manipulated to access other users' files"""

        try:
            # Get original file
            resp1 = self.client.get(file_url, timeout=10)

            if resp1.status_code != 200 or len(resp1.content) < 1000:
                return None

            # Generate test IDs
            test_ids = self._generate_test_ids(original_id)

            for test_id in test_ids[:3]:  # Test up to 3 variations
                # Replace ID in URL
                test_url = file_url.replace(original_id, test_id)

                if test_url == file_url:
                    continue

                resp2 = self.client.get(test_url, timeout=10)

                if resp2.status_code == 200 and len(resp2.content) > 1000:
                    # Check if files are different
                    if len(resp1.content) != len(resp2.content):
                        # IDOR confirmed!

                        # Determine sensitivity
                        is_sensitive = any(pattern in file_url.lower()
                                         for pattern in ['aadhar', 'pan', 'passport',
                                                        'license', 'medical', 'bank'])

                        severity = "CRITICAL" if is_sensitive else "HIGH"
                        cvss = 9.3 if is_sensitive else 8.5

                        return Finding(
                            vuln_class="IDOR - File Access via ID Manipulation",
                            severity=severity,
                            cvss=cvss,
                            url=file_url,
                            description=f"Files can be accessed by manipulating ID in URL. "
                                      f"Original ID {original_id} changed to {test_id} "
                                      f"returns different file content." +
                                      (" SENSITIVE DOCUMENTS EXPOSED!" if is_sensitive else ""),
                            evidence={
                                "original_url": file_url,
                                "manipulated_url": test_url,
                                "original_id": original_id,
                                "test_id": test_id,
                                "both_accessible": True,
                                "files_differ": True,
                            },
                            remediation=[
                                "Implement authorization checks before serving files",
                                "Use UUIDs or secure tokens instead of sequential IDs",
                                "Verify user ownership of requested files",
                                "Store files outside web root",
                                "Implement access logging and monitoring",
                            ],
                            tags=["idor", "file-exposure", "authorization"],
                        )

        except Exception:
            pass

        return None

    def _test_api_idor(self, base_url: str, callback=None):
        """Test API endpoints for IDOR"""
        if callback:
            callback("probe", "Testing API IDOR")

        api_paths = ["/api", "/api/v1", "/api/v2", "/v1", "/v2"]

        for api_path in api_paths:
            api_url = urljoin(base_url, api_path)

            # Common API IDOR endpoints
            endpoints = [
                "/user/1", "/users/1", "/profile/1",
                "/document/1", "/file/1", "/order/1",
            ]

            for endpoint in endpoints:
                test_url = urljoin(api_url, endpoint)

                try:
                    resp1 = self.client.get(test_url, timeout=8)

                    if resp1.status_code == 200:
                        # Try different ID
                        test_url2 = test_url.replace("/1", "/2")
                        resp2 = self.client.get(test_url2, timeout=8)

                        if resp2.status_code == 200 and self._responses_differ(resp1, resp2):
                            # Check for sensitive data in JSON
                            has_sensitive = False
                            try:
                                data1 = resp1.json()
                                data2 = resp2.json()
                                has_sensitive = self._json_has_sensitive_data(data1) or \
                                              self._json_has_sensitive_data(data2)
                            except Exception:
                                pass

                            severity = "HIGH" if has_sensitive else "MEDIUM"

                            self.findings.append(Finding(
                                vuln_class="API IDOR",
                                severity=severity,
                                cvss=8.0 if has_sensitive else 6.0,
                                url=test_url,
                                description=f"API endpoint allows access to different users' data "
                                          f"by changing ID parameter.",
                                evidence={
                                    "endpoint": endpoint,
                                    "test_ids": ["1", "2"],
                                    "both_accessible": True,
                                    "sensitive_data": has_sensitive,
                                },
                                remediation=[
                                    "Implement object-level authorization",
                                    "Verify user permissions before returning data",
                                    "Use UUIDs instead of sequential IDs",
                                ],
                                tags=["idor", "api", "authorization"],
                            ))

                            return  # Found IDOR

                except Exception:
                    continue

    def _extract_file_urls(self, html: str, base_url: str) -> List[str]:
        """Extract file URLs from HTML"""
        file_urls = []

        # Find URLs with file extensions
        url_pattern = r'(?:href|src)=["\']([^"\']+\.(?:pdf|doc|docx|jpg|jpeg|png|gif|zip))["\']'
        matches = re.findall(url_pattern, html, re.IGNORECASE)

        for match in matches:
            full_url = urljoin(base_url, match)
            file_urls.append(full_url)

        return file_urls

    def _generate_test_ids(self, original_id: str) -> List[str]:
        """Generate test IDs based on original ID pattern"""
        test_ids = []

        try:
            # If numeric, try sequential
            num_id = int(original_id)
            test_ids.extend([
                str(num_id + 1),
                str(num_id - 1),
                str(num_id + 10),
                str(num_id + 100),
            ])
        except ValueError:
            # If alphanumeric, try variations
            if original_id.isalnum():
                # Try incrementing last digit
                if original_id[-1].isdigit():
                    last_digit = int(original_id[-1])
                    test_ids.append(original_id[:-1] + str((last_digit + 1) % 10))

        return test_ids

    def _responses_differ(self, resp1, resp2) -> bool:
        """Check if two responses contain different data"""
        # Different lengths
        if abs(len(resp1.content) - len(resp2.content)) > 100:
            return True

        # Different content
        if resp1.content != resp2.content:
            return True

        return False

    def _contains_sensitive_data(self, text: str) -> bool:
        """Check if text contains sensitive data patterns"""
        text_lower = text.lower()

        for pattern in self.SENSITIVE_DATA_PATTERNS:
            if re.search(pattern, text_lower):
                return True

        return False

    def _json_has_sensitive_data(self, data: dict) -> bool:
        """Check if JSON contains sensitive data"""
        if not isinstance(data, dict):
            return False

        sensitive_keys = [
            'aadhar', 'aadhaar', 'pan', 'passport', 'ssn',
            'credit_card', 'bank_account', 'salary', 'income',
            'medical', 'health', 'dob', 'date_of_birth',
            'phone', 'mobile', 'email', 'address'
        ]

        for key in data.keys():
            if any(sens in key.lower() for sens in sensitive_keys):
                return True

        return False
