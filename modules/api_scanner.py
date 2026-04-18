"""
API Security Scanner
- GraphQL introspection exposure
- REST API endpoint discovery
- API key exposure detection
- Rate limiting bypass
- Mass assignment vulnerabilities
- BOLA/IDOR patterns
"""

import re
import json
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse

from ..core.finding import Finding
from ..core.http_client import AdaptiveHTTPClient


class APIScanner:
    """API security scanner for REST and GraphQL"""

    # Common API paths
    API_PATHS = [
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/graphql", "/graphiql", "/playground",
        "/rest", "/v1", "/v2", "/v3",
        "/swagger.json", "/swagger.yaml", "/openapi.json",
        "/api-docs", "/docs", "/redoc",
        "/.well-known/openapi.json",
    ]

    # GraphQL introspection query
    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
        __schema {
            types {
                name
                kind
                fields {
                    name
                }
            }
            queryType { name }
            mutationType { name }
        }
    }
    """

    def __init__(self, client: AdaptiveHTTPClient):
        self.client = client
        self.findings: List[Finding] = []

    def scan(self, base_url: str, callback=None) -> List[Finding]:
        """
        Scan for API security issues

        Args:
            base_url: Target URL
            callback: Progress callback

        Returns:
            List of findings
        """
        self.findings = []

        if callback:
            callback("info", "Scanning API endpoints")

        # Test GraphQL endpoints
        self._test_graphql(base_url, callback)

        # Test REST API exposure
        self._test_api_documentation(base_url, callback)

        # Test for API key exposure
        self._test_api_key_exposure(base_url, callback)

        # Test rate limiting
        self._test_rate_limiting(base_url, callback)

        # Test BOLA patterns
        self._test_bola_patterns(base_url, callback)

        return self.findings

    def _test_graphql(self, base_url: str, callback=None):
        """Test for GraphQL introspection and misconfigurations"""
        if callback:
            callback("probe", "Testing GraphQL endpoints")

        graphql_endpoints = [
            "/graphql", "/graphiql", "/v1/graphql",
            "/api/graphql", "/query", "/gql"
        ]

        for endpoint in graphql_endpoints:
            url = urljoin(base_url, endpoint)

            try:
                # Test introspection
                resp = self.client.post(
                    url,
                    json={"query": self.INTROSPECTION_QUERY},
                    headers={"Content-Type": "application/json"},
                    timeout=10
                )

                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if "data" in data and "__schema" in (data.get("data") or {}):
                            schema = data["data"]["__schema"]
                            types_count = len(schema.get("types", []))

                            self.findings.append(Finding(
                                vuln_class="GraphQL Introspection Enabled",
                                severity="MEDIUM",
                                cvss=5.5,
                                url=url,
                                description=f"GraphQL introspection is enabled, exposing "
                                           f"{types_count} types in the schema. Attackers can "
                                           f"enumerate all queries, mutations, and types.",
                                evidence={
                                    "types_count": types_count,
                                    "has_mutations": schema.get("mutationType") is not None,
                                },
                                remediation=[
                                    "Disable introspection in production",
                                    "Use query whitelisting/persisted queries",
                                    "Implement proper authentication",
                                ],
                                tags=["api", "graphql", "introspection"],
                            ))

                            # Test for mutation without auth
                            self._test_graphql_mutations(url, schema, callback)
                            return  # Found GraphQL endpoint

                    except (json.JSONDecodeError, KeyError):
                        pass

                # Also check GET for GraphiQL interface
                resp_get = self.client.get(url, timeout=10)
                if resp_get.status_code == 200 and "graphiql" in resp_get.text.lower():
                    self.findings.append(Finding(
                        vuln_class="GraphiQL Interface Exposed",
                        severity="LOW",
                        cvss=3.5,
                        url=url,
                        description="GraphiQL interactive interface is publicly accessible",
                        remediation=[
                            "Restrict GraphiQL to development environments",
                            "Add authentication to GraphQL endpoints",
                        ],
                        tags=["api", "graphql", "interface"],
                    ))

            except Exception:
                continue

    def _test_graphql_mutations(self, url: str, schema: Dict, callback=None):
        """Test if sensitive mutations are accessible without auth"""
        if not schema.get("mutationType"):
            return

        # Get mutation type name
        mutation_type = schema["mutationType"]["name"]

        # Find mutation type in types
        for type_info in schema.get("types", []):
            if type_info.get("name") == mutation_type and type_info.get("fields"):
                sensitive_mutations = []
                for field in type_info["fields"]:
                    field_name = field.get("name", "").lower()
                    if any(x in field_name for x in [
                        "delete", "remove", "update", "create", "admin",
                        "password", "user", "role", "permission"
                    ]):
                        sensitive_mutations.append(field["name"])

                if sensitive_mutations:
                    self.findings.append(Finding(
                        vuln_class="Sensitive GraphQL Mutations Exposed",
                        severity="HIGH",
                        cvss=7.5,
                        url=url,
                        description=f"Potentially sensitive mutations found: "
                                   f"{', '.join(sensitive_mutations[:5])}",
                        evidence={"mutations": sensitive_mutations[:10]},
                        remediation=[
                            "Implement proper authorization on mutations",
                            "Use field-level permissions",
                            "Audit all mutation resolvers",
                        ],
                        tags=["api", "graphql", "authorization"],
                    ))
                break

    def _test_api_documentation(self, base_url: str, callback=None):
        """Test for exposed API documentation"""
        if callback:
            callback("probe", "Testing API documentation exposure")

        doc_endpoints = [
            ("/swagger.json", "Swagger/OpenAPI JSON"),
            ("/swagger.yaml", "Swagger/OpenAPI YAML"),
            ("/openapi.json", "OpenAPI JSON"),
            ("/api-docs", "API Documentation"),
            ("/swagger-ui/", "Swagger UI"),
            ("/swagger-ui.html", "Swagger UI"),
            ("/redoc", "ReDoc"),
            ("/docs", "API Docs"),
            ("/api/docs", "API Documentation"),
            ("/v1/swagger.json", "Swagger v1"),
            ("/v2/swagger.json", "Swagger v2"),
        ]

        for path, doc_type in doc_endpoints:
            url = urljoin(base_url, path)

            try:
                resp = self.client.get(url, timeout=10)

                if resp.status_code == 200:
                    # Check if it's actual API documentation
                    content = resp.text.lower()
                    is_doc = any(x in content for x in [
                        '"swagger"', '"openapi"', '"paths"',
                        'swagger-ui', 'api-docs', 'redoc'
                    ])

                    if is_doc or path.endswith('.json') or path.endswith('.yaml'):
                        # Count endpoints if JSON
                        endpoint_count = 0
                        try:
                            data = resp.json()
                            if "paths" in data:
                                endpoint_count = len(data["paths"])
                        except Exception:
                            pass

                        self.findings.append(Finding(
                            vuln_class="API Documentation Exposed",
                            severity="LOW",
                            cvss=3.5,
                            url=url,
                            description=f"{doc_type} is publicly accessible" +
                                       (f" ({endpoint_count} endpoints)" if endpoint_count else ""),
                            evidence={
                                "doc_type": doc_type,
                                "endpoint_count": endpoint_count,
                            },
                            remediation=[
                                "Restrict API documentation to authenticated users",
                                "Move documentation to internal networks",
                            ],
                            tags=["api", "documentation"],
                        ))
                        return  # Found one doc, no need to continue

            except Exception:
                continue

    def _test_api_key_exposure(self, base_url: str, callback=None):
        """Test for API keys in common locations"""
        if callback:
            callback("probe", "Testing for API key exposure")

        try:
            resp = self.client.get(base_url, timeout=10)
            body = resp.text

            # API key patterns
            api_key_patterns = [
                (r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "API Key"),
                (r'["\']?apikey["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "API Key"),
                (r'["\']?secret[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "Secret Key"),
                (r'["\']?access[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "Access Token"),
                (r'Bearer\s+([a-zA-Z0-9_\-\.]+)', "Bearer Token"),
                (r'sk_live_[a-zA-Z0-9]{24,}', "Stripe Secret Key"),
                (r'pk_live_[a-zA-Z0-9]{24,}', "Stripe Publishable Key"),
                (r'AKIA[A-Z0-9]{16}', "AWS Access Key"),
                (r'ghp_[a-zA-Z0-9]{36}', "GitHub Token"),
                (r'gho_[a-zA-Z0-9]{36}', "GitHub OAuth Token"),
            ]

            for pattern, key_type in api_key_patterns:
                matches = re.findall(pattern, body, re.IGNORECASE)
                if matches:
                    # Filter likely false positives
                    real_keys = [m for m in matches
                                if not any(x in m.lower() for x in
                                          ['example', 'test', 'demo', 'xxx', 'your'])]

                    if real_keys:
                        self.findings.append(Finding(
                            vuln_class="API Key Exposure",
                            severity="HIGH",
                            cvss=8.0,
                            url=base_url,
                            description=f"{key_type} found in response body",
                            evidence={
                                "key_type": key_type,
                                "key_preview": real_keys[0][:10] + "..." if real_keys else "",
                            },
                            remediation=[
                                "Remove API keys from client-side code",
                                "Rotate exposed keys immediately",
                                "Use environment variables for secrets",
                            ],
                            tags=["api", "secrets", "exposure"],
                        ))
                        return  # Found exposure

        except Exception:
            pass

    def _test_rate_limiting(self, base_url: str, callback=None):
        """Test for rate limiting on API endpoints"""
        if callback:
            callback("probe", "Testing rate limiting")

        api_endpoints = ["/api", "/api/v1", "/graphql", "/login", "/auth"]

        for endpoint in api_endpoints:
            url = urljoin(base_url, endpoint)

            try:
                resp = self.client.get(url, timeout=5)
                if resp.status_code == 404:
                    continue

                # Check for rate limit headers
                rate_headers = [
                    "X-RateLimit-Limit", "X-RateLimit-Remaining",
                    "X-Rate-Limit-Limit", "RateLimit-Limit",
                    "Retry-After", "X-Retry-After"
                ]

                has_rate_limit = any(h.lower() in [k.lower() for k in resp.headers.keys()]
                                    for h in rate_headers)

                if not has_rate_limit:
                    # Make rapid requests to test
                    consecutive_success = 0
                    for _ in range(10):
                        test_resp = self.client.get(url, timeout=5)
                        if test_resp.status_code not in [429, 503]:
                            consecutive_success += 1

                    if consecutive_success >= 10:
                        self.findings.append(Finding(
                            vuln_class="Missing Rate Limiting",
                            severity="MEDIUM",
                            cvss=5.0,
                            url=url,
                            description="API endpoint does not appear to have rate limiting",
                            evidence={
                                "consecutive_requests": consecutive_success,
                                "rate_limit_headers": "Not found",
                            },
                            remediation=[
                                "Implement rate limiting on all API endpoints",
                                "Add rate limit headers for transparency",
                                "Consider using API gateway with built-in rate limiting",
                            ],
                            tags=["api", "rate-limiting"],
                        ))
                        return  # Found one issue

            except Exception:
                continue

    def _test_bola_patterns(self, base_url: str, callback=None):
        """Test for BOLA/IDOR-susceptible patterns"""
        if callback:
            callback("probe", "Checking for BOLA patterns")

        # Common IDOR-prone endpoints
        idor_patterns = [
            "/api/user/{id}", "/api/users/{id}",
            "/api/account/{id}", "/api/profile/{id}",
            "/api/order/{id}", "/api/orders/{id}",
            "/api/document/{id}", "/api/file/{id}",
            "/api/invoice/{id}", "/api/payment/{id}",
        ]

        found_patterns = []

        for pattern in idor_patterns:
            # Test with numeric ID
            test_url = urljoin(base_url, pattern.replace("{id}", "1"))

            try:
                resp = self.client.get(test_url, timeout=8)

                # If we get data without auth, might be BOLA
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if data and isinstance(data, dict):
                            found_patterns.append({
                                "pattern": pattern,
                                "response_keys": list(data.keys())[:5],
                            })
                    except Exception:
                        pass

            except Exception:
                continue

        if found_patterns:
            self.findings.append(Finding(
                vuln_class="Potential BOLA/IDOR Endpoints",
                severity="LOW",  # Low until confirmed with different user
                cvss=4.0,
                url=base_url,
                description="Found API endpoints with predictable object references. "
                           "Manual testing required to confirm BOLA vulnerability.",
                evidence={"patterns": found_patterns},
                remediation=[
                    "Implement authorization checks on object access",
                    "Use UUIDs instead of sequential IDs",
                    "Add object-level permission validation",
                ],
                tags=["api", "bola", "idor"],
            ))
