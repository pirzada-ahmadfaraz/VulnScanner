"""
AI-Powered Vulnerability Analysis Engine
Uses Claude API for:
- Intelligent vulnerability discovery
- Finding verification and validation
- Response analysis for hidden vulnerabilities
- Adaptive payload generation
- Context-aware security testing
"""

import os
import re
import json
import time
from typing import List, Dict, Optional, Tuple, Any
from urllib.parse import urljoin, urlparse, parse_qs
from dataclasses import dataclass

try:
    import anthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False

from ..core.finding import Finding
from ..core.http_client import AdaptiveHTTPClient


@dataclass
class AIAnalysisResult:
    """Result from AI analysis"""
    is_vulnerable: bool
    confidence: float  # 0.0 to 1.0
    vulnerability_type: str
    severity: str
    description: str
    evidence: Dict
    exploitation_steps: List[str]
    remediation: List[str]
    false_positive_reason: Optional[str] = None


@dataclass
class AIFixProposal:
    """AI-generated remediation proposal for a finding"""
    finding_fingerprint: str       # Links back to the Finding
    summary: str                   # One-line fix summary
    code_snippets: List[Dict]      # [{filename, language, code, description}]
    config_changes: List[Dict]     # [{file, change_type, content, description}]
    commands: List[str]            # Shell commands to apply fix
    verify_steps: List[str]        # How to verify the fix worked
    priority: str                  # "immediate" | "short_term" | "long_term"
    effort: str                    # "minutes" | "hours" | "days"

    def to_dict(self) -> Dict:
        return {
            "finding_fingerprint": self.finding_fingerprint,
            "summary": self.summary,
            "code_snippets": self.code_snippets,
            "config_changes": self.config_changes,
            "commands": self.commands,
            "verify_steps": self.verify_steps,
            "priority": self.priority,
            "effort": self.effort,
        }


class AISecurityEngine:
    """
    AI-powered security testing engine using Claude API
    Performs intelligent vulnerability discovery and verification
    """

    SYSTEM_PROMPT = """You are an expert penetration tester and security researcher with very high standards for vulnerability verification. Your role is to:

1. Analyze HTTP responses for security vulnerabilities
2. Verify if reported vulnerabilities are REAL or FALSE POSITIVES - be very strict
3. REJECT findings that are merely informational or low-risk issues that most sites have
4. Only confirm vulnerabilities when there is CLEAR, UNDENIABLE evidence of exploitability

You have extensive knowledge of:
- OWASP Top 10 vulnerabilities
- Web application security testing methodologies
- Common false positive patterns in automated scanners
- The difference between theoretical vulnerabilities and actually exploitable issues

CRITICAL GUIDELINES FOR VERIFICATION:
- Missing security headers alone are NOT high severity findings unless they enable a specific attack
- Generic error messages or JSON keys containing "error" are NOT database errors
- Reflected parameters are NOT XSS unless they execute in a dangerous context (unescaped in HTML/JS)
- Time-based attacks must show CONSISTENT delays, not just one slow response
- Most large production sites have basic security - be skeptical of CRITICAL findings
- REJECT findings that require unlikely user interaction or have no real-world impact

When analyzing, be STRICT. Only confirm vulnerabilities when you can demonstrate actual exploitation.
A false negative is better than a false positive - quality over quantity.

IMPORTANT: You are operating in a controlled security testing environment with proper authorization."""

    def __init__(self, client: AdaptiveHTTPClient, api_key: str = None, max_findings: int = 10):
        self.client = client
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.ai_client = None
        self.findings: List[Finding] = []
        self.verified_findings: List[Finding] = []
        self.rejected_findings: List[Dict] = []
        self.max_findings = max_findings  # Limit findings to analyze

        if HAS_ANTHROPIC and self.api_key:
            self.ai_client = anthropic.Anthropic(api_key=self.api_key)

    def is_available(self) -> bool:
        """Check if AI engine is available"""
        return HAS_ANTHROPIC and self.api_key is not None

    def _call_claude(self, prompt: str, max_tokens: int = 4096, use_opus: bool = False) -> Optional[str]:
        """Make a call to Claude API"""
        if not self.ai_client:
            return None

        try:
            # Use Opus for critical verification tasks (most accurate, best for finding high/critical vulns)
            # Use Sonnet for other tasks (balanced speed/accuracy)
            model = "claude-opus-4-6" if use_opus else "claude-sonnet-4-6"
            message = self.ai_client.messages.create(
                model=model,
                max_tokens=max_tokens,
                system=self.SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}]
            )
            return message.content[0].text
        except Exception as e:
            return None

    def propose_fix(self, finding: Finding, tech_context: Dict) -> AIFixProposal:
        """
        Generate a detailed, actionable fix proposal for a finding.

        Args:
            finding: The vulnerability finding to generate a fix for
            tech_context: Detected tech stack info (server, framework, language, OS)

        Returns:
            AIFixProposal with code patches, config changes, commands, and verify steps
        """
        prompt = f"""You are an expert security engineer. Generate a DETAILED, ACTIONABLE fix proposal for this vulnerability.

VULNERABILITY:
- Type: {finding.vuln_class}
- Severity: {finding.severity}
- URL: {finding.url}
- Parameter: {finding.parameter or 'N/A'}
- Description: {finding.description}
- Evidence: {json.dumps(finding.evidence, indent=2, default=str) if finding.evidence else 'None'}
- Current Remediation Advice: {json.dumps(finding.remediation, default=str) if finding.remediation else 'None'}

TARGET TECH STACK:
{json.dumps(tech_context, indent=2, default=str)}

Generate a fix proposal with:
1. A one-line summary of the fix
2. Code snippets (actual patches with filenames and language)
3. Configuration file changes (with file paths and content)
4. Shell commands to apply the fix
5. Verification steps to confirm the fix worked
6. Priority: "immediate" (active exploitation risk), "short_term" (fix within days), "long_term" (hardening)
7. Effort estimate: "minutes", "hours", or "days"

Be SPECIFIC to the detected tech stack. If Nginx is detected, show Nginx config. If Node.js, show Node.js code. etc.

Respond in this exact JSON format:
{{
    "summary": "one-line fix summary",
    "code_snippets": [
        {{"filename": "path/to/file", "language": "python", "code": "actual code", "description": "what this does"}}
    ],
    "config_changes": [
        {{"file": "config/path", "change_type": "modify", "content": "config content", "description": "what to change"}}
    ],
    "commands": ["shell command 1", "shell command 2"],
    "verify_steps": ["how to verify step 1", "how to verify step 2"],
    "priority": "immediate|short_term|long_term",
    "effort": "minutes|hours|days"
}}"""

        response = self._call_claude(prompt, max_tokens=4096)

        if response:
            try:
                json_match = re.search(r'\{[\s\S]*\}', response)
                if json_match:
                    data = json.loads(json_match.group())
                    return AIFixProposal(
                        finding_fingerprint=finding.fingerprint,
                        summary=data.get("summary", "See remediation advice"),
                        code_snippets=data.get("code_snippets", []),
                        config_changes=data.get("config_changes", []),
                        commands=data.get("commands", []),
                        verify_steps=data.get("verify_steps", []),
                        priority=data.get("priority", "short_term"),
                        effort=data.get("effort", "hours"),
                    )
            except json.JSONDecodeError:
                pass

        # Fallback — return proposal with existing remediation as summary
        fallback_summary = finding.remediation[0] if finding.remediation else "Review and apply standard remediation"
        return AIFixProposal(
            finding_fingerprint=finding.fingerprint,
            summary=fallback_summary,
            code_snippets=[],
            config_changes=[],
            commands=[],
            verify_steps=[],
            priority="short_term",
            effort="hours",
        )

    def verify_finding(self, finding: Finding, base_url: str) -> AIAnalysisResult:
        """
        Use AI to verify if a finding is a true positive

        Args:
            finding: The finding to verify
            base_url: Target base URL

        Returns:
            AIAnalysisResult with verification details
        """
        # Gather additional evidence by re-testing
        evidence_data = self._gather_evidence(finding, base_url)

        prompt = f"""Analyze this potential security vulnerability and determine if it's a TRUE POSITIVE or FALSE POSITIVE.

BE VERY STRICT - reject findings that are:
- Missing headers (these are low-severity config issues, not vulnerabilities)
- Generic information disclosure (server banners, technology detection)
- Theoretical issues with no proof of exploitability
- Common issues that 99% of sites have

REPORTED VULNERABILITY:
- Type: {finding.vuln_class}
- Severity: {finding.severity}
- URL: {finding.url}
- Parameter: {finding.parameter or 'N/A'}
- Description: {finding.description}
- Original Evidence: {json.dumps(finding.evidence, indent=2) if finding.evidence else 'None'}

ADDITIONAL TESTING RESULTS:
{json.dumps(evidence_data, indent=2)}

VERIFICATION TASKS:
1. Is this actually exploitable in a real attack scenario?
2. Is the evidence conclusive or just circumstantial?
3. Could this be a false positive from pattern matching?
4. What is the REAL impact if exploited?
5. Would a professional pentester report this?

Respond in this exact JSON format:
{{
    "is_vulnerable": true/false,
    "confidence": 0.0-1.0,
    "vulnerability_type": "specific vulnerability name",
    "severity": "CRITICAL/HIGH/MEDIUM/LOW/INFO",
    "description": "detailed description of the finding",
    "evidence": {{"key": "value pairs of proof"}},
    "exploitation_steps": ["step 1", "step 2"],
    "remediation": ["fix 1", "fix 2"],
    "false_positive_reason": "reason if false positive, null otherwise"
}}

Default to FALSE POSITIVE unless you have strong evidence of exploitability."""

        # Use Opus for verification (most accurate, best for finding critical vulns)
        response = self._call_claude(prompt, use_opus=True)

        if response:
            try:
                # Extract JSON from response
                json_match = re.search(r'\{[\s\S]*\}', response)
                if json_match:
                    data = json.loads(json_match.group())
                    return AIAnalysisResult(
                        is_vulnerable=data.get("is_vulnerable", False),
                        confidence=data.get("confidence", 0.5),
                        vulnerability_type=data.get("vulnerability_type", finding.vuln_class),
                        severity=data.get("severity", finding.severity),
                        description=data.get("description", finding.description),
                        evidence=data.get("evidence", {}),
                        exploitation_steps=data.get("exploitation_steps", []),
                        remediation=data.get("remediation", finding.remediation or []),
                        false_positive_reason=data.get("false_positive_reason"),
                    )
            except json.JSONDecodeError:
                pass

        # Fallback - be conservative and reject unclear findings
        return AIAnalysisResult(
            is_vulnerable=False,
            confidence=0.3,
            vulnerability_type=finding.vuln_class,
            severity="INFO",
            description=finding.description,
            evidence=finding.evidence or {},
            exploitation_steps=[],
            remediation=finding.remediation or [],
            false_positive_reason="Could not verify - treating as potential false positive",
        )

    def _gather_evidence(self, finding: Finding, base_url: str) -> Dict:
        """Gather additional evidence for verification"""
        evidence = {
            "retests": [],
            "variations": [],
        }

        url = finding.url or base_url
        param = finding.parameter

        try:
            # Re-test the original request
            resp = self.client.get(url, timeout=10)
            evidence["retests"].append({
                "url": url,
                "status": resp.status_code,
                "length": len(resp.content),
                "headers": dict(resp.headers),
                "body_preview": resp.text[:1000],
            })

            # Test variations based on vulnerability type
            if "xss" in finding.vuln_class.lower():
                test_payloads = [
                    "<script>alert(1)</script>",
                    "<img src=x onerror=alert(1)>",
                    "javascript:alert(1)",
                ]
                for payload in test_payloads:
                    test_url = f"{url}?{param}={payload}" if param else url
                    try:
                        var_resp = self.client.get(test_url, timeout=5)
                        evidence["variations"].append({
                            "payload": payload,
                            "reflected": payload in var_resp.text,
                            "encoded": any(x in var_resp.text for x in [
                                "&lt;script&gt;", "\\u003c", "%3C"
                            ]),
                            "status": var_resp.status_code,
                        })
                    except Exception:
                        pass

            elif "sql" in finding.vuln_class.lower():
                test_payloads = ["'", "\"", "' OR '1'='1", "1; SELECT 1--"]
                for payload in test_payloads:
                    test_url = f"{url}?{param}={payload}" if param else url
                    try:
                        var_resp = self.client.get(test_url, timeout=5)
                        evidence["variations"].append({
                            "payload": payload,
                            "error_in_response": any(x in var_resp.text.lower() for x in [
                                "sql", "mysql", "syntax", "query", "oracle", "postgresql"
                            ]),
                            "status": var_resp.status_code,
                            "length_diff": abs(len(var_resp.content) - evidence["retests"][0]["length"]),
                        })
                    except Exception:
                        pass

        except Exception:
            pass

        return evidence

    def discover_vulnerabilities(self, base_url: str, response_data: Dict,
                                  callback=None) -> List[Finding]:
        """
        Use AI to discover vulnerabilities from response analysis

        Args:
            base_url: Target URL
            response_data: Collected response data from scanning
            callback: Progress callback

        Returns:
            List of discovered findings
        """
        if callback:
            callback("probe", "AI analyzing responses for vulnerabilities")

        prompt = f"""Analyze this web application response data and identify ALL potential security vulnerabilities.

TARGET: {base_url}

COLLECTED DATA:
{json.dumps(response_data, indent=2, default=str)[:15000]}

ANALYSIS REQUIREMENTS:
1. Look for information disclosure in headers, error messages, comments
2. Identify potential injection points in parameters and inputs
3. Check for authentication/authorization weaknesses
4. Analyze JavaScript for DOM-based vulnerabilities
5. Look for sensitive data exposure
6. Check for misconfigurations
7. Identify business logic issues
8. Look for API security problems

For each vulnerability found, provide:
- Specific URL/endpoint affected
- Parameter or component involved
- Clear evidence from the response
- Exploitation potential
- Severity assessment

Respond with a JSON array of findings:
[
    {{
        "vuln_class": "vulnerability type",
        "severity": "CRITICAL/HIGH/MEDIUM/LOW/INFO",
        "cvss": 0.0-10.0,
        "url": "affected URL",
        "parameter": "affected parameter or null",
        "description": "detailed description",
        "evidence": {{"key": "proof"}},
        "exploitation": "how to exploit",
        "remediation": ["fix 1", "fix 2"],
        "confidence": 0.0-1.0
    }}
]

Only include findings with clear evidence. No speculation."""

        # Use Opus for discovery (most accurate for finding critical vulnerabilities)
        response = self._call_claude(prompt, max_tokens=8192, use_opus=True)

        findings = []
        if response:
            try:
                # Extract JSON array from response
                json_match = re.search(r'\[[\s\S]*\]', response)
                if json_match:
                    data = json.loads(json_match.group())
                    for item in data:
                        # Only include HIGH confidence findings (0.8+)
                        if item.get("confidence", 0) >= 0.8:
                            findings.append(Finding(
                                vuln_class=item.get("vuln_class", "AI-Discovered Issue"),
                                severity=item.get("severity", "MEDIUM"),
                                cvss=item.get("cvss", 5.0),
                                url=item.get("url", base_url),
                                parameter=item.get("parameter"),
                                description=item.get("description", ""),
                                evidence=item.get("evidence", {}),
                                remediation=item.get("remediation", []),
                                confidence=item.get("confidence", 0.7),
                                tags=["ai-discovered"],
                            ))
            except json.JSONDecodeError:
                pass

        return findings

    def generate_attack_payloads(self, context: Dict) -> List[Dict]:
        """
        Generate context-aware attack payloads using AI

        Args:
            context: Information about the target (tech stack, WAF, etc.)

        Returns:
            List of payload dictionaries
        """
        prompt = f"""Generate targeted security testing payloads based on this context:

TARGET CONTEXT:
{json.dumps(context, indent=2)}

Generate payloads for:
1. XSS (considering any detected WAF/filters)
2. SQL Injection (for detected database type)
3. Command Injection (for detected OS)
4. SSTI (for detected template engine)
5. Path Traversal
6. Authentication Bypass

For each category, provide 5 payloads optimized for this specific target.
Consider bypass techniques for any detected WAF.

Respond in JSON format:
{{
    "xss": [
        {{"payload": "...", "context": "html/attribute/js", "bypass_technique": "..."}}
    ],
    "sqli": [
        {{"payload": "...", "db_type": "mysql/postgres/etc", "technique": "error/blind/time"}}
    ],
    "command_injection": [
        {{"payload": "...", "os": "linux/windows", "technique": "..."}}
    ],
    "ssti": [
        {{"payload": "...", "engine": "jinja2/twig/etc", "technique": "..."}}
    ],
    "path_traversal": [
        {{"payload": "...", "technique": "..."}}
    ],
    "auth_bypass": [
        {{"payload": "...", "technique": "..."}}
    ]
}}"""

        response = self._call_claude(prompt)

        if response:
            try:
                json_match = re.search(r'\{[\s\S]*\}', response)
                if json_match:
                    return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass

        return {}

    def analyze_for_business_logic(self, base_url: str, endpoints: List[Dict],
                                    callback=None) -> List[Finding]:
        """
        Analyze application flow for business logic vulnerabilities

        Args:
            base_url: Target URL
            endpoints: List of discovered endpoints with their behavior
            callback: Progress callback

        Returns:
            List of business logic findings
        """
        if callback:
            callback("probe", "AI analyzing business logic")

        prompt = f"""Analyze these API endpoints for business logic vulnerabilities:

TARGET: {base_url}

ENDPOINTS:
{json.dumps(endpoints, indent=2)[:10000]}

Look for:
1. Race conditions (TOCTOU)
2. Price manipulation
3. Quantity tampering
4. Coupon/discount abuse
5. Account takeover flows
6. Privilege escalation paths
7. IDOR patterns
8. State manipulation
9. Workflow bypass
10. Rate limit bypass for sensitive operations

Respond with JSON array of findings:
[
    {{
        "vuln_class": "Business Logic - specific issue",
        "severity": "severity level",
        "url": "affected endpoint",
        "description": "detailed description",
        "attack_scenario": "how to exploit step by step",
        "impact": "business impact",
        "remediation": ["fixes"]
    }}
]"""

        # Use Opus for business logic analysis (most accurate for complex vulnerabilities)
        response = self._call_claude(prompt, use_opus=True)

        findings = []
        if response:
            try:
                json_match = re.search(r'\[[\s\S]*\]', response)
                if json_match:
                    data = json.loads(json_match.group())
                    for item in data:
                        findings.append(Finding(
                            vuln_class=item.get("vuln_class", "Business Logic Flaw"),
                            severity=item.get("severity", "MEDIUM"),
                            url=item.get("url", base_url),
                            description=item.get("description", "") +
                                       f"\n\nAttack Scenario: {item.get('attack_scenario', '')}",
                            evidence={"impact": item.get("impact", "")},
                            remediation=item.get("remediation", []),
                            tags=["ai-discovered", "business-logic"],
                        ))
            except json.JSONDecodeError:
                pass

        return findings

    def deep_scan_endpoint(self, url: str, method: str = "GET",
                           params: Dict = None, callback=None) -> List[Finding]:
        """
        Perform deep AI-guided scanning of a specific endpoint

        Args:
            url: Endpoint URL
            method: HTTP method
            params: Parameters to test
            callback: Progress callback

        Returns:
            List of findings
        """
        if callback:
            callback("probe", f"AI deep scanning {url[:50]}...")

        findings = []

        # Collect baseline response
        try:
            if method == "GET":
                baseline = self.client.get(url, params=params, timeout=10)
            else:
                baseline = self.client.post(url, data=params, timeout=10)

            baseline_data = {
                "url": url,
                "method": method,
                "params": params,
                "status": baseline.status_code,
                "headers": dict(baseline.headers),
                "body": baseline.text[:5000],
                "cookies": dict(baseline.cookies),
            }

            # Ask AI for attack suggestions
            prompt = f"""Analyze this endpoint and suggest specific attacks to try:

ENDPOINT DATA:
{json.dumps(baseline_data, indent=2)}

Based on the response, suggest:
1. Specific payloads to test each parameter
2. Header manipulation attacks
3. Authentication bypass attempts
4. Any observable vulnerabilities in the response

Respond with JSON:
{{
    "parameter_tests": [
        {{"param": "name", "payloads": ["p1", "p2"], "vuln_type": "xss/sqli/etc"}}
    ],
    "header_tests": [
        {{"header": "name", "value": "test value", "purpose": "what to look for"}}
    ],
    "observed_issues": [
        {{"issue": "description", "evidence": "from response", "severity": "level"}}
    ]
}}"""

            # Use Opus for deep endpoint scanning (most accurate)
            ai_response = self._call_claude(prompt, use_opus=True)

            if ai_response:
                try:
                    json_match = re.search(r'\{[\s\S]*\}', ai_response)
                    if json_match:
                        suggestions = json.loads(json_match.group())

                        # Execute suggested tests
                        for test in suggestions.get("parameter_tests", []):
                            param_name = test.get("param")
                            for payload in test.get("payloads", [])[:3]:
                                test_params = {**(params or {}), param_name: payload}
                                try:
                                    if method == "GET":
                                        test_resp = self.client.get(url, params=test_params, timeout=8)
                                    else:
                                        test_resp = self.client.post(url, data=test_params, timeout=8)

                                    # Check if payload had effect
                                    if self._check_payload_effect(payload, test_resp, baseline):
                                        findings.append(Finding(
                                            vuln_class=f"Potential {test.get('vuln_type', 'Injection')}",
                                            severity="MEDIUM",
                                            url=url,
                                            parameter=param_name,
                                            description=f"Parameter {param_name} appears vulnerable. "
                                                       f"Payload: {payload[:50]}",
                                            evidence={
                                                "payload": payload,
                                                "response_change": True,
                                            },
                                            tags=["ai-discovered", "needs-verification"],
                                        ))
                                except Exception:
                                    pass

                        # Add any directly observed issues
                        for issue in suggestions.get("observed_issues", []):
                            findings.append(Finding(
                                vuln_class=issue.get("issue", "Observed Issue"),
                                severity=issue.get("severity", "INFO"),
                                url=url,
                                description=issue.get("issue", ""),
                                evidence={"observation": issue.get("evidence", "")},
                                tags=["ai-discovered"],
                            ))

                except json.JSONDecodeError:
                    pass

        except Exception:
            pass

        return findings

    def _check_payload_effect(self, payload: str, test_resp, baseline_resp) -> bool:
        """Check if payload had a meaningful effect on response"""
        # Status code change
        if test_resp.status_code != baseline_resp.status_code:
            return True

        # Significant length change
        len_diff = abs(len(test_resp.content) - len(baseline_resp.content))
        if len_diff > 100:
            return True

        # Payload reflection
        if payload in test_resp.text:
            return True

        # Error messages
        error_indicators = [
            "error", "exception", "warning", "syntax", "unexpected",
            "invalid", "failed", "denied", "forbidden"
        ]
        baseline_errors = sum(1 for e in error_indicators if e in baseline_resp.text.lower())
        test_errors = sum(1 for e in error_indicators if e in test_resp.text.lower())
        if test_errors > baseline_errors:
            return True

        return False

    def detect_chains(self, findings: List[Finding], callback=None) -> List[Dict]:
        """
        Detect vulnerability chains - combinations of findings that together
        create higher-impact attacks.

        Args:
            findings: List of all verified findings
            callback: Progress callback

        Returns:
            List of chain dicts describing attack chains
        """
        if len(findings) < 2:
            return []

        # Build a summary of all findings
        findings_summary = ""
        for i, f in enumerate(findings, 1):
            findings_summary += (
                f"{i}. vuln_class={f.vuln_class}, severity={f.severity}, "
                f"url={f.url}, parameter={f.parameter or 'N/A'}\n"
            )

        prompt = f"""Analyze these vulnerability findings and identify ATTACK CHAINS where multiple vulnerabilities can be combined for greater impact.

FINDINGS:
{findings_summary}

Look for chains like:
- SSRF + Open Redirect = Internal network access
- XSS + CSRF = Account takeover
- Info Disclosure + SQLi = Database compromise
- Auth bypass + IDOR = Mass data exfiltration
- Open Redirect + OAuth = Token theft

Only report chains where the findings ACTUALLY EXIST in the list above.
Each chain must involve 2+ findings that are present.

Respond with JSON array:
[
    {{
        "chain_name": "descriptive name",
        "severity": "CRITICAL/HIGH/MEDIUM",
        "findings": ["vuln_class1", "vuln_class2"],
        "combined_impact": "what the chain achieves",
        "exploitation_path": ["step 1", "step 2", "step 3"]
    }}
]

Return empty array [] if no meaningful chains exist."""

        # Use Opus for chain detection (most accurate for complex attack paths)
        response = self._call_claude(prompt, use_opus=True)

        if response:
            try:
                json_match = re.search(r'\[[\s\S]*\]', response)
                if json_match:
                    chains = json.loads(json_match.group())
                    if isinstance(chains, list):
                        return chains
            except json.JSONDecodeError:
                pass

        return []

    def plan_attack(self, target: str, recon_data: Dict,
                     surface_data: Dict) -> List[Dict]:
        """
        AI generates up to 15 targeted test plans based on recon and surface data.

        Args:
            target: Primary target URL/domain
            recon_data: Subdomains, open ports, live hosts from recon phase
            surface_data: Endpoints, forms, params, tech stack from surface mapping

        Returns:
            List of attack plan dicts with url, method, params, test_type, rationale
        """
        if not self.ai_client:
            return []

        prompt = f"""You are planning a targeted penetration test. Based on the reconnaissance and surface mapping data below, generate up to 15 specific, high-value test plans.

TARGET: {target}

RECON DATA (subdomains, ports, live hosts):
{json.dumps(recon_data, indent=2, default=str)[:6000]}

SURFACE DATA (endpoints, forms, parameters, tech stack):
{json.dumps(surface_data, indent=2, default=str)[:8000]}

For each test plan, consider:
- Which endpoints have the most parameters (highest attack surface)
- Which forms handle sensitive data (auth, payment, profile)
- Tech stack weaknesses (known CVEs, common misconfigurations)
- Parameter types that suggest injection points
- Authentication/authorization boundaries to test

Respond with a JSON array of up to 15 test plans:
[
    {{
        "url": "full URL to test",
        "method": "GET or POST",
        "params": {{"param_name": "test_value"}},
        "test_type": "xss|sqli|ssrf|idor|auth_bypass|ssti|command_injection|path_traversal|business_logic",
        "rationale": "why this specific test on this endpoint"
    }}
]

Prioritize by likely impact. Focus on endpoints that handle user input, authentication, file operations, or external requests."""

        # Use Opus for attack planning (most accurate for strategic analysis)
        response = self._call_claude(prompt, max_tokens=4096, use_opus=True)

        if response:
            try:
                json_match = re.search(r'\[[\s\S]*\]', response)
                if json_match:
                    plans = json.loads(json_match.group())
                    if isinstance(plans, list):
                        return plans[:15]
            except json.JSONDecodeError:
                pass

        return []

    def generate_summary(self, findings: List[Finding], chains: List[Dict],
                          scan_info: Dict) -> str:
        """
        Generate an executive summary for C-level readers.

        Args:
            findings: All verified findings
            chains: Detected attack chains
            scan_info: Scan metadata (target, duration, modules run, etc.)

        Returns:
            Executive summary text string
        """
        if not self.ai_client:
            return ""

        findings_summary = []
        for f in findings:
            findings_summary.append({
                "vuln_class": f.vuln_class,
                "severity": f.severity,
                "cvss": f.cvss,
                "url": f.url,
                "description": f.description[:200],
            })

        prompt = f"""Write a concise executive summary of this penetration test for C-level executives and non-technical stakeholders.

SCAN INFO:
{json.dumps(scan_info, indent=2, default=str)}

FINDINGS ({len(findings)} total):
{json.dumps(findings_summary, indent=2, default=str)[:8000]}

ATTACK CHAINS ({len(chains)} detected):
{json.dumps(chains, indent=2, default=str)[:3000]}

Write the summary in this structure (plain text, no markdown):
1. OVERALL RISK ASSESSMENT (1-2 sentences: critical/high/moderate/low risk posture)
2. KEY FINDINGS (3-5 bullet points of the most impactful issues)
3. ATTACK CHAINS (if any — describe in business terms, not technical jargon)
4. RECOMMENDED ACTIONS (prioritized list of 3-5 remediation steps)
5. POSITIVE OBSERVATIONS (1-2 things done well, if applicable)

Keep it under 500 words. Use business impact language, not technical jargon. Replace "XSS" with "script injection", "SQLi" with "database injection", etc."""

        # Use Opus for executive summary (most accurate and articulate)
        response = self._call_claude(prompt, max_tokens=2048, use_opus=True)
        return response.strip() if response else ""

    def scan(self, base_url: str, existing_findings: List[Finding] = None,
             response_data: Dict = None, callback=None) -> Tuple[List[Finding], List[Finding], List[Dict]]:
        """
        Main AI scanning entry point

        Args:
            base_url: Target URL
            existing_findings: Findings from other modules to verify
            response_data: Collected response data for analysis
            callback: Progress callback

        Returns:
            Tuple of (verified_findings, new_findings, chains)
        """
        verified = []
        discovered = []

        if not self.is_available():
            if callback:
                callback("error", "AI engine not available (missing API key or anthropic library)")
            return existing_findings or [], [], []

        if callback:
            callback("info", "AI Security Engine activated")

        # Step 1: Filter and prioritize findings
        if existing_findings:
            # Limit to max_findings (default 10) to save time and tokens
            # Take first N findings as-is (no sorting by severity)
            findings_to_verify = existing_findings[:self.max_findings]
            skipped_count = len(existing_findings) - len(findings_to_verify)

            if callback and skipped_count > 0:
                callback("info", f"Analyzing first {len(findings_to_verify)} findings (skipped {skipped_count} to save time)")
            elif callback:
                callback("probe", f"Verifying {len(findings_to_verify)} findings with AI")

            # Batch verification for speed
            import concurrent.futures
            from threading import Lock

            verified_lock = Lock()
            rejected_lock = Lock()

            def verify_single(finding):
                result = self.verify_finding(finding, base_url)

                if result.is_vulnerable and result.confidence >= 0.8:
                    # Update finding with AI analysis
                    finding.description = result.description
                    finding.severity = result.severity
                    finding.evidence = result.evidence
                    finding.remediation = result.remediation
                    finding.confidence = result.confidence

                    with verified_lock:
                        verified.append(finding)

                    if callback:
                        callback("success", f"✓ Verified: {finding.vuln_class}")
                else:
                    with rejected_lock:
                        self.rejected_findings.append({
                            "original": finding.to_dict(),
                            "reason": result.false_positive_reason,
                        })
                    if callback:
                        callback("info", f"✗ Rejected: {finding.vuln_class}")

            # Parallel verification (up to 3 concurrent API calls)
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                executor.map(verify_single, findings_to_verify)

        # Step 2: Discover new vulnerabilities (only if we have capacity)
        if response_data and len(verified) < self.max_findings:
            if callback:
                callback("probe", "AI discovering additional vulnerabilities")

            new_findings = self.discover_vulnerabilities(base_url, response_data, callback)
            # Limit discoveries too
            remaining_slots = self.max_findings - len(verified)
            discovered.extend(new_findings[:remaining_slots])

            if callback:
                callback("info", f"AI discovered {len(new_findings)} additional issues")

        # Step 3: Business logic analysis if we have endpoint data (skip if at limit)
        if response_data and response_data.get("endpoints") and len(verified + discovered) < self.max_findings:
            bl_findings = self.analyze_for_business_logic(
                base_url, response_data["endpoints"], callback
            )
            remaining_slots = self.max_findings - len(verified) - len(discovered)
            discovered.extend(bl_findings[:remaining_slots])

        self.verified_findings = verified
        self.findings = discovered

        # Step 4: Chain detection
        chains = []
        all_findings = verified + discovered
        if len(all_findings) >= 2:
            if callback:
                callback("probe", "AI detecting vulnerability chains")
            chains = self.detect_chains(all_findings, callback)
            if callback and chains:
                callback("success", f"Detected {len(chains)} attack chain(s)")

        return verified, discovered, chains
