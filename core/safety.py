"""
Target Safety Controls
- Rate limiting
- Scope enforcement
- Safe mode (disable destructive payloads)
- Request counting and stats
"""

import time
import threading
from typing import Set, Optional
from urllib.parse import urlparse


class RateLimiter:
    """Token-bucket rate limiter for HTTP requests"""

    def __init__(self, requests_per_second: float = 10.0):
        self.rps = requests_per_second
        self.interval = 1.0 / requests_per_second if requests_per_second > 0 else 0
        self._lock = threading.Lock()
        self._last_request = 0.0
        self.total_requests = 0
        self.total_wait_time = 0.0

    def wait(self):
        """Block until we can make the next request"""
        if self.interval <= 0:
            self.total_requests += 1
            return

        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_request
            if elapsed < self.interval:
                wait_time = self.interval - elapsed
                self.total_wait_time += wait_time
                time.sleep(wait_time)
            self._last_request = time.monotonic()
            self.total_requests += 1


class ScopeChecker:
    """Enforce scanning scope - only allow requests to approved domains"""

    def __init__(self, allowed_domains: Set[str] = None):
        self.allowed_domains: Set[str] = set()
        self.blocked_count = 0
        self._lock = threading.Lock()

        if allowed_domains:
            for d in allowed_domains:
                # Store with and without www
                d = d.lower().strip()
                self.allowed_domains.add(d)
                if d.startswith('www.'):
                    self.allowed_domains.add(d[4:])
                else:
                    self.allowed_domains.add(f'www.{d}')

    def is_in_scope(self, url: str) -> bool:
        """Check if URL is within the allowed scope"""
        if not self.allowed_domains:
            return True  # No scope = everything allowed

        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
            hostname = hostname.lower()

            # Check exact match
            if hostname in self.allowed_domains:
                return True

            # Check subdomain match (*.example.com)
            for allowed in self.allowed_domains:
                if hostname.endswith(f'.{allowed}'):
                    return True

            with self._lock:
                self.blocked_count += 1
            return False

        except Exception:
            return False


class SafetyConfig:
    """Central safety configuration"""

    def __init__(self, rate_limit: float = 0, scope_domains: Set[str] = None,
                 safe_mode: bool = False):
        self.rate_limiter = RateLimiter(rate_limit) if rate_limit > 0 else None
        self.scope = ScopeChecker(scope_domains) if scope_domains else None
        self.safe_mode = safe_mode
        self.requests_made = 0
        self.requests_blocked = 0
        self._lock = threading.Lock()

    def check_request(self, url: str) -> bool:
        """Check if request is allowed. Returns False if blocked by scope."""
        # Scope check
        if self.scope and not self.scope.is_in_scope(url):
            with self._lock:
                self.requests_blocked += 1
            return False

        # Rate limit (blocks until allowed)
        if self.rate_limiter:
            self.rate_limiter.wait()

        with self._lock:
            self.requests_made += 1
        return True

    def get_stats(self) -> dict:
        return {
            "total_requests": self.requests_made,
            "blocked_by_scope": self.requests_blocked,
            "rate_limit_rps": self.rate_limiter.rps if self.rate_limiter else None,
            "rate_limit_wait_total": round(self.rate_limiter.total_wait_time, 2) if self.rate_limiter else 0,
            "safe_mode": self.safe_mode,
            "scope_domains": list(self.scope.allowed_domains) if self.scope else None,
        }
