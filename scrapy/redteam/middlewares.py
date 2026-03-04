"""
Red Team Middlewares
====================
Custom Scrapy middlewares for red team operations:
  - User-agent rotation
  - Custom request headers
  - Rate limiting / polite crawling
  - Retry handling for auth/forbidden responses
"""

from __future__ import annotations

import logging
import random
import time
from typing import TYPE_CHECKING

from scrapy import signals
from scrapy.downloadermiddlewares.retry import RetryMiddleware
from scrapy.http import Request, Response
from scrapy.utils.response import response_status_message

if TYPE_CHECKING:
    from scrapy import Spider
    from scrapy.crawler import Crawler

logger = logging.getLogger(__name__)

# Common browser user agents for rotation
_USER_AGENTS = [
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Chrome on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Firefox on Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Safari on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    # Mobile Chrome on Android
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.44 Mobile Safari/537.36",
]


class UserAgentRotationMiddleware:
    """Rotates the User-Agent header on each request.

    Settings:
        REDTEAM_USER_AGENTS: list of user agent strings (defaults to _USER_AGENTS)
        REDTEAM_ROTATE_UA: bool (default True)
    """

    def __init__(self, user_agents: list[str], rotate: bool = True):
        self.user_agents = user_agents
        self.rotate = rotate

    @classmethod
    def from_crawler(cls, crawler: Crawler) -> UserAgentRotationMiddleware:
        user_agents = crawler.settings.getlist("REDTEAM_USER_AGENTS", _USER_AGENTS)
        rotate = crawler.settings.getbool("REDTEAM_ROTATE_UA", True)
        return cls(user_agents, rotate)

    def process_request(self, request: Request, spider: Spider) -> None:
        if self.rotate and self.user_agents:
            request.headers["User-Agent"] = random.choice(self.user_agents)


class RedTeamHeadersMiddleware:
    """Injects common headers to make requests appear as legitimate browser traffic.

    Settings:
        REDTEAM_EXTRA_HEADERS: dict of extra headers to inject
        REDTEAM_SPOOF_REFERRER: bool - add a plausible Referer header
    """

    _DEFAULT_HEADERS = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
    }

    def __init__(self, extra_headers: dict, spoof_referrer: bool):
        self.extra_headers = extra_headers
        self.spoof_referrer = spoof_referrer

    @classmethod
    def from_crawler(cls, crawler: Crawler) -> RedTeamHeadersMiddleware:
        extra = crawler.settings.getdict("REDTEAM_EXTRA_HEADERS", {})
        spoof = crawler.settings.getbool("REDTEAM_SPOOF_REFERRER", False)
        return cls(extra, spoof)

    def process_request(self, request: Request, spider: Spider) -> None:
        for header, value in self._DEFAULT_HEADERS.items():
            if header not in request.headers:
                request.headers[header] = value
        for header, value in self.extra_headers.items():
            request.headers[header] = value


class AdaptiveRateLimitMiddleware:
    """Slows down crawl rate when the server responds with rate-limit indicators.

    Watches for 429 Too Many Requests and 503 Service Unavailable and
    dynamically backs off, then resumes.

    Settings:
        REDTEAM_RATE_LIMIT_BACKOFF: seconds to wait on rate limit (default 30)
        REDTEAM_RATE_LIMIT_CODES: HTTP status codes to treat as rate limits
    """

    def __init__(self, backoff: float, codes: list[int]):
        self.backoff = backoff
        self.codes = codes
        self._throttled_until: float = 0.0

    @classmethod
    def from_crawler(cls, crawler: Crawler) -> AdaptiveRateLimitMiddleware:
        backoff = crawler.settings.getfloat("REDTEAM_RATE_LIMIT_BACKOFF", 30.0)
        codes = crawler.settings.getlist("REDTEAM_RATE_LIMIT_CODES", [429, 503])
        return cls(backoff, [int(c) for c in codes])

    def process_request(self, request: Request, spider: Spider) -> None:
        remaining = self._throttled_until - time.monotonic()
        if remaining > 0:
            logger.debug("Rate limit backoff: sleeping %.1fs", remaining)
            time.sleep(remaining)

    def process_response(
        self, request: Request, response: Response, spider: Spider
    ) -> Response:
        if response.status in self.codes:
            retry_after = response.headers.get("Retry-After", b"").decode("utf-8", errors="ignore")
            try:
                wait = float(retry_after)
            except (ValueError, TypeError):
                wait = self.backoff
            logger.warning(
                "Rate limited (HTTP %d) on %s - backing off %.0fs",
                response.status,
                request.url,
                wait,
            )
            self._throttled_until = time.monotonic() + wait
        return response
