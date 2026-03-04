"""
Red Team Default Settings
=========================
Default Scrapy settings for red team crawling operations.
Import or merge these into your project's settings.py.

Usage in a Scrapy project settings.py:
    from scrapy.redteam.settings import REDTEAM_SETTINGS
    locals().update(REDTEAM_SETTINGS)

Or run directly with environment override:
    scrapy runspider redteam_spider.py -s REDTEAM_TARGET=https://target.example.com
"""

from __future__ import annotations

# ──────────────────────────────────────────────────────────────────────────────
# Core Scrapy settings tuned for red team recon
# ──────────────────────────────────────────────────────────────────────────────
REDTEAM_SETTINGS: dict = {
    # Concurrency - keep low to avoid detection / overloading target
    "CONCURRENT_REQUESTS": 8,
    "CONCURRENT_REQUESTS_PER_DOMAIN": 4,
    "DOWNLOAD_DELAY": 0.5,          # seconds between requests per domain
    "RANDOMIZE_DOWNLOAD_DELAY": True,

    # Crawl depth control
    "DEPTH_LIMIT": 5,
    "DEPTH_PRIORITY": 1,            # BFS order (shallower pages first)

    # Do NOT honor robots.txt (red team recon)
    "ROBOTSTXT_OBEY": False,

    # Follow redirects
    "REDIRECT_MAX_TIMES": 5,

    # Cookies
    "COOKIES_ENABLED": True,
    "COOKIES_DEBUG": False,

    # Logging
    "LOG_LEVEL": "INFO",

    # Output encoding
    "FEED_EXPORT_ENCODING": "utf-8",

    # Middlewares
    "DOWNLOADER_MIDDLEWARES": {
        # Disable built-in UA middleware
        "scrapy.downloadermiddlewares.useragent.UserAgentMiddleware": None,
        # Enable red team middlewares
        "scrapy.redteam.middlewares.UserAgentRotationMiddleware": 400,
        "scrapy.redteam.middlewares.RedTeamHeadersMiddleware": 410,
        "scrapy.redteam.middlewares.AdaptiveRateLimitMiddleware": 420,
        # Keep retry and redirect
        "scrapy.downloadermiddlewares.retry.RetryMiddleware": 550,
        "scrapy.downloadermiddlewares.redirect.RedirectMiddleware": 600,
        "scrapy.downloadermiddlewares.httpcompression.HttpCompressionMiddleware": 810,
    },

    # Item pipelines
    "ITEM_PIPELINES": {
        "scrapy.redteam.pipelines.DeduplicationPipeline": 100,
        "scrapy.redteam.pipelines.SeverityFilterPipeline": 200,
        "scrapy.redteam.pipelines.FindingsSummaryPipeline": 800,
        "scrapy.redteam.pipelines.JsonLinesExportPipeline": 900,
    },

    # ──────────────────────────────────────────────────────────────────────
    # Red team specific settings
    # ──────────────────────────────────────────────────────────────────────

    # User agent rotation
    "REDTEAM_ROTATE_UA": True,

    # Minimum severity to keep (critical/high/medium/low)
    "REDTEAM_MIN_SEVERITY": "low",

    # Whether to probe sensitive paths (/.git, /.env, etc.)
    "REDTEAM_PROBE_PATHS": True,

    # Max sensitive paths to probe (set 0 for unlimited)
    "REDTEAM_MAX_PROBE_PATHS": 0,

    # Whether to analyse security headers
    "REDTEAM_ANALYSE_HEADERS": True,

    # Whether to analyse cookies
    "REDTEAM_ANALYSE_COOKIES": True,

    # Whether to extract and analyse HTML comments
    "REDTEAM_EXTRACT_COMMENTS": True,

    # Whether to detect technologies
    "REDTEAM_DETECT_TECHNOLOGIES": True,

    # Whether to extract forms and analyse them
    "REDTEAM_EXTRACT_FORMS": True,

    # Whether to search for sensitive data patterns in responses
    "REDTEAM_SCAN_SENSITIVE_DATA": True,

    # Max length of response body to scan for sensitive data (chars)
    "REDTEAM_SCAN_MAX_BODY_LENGTH": 1_000_000,

    # Output directory for findings
    "REDTEAM_OUTPUT_DIR": "redteam_output",

    # Rate limit backoff in seconds when 429/503 received
    "REDTEAM_RATE_LIMIT_BACKOFF": 30.0,

    # Retry on these additional codes
    "RETRY_HTTP_CODES": [500, 502, 503, 504, 408, 429],
    "RETRY_TIMES": 3,

    # Store responses for failed requests
    "HTTPERROR_ALLOW_ALL": True,    # Pass all HTTP codes to spider for analysis
}
