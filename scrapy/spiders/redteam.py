"""
RedTeamSpider - Hybrid Webcrawler / Scraper
============================================
A Scrapy spider for authorized red team reconnaissance that combines:

  * Web crawling  – follows links across the target domain (like CrawlSpider)
  * Web scraping  – extracts security-relevant data from every page

Findings emitted (see scrapy.redteam.items):
  - EndpointItem        discovered URLs / API endpoints
  - FormItem            HTML forms with input fields
  - SensitiveDataItem   credentials, keys, PII, connection strings …
  - SecurityHeaderItem  missing / misconfigured security headers
  - CookieItem          cookies lacking Secure / HttpOnly / SameSite flags
  - TechnologyItem      CMS, framework, server, library detections
  - ExposedFileItem     sensitive paths that return non-404 responses
  - CommentItem         interesting HTML/JS comments
  - ErrorPageItem       401 / 403 / 500 responses with info leakage

Usage:
    # Simplest – run in-place:
    scrapy runspider scrapy/spiders/redteam.py -a url=https://target.example.com

    # With scope restriction:
    scrapy runspider scrapy/spiders/redteam.py \
        -a url=https://target.example.com \
        -a allowed_domains=target.example.com,api.target.example.com \
        -a depth=3

    # From a Scrapy project (after adding to SPIDER_MODULES):
    scrapy crawl redteam -a url=https://target.example.com

    # Adjust output:
    scrapy runspider scrapy/spiders/redteam.py \
        -a url=https://target.example.com \
        -s REDTEAM_OUTPUT_FILE=findings.jsonl \
        -s LOG_LEVEL=DEBUG

IMPORTANT: Only use against systems you own or have explicit written
           authorization to test. Unauthorised use may be illegal.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlparse

from scrapy import Spider, signals
from scrapy.http import Request, Response
from scrapy.linkextractors import LinkExtractor

from scrapy.redteam.items import (
    CommentItem,
    CookieItem,
    EndpointItem,
    ErrorPageItem,
    ExposedFileItem,
    FormItem,
    SecurityHeaderItem,
    SensitiveDataItem,
    TechnologyItem,
)
from scrapy.redteam.patterns import (
    INSECURE_HEADER_PATTERNS,
    INTERESTING_COMMENT_PATTERNS,
    SECURITY_HEADERS_REQUIRED,
    SENSITIVE_PATHS,
    SENSITIVE_PATTERNS,
    TECH_FINGERPRINTS,
)
from scrapy.redteam.settings import REDTEAM_SETTINGS

if TYPE_CHECKING:
    from collections.abc import Generator, Iterator

logger = logging.getLogger(__name__)

# HTML comment pattern
_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
# JS single-line comment
_JS_COMMENT_SINGLE_RE = re.compile(r"//(.+)$", re.MULTILINE)
# JS block comment
_JS_COMMENT_BLOCK_RE = re.compile(r"/\*(.*?)\*/", re.DOTALL)
# Script tag src
_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
# Link / href
_LINK_HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.I)
# Endpoint-like strings in JS files
_JS_ENDPOINT_RE = re.compile(
    r"""(?:["'`])(/(?:api|v\d+|graphql|rest|endpoint|service)[/\w\-\.?=&]*)["'`]""",
    re.I,
)


class RedTeamSpider(Spider):
    """Hybrid webcrawler + scraper for authorized red team reconnaissance.

    Spider arguments (``-a key=value``):
        url             Target URL to start crawling (required).
        allowed_domains Comma-separated list of domains to stay within.
                        Defaults to the domain of *url*.
        depth           Maximum crawl depth (overrides DEPTH_LIMIT).
        probe_paths     "true"/"false" – probe sensitive paths (default: true).
        scan_data       "true"/"false" – scan for sensitive data (default: true).
        output_file     Path for JSONL output (overrides REDTEAM_OUTPUT_FILE).
    """

    name = "redteam"
    custom_settings = REDTEAM_SETTINGS

    # ──────────────────────────────────────────────────────────────────────────
    # Initialisation
    # ──────────────────────────────────────────────────────────────────────────

    def __init__(
        self,
        url: str = "",
        allowed_domains: str = "",
        depth: str = "",
        probe_paths: str = "true",
        scan_data: str = "true",
        output_file: str = "",
        **kwargs: Any,
    ):
        super().__init__(**kwargs)
        if not url:
            raise ValueError("Spider argument 'url' is required. Use -a url=https://target.example.com")

        self.start_url = url.rstrip("/")
        parsed = urlparse(self.start_url)
        self._target_host = parsed.netloc

        # Allowed domains
        if allowed_domains:
            self.allowed_domains: list[str] = [d.strip() for d in allowed_domains.split(",")]
        else:
            self.allowed_domains = [parsed.netloc]

        # Per-instance setting overrides
        self._probe_paths = probe_paths.lower() not in ("false", "0", "no")
        self._scan_data = scan_data.lower() not in ("false", "0", "no")
        if depth:
            self.custom_settings = {**REDTEAM_SETTINGS, "DEPTH_LIMIT": int(depth)}
        if output_file:
            self.custom_settings = {**self.custom_settings, "REDTEAM_OUTPUT_FILE": output_file}

        # Link extractor – stay within allowed domains, follow all extensions
        self._link_extractor = LinkExtractor(
            allow_domains=self.allowed_domains,
            deny_extensions=[],  # crawl ALL extensions (js, pdf, xml, …)
            unique=True,
        )

        # Track probed paths per host to avoid duplicates
        self._probed_paths: set[str] = set()

    # ──────────────────────────────────────────────────────────────────────────
    # Entry points
    # ──────────────────────────────────────────────────────────────────────────

    def start_requests(self) -> Iterator[Request]:
        logger.info("RedTeamSpider starting on: %s", self.start_url)
        logger.info("Allowed domains: %s", self.allowed_domains)
        yield Request(self.start_url, callback=self.parse, errback=self._errback)

    def parse(self, response: Response) -> Generator:
        """Primary callback – analyse response and schedule further crawling."""
        yield from self._analyse_response(response)
        yield from self._crawl_links(response)
        if self._probe_paths:
            yield from self._schedule_path_probes(response)

    # ──────────────────────────────────────────────────────────────────────────
    # Core analysis dispatcher
    # ──────────────────────────────────────────────────────────────────────────

    def _analyse_response(self, response: Response) -> Generator:
        """Run all scraping analysis modules on a response."""
        # Always record the endpoint
        yield self._make_endpoint_item(response)

        # Security headers (every response)
        settings = self.crawler.settings
        if settings.getbool("REDTEAM_ANALYSE_HEADERS", True):
            header_item = self._analyse_security_headers(response)
            if header_item:
                yield header_item

        # Cookies
        if settings.getbool("REDTEAM_ANALYSE_COOKIES", True):
            yield from self._analyse_cookies(response)

        # Technology detection
        if settings.getbool("REDTEAM_DETECT_TECHNOLOGIES", True):
            yield from self._detect_technologies(response)

        # Error pages
        if response.status in (400, 401, 403, 404, 500, 502, 503):
            yield from self._analyse_error_page(response)

        # HTML-specific analysis
        content_type = response.headers.get("Content-Type", b"").decode("utf-8", errors="ignore").lower()
        if "html" in content_type:
            if settings.getbool("REDTEAM_EXTRACT_FORMS", True):
                yield from self._extract_forms(response)
            if settings.getbool("REDTEAM_EXTRACT_COMMENTS", True):
                yield from self._extract_html_comments(response)
            if self._scan_data and settings.getbool("REDTEAM_SCAN_SENSITIVE_DATA", True):
                yield from self._scan_for_sensitive_data(response, source="html_body")

        # JavaScript files
        if "javascript" in content_type or response.url.endswith(".js"):
            if settings.getbool("REDTEAM_EXTRACT_COMMENTS", True):
                yield from self._extract_js_comments(response)
            if self._scan_data and settings.getbool("REDTEAM_SCAN_SENSITIVE_DATA", True):
                yield from self._scan_for_sensitive_data(response, source="js_file")
            yield from self._extract_js_endpoints(response)

        # Scan response headers for sensitive data
        if self._scan_data and settings.getbool("REDTEAM_SCAN_SENSITIVE_DATA", True):
            yield from self._scan_headers_for_sensitive_data(response)

    # ──────────────────────────────────────────────────────────────────────────
    # Crawling – link following
    # ──────────────────────────────────────────────────────────────────────────

    def _crawl_links(self, response: Response) -> Generator[Request, None, None]:
        """Extract and follow all in-scope links."""
        for link in self._link_extractor.extract_links(response):
            yield response.follow(
                link,
                callback=self.parse,
                errback=self._errback,
            )

    def _schedule_path_probes(self, response: Response) -> Generator[Request, None, None]:
        """Schedule requests to common sensitive paths on the target host."""
        parsed = urlparse(response.url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        settings = self.crawler.settings
        max_probes = settings.getint("REDTEAM_MAX_PROBE_PATHS", 0)

        probed = 0
        for path, file_type, severity, description in SENSITIVE_PATHS:
            if max_probes and probed >= max_probes:
                break
            probe_key = f"{base}{path}"
            if probe_key in self._probed_paths:
                continue
            self._probed_paths.add(probe_key)
            probed += 1
            yield Request(
                urljoin(base, path),
                callback=self._parse_probe,
                errback=self._errback,
                meta={
                    "probe_path": path,
                    "probe_file_type": file_type,
                    "probe_severity": severity,
                    "probe_description": description,
                    "dont_redirect": False,
                },
                priority=10,  # Probe requests get higher priority
            )

    # ──────────────────────────────────────────────────────────────────────────
    # Probe callback
    # ──────────────────────────────────────────────────────────────────────────

    def _parse_probe(self, response: Response) -> Generator:
        """Handle response to a sensitive path probe."""
        path = response.meta["probe_path"]
        file_type = response.meta["probe_file_type"]
        severity = response.meta["probe_severity"]
        description = response.meta["probe_description"]

        # Anything not 404/410 is potentially interesting
        if response.status not in (404, 410):
            content_length = int(response.headers.get("Content-Length", 0) or 0)
            yield ExposedFileItem(
                url=response.url,
                path=path,
                status_code=response.status,
                content_length=content_length,
                file_type=file_type,
                severity=severity,
                description=description,
            )
            # Also run full analysis on found sensitive files
            yield from self._analyse_response(response)

    # ──────────────────────────────────────────────────────────────────────────
    # Analysis modules
    # ──────────────────────────────────────────────────────────────────────────

    def _make_endpoint_item(self, response: Response) -> EndpointItem:
        content_type = response.headers.get("Content-Type", b"").decode("utf-8", errors="ignore").split(";")[0].strip()
        parsed = urlparse(response.url)
        query_params = [p.split("=")[0] for p in parsed.query.split("&") if "=" in p] if parsed.query else []

        endpoint_type = "page"
        if "/api/" in response.url or "/v1/" in response.url or "/v2/" in response.url:
            endpoint_type = "api"
        elif response.url.endswith(".js"):
            endpoint_type = "js"
        elif any(response.url.endswith(ext) for ext in (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".zip", ".tar", ".gz")):
            endpoint_type = "file"

        return EndpointItem(
            url=response.url,
            method="GET",
            status_code=response.status,
            content_type=content_type,
            source_url=response.request.headers.get("Referer", b"").decode("utf-8", errors="ignore"),
            endpoint_type=endpoint_type,
            parameters=query_params,
            technologies=[],
        )

    def _analyse_security_headers(self, response: Response) -> SecurityHeaderItem | None:
        headers = {k.decode("utf-8", errors="ignore"): v.decode("utf-8", errors="ignore")
                   for k, v in response.headers.items()}
        headers_lower = {k.lower(): v for k, v in headers.items()}

        missing = [h for h in SECURITY_HEADERS_REQUIRED if h.lower() not in headers_lower]
        insecure = []
        for header, pattern, issue in INSECURE_HEADER_PATTERNS:
            value = headers_lower.get(header.lower(), "")
            if value and pattern.search(value):
                insecure.append({"header": header, "value": value, "issue": issue})

        # CORS analysis
        cors_origin = headers_lower.get("access-control-allow-origin", "")
        cors_credentials = headers_lower.get("access-control-allow-credentials", "")
        cors_policy: dict[str, str] = {}
        if cors_origin:
            cors_policy["allow_origin"] = cors_origin
            cors_policy["allow_credentials"] = cors_credentials
            if cors_origin == "*" and cors_credentials.lower() == "true":
                insecure.append({
                    "header": "CORS",
                    "value": f"Origin=*, Credentials=true",
                    "issue": "Wildcard CORS with credentials is rejected by browsers but indicates misconfiguration",
                })

        # Score: start at 100, deduct for missing/insecure
        score = 100 - (len(missing) * 10) - (len(insecure) * 15)
        score = max(0, score)

        return SecurityHeaderItem(
            url=response.url,
            present={k: v for k, v in headers.items() if k.lower() in [h.lower() for h in SECURITY_HEADERS_REQUIRED]},
            missing=missing,
            insecure=insecure,
            score=score,
            server_banner=headers_lower.get("server", ""),
            cors_policy=cors_policy,
        )

    def _analyse_cookies(self, response: Response) -> Generator[CookieItem, None, None]:
        for cookie_header in response.headers.getlist("Set-Cookie"):
            raw = cookie_header.decode("utf-8", errors="ignore")
            parts = [p.strip() for p in raw.split(";")]
            if not parts:
                continue

            # First part is name=value
            name_val = parts[0].split("=", 1)
            name = name_val[0].strip()
            value = name_val[1].strip() if len(name_val) > 1 else ""

            attrs = {p.split("=")[0].strip().lower(): (p.split("=", 1)[1].strip() if "=" in p else "true")
                     for p in parts[1:]}

            secure = "secure" in attrs
            httponly = "httponly" in attrs
            samesite = attrs.get("samesite", "")
            domain = attrs.get("domain", "")
            path = attrs.get("path", "/")

            issues = []
            if not secure:
                issues.append("Missing Secure flag – cookie transmitted over HTTP")
            if not httponly:
                issues.append("Missing HttpOnly flag – accessible via JavaScript (XSS risk)")
            if not samesite:
                issues.append("Missing SameSite attribute – CSRF risk")
            elif samesite.lower() == "none" and not secure:
                issues.append("SameSite=None without Secure flag is invalid")

            is_session = any(k in name.lower() for k in ("session", "sess", "auth", "token", "sid"))

            if issues or is_session:
                yield CookieItem(
                    url=response.url,
                    name=name,
                    value_preview=value[:20] if value else "",
                    secure=secure,
                    httponly=httponly,
                    samesite=samesite,
                    domain=domain,
                    path=path,
                    is_session_cookie=is_session,
                    issues=issues,
                )

    def _detect_technologies(self, response: Response) -> Generator[TechnologyItem, None, None]:
        headers_str = "\n".join(
            f"{k.decode('utf-8', errors='ignore')}: {v.decode('utf-8', errors='ignore')}"
            for k, v in response.headers.items()
        )
        body = response.text if hasattr(response, "text") else ""
        cookies_str = "; ".join(
            h.decode("utf-8", errors="ignore") for h in response.headers.getlist("Set-Cookie")
        )

        for fp in TECH_FINGERPRINTS:
            matched = False
            evidence_parts = []

            for source, pattern in fp.get("patterns", {}).items():
                if not pattern.pattern:  # empty pattern
                    continue
                if source == "header" and pattern.search(headers_str):
                    matched = True
                    evidence_parts.append(f"header match")
                elif source == "html" and pattern.search(body):
                    matched = True
                    evidence_parts.append(f"html match: {pattern.pattern[:40]}")
                elif source == "js" and pattern.search(body):
                    matched = True
                    evidence_parts.append(f"js match")
                elif source == "cookie" and pattern.search(cookies_str):
                    matched = True
                    evidence_parts.append(f"cookie match")

            if matched:
                version = ""
                if fp.get("version_pattern"):
                    m = fp["version_pattern"].search(headers_str + "\n" + body)
                    if m:
                        version = m.group(1) if m.lastindex else m.group(0)

                yield TechnologyItem(
                    url=response.url,
                    name=fp["name"],
                    version=version,
                    category=fp["category"],
                    evidence="; ".join(evidence_parts),
                    cpe="",
                )

    def _extract_forms(self, response: Response) -> Generator[FormItem, None, None]:
        for form in response.css("form"):
            action = form.attrib.get("action", "")
            action_url = urljoin(response.url, action) if action else response.url
            method = form.attrib.get("method", "GET").upper()

            inputs = []
            for inp in form.css("input, textarea, select"):
                input_info = {
                    "name": inp.attrib.get("name", ""),
                    "type": inp.attrib.get("type", "text"),
                    "value": inp.attrib.get("value", "")[:50],  # truncate
                    "placeholder": inp.attrib.get("placeholder", ""),
                }
                inputs.append(input_info)

            input_types = [i["type"].lower() for i in inputs]
            input_names = [i["name"].lower() for i in inputs]
            has_csrf = any(
                "csrf" in n or "token" in n or "_token" in n for n in input_names
            )
            is_login = any(t == "password" for t in input_types) or any(
                k in n for n in input_names for k in ("user", "login", "email", "pass")
            )
            is_search = any(k in n for n in input_names for k in ("search", "query", "q"))
            is_upload = "file" in input_types

            yield FormItem(
                url=response.url,
                action=action_url,
                method=method,
                inputs=inputs,
                has_csrf_token=has_csrf,
                is_login_form=is_login,
                is_search_form=is_search,
                is_upload_form=is_upload,
            )

    def _extract_html_comments(self, response: Response) -> Generator[CommentItem, None, None]:
        body = response.text if hasattr(response, "text") else ""
        for match in _HTML_COMMENT_RE.finditer(body):
            comment = match.group(1).strip()
            if not comment or len(comment) < 5:
                continue
            interesting_reasons = []
            for reason, pattern in INTERESTING_COMMENT_PATTERNS:
                if pattern.search(comment):
                    interesting_reasons.append(reason)
            if interesting_reasons:
                yield CommentItem(
                    url=response.url,
                    comment=comment[:500],
                    source="html",
                    interesting=interesting_reasons,
                )

    def _extract_js_comments(self, response: Response) -> Generator[CommentItem, None, None]:
        body = response.text if hasattr(response, "text") else ""
        comments = []
        for m in _JS_COMMENT_SINGLE_RE.finditer(body):
            comments.append(m.group(1).strip())
        for m in _JS_COMMENT_BLOCK_RE.finditer(body):
            comments.append(m.group(1).strip())

        for comment in comments:
            if not comment or len(comment) < 5:
                continue
            interesting_reasons = []
            for reason, pattern in INTERESTING_COMMENT_PATTERNS:
                if pattern.search(comment):
                    interesting_reasons.append(reason)
            if interesting_reasons:
                yield CommentItem(
                    url=response.url,
                    comment=comment[:500],
                    source="js",
                    interesting=interesting_reasons,
                )

    def _extract_js_endpoints(self, response: Response) -> Generator[EndpointItem, None, None]:
        """Extract API endpoint strings from JavaScript files."""
        body = response.text if hasattr(response, "text") else ""
        seen: set[str] = set()
        for match in _JS_ENDPOINT_RE.finditer(body):
            endpoint = match.group(1)
            if endpoint in seen:
                continue
            seen.add(endpoint)
            full_url = urljoin(response.url, endpoint)
            yield EndpointItem(
                url=full_url,
                method="GET",
                status_code=0,  # Not yet requested
                content_type="",
                source_url=response.url,
                endpoint_type="api",
                parameters=[],
                technologies=[],
            )

    def _scan_for_sensitive_data(
        self, response: Response, source: str
    ) -> Generator[SensitiveDataItem, None, None]:
        settings = self.crawler.settings
        max_len = settings.getint("REDTEAM_SCAN_MAX_BODY_LENGTH", 1_000_000)
        body = response.text[:max_len] if hasattr(response, "text") else ""

        for name, pattern, confidence, should_redact in SENSITIVE_PATTERNS:
            for match in pattern.finditer(body):
                matched_text = match.group(0)
                # Get surrounding context (±60 chars)
                start = max(0, match.start() - 60)
                end = min(len(body), match.end() + 60)
                context = body[start:end].replace("\n", " ").replace("\r", "")

                if should_redact:
                    display = matched_text[:4] + "*" * (len(matched_text) - 4) if len(matched_text) > 4 else "****"
                else:
                    display = matched_text

                yield SensitiveDataItem(
                    url=response.url,
                    pattern_name=name,
                    match=display,
                    context=context[:200],
                    source=source,
                    confidence=confidence,
                    redacted=should_redact,
                )

    def _scan_headers_for_sensitive_data(
        self, response: Response
    ) -> Generator[SensitiveDataItem, None, None]:
        headers_text = "\n".join(
            f"{k.decode('utf-8', errors='ignore')}: {v.decode('utf-8', errors='ignore')}"
            for k, v in response.headers.items()
        )
        for name, pattern, confidence, should_redact in SENSITIVE_PATTERNS:
            m = pattern.search(headers_text)
            if m:
                matched_text = m.group(0)
                display = matched_text[:4] + "****" if should_redact and len(matched_text) > 4 else matched_text
                yield SensitiveDataItem(
                    url=response.url,
                    pattern_name=name,
                    match=display,
                    context=headers_text[:200],
                    source="header",
                    confidence=confidence,
                    redacted=should_redact,
                )

    def _analyse_error_page(self, response: Response) -> Generator[ErrorPageItem, None, None]:
        body = response.text if hasattr(response, "text") else ""
        body_lower = body.lower()

        error_types = {
            400: "bad_request",
            401: "auth_required",
            403: "forbidden",
            404: "not_found",
            500: "server_error",
            502: "bad_gateway",
            503: "service_unavailable",
        }
        error_type = error_types.get(response.status, f"http_{response.status}")

        # Check for stack traces / debug info leakage
        stack_indicators = [
            "stack trace", "traceback", "at line", "exception in", "caused by",
            "debug info", "symfony", "django debug", "whitelabel error",
        ]
        has_stack_trace = any(ind in body_lower for ind in stack_indicators)

        # Extract server/tech info leaked in error page
        server_info_indicators = []
        server_header = response.headers.get("Server", b"").decode("utf-8", errors="ignore")
        if server_header:
            server_info_indicators.append(f"Server: {server_header}")
        powered_by = response.headers.get("X-Powered-By", b"").decode("utf-8", errors="ignore")
        if powered_by:
            server_info_indicators.append(f"X-Powered-By: {powered_by}")

        if response.status in (401, 403, 500) or has_stack_trace:
            yield ErrorPageItem(
                url=response.url,
                status_code=response.status,
                error_type=error_type,
                server_info=server_info_indicators,
                stack_trace=has_stack_trace,
                source_url=response.request.headers.get("Referer", b"").decode("utf-8", errors="ignore"),
            )

    # ──────────────────────────────────────────────────────────────────────────
    # Error handler
    # ──────────────────────────────────────────────────────────────────────────

    def _errback(self, failure: Any) -> None:
        request = failure.request
        logger.debug("Request failed: %s – %s", request.url, failure.getErrorMessage())
