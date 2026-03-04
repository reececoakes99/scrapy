"""
Red Team Finding Items
======================
Structured data classes for storing security findings discovered during crawling.
"""

from __future__ import annotations

import scrapy


class EndpointItem(scrapy.Item):
    """A discovered URL/endpoint."""

    url = scrapy.Field()
    method = scrapy.Field()          # GET, POST, etc.
    status_code = scrapy.Field()
    content_type = scrapy.Field()
    source_url = scrapy.Field()      # Where we found the link
    endpoint_type = scrapy.Field()   # page, api, file, form_action, js, etc.
    parameters = scrapy.Field()      # Query params discovered
    technologies = scrapy.Field()    # Detected tech stack


class FormItem(scrapy.Item):
    """A discovered HTML form."""

    url = scrapy.Field()             # Page containing the form
    action = scrapy.Field()          # Form action URL
    method = scrapy.Field()          # GET or POST
    inputs = scrapy.Field()          # List of {name, type, value} dicts
    has_csrf_token = scrapy.Field()
    is_login_form = scrapy.Field()
    is_search_form = scrapy.Field()
    is_upload_form = scrapy.Field()


class SensitiveDataItem(scrapy.Item):
    """A potential sensitive data finding."""

    url = scrapy.Field()
    pattern_name = scrapy.Field()    # e.g. "aws_access_key", "email", "jwt_token"
    match = scrapy.Field()           # The matched string (redacted if needed)
    context = scrapy.Field()         # Surrounding text snippet
    source = scrapy.Field()          # "html_body", "js_file", "html_comment", "header"
    confidence = scrapy.Field()      # high / medium / low
    redacted = scrapy.Field()        # Whether match was redacted


class SecurityHeaderItem(scrapy.Item):
    """HTTP security header analysis for a URL."""

    url = scrapy.Field()
    present = scrapy.Field()         # Dict of header -> value for present headers
    missing = scrapy.Field()         # List of missing recommended headers
    insecure = scrapy.Field()        # List of {header, value, issue} dicts
    score = scrapy.Field()           # Simple 0-100 security score
    server_banner = scrapy.Field()   # Server header value (version disclosure)
    cors_policy = scrapy.Field()     # CORS configuration details


class CookieItem(scrapy.Item):
    """Cookie security analysis."""

    url = scrapy.Field()
    name = scrapy.Field()
    value_preview = scrapy.Field()   # First 20 chars only
    secure = scrapy.Field()
    httponly = scrapy.Field()
    samesite = scrapy.Field()
    domain = scrapy.Field()
    path = scrapy.Field()
    is_session_cookie = scrapy.Field()
    issues = scrapy.Field()          # List of security issues


class TechnologyItem(scrapy.Item):
    """Detected technology/software."""

    url = scrapy.Field()
    name = scrapy.Field()            # e.g. "WordPress", "jQuery", "nginx"
    version = scrapy.Field()         # Version if detected
    category = scrapy.Field()        # cms, framework, server, library, etc.
    evidence = scrapy.Field()        # What triggered detection
    cpe = scrapy.Field()             # CPE identifier if known


class ExposedFileItem(scrapy.Item):
    """A sensitive/exposed file or path discovered."""

    url = scrapy.Field()
    path = scrapy.Field()
    status_code = scrapy.Field()
    content_length = scrapy.Field()
    file_type = scrapy.Field()       # config, backup, git, env, etc.
    severity = scrapy.Field()        # critical / high / medium / low
    description = scrapy.Field()


class CommentItem(scrapy.Item):
    """Interesting HTML/JS comment."""

    url = scrapy.Field()
    comment = scrapy.Field()
    source = scrapy.Field()          # "html" or "js"
    interesting = scrapy.Field()     # Reason it was flagged (has IP, path, cred hint, etc.)


class ErrorPageItem(scrapy.Item):
    """Error page or unexpected response."""

    url = scrapy.Field()
    status_code = scrapy.Field()
    error_type = scrapy.Field()      # "auth_required", "forbidden", "server_error", etc.
    server_info = scrapy.Field()     # Tech info leaked in error page
    stack_trace = scrapy.Field()     # Whether a stack trace was found
    source_url = scrapy.Field()
