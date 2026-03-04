"""
Red Team Detection Patterns
============================
Regex patterns for identifying sensitive data, technologies, and security issues
in crawled web content.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Sensitive Data Patterns
# Each entry: (name, compiled_regex, confidence, should_redact)
# ---------------------------------------------------------------------------

SENSITIVE_PATTERNS: list[tuple[str, re.Pattern, str, bool]] = [
    # Cloud credentials
    (
        "aws_access_key",
        re.compile(r"(?<![A-Z0-9])(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])", re.I),
        "high",
        True,
    ),
    (
        "aws_secret_key",
        re.compile(
            r"(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key[_\-\s]*[=:][_\-\s]*([A-Za-z0-9+/]{40})"
        ),
        "high",
        True,
    ),
    (
        "gcp_service_account",
        re.compile(r'"type"\s*:\s*"service_account"'),
        "high",
        False,
    ),
    (
        "azure_connection_string",
        re.compile(
            r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+",
            re.I,
        ),
        "high",
        True,
    ),
    # Tokens and keys
    (
        "jwt_token",
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "high",
        True,
    ),
    (
        "generic_api_key",
        re.compile(
            r"(?i)(?:api[_\-]?key|apikey|api[_\-]?secret|access[_\-]?token|auth[_\-]?token)"
            r"[_\-\s]*[=:][_\-\s]*['\"]?([A-Za-z0-9_\-]{20,})['\"]?",
        ),
        "medium",
        True,
    ),
    (
        "bearer_token",
        re.compile(r"(?i)Bearer\s+([A-Za-z0-9_\-\.=]+)"),
        "high",
        True,
    ),
    (
        "github_token",
        re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"),
        "high",
        True,
    ),
    (
        "private_key_header",
        re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"),
        "critical",
        False,
    ),
    # Passwords
    (
        "password_in_url",
        re.compile(r"(?i)[?&;](?:pass(?:word)?|pwd|passwd)[=:]([^&\s\"']{4,})"),
        "high",
        True,
    ),
    (
        "password_in_code",
        re.compile(
            r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{4,})['\"]"
        ),
        "medium",
        True,
    ),
    # Network and infrastructure
    (
        "internal_ip",
        re.compile(
            r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3})\b"
        ),
        "medium",
        False,
    ),
    (
        "ipv4_address",
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
        "low",
        False,
    ),
    # PII
    (
        "email_address",
        re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
        "low",
        False,
    ),
    (
        "phone_number",
        re.compile(
            r"(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)"
        ),
        "low",
        False,
    ),
    # Database connection strings
    (
        "db_connection_string",
        re.compile(
            r"(?i)(?:mysql|postgres(?:ql)?|mongodb|redis|mssql|oracle)"
            r"://[^\s\"'<>]+",
        ),
        "high",
        True,
    ),
    (
        "sql_connection_string",
        re.compile(
            r"(?i)(?:Server|Data Source|Initial Catalog|User Id|Password)\s*="
            r"[^;\"']{3,}",
        ),
        "high",
        True,
    ),
    # Paths and debug info
    (
        "unix_path",
        re.compile(r"(?<!['\"])(/(?:home|etc|var|usr|opt|root|srv|proc)/[^\s\"'<>]{4,})"),
        "low",
        False,
    ),
    (
        "windows_path",
        re.compile(r"[Cc]:\\(?:Users|Windows|Program Files)[\\][^\s\"'<>]{4,}"),
        "low",
        False,
    ),
    # Crypto
    (
        "hex_secret",
        re.compile(r"(?i)(?:secret|key|token|hash|salt)\s*[=:]\s*['\"]?([0-9a-f]{32,})['\"]?"),
        "medium",
        True,
    ),
]

# ---------------------------------------------------------------------------
# Technology Fingerprints
# Each entry: (name, version_group, category, {source: pattern})
# sources: "header", "html", "js", "cookie"
# ---------------------------------------------------------------------------

TECH_FINGERPRINTS: list[dict] = [
    # CMS
    {
        "name": "WordPress",
        "category": "cms",
        "patterns": {
            "html": re.compile(r"/wp-content/|/wp-includes/|wp-json"),
            "header": re.compile(r""),
        },
        "version_pattern": re.compile(r'<meta name="generator" content="WordPress ([^"]+)"', re.I),
    },
    {
        "name": "Drupal",
        "category": "cms",
        "patterns": {
            "html": re.compile(r'(?:Drupal\.settings|drupal\.js|/sites/default/files/)'),
            "header": re.compile(r"X-Generator:\s*Drupal", re.I),
        },
        "version_pattern": re.compile(r'<meta name="generator" content="Drupal ([^"]+)"', re.I),
    },
    {
        "name": "Joomla",
        "category": "cms",
        "patterns": {
            "html": re.compile(r'/media/jui/|Joomla!|com_content'),
            "header": re.compile(r""),
        },
        "version_pattern": re.compile(r'<meta name="generator" content="Joomla! ([^"]+)"', re.I),
    },
    # Frameworks
    {
        "name": "Django",
        "category": "framework",
        "patterns": {
            "html": re.compile(r'csrfmiddlewaretoken|__django'),
            "header": re.compile(r""),
            "cookie": re.compile(r"csrftoken|sessionid"),
        },
        "version_pattern": None,
    },
    {
        "name": "Ruby on Rails",
        "category": "framework",
        "patterns": {
            "header": re.compile(r"X-Runtime:|X-Powered-By:\s*Phusion Passenger", re.I),
            "html": re.compile(r'rails\.js|authenticity_token'),
            "cookie": re.compile(r"_session_id|_rails"),
        },
        "version_pattern": None,
    },
    {
        "name": "Laravel",
        "category": "framework",
        "patterns": {
            "html": re.compile(r'laravel|_token.*CSRF'),
            "header": re.compile(r""),
            "cookie": re.compile(r"laravel_session|XSRF-TOKEN"),
        },
        "version_pattern": None,
    },
    {
        "name": "ASP.NET",
        "category": "framework",
        "patterns": {
            "header": re.compile(r"X-Powered-By:\s*ASP\.NET|X-AspNet-Version", re.I),
            "html": re.compile(r'__VIEWSTATE|__EVENTVALIDATION|WebForm'),
            "cookie": re.compile(r"ASP\.NET_SessionId|\.ASPXAUTH", re.I),
        },
        "version_pattern": re.compile(r"X-AspNet-Version:\s*([^\r\n]+)", re.I),
    },
    {
        "name": "Spring Boot",
        "category": "framework",
        "patterns": {
            "header": re.compile(r""),
            "html": re.compile(r'Whitelabel Error Page|Spring Boot'),
        },
        "version_pattern": None,
    },
    # Servers
    {
        "name": "nginx",
        "category": "server",
        "patterns": {
            "header": re.compile(r"Server:\s*nginx", re.I),
        },
        "version_pattern": re.compile(r"Server:\s*nginx/([^\s\r\n]+)", re.I),
    },
    {
        "name": "Apache",
        "category": "server",
        "patterns": {
            "header": re.compile(r"Server:\s*Apache", re.I),
        },
        "version_pattern": re.compile(r"Server:\s*Apache/([^\s\r\n]+)", re.I),
    },
    {
        "name": "IIS",
        "category": "server",
        "patterns": {
            "header": re.compile(r"Server:\s*Microsoft-IIS", re.I),
        },
        "version_pattern": re.compile(r"Server:\s*Microsoft-IIS/([^\s\r\n]+)", re.I),
    },
    # JS Libraries
    {
        "name": "jQuery",
        "category": "library",
        "patterns": {
            "html": re.compile(r'jquery(?:\.min)?\.js'),
            "js": re.compile(r'jQuery v([0-9.]+)'),
        },
        "version_pattern": re.compile(r'jquery[.-]([0-9]+\.[0-9]+\.[0-9]+)', re.I),
    },
    {
        "name": "React",
        "category": "library",
        "patterns": {
            "html": re.compile(r'react(?:\.production\.min)?\.js|data-reactroot|__NEXT_DATA__'),
            "js": re.compile(r'React\.createElement'),
        },
        "version_pattern": None,
    },
    {
        "name": "Angular",
        "category": "library",
        "patterns": {
            "html": re.compile(r'ng-app|ng-version|angular(?:\.min)?\.js'),
        },
        "version_pattern": re.compile(r'ng-version="([^"]+)"'),
    },
    # WAF / CDN
    {
        "name": "Cloudflare",
        "category": "waf_cdn",
        "patterns": {
            "header": re.compile(r"CF-Ray:|Server:\s*cloudflare", re.I),
            "cookie": re.compile(r"__cflb|__cfuid|cf_clearance"),
        },
        "version_pattern": None,
    },
    {
        "name": "AWS WAF",
        "category": "waf_cdn",
        "patterns": {
            "header": re.compile(r"x-amz-|X-AMZ-RequestId", re.I),
        },
        "version_pattern": None,
    },
]

# ---------------------------------------------------------------------------
# Sensitive Path Probes
# Paths to probe for exposed sensitive files/endpoints
# Each entry: (path, file_type, severity, description)
# ---------------------------------------------------------------------------

SENSITIVE_PATHS: list[tuple[str, str, str, str]] = [
    # VCS
    ("/.git/HEAD", "git", "critical", "Git repository exposed"),
    ("/.git/config", "git", "critical", "Git config exposed"),
    ("/.svn/entries", "svn", "critical", "SVN repository exposed"),
    ("/.hg/hgrc", "hg", "critical", "Mercurial repository exposed"),
    # Env / Config
    ("/.env", "config", "critical", "Environment file exposed"),
    ("/.env.local", "config", "critical", "Local environment file exposed"),
    ("/.env.production", "config", "critical", "Production environment file exposed"),
    ("/.env.backup", "config", "critical", "Backup environment file exposed"),
    ("/config.php", "config", "high", "PHP config file exposed"),
    ("/config.yaml", "config", "high", "YAML config file exposed"),
    ("/config.yml", "config", "high", "YAML config file exposed"),
    ("/config.json", "config", "high", "JSON config file exposed"),
    ("/settings.py", "config", "high", "Django settings file exposed"),
    ("/wp-config.php.bak", "backup", "critical", "WordPress config backup exposed"),
    ("/database.yml", "config", "high", "Database config exposed"),
    ("/secrets.yml", "config", "critical", "Secrets file exposed"),
    # Backups
    ("/backup.zip", "backup", "high", "Backup archive exposed"),
    ("/backup.tar.gz", "backup", "high", "Backup archive exposed"),
    ("/backup.sql", "backup", "critical", "SQL backup exposed"),
    ("/dump.sql", "backup", "critical", "SQL dump exposed"),
    ("/db.sql", "backup", "critical", "Database dump exposed"),
    ("/backup.sql.gz", "backup", "critical", "Compressed SQL backup exposed"),
    # Admin / Dev interfaces
    ("/admin", "admin", "medium", "Admin interface"),
    ("/admin/", "admin", "medium", "Admin interface"),
    ("/administrator", "admin", "medium", "Admin interface"),
    ("/phpmyadmin", "admin", "high", "phpMyAdmin exposed"),
    ("/phpmyadmin/", "admin", "high", "phpMyAdmin exposed"),
    ("/pma/", "admin", "high", "phpMyAdmin exposed"),
    ("/wp-admin/", "admin", "medium", "WordPress admin"),
    ("/wp-login.php", "admin", "medium", "WordPress login"),
    ("/django-admin/", "admin", "medium", "Django admin"),
    ("/console", "admin", "high", "Debug console exposed"),
    ("/actuator", "admin", "high", "Spring Boot Actuator exposed"),
    ("/actuator/env", "admin", "critical", "Spring Boot Actuator env exposed"),
    ("/actuator/dump", "admin", "critical", "Spring Boot Actuator dump exposed"),
    ("/actuator/heapdump", "admin", "critical", "Spring Boot heap dump exposed"),
    # API
    ("/api", "api", "low", "API endpoint"),
    ("/api/v1", "api", "low", "API v1 endpoint"),
    ("/api/v2", "api", "low", "API v2 endpoint"),
    ("/swagger", "api", "medium", "Swagger UI exposed"),
    ("/swagger-ui.html", "api", "medium", "Swagger UI exposed"),
    ("/swagger/index.html", "api", "medium", "Swagger UI exposed"),
    ("/api-docs", "api", "medium", "API docs exposed"),
    ("/openapi.json", "api", "medium", "OpenAPI spec exposed"),
    ("/openapi.yaml", "api", "medium", "OpenAPI spec exposed"),
    ("/graphql", "api", "medium", "GraphQL endpoint"),
    ("/graphiql", "api", "medium", "GraphiQL interface exposed"),
    # Sensitive files
    ("/robots.txt", "recon", "low", "robots.txt (enumeration)"),
    ("/sitemap.xml", "recon", "low", "Sitemap (enumeration)"),
    ("/.htaccess", "config", "high", "Apache htaccess exposed"),
    ("/.htpasswd", "config", "critical", "Apache htpasswd exposed"),
    ("/web.config", "config", "high", "IIS web.config exposed"),
    ("/crossdomain.xml", "config", "medium", "Flash crossdomain policy"),
    ("/clientaccesspolicy.xml", "config", "medium", "Silverlight policy"),
    # Debug / Logs
    ("/error.log", "log", "high", "Error log exposed"),
    ("/access.log", "log", "high", "Access log exposed"),
    ("/debug.log", "log", "high", "Debug log exposed"),
    ("/phpinfo.php", "debug", "high", "PHP info page exposed"),
    ("/info.php", "debug", "high", "PHP info page exposed"),
    ("/test.php", "debug", "medium", "PHP test page exposed"),
    ("/server-status", "debug", "high", "Apache server-status exposed"),
    ("/server-info", "debug", "high", "Apache server-info exposed"),
    # Package/Build artifacts
    ("/package.json", "config", "medium", "NPM package manifest exposed"),
    ("/composer.json", "config", "medium", "Composer manifest exposed"),
    ("/Gemfile", "config", "medium", "Ruby Gemfile exposed"),
    ("/requirements.txt", "config", "low", "Python requirements exposed"),
    ("/Dockerfile", "config", "medium", "Dockerfile exposed"),
    ("/docker-compose.yml", "config", "high", "Docker compose config exposed"),
    ("/docker-compose.yaml", "config", "high", "Docker compose config exposed"),
    # SSH / Keys
    ("/.ssh/id_rsa", "key", "critical", "SSH private key exposed"),
    ("/.ssh/authorized_keys", "key", "critical", "SSH authorized keys exposed"),
    ("/id_rsa", "key", "critical", "SSH private key exposed"),
    ("/server.key", "key", "critical", "SSL/TLS private key exposed"),
]

# ---------------------------------------------------------------------------
# Security Header Checks
# ---------------------------------------------------------------------------

SECURITY_HEADERS_REQUIRED = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

SECURITY_HEADERS_DEPRECATED = [
    "X-XSS-Protection",  # Deprecated and can introduce vulnerabilities
]

INSECURE_HEADER_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    (
        "Server",
        re.compile(r".+/\d"),  # Contains version number
        "Version disclosure in Server header",
    ),
    (
        "X-Powered-By",
        re.compile(r".+"),
        "Technology disclosure via X-Powered-By header",
    ),
    (
        "Access-Control-Allow-Origin",
        re.compile(r"^\*$"),
        "Wildcard CORS policy allows any origin",
    ),
    (
        "X-Frame-Options",
        re.compile(r"(?i)^ALLOWALL$"),
        "X-Frame-Options set to ALLOWALL allows framing from any origin",
    ),
]

# ---------------------------------------------------------------------------
# Interesting comment patterns
# ---------------------------------------------------------------------------

INTERESTING_COMMENT_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("credentials", re.compile(r"(?i)password|passwd|credential|secret|token|key", re.I)),
    ("todo_fixme", re.compile(r"(?i)\b(?:TODO|FIXME|HACK|XXX|BUG|SECURITY)\b")),
    ("internal_path", re.compile(r"(?:/home/|/var/|/etc/|C:\\Users\\)")),
    ("internal_ip", re.compile(r"10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.1[6-9]\.\d+\.\d+")),
    ("debug_info", re.compile(r"(?i)debug|test|staging|dev\b|localhost")),
    ("version_info", re.compile(r"v\d+\.\d+|version\s*[=:]\s*\d")),
    ("api_endpoint", re.compile(r"/api/|/v\d+/|\.json|\.xml")),
]
