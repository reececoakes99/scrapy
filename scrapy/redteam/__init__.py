"""
Scrapy Red Team Module
======================
Hybrid webcrawler/scraper for authorized penetration testing and red team operations.

Components:
    - RedTeamSpider: Hybrid crawler+scraper spider (scrapy.spiders.redteam)
    - items: Structured finding data classes
    - patterns: Regex patterns for sensitive data detection
    - pipelines: Finding deduplication and export
    - middlewares: UA rotation, custom headers, rate limiting
    - settings: Default red team configuration

Usage:
    scrapy runspider -a url=https://target.example.com scrapy/spiders/redteam.py

IMPORTANT: Only use against systems you own or have explicit written authorization to test.
"""
