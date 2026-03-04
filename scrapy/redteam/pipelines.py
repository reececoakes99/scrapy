"""
Red Team Pipelines
==================
Item processing pipelines for deduplication, filtering, and exporting findings.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING, Any

from itemadapter import ItemAdapter

from scrapy.exceptions import DropItem

if TYPE_CHECKING:
    from scrapy import Spider
    from scrapy.crawler import Crawler

logger = logging.getLogger(__name__)


class DeduplicationPipeline:
    """Drop duplicate findings based on (url, pattern_name) or (url, path) keys."""

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def process_item(self, item: Any, spider: Spider) -> Any:
        adapter = ItemAdapter(item)
        key_parts = [
            adapter.get("url", ""),
            adapter.get("pattern_name", ""),
            adapter.get("path", ""),
            adapter.get("name", ""),  # for TechnologyItem
        ]
        key = "|".join(str(p) for p in key_parts)
        if key in self._seen:
            raise DropItem(f"Duplicate finding: {key}")
        self._seen.add(key)
        return item


class SeverityFilterPipeline:
    """Drop findings below a configured minimum severity.

    Settings:
        REDTEAM_MIN_SEVERITY: one of critical/high/medium/low (default: low)
    """

    _LEVELS = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    def __init__(self, min_severity: str):
        self.min_level = self._LEVELS.get(min_severity.lower(), 1)

    @classmethod
    def from_crawler(cls, crawler: Crawler) -> SeverityFilterPipeline:
        min_sev = crawler.settings.get("REDTEAM_MIN_SEVERITY", "low")
        return cls(min_sev)

    def process_item(self, item: Any, spider: Spider) -> Any:
        adapter = ItemAdapter(item)
        severity = adapter.get("severity") or adapter.get("confidence", "low")
        level = self._LEVELS.get(str(severity).lower(), 1)
        if level < self.min_level:
            raise DropItem(f"Below min severity ({severity}): {adapter.get('url')}")
        return item


class FindingsSummaryPipeline:
    """Accumulates findings and prints a summary report when the spider closes."""

    def __init__(self) -> None:
        self._counts: dict[str, int] = defaultdict(int)
        self._high_value: list[dict] = []

    @classmethod
    def from_crawler(cls, crawler: Crawler) -> FindingsSummaryPipeline:
        instance = cls()
        crawler.signals.connect(instance.spider_closed, signal=__import__("scrapy").signals.spider_closed)
        return instance

    def process_item(self, item: Any, spider: Spider) -> Any:
        item_type = type(item).__name__
        self._counts[item_type] += 1

        adapter = ItemAdapter(item)
        severity = adapter.get("severity") or adapter.get("confidence", "")
        if severity in ("critical", "high"):
            self._high_value.append({
                "type": item_type,
                "url": adapter.get("url", ""),
                "detail": (
                    adapter.get("pattern_name")
                    or adapter.get("description")
                    or adapter.get("name")
                    or ""
                ),
                "severity": severity,
            })
        return item

    def spider_closed(self, spider: Spider) -> None:
        logger.info("=" * 60)
        logger.info("RED TEAM FINDINGS SUMMARY")
        logger.info("=" * 60)
        for item_type, count in sorted(self._counts.items()):
            logger.info("  %-35s %d", item_type, count)
        logger.info("-" * 60)
        if self._high_value:
            logger.info("HIGH VALUE FINDINGS:")
            for finding in self._high_value:
                logger.info(
                    "  [%s] %s - %s (%s)",
                    finding["severity"].upper(),
                    finding["type"],
                    finding["url"],
                    finding["detail"],
                )
        logger.info("=" * 60)


class JsonLinesExportPipeline:
    """Exports all findings to a JSONL file, grouped by item type.

    Settings:
        REDTEAM_OUTPUT_DIR: directory for output files (default: "./redteam_output")
        REDTEAM_OUTPUT_FILE: single output file for all findings (overrides OUTPUT_DIR)
    """

    def __init__(self, output_dir: Path | None, output_file: Path | None):
        self.output_dir = output_dir
        self.output_file = output_file
        self._files: dict[str, Any] = {}
        self._single_file: Any = None

    @classmethod
    def from_crawler(cls, crawler: Crawler) -> JsonLinesExportPipeline:
        output_dir_str = crawler.settings.get("REDTEAM_OUTPUT_DIR")
        output_file_str = crawler.settings.get("REDTEAM_OUTPUT_FILE")
        output_dir = Path(output_dir_str) if output_dir_str else Path("redteam_output")
        output_file = Path(output_file_str) if output_file_str else None
        return cls(output_dir, output_file)

    def open_spider(self, spider: Spider) -> None:
        if self.output_file:
            self.output_file.parent.mkdir(parents=True, exist_ok=True)
            self._single_file = open(self.output_file, "w", encoding="utf-8")
        else:
            self.output_dir.mkdir(parents=True, exist_ok=True)

    def close_spider(self, spider: Spider) -> None:
        if self._single_file:
            self._single_file.close()
        for f in self._files.values():
            f.close()
        if self.output_dir and not self.output_file:
            logger.info("Red team findings written to: %s/", self.output_dir)
        elif self.output_file:
            logger.info("Red team findings written to: %s", self.output_file)

    def process_item(self, item: Any, spider: Spider) -> Any:
        adapter = ItemAdapter(item)
        line = json.dumps(dict(adapter), ensure_ascii=False) + "\n"

        if self._single_file:
            self._single_file.write(line)
        else:
            item_type = type(item).__name__
            if item_type not in self._files:
                output_path = self.output_dir / f"{item_type}.jsonl"
                self._files[item_type] = open(output_path, "w", encoding="utf-8")
            self._files[item_type].write(line)

        return item
