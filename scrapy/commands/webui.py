from __future__ import annotations

from typing import TYPE_CHECKING

from scrapy.commands import ScrapyCommand

if TYPE_CHECKING:
    import argparse


class Command(ScrapyCommand):
    requires_project = False
    requires_crawler_process = False

    def syntax(self) -> str:
        return "[options]"

    def short_desc(self) -> str:
        return "Start the Scrapy interactive Web UI"

    def long_desc(self) -> str:
        return (
            "Launch a local web server that provides a live interactive interface "
            "for running Scrapy crawls. You can enter a target URL, set the crawl "
            "depth, and start or stop the crawler — all from your browser. "
            "Requires Flask (pip install flask)."
        )

    def add_options(self, parser: argparse.ArgumentParser) -> None:
        super().add_options(parser)
        parser.add_argument(
            "--host",
            dest="host",
            default="127.0.0.1",
            metavar="HOST",
            help="host to bind the web UI server to (default: 127.0.0.1)",
        )
        parser.add_argument(
            "--port",
            dest="port",
            type=int,
            default=6800,
            metavar="PORT",
            help="port to run the web UI server on (default: 6800)",
        )
        parser.add_argument(
            "--no-browser",
            dest="no_browser",
            action="store_true",
            default=False,
            help="do not open a browser tab automatically",
        )

    def run(self, args: list[str], opts: argparse.Namespace) -> None:
        try:
            from scrapy.webui.server import run
        except ImportError as exc:
            raise SystemExit(
                f"Cannot start Scrapy Web UI: {exc}\n"
                "Install the required dependency with:  pip install flask"
            ) from exc

        run(
            host=opts.host,
            port=opts.port,
            open_browser=not opts.no_browser,
        )
