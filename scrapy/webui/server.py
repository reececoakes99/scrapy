"""
Scrapy Web UI server.

A Flask-based web server that provides a live interactive interface for
running Scrapy crawls. Streams real-time output to the browser via
Server-Sent Events (SSE).
"""

from __future__ import annotations

import json
import os
import queue
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Generator
from pathlib import Path
from typing import Any

try:
    from flask import Flask, Response, render_template, request, jsonify
except ImportError as exc:
    raise ImportError(
        "The Scrapy Web UI requires Flask. Install it with: pip install flask"
    ) from exc

# ---------------------------------------------------------------------------
# Flask app setup
# ---------------------------------------------------------------------------

_TEMPLATES_DIR = Path(__file__).parent / "templates"
app = Flask(__name__, template_folder=str(_TEMPLATES_DIR))
app.config["SECRET_KEY"] = os.urandom(24)

# ---------------------------------------------------------------------------
# Shared crawler state
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_crawl_process: subprocess.Popen | None = None  # type: ignore[type-arg]
_event_queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=2000)
_crawl_stats: dict[str, Any] = {}
_crawl_status: str = "idle"  # idle | running | stopped | finished


def _reset_state() -> None:
    global _crawl_stats, _crawl_status
    _crawl_stats = {}
    _crawl_status = "idle"
    # Drain the queue
    while not _event_queue.empty():
        try:
            _event_queue.get_nowait()
        except queue.Empty:
            break


# ---------------------------------------------------------------------------
# Generic spider script written to a temp file
# ---------------------------------------------------------------------------

_GENERIC_SPIDER_TEMPLATE = """\
import scrapy

class WebUISpider(scrapy.Spider):
    name = "webui_spider"
    custom_settings = {{
        "DEPTH_LIMIT": {depth},
        "LOG_LEVEL": "INFO",
        "ROBOTSTXT_OBEY": True,
        "CONCURRENT_REQUESTS": 8,
        "DOWNLOAD_DELAY": 0.25,
    }}

    def start_requests(self):
        for url in {start_urls!r}:
            yield scrapy.Request(url, callback=self.parse)

    def parse(self, response):
        self.logger.info("Scraped: %s (status=%s)", response.url, response.status)
        title = response.css("title::text").get("(no title)")
        yield {{
            "url": response.url,
            "status": response.status,
            "title": title.strip(),
        }}
        if self.settings.getint("DEPTH_LIMIT", 0) != 1:
            for href in response.css("a::attr(href)").getall():
                yield response.follow(href, callback=self.parse)
"""


def _write_spider_file(start_urls: list[str], depth: int) -> str:
    """Write a generic spider to a temporary file and return its path."""
    spider_code = _GENERIC_SPIDER_TEMPLATE.format(
        depth=depth,
        start_urls=start_urls,
    )
    fd, path = tempfile.mkstemp(suffix=".py", prefix="scrapy_webui_spider_")
    with os.fdopen(fd, "w") as f:
        f.write(spider_code)
    return path


# ---------------------------------------------------------------------------
# Background thread: read subprocess output and push events
# ---------------------------------------------------------------------------

def _stream_process(proc: subprocess.Popen, spider_file: str) -> None:  # type: ignore[type-arg]
    global _crawl_status

    assert proc.stdout is not None
    try:
        for raw_line in proc.stdout:
            line = raw_line.rstrip("\n")
            if not line:
                continue
            # Parse simple stat updates out of Scrapy log lines
            stats = _extract_stats(line)
            _event_queue.put({"type": "log", "data": line, "stats": stats})

        proc.wait()
    finally:
        # Clean up temp spider file
        try:
            os.unlink(spider_file)
        except OSError:
            pass

    with _lock:
        _crawl_status = "finished" if proc.returncode == 0 else "stopped"

    _event_queue.put(
        {
            "type": "done",
            "data": f"Crawl {'finished' if proc.returncode == 0 else 'stopped'} "
                    f"(exit code {proc.returncode})",
            "stats": _crawl_stats,
        }
    )


# Very lightweight stat extraction – avoids pulling in the entire Scrapy
# settings/stats machinery into the web server process.
_STAT_KEYWORDS = {
    "downloader/request_count": "requests",
    "downloader/response_count": "responses",
    "item_scraped_count": "items",
    "downloader/exception_count": "errors",
    "finish_reason": "finish_reason",
}


def _extract_stats(line: str) -> dict[str, Any]:
    """Best-effort extraction of stats from a Scrapy log line."""
    updates: dict[str, Any] = {}
    # Scrapy dumps stats as: "{'key': value, ...}"
    if "item_scraped_count" in line or "downloader/request_count" in line:
        try:
            start = line.index("{")
            end = line.rindex("}") + 1
            raw = line[start:end].replace("'", '"')
            data = json.loads(raw)
            for k, label in _STAT_KEYWORDS.items():
                if k in data:
                    updates[label] = data[k]
            _crawl_stats.update(updates)
        except (ValueError, json.JSONDecodeError, KeyError):
            pass
    return updates


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------

@app.route("/")
def index() -> str:
    return render_template("index.html")


@app.route("/api/start", methods=["POST"])
def start_crawl() -> Response:
    global _crawl_process, _crawl_status

    data = request.get_json(force=True)
    url: str = (data.get("url") or "").strip()
    try:
        depth = max(0, int(data.get("depth", 1)))
    except (TypeError, ValueError):
        depth = 1

    if not url:
        return jsonify({"error": "url is required"}), 400

    with _lock:
        if _crawl_status == "running":
            return jsonify({"error": "A crawl is already running"}), 409

        _reset_state()
        _crawl_status = "running"

    spider_file = _write_spider_file([url], depth)

    cmd = [
        sys.executable, "-m", "scrapy", "runspider", spider_file,
    ]

    env = os.environ.copy()
    env["SCRAPY_SETTINGS_MODULE"] = ""  # use defaults only

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env,
        )
    except Exception as exc:  # noqa: BLE001
        with _lock:
            _crawl_status = "idle"
        try:
            os.unlink(spider_file)
        except OSError:
            pass
        return jsonify({"error": str(exc)}), 500

    with _lock:
        _crawl_process = proc

    t = threading.Thread(target=_stream_process, args=(proc, spider_file), daemon=True)
    t.start()

    return jsonify({"status": "started"})


@app.route("/api/stop", methods=["POST"])
def stop_crawl() -> Response:
    global _crawl_process, _crawl_status

    with _lock:
        proc = _crawl_process
        if proc is None or _crawl_status != "running":
            return jsonify({"error": "No active crawl to stop"}), 409
        _crawl_status = "stopped"

    # Send SIGTERM first; escalate to SIGKILL after a short wait
    try:
        if sys.platform == "win32":
            proc.terminate()
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (ProcessLookupError, OSError):
        try:
            proc.terminate()
        except OSError:
            pass

    return jsonify({"status": "stopping"})


@app.route("/api/status")
def crawl_status() -> Response:
    with _lock:
        status = _crawl_status
        stats = dict(_crawl_stats)
    return jsonify({"status": status, "stats": stats})


@app.route("/api/stream")
def event_stream() -> Response:
    """Server-Sent Events endpoint for live crawl output."""

    def generate() -> Generator[str, None, None]:
        # Send a heartbeat immediately so the browser knows the connection is live
        yield "event: heartbeat\ndata: {}\n\n"
        while True:
            try:
                event = _event_queue.get(timeout=15)
                payload = json.dumps(event)
                yield f"data: {payload}\n\n"
                if event.get("type") == "done":
                    return
            except queue.Empty:
                # heartbeat to keep the connection alive
                yield "event: heartbeat\ndata: {}\n\n"

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(host: str = "127.0.0.1", port: int = 6800, open_browser: bool = True) -> None:
    """Start the Scrapy Web UI server."""
    import webbrowser

    url = f"http://{host}:{port}"
    print(f"Scrapy Web UI running at {url}")
    print("Press Ctrl+C to quit.")

    if open_browser:
        # Give Flask a moment to start before opening the browser
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()

    app.run(host=host, port=port, threaded=True, use_reloader=False)
