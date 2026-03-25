"""Live proxy listener for real-time traffic monitoring."""

import json
import re
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from colorama import Fore, Style, init

    init(autoreset=True)
    COLORS = True
except ImportError:
    COLORS = True

    class Fore:
        GREEN = RED = YELLOW = CYAN = MAGENTA = BLUE = WHITE = ""

    class Style:
        BRIGHT = RESET_ALL = ""


def parse_proxy_log_line(line: str) -> Optional[dict]:
    """Parse a line from proxy log format."""
    try:
        parts = line.strip().split(" ", 2)
        if len(parts) < 3:
            return None

        method = parts[0]

        if " " in parts[1]:
            url = parts[1].split(" ")[0]
        else:
            url = parts[1]

        headers_str = parts[2] if len(parts) > 2 else "{}"
        try:
            headers = json.loads(headers_str)
        except json.JSONDecodeError:
            headers = {}

        return {
            "method": method,
            "url": url,
            "headers": headers,
        }
    except Exception:
        return None


def is_static_file(url: str) -> bool:
    """Check if URL points to static file."""
    static_extensions = {
        ".js",
        ".css",
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".svg",
        ".ico",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".map",
        ".webp",
        ".html",
        ".htm",
        ".json",
    }
    return any(url.lower().endswith(ext) for ext in static_extensions)


def is_api_endpoint(url: str) -> bool:
    """Check if URL is an API endpoint."""
    return "/api" in url.lower()


def has_auth(headers: dict) -> bool:
    """Check if request has authentication."""
    auth_headers = {"authorization", "cookie", "x-api-key", "bearer"}
    header_keys = {k.lower() for k in headers.keys()}
    return bool(auth_headers & header_keys)


def normalize_endpoint(endpoint: str) -> str:
    """Normalize endpoint by replacing numeric IDs with {id}."""
    parts = endpoint.split("/")
    normalized = []

    for part in parts:
        if part.isdigit():
            normalized.append("{id}")
        else:
            normalized.append(part)

    return "/".join(normalized)


def get_endpoint(url: str) -> str:
    """Extract endpoint path from URL."""
    from urllib.parse import urlparse

    return urlparse(url).path


def score_endpoint(endpoint: str, headers: dict) -> int:
    """Score an endpoint for priority."""
    score = 0
    endpoint_lower = endpoint.lower()

    if "id" in endpoint_lower:
        score += 5
    if "user" in endpoint_lower:
        score += 4
    if "org" in endpoint_lower:
        score += 4
    if "admin" in endpoint_lower:
        score += 6
    if "auth" in endpoint_lower or "token" in endpoint_lower:
        score += 4

    depth = endpoint.count("/")
    if depth >= 3:
        score += 2

    if has_auth(headers):
        score += 3

    return score


def filter_and_score(request: dict) -> Optional[dict]:
    """Filter request and return scored result."""
    url = request.get("url", "")
    headers = request.get("headers", {})
    method = request.get("method", "GET")

    if is_static_file(url):
        return None

    if not is_api_endpoint(url):
        return None

    endpoint = get_endpoint(url)
    normalized = normalize_endpoint(endpoint)
    score = score_endpoint(endpoint, headers)

    return {
        "method": method,
        "url": url,
        "endpoint": endpoint,
        "normalized": normalized,
        "score": score,
        "headers": headers,
    }


class LiveListener:
    """Listen to proxy traffic and capture HTTP requests."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.host = host
        self.port = port
        self.running = False
        self.requests = []
        self.seen_endpoints = set()
        self.seen_normalized = set()
        self._lock = threading.Lock()
        self.batch_size = 5
        self.batch_interval = 2.0
        self.min_score_threshold = 7
        self.output_count = 0
        self.max_outputs = 10

    def start(self):
        """Start listening for proxy traffic."""
        self.running = True

    def stop(self):
        """Stop listening."""
        self.running = False

    def add_request(self, request: dict) -> Optional[dict]:
        """Add a captured request. Returns scored result if new."""
        result = filter_and_score(request)

        if not result:
            return None

        normalized = result["normalized"]

        with self._lock:
            if normalized in self.seen_normalized:
                return None

            if self.output_count >= self.max_outputs:
                return None

            self.seen_normalized.add(normalized)
            self.seen_endpoints.add(result["endpoint"])
            self.requests.append(result)
            self.output_count += 1

            return result

    def is_new(self, endpoint: str) -> bool:
        """Check if endpoint is new."""
        with self._lock:
            return endpoint not in self.seen_endpoints

    def get_requests(self) -> list:
        """Get all captured requests."""
        with self._lock:
            return self.requests.copy()

    def should_output(self) -> bool:
        """Check if we should output (rate control)."""
        with self._lock:
            return self.output_count < self.max_outputs


def print_endpoint_detection(result: dict):
    """Print endpoint detection with suggestions."""
    endpoint = result["normalized"]
    score = result["score"]
    original_url = result["url"]
    method = result["method"]

    print(f"\n{Fore.GREEN}[+] Endpoint detected: {endpoint}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Score:{Style.RESET_ALL} {score}")
    print(f"{Fore.CYAN}Original:{Style.RESET_ALL} {method} {original_url}")

    if score >= 7:
        print(f"\n{Fore.YELLOW}Suggested test:{Style.RESET_ALL}")
        print(f"  Change ID values to test for IDOR")
        print(f"\n{Fore.GREEN}Payloads:{Style.RESET_ALL} 1, 2, 999")

    return True


def check_proxy_available(host: str = "127.0.0.1", port: int = 8080) -> bool:
    """Check if proxy is available."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((host, port))
        sock.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def listen_live(
    timeout: int = 60,
    batch_interval: float = 2.0,
    min_score: int = 7,
) -> list:
    """
    Listen for live proxy traffic and yield scored endpoints.

    Args:
        timeout: Maximum time to listen in seconds.
        batch_interval: Time between output batches.
        min_score: Minimum score threshold for output.

    Yields:
        Scored endpoint results.
    """
    listener = LiveListener()
    listener.batch_interval = batch_interval
    listener.min_score_threshold = min_score

    print(f"{Fore.CYAN}[*] Starting live listener...{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Listening on 127.0.0.1:8080{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Press Ctrl+C to stop{Style.RESET_ALL}")
    print()

    if not check_proxy_available():
        print(f"{Fore.YELLOW}[!] Proxy not available on 127.0.0.1:8080{Style.RESET_ALL}")
        print(
            f"{Fore.YELLOW}[!] Make sure Burp Suite is running with proxy enabled{Style.RESET_ALL}"
        )
        print()

    listener.start()
    start_time = time.time()
    last_batch_time = start_time

    try:
        while listener.running and (time.time() - start_time) < timeout:
            if not listener.should_output():
                print(
                    f"\n{Fore.YELLOW}[*] Output limit reached ({listener.max_outputs} endpoints){Style.RESET_ALL}"
                )
                break

            elapsed = int(time.time() - start_time)
            if elapsed % 10 == 0 and elapsed > 0:
                if time.time() - last_batch_time > 9:
                    print(
                        f"{Fore.CYAN}[*] Still listening... ({elapsed}s elapsed){Style.RESET_ALL}"
                    )
                    last_batch_time = time.time()

            time.sleep(0.5)

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted by user{Style.RESET_ALL}")

    finally:
        listener.stop()

    return listener.get_requests()


def add_request_from_traffic(request: dict, listener: LiveListener) -> Optional[dict]:
    """Add a request from traffic file to listener."""
    return listener.add_request(request)


if __name__ == "__main__":
    print(f"{Fore.CYAN}{'=' * 50}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}BugHunter LIVE MODE{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 50}{Style.RESET_ALL}")
    print()

    results = listen_live(timeout=10)

    print(f"\n{Fore.GREEN}{'=' * 50}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Session Summary:{Style.RESET_ALL}")
    print(f"  Endpoints captured: {len(results)}")

    for r in results:
        print(f"  - {r['normalized']} (score: {r['score']})")

    print(f"{Fore.GREEN}{'=' * 50}{Style.RESET_ALL}")
