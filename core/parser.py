"""Traffic parser for reading JSON traffic files."""

import json
import re
from pathlib import Path
from typing import Optional


def parse_traffic_file(filepath: str) -> list[dict]:
    """
    Parse a JSON traffic file and extract structured request data.

    Args:
        filepath: Path to the JSON file.

    Returns:
        List of dicts with url, method, params, headers.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Traffic file not found: {filepath}")

    with open(path, "r") as f:
        data = json.load(f)

    requests = []

    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        if "requests" in data:
            items = data["requests"]
        elif "har" in data:
            items = _parse_har(data)
        else:
            items = [data]
    else:
        raise ValueError(f"Unexpected JSON format in {filepath}")

    for item in items:
        request = _extract_request(item)
        if request:
            requests.append(request)

    return requests


def _parse_har(data: dict) -> list:
    """Parse HAR format traffic data."""
    entries = data.get("har", {}).get("entries", [])
    return [e.get("request", {}) for e in entries]


def _extract_request(item: dict) -> Optional[dict]:
    """Extract structured request data from a single item."""
    try:
        url = ""
        method = "GET"
        params = {}
        headers = {}

        if isinstance(item, str):
            url = item
        elif isinstance(item, dict):
            url = item.get("url") or item.get("request", {}).get("url", "")
            method = item.get("method") or item.get("request", {}).get("method", "GET")

            if "params" in item:
                raw_params = item["params"]
                if isinstance(raw_params, list):
                    for p in raw_params:
                        name = p.get("name", "")
                        value = p.get("value", "")
                        if name:
                            params[name] = value
                elif isinstance(raw_params, dict):
                    params = raw_params
                elif isinstance(raw_params, str):
                    params = {"data": raw_params}

            if "headers" in item:
                raw_headers = item["headers"]
                if isinstance(raw_headers, list):
                    for h in raw_headers:
                        name = h.get("name", "")
                        value = h.get("value", "")
                        if name:
                            headers[name.lower()] = value
                elif isinstance(raw_headers, dict):
                    headers = {k.lower(): v for k, v in raw_headers.items()}

            if "query" in item:
                query = item["query"]
                if isinstance(query, list):
                    for q in query:
                        name = q.get("name", "")
                        value = q.get("value", "")
                        if name:
                            params[name] = value
                elif isinstance(query, dict):
                    params.update(query)

        if not url:
            return None

        return {
            "url": url,
            "method": method.upper(),
            "params": params,
            "headers": headers,
        }

    except Exception:
        return None


def get_endpoint(url: str) -> str:
    """Extract endpoint path from URL."""
    from urllib.parse import urlparse

    return urlparse(url).path


def has_auth(headers: dict) -> bool:
    """Check if request has authentication."""
    auth_headers = {"authorization", "cookie", "x-api-key", "bearer"}
    header_keys = {k.lower() for k in headers.keys()}
    return bool(auth_headers & header_keys)


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


def filter_traffic(requests: list[dict]) -> list[dict]:
    """
    Filter traffic based on security testing criteria.

    KEEP:
    - Endpoints containing /api
    - Authenticated requests (has cookies or auth header)

    REMOVE:
    - Static files (.js, .css, images)
    - Irrelevant endpoints

    Args:
        requests: List of request dicts from parse_traffic_file.

    Returns:
        Filtered list of requests.
    """
    filtered = []

    for req in requests:
        url = req.get("url", "")
        headers = req.get("headers", {})

        if is_static_file(url):
            continue

        if not is_api_endpoint(url):
            continue

        if not has_auth(headers):
            continue

        filtered.append(req)

    return filtered


def filter_and_score(requests: list[dict]) -> list[dict]:
    """
    Filter traffic and score each endpoint.

    Args:
        requests: List of request dicts.

    Returns:
        List of dicts with endpoint, score, and original request data.
    """
    filtered = filter_traffic(requests)
    scored = []

    for req in filtered:
        endpoint = get_endpoint(req["url"])
        score = _score_endpoint(endpoint, req.get("params", {}), req.get("headers", {}))
        scored.append(
            {
                "endpoint": endpoint,
                "score": score,
                "url": req["url"],
                "method": req.get("method", "GET"),
                "params": req.get("params", {}),
                "headers": req.get("headers", {}),
            }
        )

    return sorted(scored, key=lambda x: x["score"], reverse=True)


def _score_endpoint(endpoint: str, params: dict, headers: dict) -> int:
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
    if "token" in endpoint_lower or "auth" in endpoint_lower:
        score += 4

    depth = endpoint.count("/")
    if depth > 2:
        score += 2

    param_keys = [k.lower() for k in params.keys()]
    if "id" in param_keys:
        score += 5
    if "user_id" in param_keys:
        score += 6

    return score


def normalize_endpoint(endpoint: str) -> str:
    """
    Normalize endpoint by replacing numeric IDs with {id} placeholder.

    Converts:
    /api/orgs/123/pipelines → /api/orgs/{id}/pipelines
    /api/users/456 → /api/users/{id}

    Args:
        endpoint: The endpoint path to normalize.

    Returns:
        Normalized endpoint with placeholders.
    """
    parts = endpoint.split("/")
    normalized = []

    for part in parts:
        if part.isdigit():
            normalized.append("{id}")
        else:
            normalized.append(part)

    return "/".join(normalized)


def group_endpoints(endpoints: list[str]) -> dict[str, list[str]]:
    """
    Group similar endpoints by their normalized form.

    Args:
        endpoints: List of endpoint paths.

    Returns:
        Dict mapping normalized endpoint to list of original endpoints.
    """
    groups = {}

    for ep in endpoints:
        normalized = normalize_endpoint(ep)
        if normalized not in groups:
            groups[normalized] = []
        groups[normalized].append(ep)

    return groups


def generate_request_pack(
    targets: list[dict], payloads: list[str], base_url: str = "https://target.com"
) -> list[dict]:
    """
    Generate full request objects from targets and payloads.

    Args:
        targets: List of target dicts with endpoint, params, headers.
        payloads: List of payload values to test.
        base_url: Base URL for requests.

    Returns:
        List of request dicts ready for execution.
    """
    requests = []

    for target in targets:
        endpoint = target.get("endpoint", "/")
        existing_params = target.get("params", {})
        headers = target.get("headers", {})

        param_name = "id"
        if existing_params:
            if isinstance(existing_params, dict):
                param_name = list(existing_params.keys())[0]
            elif isinstance(existing_params, list) and existing_params:
                param_name = existing_params[0]

        for payload in payloads:
            url = f"{base_url.rstrip('/')}{endpoint}?{param_name}={payload}"

            request = {
                "method": target.get("method", "GET"),
                "url": url,
                "endpoint": endpoint,
                "param": param_name,
                "payload": payload,
                "headers": headers.copy() if headers else {},
            }
            requests.append(request)

    return requests


def save_request_pack(requests: list[dict], filepath: str = None) -> str:
    """
    Save request pack to JSON file.

    Args:
        requests: List of request dicts.
        filepath: Optional custom filepath.

    Returns:
        Path to saved file.
    """
    import json
    from pathlib import Path

    if filepath is None:
        filepath = Path(__file__).parent.parent / "data" / "output" / "requests.json"

    Path(filepath).parent.mkdir(parents=True, exist_ok=True)

    with open(filepath, "w") as f:
        json.dump({"requests": requests, "count": len(requests)}, f, indent=2)

    return str(filepath)


def save_responses(responses: list[dict], filepath: str = None) -> str:
    """
    Save response data to JSON file.

    Args:
        responses: List of response dicts.
        filepath: Optional custom filepath.

    Returns:
        Path to saved file.
    """
    if filepath is None:
        filepath = Path(__file__).parent.parent / "data" / "output" / "responses.json"

    Path(filepath).parent.mkdir(parents=True, exist_ok=True)

    with open(filepath, "w") as f:
        json.dump({"responses": responses, "count": len(responses)}, f, indent=2)

    return str(filepath)
