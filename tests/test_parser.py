"""Tests for the parser module."""

import json
import tempfile
from pathlib import Path

import pytest

from core.parser import (
    parse_traffic_file,
    get_endpoint,
    has_auth,
    is_static_file,
    is_api_endpoint,
    filter_traffic,
    generate_request_pack,
    normalize_endpoint,
)


class TestGetEndpoint:
    """Tests for get_endpoint function."""

    def test_extracts_path_from_url(self):
        url = "https://example.com/api/users?id=123"
        assert get_endpoint(url) == "/api/users"

    def test_handles_path_only(self):
        url = "/api/users/456"
        assert get_endpoint(url) == "/api/users/456"


class TestHasAuth:
    """Tests for has_auth function."""

    def test_detects_cookie_auth(self):
        headers = {"cookie": "session=abc123"}
        assert has_auth(headers) is True

    def test_detects_authorization_header(self):
        headers = {"authorization": "Bearer token123"}
        assert has_auth(headers) is True

    def test_detects_lowercase_auth_header(self):
        headers = {"authorization": "Basic abc123"}
        assert has_auth(headers) is True

    def test_no_auth_when_empty(self):
        headers = {}
        assert has_auth(headers) is False

    def test_no_auth_with_regular_headers(self):
        headers = {"content-type": "application/json"}
        assert has_auth(headers) is False


class TestIsStaticFile:
    """Tests for is_static_file function."""

    def test_detects_js_files(self):
        assert is_static_file("https://example.com/app.js") is True
        assert is_static_file("https://example.com/static/app.min.js") is True

    def test_detects_css_files(self):
        assert is_static_file("https://example.com/style.css") is True

    def test_detects_image_files(self):
        assert is_static_file("https://example.com/logo.png") is True
        assert is_static_file("https://example.com/image.jpg") is True

    def test_allows_api_endpoints(self):
        assert is_static_file("https://example.com/api/users") is False

    def test_case_insensitive(self):
        assert is_static_file("https://example.com/APP.JS") is True


class TestIsApiEndpoint:
    """Tests for is_api_endpoint function."""

    def test_detects_api_in_path(self):
        assert is_api_endpoint("https://example.com/api/users") is True
        assert is_api_endpoint("https://example.com/API/data") is True

    def test_rejects_non_api(self):
        assert is_api_endpoint("https://example.com/users") is False
        assert is_api_endpoint("https://example.com/about") is False


class TestNormalizeEndpoint:
    """Tests for normalize_endpoint function."""

    def test_replaces_numeric_ids(self):
        assert normalize_endpoint("/api/orgs/123/pipelines") == "/api/orgs/{id}/pipelines"
        assert normalize_endpoint("/api/users/456") == "/api/users/{id}"

    def test_preserves_non_numeric(self):
        assert normalize_endpoint("/api/users/profile") == "/api/users/profile"

    def test_handles_multiple_ids(self):
        assert normalize_endpoint("/api/orgs/123/users/456") == "/api/orgs/{id}/users/{id}"


class TestFilterTraffic:
    """Tests for filter_traffic function."""

    def test_filters_static_files(self):
        requests = [
            {"url": "https://example.com/app.js", "headers": {}, "params": {}},
            {"url": "https://example.com/api/users", "headers": {"cookie": "x"}, "params": {}},
        ]
        filtered = filter_traffic(requests)
        assert len(filtered) == 1
        assert filtered[0]["url"] == "https://example.com/api/users"

    def test_filters_non_api(self):
        requests = [
            {"url": "https://example.com/about", "headers": {}, "params": {}},
            {"url": "https://example.com/api/users", "headers": {"cookie": "x"}, "params": {}},
        ]
        filtered = filter_traffic(requests)
        assert len(filtered) == 1

    def test_filters_unauthenticated(self):
        requests = [
            {"url": "https://example.com/api/public", "headers": {}, "params": {}},
            {
                "url": "https://example.com/api/users",
                "headers": {"authorization": "Bearer"},
                "params": {},
            },
        ]
        filtered = filter_traffic(requests)
        assert len(filtered) == 1


class TestGenerateRequestPack:
    """Tests for generate_request_pack function."""

    def test_generates_requests_with_payloads(self):
        targets = [
            {"endpoint": "/api/users", "method": "GET", "params": {"id": "1"}, "headers": {}}
        ]
        payloads = ["1", "2", "999"]

        requests = generate_request_pack(targets, payloads, "https://target.com")

        assert len(requests) == 3
        assert requests[0]["url"] == "https://target.com/api/users?id=1"
        assert requests[1]["url"] == "https://target.com/api/users?id=2"
        assert requests[2]["url"] == "https://target.com/api/users?id=999"

    def test_preserves_headers(self):
        targets = [
            {
                "endpoint": "/api/data",
                "method": "GET",
                "params": {},
                "headers": {"cookie": "session=abc"},
            }
        ]
        requests = generate_request_pack(targets, ["1"], "https://target.com")

        assert len(requests) == 1
        assert requests[0]["headers"]["cookie"] == "session=abc"


class TestParseTrafficFile:
    """Tests for parse_traffic_file function."""

    def test_parses_json_list(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(
                [
                    {
                        "url": "https://example.com/api/users",
                        "method": "GET",
                        "params": {},
                        "headers": {},
                    },
                ],
                f,
            )
            f.flush()

            requests = parse_traffic_file(f.name)
            assert len(requests) == 1
            assert requests[0]["url"] == "https://example.com/api/users"

            Path(f.name).unlink()

    def test_handles_requests_object(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(
                {
                    "requests": [
                        {
                            "url": "https://example.com/api/users",
                            "method": "GET",
                            "params": {},
                            "headers": {},
                        },
                    ]
                },
                f,
            )
            f.flush()

            requests = parse_traffic_file(f.name)
            assert len(requests) == 1

            Path(f.name).unlink()

    def test_raises_on_missing_file(self):
        with pytest.raises(FileNotFoundError):
            parse_traffic_file("/nonexistent/file.json")
