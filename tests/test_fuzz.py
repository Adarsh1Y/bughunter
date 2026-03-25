"""Tests for the fuzz module."""

import pytest

from agents.fuzz import (
    generate_payloads,
    get_payloads_for_target,
    fuzz_param,
)


class TestGeneratePayloads:
    """Tests for generate_payloads function."""

    def test_generates_idor_payloads(self):
        payloads = generate_payloads("IDOR")
        assert "1" in payloads
        assert "2" in payloads
        assert "999" in payloads

    def test_generates_xss_payloads(self):
        payloads = generate_payloads("XSS")
        assert len(payloads) > 0
        assert any("<script>" in p for p in payloads)

    def test_generates_sqli_payloads(self):
        payloads = generate_payloads("SQLI")
        assert len(payloads) > 0

    def test_generates_auth_payloads(self):
        payloads = generate_payloads("AUTH")
        assert len(payloads) > 0

    def test_generates_rce_payloads(self):
        payloads = generate_payloads("RCE")
        assert len(payloads) > 0

    def test_respects_count_parameter(self):
        payloads = generate_payloads("IDOR", count=2)
        assert len(payloads) <= 2

    def test_unknown_type_returns_generic(self):
        payloads = generate_payloads("UNKNOWN")
        assert len(payloads) > 0


class TestGetPayloadsForTarget:
    """Tests for get_payloads_for_target function."""

    def test_uses_vulnerability_type(self):
        target = {"vulnerability": "IDOR"}
        payloads = get_payloads_for_target(target)
        assert "1" in payloads

    def test_respects_count(self):
        target = {"vulnerability": "XSS"}
        payloads = get_payloads_for_target(target, count=1)
        assert len(payloads) <= 1

    def test_handles_missing_vulnerability(self):
        target = {}
        payloads = get_payloads_for_target(target)
        assert isinstance(payloads, list)


class TestFuzzParam:
    """Tests for fuzz_param function."""

    def test_returns_list(self):
        result = fuzz_param("test")
        assert isinstance(result, list)

    def test_respects_custom_payloads(self):
        custom = ["a", "b", "c"]
        result = fuzz_param("test", custom)
        assert len(result) > 0
