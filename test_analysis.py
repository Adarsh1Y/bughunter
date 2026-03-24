"""Test analysis agent with JSON output."""

from agents.analysis import analyze
import json

SAMPLE_URLS = """
https://example.com/api/v1/users?id=123
https://example.com/admin/login
https://example.com/search?q=test
https://example.com/api/data?token=secret
https://example.com/upload?file=test.pdf
"""

print("Testing analysis agent with JSON output...")
print("Input URLs:")
print(SAMPLE_URLS)
print("-" * 50)

result = analyze(SAMPLE_URLS)
print("Analysis Result (JSON):")
print(json.dumps(result, indent=2))
