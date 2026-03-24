"""Test analysis agent with JSON output."""

from core.llm import call_ollama

prompt = """For URL https://example.com/api?id=123, output ONLY this JSON:
[{"endpoint": "/api", "params": ["id"], "risk": "high", "vulnerability": "IDOR", "confidence": 0.8}]"""

print("Testing JSON output...")
result = call_ollama(prompt)
print("RAW:", repr(result))

import json
import re

json_match = re.search(r'\[.*\]', result, re.DOTALL)
if json_match:
    print("MATCHED:", json_match.group())
    try:
        print("PARSED:", json.loads(json_match.group()))
    except Exception as e:
        print("PARSE ERROR:", e)
