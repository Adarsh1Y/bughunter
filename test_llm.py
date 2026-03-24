"""Test LLM interface."""

from core.llm import call_ollama

print("Testing LLM interface...")
response = call_ollama("Say hello in one line")
print(f"Response: {response}")
