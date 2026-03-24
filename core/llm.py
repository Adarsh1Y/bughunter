"""LLM Interface for Ollama - optimized for low RAM."""

import subprocess
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import cache

DEFAULT_MODEL = "llama3.2:1b"
DEFAULT_TIMEOUT = 60


def call_ollama(
    prompt: str,
    model: Optional[str] = None,
    timeout: Optional[int] = None,
    use_cache: bool = True
) -> str:
    """
    Call Ollama with a prompt and return the response.
    
    Args:
        prompt: The prompt string to send to the model.
        model: The Ollama model to use.
        timeout: Timeout in seconds.
        use_cache: Whether to use cache.
    
    Returns:
        The model's response as a string.
    """
    from config import get
    
    cfg_model = get("llm_models.analysis", DEFAULT_MODEL)
    cfg_timeout = get("llm_timeout", DEFAULT_TIMEOUT)
    cfg_cache_enabled = get("use_cache", True)
    
    model = model or cfg_model or DEFAULT_MODEL
    timeout = timeout or cfg_timeout or DEFAULT_TIMEOUT
    use_cache = use_cache and cfg_cache_enabled
    
    cache_key = cache.get_key(prompt, model)
    
    if use_cache and cache.has(cache_key):
        return cache.get(cache_key)
    
    try:
        result = subprocess.run(
            ["ollama", "run", model],
            input=prompt,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        
        if result.returncode != 0:
            raise Exception(f"Ollama error: {result.stderr}")
        
        output = result.stdout.strip()
        
        if use_cache:
            cache.set(cache_key, output)
        
        return output
    
    except subprocess.TimeoutExpired:
        raise Exception(f"LLM timeout after {timeout}s")
    
    except FileNotFoundError:
        raise Exception("Ollama not found")
    
    except Exception as e:
        raise Exception(f"LLM failed: {str(e)}")


def clear_cache() -> None:
    """Clear the LLM cache."""
    cache.clear()


def get_cache_stats() -> dict:
    """Get cache statistics."""
    return cache.get_stats()


if __name__ == "__main__":
    print("Testing LLM interface...")
    try:
        response = call_ollama("Say hello")
        print(f"Response: {response}")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
