"""Cache system for LLM responses - reduces RAM and speeds up execution."""

import hashlib
import json
from pathlib import Path
from typing import Optional

_cache: dict = {}
_cache_loaded: bool = False


def _get_cache_path() -> Path:
    """Get cache file path."""
    base = Path(__file__).parent.parent / "data" / "output"
    base.mkdir(parents=True, exist_ok=True)
    return base / "cache.json"


def load_cache() -> dict:
    """Load cache from disk into memory."""
    global _cache, _cache_loaded
    if _cache_loaded:
        return _cache
    
    cache_path = _get_cache_path()
    if cache_path.exists():
        try:
            with open(cache_path) as f:
                _cache = json.load(f)
        except (json.JSONDecodeError, IOError):
            _cache = {}
    
    _cache_loaded = True
    return _cache


def save_cache() -> None:
    """Save in-memory cache to disk."""
    cache_path = _get_cache_path()
    try:
        with open(cache_path, 'w') as f:
            json.dump(_cache, f, indent=2)
    except IOError:
        pass


def get(key: str) -> Optional[str]:
    """Get cached value by key."""
    load_cache()
    return _cache.get(key)


def set(key: str, value: str) -> None:
    """Set cached value."""
    load_cache()
    _cache[key] = value
    save_cache()


def get_key(prompt: str, model: str = "") -> str:
    """Generate cache key from prompt and model."""
    content = f"{model}:{prompt}"
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def has(key: str) -> bool:
    """Check if key exists in cache."""
    load_cache()
    return key in _cache


def clear() -> None:
    """Clear all cache."""
    global _cache, _cache_loaded
    _cache = {}
    _cache_loaded = False
    
    cache_path = _get_cache_path()
    if cache_path.exists():
        cache_path.unlink()


def size() -> int:
    """Get number of cached entries."""
    load_cache()
    return len(_cache)


def get_stats() -> dict:
    """Get cache statistics."""
    load_cache()
    return {
        "entries": len(_cache),
        "path": str(_get_cache_path()),
        "loaded": _cache_loaded
    }
