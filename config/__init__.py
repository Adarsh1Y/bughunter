"""Configuration loader for bug hunter system."""

import json
from pathlib import Path

_config = None


def load_config(config_path: str | None = None) -> dict:
    """
    Load configuration from JSON file.
    
    Args:
        config_path: Path to config file. Defaults to config/settings.json
    
    Returns:
        Configuration dict.
    """
    global _config
    
    if _config is not None:
        return _config
    
    if config_path is None:
        base_path = Path(__file__).parent.parent
        config_path = base_path / "config" / "settings.json"
    
    try:
        with open(config_path) as f:
            _config = json.load(f)
        return _config
    except (FileNotFoundError, json.JSONDecodeError):
        return get_default_config()


def get_default_config() -> dict:
    """Return default configuration."""
    return {
        "mode": "low_ram",
        "max_targets": 3,
        "max_input_size": 1500,
        "max_payloads": 5,
        "use_cache": True,
        "llm_timeout": 60,
        "llm_models": {
            "analysis": "llama3.2:1b",
            "strategy": "llama3.2:1b",
            "report": "llama3.2:1b",
            "response": "llama3.2:1b"
        },
        "low_ram": {
            "reduce_payload_count": True,
            "skip_heavy_analysis": True,
            "cache_aggressive": True,
            "max_response_size": 200
        },
        "logging": {
            "level": "INFO",
            "verbose": False
        }
    }


def get(key: str, default=None):
    """Get config value by key."""
    config = load_config()
    keys = key.split(".")
    value = config
    for k in keys:
        value = value.get(k, default)
    return value


def is_low_ram_mode() -> bool:
    """Check if low RAM mode is enabled."""
    return load_config().get("mode") == "low_ram"


def reload():
    """Force reload configuration."""
    global _config
    _config = None
    return load_config()
