"""Logging utility for bug hunter system."""

import sys
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))


def _get_log_level() -> str:
    """Get log level from config."""
    try:
        from config import get
        return get("logging.level", "INFO")
    except:
        return "INFO"


def _is_verbose() -> bool:
    """Check if verbose logging is enabled."""
    try:
        from config import get
        return get("logging.verbose", False)
    except:
        return False


class Logger:
    """Simple logger for the bug hunter system."""
    
    LEVELS = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3}
    
    def __init__(self, name: str = "BugHunter"):
        self.name = name
        self.level = self.LEVELS.get(_get_log_level(), 1)
        self.verbose = _is_verbose()
    
    def debug(self, msg: str):
        """Log debug message."""
        if self.verbose and self.level <= 0:
            print(f"[DEBUG] {msg}")
    
    def info(self, msg: str):
        """Log info message."""
        if self.level <= 1:
            print(f"[INFO] {msg}")
    
    def warning(self, msg: str):
        """Log warning message."""
        if self.level <= 2:
            print(f"[WARNING] {msg}")
    
    def error(self, msg: str):
        """Log error message."""
        if self.level <= 3:
            print(f"[ERROR] {msg}")
    
    def log(self, msg: str, level: str = "INFO"):
        """Log a message at the specified level."""
        level_upper = level.upper()
        if hasattr(self, level_lower := level_upper.lower()):
            getattr(self, level_lower)(msg)


def get_logger(name: str = "BugHunter") -> Logger:
    """Get a logger instance."""
    return Logger(name)


def log_event(event: str, data: dict = None):
    """Log an event to file."""
    log_dir = Path(__file__).parent.parent / "logs"
    log_dir.mkdir(exist_ok=True)
    
    log_file = log_dir / f"bughunter_{datetime.now().strftime('%Y%m%d')}.log"
    
    timestamp = datetime.now().isoformat()
    entry = f"[{timestamp}] {event}"
    
    if data:
        import json
        entry += f" | {json.dumps(data)}"
    
    entry += "\n"
    
    try:
        with open(log_file, "a") as f:
            f.write(entry)
    except IOError:
        pass


def log_to_file(message: str, filename: str = "activity.log"):
    """Log message to a file."""
    log_dir = Path(__file__).parent.parent / "logs"
    log_dir.mkdir(exist_ok=True)
    
    log_file = log_dir / filename
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        with open(log_file, "a") as f:
            f.write(f"[{timestamp}] {message}\n")
    except IOError:
        pass
