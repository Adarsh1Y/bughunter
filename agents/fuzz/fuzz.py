"""Fuzz engine for payload generation - optimized for low RAM."""

IDOR_PAYLOADS = ["1", "2", "999"]
XSS_PAYLOADS = ["<script>alert(1)</script>"]
SQLI_PAYLOADS = ["' OR 1=1 --"]
AUTH_PAYLOADS = ["null", "token123"]
RCE_PAYLOADS = ["; ls", "| id"]
GENERIC_PAYLOADS = ["<script>alert(1)</script>", "' OR 1=1 --"]


def _is_low_ram() -> bool:
    """Check if low RAM mode is enabled."""
    try:
        from config import get
        return get("mode") == "low_ram"
    except:
        return False


def _get_max_payloads() -> int:
    """Get max payloads from config."""
    try:
        from config import get
        result = get("max_payloads", 5)
        return int(result) if result else 5
    except:
        return 5


def generate_payloads(vuln_type: str, count: int | None = None) -> list:
    """
    Generate payloads for a vulnerability type.
    
    Args:
        vuln_type: Type of vulnerability (IDOR, XSS, SQLI, AUTH, RCE).
        count: Maximum number of payloads (uses config if None).
    
    Returns:
        List of payload strings.
    """
    payload_map = {
        "IDOR": IDOR_PAYLOADS,
        "XSS": XSS_PAYLOADS,
        "SQLI": SQLI_PAYLOADS,
        "AUTH": AUTH_PAYLOADS,
        "RCE": RCE_PAYLOADS,
    }
    
    payloads = payload_map.get(vuln_type, GENERIC_PAYLOADS)
    
    if count is None:
        count = _get_max_payloads()
    
    return payloads[:count]


def get_payloads_for_target(target: dict, count: int | None = None) -> list:
    """
    Get appropriate payloads for a target.
    
    Args:
        target: Target dict from analysis.
        count: Maximum number of payloads.
    
    Returns:
        List of payload strings.
    """
    vuln = target.get("vulnerability", "")
    return generate_payloads(vuln, count)


def fuzz_param(param: str, base_payloads: list | None = None) -> list:
    """
    Generate fuzzed variations of a parameter value.
    """
    if base_payloads is None:
        base_payloads = GENERIC_PAYLOADS
    
    max_count = _get_max_payloads()
    fuzzed = list(base_payloads[:max_count])
    
    return fuzzed[:max_count]
