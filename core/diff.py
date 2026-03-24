"""Diff viewer for comparing response data."""

import difflib
from typing import Optional


def compare(a: str, b: str, context_lines: int = 10) -> str:
    """
    Compare two strings and return a readable diff.
    
    Args:
        a: First string (baseline).
        b: Second string (response).
        context_lines: Number of lines to show (default: 10).
    
    Returns:
        Readable diff string.
    """
    if not a:
        a = ""
    if not b:
        b = ""
    
    a_lines = a.splitlines()[:context_lines]
    b_lines = b.splitlines()[:context_lines]
    
    diff = difflib.unified_diff(
        a_lines,
        b_lines,
        fromfile='baseline',
        tofile='response',
        lineterm=''
    )
    
    result = list(diff)
    
    if not result:
        return "No differences found."
    
    return '\n'.join(result)


def compare_responses(resp1: dict, resp2: dict, max_lines: int = 15) -> str:
    """
    Compare two response dicts and return diff.
    
    Args:
        resp1: First response dict.
        resp2: Second response dict.
        max_lines: Max lines of body to compare.
    
    Returns:
        Formatted diff string.
    """
    lines = []
    lines.append("=" * 50)
    lines.append("RESPONSE COMPARISON")
    lines.append("=" * 50)
    
    lines.append(f"\nBaseline ({resp1.get('user', 'user1')}):")
    lines.append(f"  Status: {resp1.get('status', 'N/A')}")
    lines.append(f"  Length: {resp1.get('length', 0)} bytes")
    
    lines.append(f"\nResponse ({resp2.get('user', 'user2')}):")
    lines.append(f"  Status: {resp2.get('status', 'N/A')}")
    lines.append(f"  Length: {resp2.get('length', 0)} bytes")
    
    body1 = resp1.get('body_preview', '')[:500]
    body2 = resp2.get('body_preview', '')[:500]
    
    lines.append("\n--- Body Diff ---")
    
    diff = compare(body1, body2, context_lines=max_lines)
    lines.append(diff)
    
    return '\n'.join(lines)


def highlight_changes(diff_output: str) -> str:
    """
    Add visual markers to diff output.
    
    Args:
        diff_output: Raw diff string.
    
    Returns:
        Highlighted diff string.
    """
    lines = diff_output.split('\n')
    highlighted = []
    
    for line in lines:
        if line.startswith('+') and not line.startswith('+++'):
            highlighted.append(f"[+GREEN]{line}[/GREEN]")
        elif line.startswith('-') and not line.startswith('---'):
            highlighted.append(f"[-RED]{line}[/RED]")
        else:
            highlighted.append(line)
    
    return '\n'.join(highlighted)


def get_diff_summary(diff_output: str) -> dict:
    """
    Get a summary of differences.
    
    Args:
        diff_output: Diff string.
    
    Returns:
        Summary dict with counts.
    """
    lines = diff_output.split('\n')
    
    additions = sum(1 for l in lines if l.startswith('+') and not l.startswith('+++'))
    deletions = sum(1 for l in lines if l.startswith('-') and not l.startswith('---'))
    
    return {
        "additions": additions,
        "deletions": deletions,
        "has_changes": additions > 0 or deletions > 0
    }
