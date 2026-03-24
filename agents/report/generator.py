"""Report generator for creating vulnerability reports."""

import json
import sys
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.llm import call_ollama


def _get_model() -> str:
    """Get model from config."""
    try:
        from config import get
        return get("llm_models.report", "llama3.2:1b")
    except:
        return "llama3.2:1b"


def generate_report(
    target: dict,
    payload: str,
    anomaly: dict,
    llm_analysis: str,
    vuln_type: str = "Unknown"
) -> dict:
    """
    Generate a structured vulnerability report.
    
    Args:
        target: Target dict from analysis.
        anomaly: Anomaly dict from response analyzer.
        llm_analysis: LLM analysis result.
        vuln_type: Vulnerability type.
    
    Returns:
        Report dict.
    """
    report = {
        "title": f"Potential {vuln_type} Vulnerability",
        "timestamp": datetime.now().isoformat(),
        "target": {
            "endpoint": target.get("endpoint"),
            "params": target.get("params"),
            "base_url": "https://target.com"
        },
        "finding": {
            "vulnerability": vuln_type,
            "risk_level": target.get("risk", "unknown"),
            "confidence": target.get("confidence", 0.5),
            "payload": payload,
            "severity": anomaly.get("severity", "medium") if anomaly else "medium"
        },
        "evidence": {
            "description": anomaly.get("description", "") if anomaly else "",
            "llm_analysis": llm_analysis
        },
        "steps": [
            f"1. Navigate to {target.get('endpoint')}?{target.get('params', [''])[0]}={payload}",
            f"2. Observe {anomaly.get('type', 'anomaly')} response",
            "3. Document the vulnerability"
        ],
        "impact": "Depends on the specific vulnerability and context.",
        "remediation": f"Implement proper input validation and sanitization for {vuln_type}."
    }
    
    return report


def generate_report_markdown(report: dict) -> str:
    """
    Generate a markdown formatted report.
    
    Args:
        report: Report dict.
    
    Returns:
        Markdown string.
    """
    md = f"""# {report['title']}

**Date:** {report['timestamp']}  
**Severity:** {report['finding']['severity'].upper()}  
**Vulnerability:** {report['finding']['vulnerability']}

## Target

- **Endpoint:** `{report['target']['endpoint']}`
- **Parameters:** {', '.join(report['target']['params'])}

## Finding Details

| Field | Value |
|-------|-------|
| Risk Level | {report['finding']['risk_level']} |
| Confidence | {report['finding']['confidence']} |
| Payload | `{report['finding']['payload']}` |

## Evidence

{report['evidence']['description']}

### LLM Analysis

{report['evidence']['llm_analysis']}

## Reproduction Steps

"""
    for step in report['steps']:
        md += f"{step}\n"
    
    md += f"""
## Impact

{report['impact']}

## Remediation

{report['remediation']}
"""
    
    return md


def save_report(report: dict, filepath: str) -> None:
    """
    Save report to JSON file.
    
    Args:
        report: Report dict.
        filepath: Output file path.
    """
    with open(filepath, 'w') as f:
        json.dump(report, f, indent=2)


def save_report_markdown(report: dict, filepath: str) -> None:
    """
    Save report to markdown file.
    
    Args:
        report: Report dict.
        filepath: Output file path.
    """
    md = generate_report_markdown(report)
    with open(filepath, 'w') as f:
        f.write(md)


def generate_with_llm(target: dict, anomaly: dict) -> str:
    """
    Use LLM to generate improved report content.
    
    Args:
        target: Target dict.
        anomaly: Anomaly dict.
    
    Returns:
        LLM-generated report in markdown.
    """
    prompt = f"""Generate a security vulnerability report for:

Endpoint: {target.get('endpoint')}
Parameters: {target.get('params')}
Vulnerability: {target.get('vulnerability')}
Risk: {target.get('risk')}

Anomaly: {anomaly.get('description')}
Payload: {anomaly.get('payload')}

Generate in this format:
Title: [vulnerability type] in [endpoint]
Severity: [high/medium/low]
Steps: [3 reproduction steps]
Impact: [1 sentence]
Remediation: [1 sentence]

Keep it concise."""

    try:
        return call_ollama(prompt, model=_get_model())
    except Exception:
        return f"# {target.get('vulnerability')} in {target.get('endpoint')}\n\nSee analysis above."
