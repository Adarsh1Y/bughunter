# BugHunter CLI

AI-assisted semi-automated bug hunting framework for security testing.

## Features

- **Analysis** - URL analysis with vulnerability detection
- **Strategy** - Target prioritization and scoring
- **Payload Generation** - Fuzzing payloads for IDOR, XSS, SQLI, etc.
- **Request Builder** - HTTP request generation
- **Burp Integration** - Proxy-based testing
- **Response Analyzer** - Anomaly detection with confidence scoring
- **Session Comparison** - Multi-user testing for IDOR detection
- **Decision Engine** - Smart filtering to reduce false positives
- **Report Generator** - Vulnerability reporting

## CLI Modes

### Interactive Mode
```bash
python main.py
```

### Auto Mode
```bash
python main.py --auto --urls https://example.com/api/users?id=1
```

### Focus Mode
```bash
python main.py --focus --urls https://example.com/api/orders?id=123
```

## Quick Start

1. Run analysis:
```bash
python main.py --auto --urls https://target.com/api/users?id=1
```

2. Review targets and payloads

3. Send requests via Burp Suite

4. Analyze responses

## Configuration

Edit `config/settings.json` to adjust:
- Mode (low_ram / normal)
- Max targets and payloads
- LLM model settings
- Safe execution limits

## Project Structure

```
bughunter/
├── agents/           # Analysis, strategy, fuzz, response
├── core/            # CLI, orchestrator, decision engine
├── config/          # Settings
└── main.py          # Entry point
```

## Requirements

- Python 3.10+
- Ollama (for LLM analysis)
- Burp Suite (for proxy testing)

## License

MIT
