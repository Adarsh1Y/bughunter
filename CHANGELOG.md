# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-03-25

### Added

- **Attack-Ready Mode**: New `--attack-ready` flag for controlled attack preparation with safety checks
- **Traffic File Support**: `--input` flag to load traffic from JSON files
- **Traffic Parsing**: Full support for JSON and HAR traffic file formats
- **Traffic Filtering**: Automatic filtering to keep only API endpoints with authentication
- **Endpoint Normalization**: Convert `/api/orgs/123` → `/api/orgs/{id}` for consistent testing
- **Enhanced Scoring**: Improved endpoint prioritization with id/user/org/depth scoring
- **Request Pack Generation**: Generate and save structured request objects
- **Confirmation Prompts**: Mandatory user confirmation before proxy execution
- **Safe Execution**: Rate limiting with configurable delays and max requests
- **Response Capture**: Capture status, length, and snippets with auto-analysis
- **Modern README**: Professional documentation with badges and examples
- **Package Configuration**: `pyproject.toml` for easy installation
- **Development Dependencies**: pytest, black, ruff, mypy configured

### Features

- `python main.py --attack-ready --input traffic.json` - Prepare and execute attacks safely
- `python main.py --auto --input traffic.json` - Auto mode with traffic file
- `python main.py --focus --input traffic.json` - Focus mode (top 1-2 targets)

### Safety

- Confirmation required before any requests sent
- max_requests limit (default: 5)
- Delay between requests (default: 1 second)
- Proxy required (127.0.0.1:8080)

## [0.1.0] - 2024-03-24

### Added

- Initial release
- Interactive CLI with menu system
- Auto mode for automated analysis
- Focus mode for top targets only
- Retest mode for quick endpoint testing
- URL analysis with vulnerability detection
- Target prioritization and scoring
- Payload generation (IDOR, XSS, SQLI, AUTH, RCE)
- HTTP request builder
- Burp Suite proxy integration
- Response analyzer with anomaly detection
- Multi-user session testing
- IDOR vulnerability detection
- Cross-user privilege escalation testing
- LLM integration (Ollama)
- Low RAM mode optimization
- Report generation (JSON/Markdown)
- Configuration system
- Logging utilities

---

## Version History

- **v1.0.0** (2024-03-25) - Professional release with attack-ready mode
- **v0.1.0** (2024-03-24) - Initial beta release
