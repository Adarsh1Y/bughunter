# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2024-03-25

### Added

- **Live Mode**: `--live` flag for real-time proxy traffic monitoring
- **Live-Attack Mode**: `--live-attack` flag for continuous monitoring with attack execution
- **Live Listener Module**: `core/live_listener.py` for real-time endpoint detection
- **Live-Attack Module**: `core/live_attack.py` for unified live monitoring and attack
- **Endpoint Queue**: `core/queue.py` for thread-safe priority queue with deduplication
- **Architecture Diagram**: `docs/images/architecture.svg`
- **Workflow Diagram**: `docs/images/workflow.svg`
- **Scoring Matrix**: `docs/images/scoring.svg`

### Features

- Real-time endpoint detection from proxy traffic
- Continuous monitoring with automatic attack suggestions
- User confirmation before any attack execution
- Thread-safe queue with duplicate prevention
- Priority-based endpoint selection
- Max attacks limit per session (default: 5)

### CLI Modes

- `python main.py --live` - Watch proxy traffic in real-time
- `python main.py --live-attack` - Continuous monitoring with attack execution

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

- **v1.1.0** (2024-03-25) - Live monitoring and live-attack modes
- **v1.0.0** (2024-03-25) - Professional release with attack-ready mode
- **v0.1.0** (2024-03-24) - Initial beta release
