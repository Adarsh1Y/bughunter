# Contributing to BugHunter

Thank you for your interest in contributing to BugHunter!

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Pull Request Process](#pull-request-process)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)

## 📜 Code of Conduct

This project adheres to a code of conduct that all contributors are expected to follow. Please be respectful and constructive in all interactions.

## 🎯 Getting Started

1. Fork the repository
2. Clone your fork locally
3. Create a new branch for your changes

## 🔧 Development Setup

### Prerequisites

- Python 3.10+
- Git
- (Optional) Ollama for LLM features

### Installation

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/bughunter.git
cd bughunter

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

## 🛠️ Making Changes

1. Create a branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```

2. Make your changes following the coding standards:

   - Use **Black** for code formatting (line length: 100)
   - Use **Ruff** for linting
   - Add type hints where possible
   - Write docstrings for all public functions

3. Run tests:
   ```bash
   pytest
   pytest --cov=bughunter  # with coverage
   ```

4. Run linting:
   ```bash
   black .
   ruff check .
   mypy .
   ```

## 🔄 Pull Request Process

### Before Submitting

- [ ] Code follows the project's style guidelines
- [ ] Self-review your changes
- [ ] Add tests for new features
- [ ] Update documentation if needed
- [ ] Ensure all tests pass
- [ ] Keep commits atomic and well-described

### Submitting

1. Push your branch:
   ```bash
   git push origin feature/your-feature-name
   ```

2. Open a Pull Request against `main`

3. Fill out the PR template completely:
   ```markdown
   ## Description
   Brief description of changes

   ## Type of Change
   - [ ] Bug fix
   - [ ] New feature
   - [ ] Breaking change
   - [ ] Documentation update

   ## Testing
   Describe testing performed

   ## Checklist
   - [ ] My code follows the style guidelines
   - [ ] I have performed self-review
   - [ ] I have commented complex code
   - [ ] I have made corresponding changes
   ```

## 🐛 Reporting Bugs

When reporting bugs, please include:

1. **Description**: Clear description of the bug
2. **Steps to Reproduce**: Detailed steps
3. **Expected Behavior**: What should happen
4. **Actual Behavior**: What happens instead
5. **Environment**:
   - Python version
   - Operating system
   - Any relevant dependencies

Use the [issue template](./.github/ISSUE_TEMPLATE/bug_report.md) when available.

## 💡 Suggesting Features

We welcome feature suggestions! Please:

1. Check existing issues first
2. Describe the feature clearly
3. Explain the use case
4. Consider backward compatibility

## 📝 Coding Standards

### Python Style

```python
# Use type hints
def function_name(param: str, optional: int = 10) -> dict:
    """Short description.

    Longer description if needed.

    Args:
        param: Description of param.
        optional: Description of optional param.

    Returns:
        Description of return value.

    Raises:
        ValueError: When this exception is raised.
    """
    pass
```

### Naming Conventions

- **Functions/Variables**: `snake_case`
- **Classes**: `PascalCase`
- **Constants**: `UPPER_SNAKE_CASE`
- **Private**: Prefix with `_`

### File Organization

```
module/
├── __init__.py          # Public API
├── private_module.py    # Internal implementation
└── subpackage/
    ├── __init__.py
    └── module.py
```

## ❓ Questions?

Feel free to open an issue for questions. We appreciate all contributions!

## 🙏 Thank You!

Every contribution is valuable. Thank you for making BugHunter better!
