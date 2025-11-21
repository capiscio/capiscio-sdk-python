# Contributing to CapiscIO A2A Security

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Getting Started

### Prerequisites

- Python 3.10 or higher
- Git

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/capiscio/a2a-security.git
cd a2a-security

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in development mode with dev dependencies
pip install -e ".[dev]"

# Verify installation
pytest --version
black --version
ruff --version
```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix
```

### 2. Make Changes

- Write clear, concise code
- Add type hints to all functions
- Follow existing code style
- Add docstrings to public APIs

### 3. Run Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=capiscio_sdk --cov-report=html

# Run specific test file
pytest tests/unit/test_config.py
```

### 4. Format Code

```bash
# Format code
black .

# Lint code
ruff check .

# Type checking
mypy capiscio_sdk
```

### 5. Commit Changes

```bash
git add .
git commit -m "feat: add new validator"
# or
git commit -m "fix: resolve rate limiting issue"
```

**Commit message format:**
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `test:` - Test changes
- `refactor:` - Code refactoring
- `chore:` - Maintenance tasks

### 6. Push and Create PR

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub.

## Code Style

- Follow PEP 8
- Use type hints
- Maximum line length: 100 characters
- Use Black for formatting
- Use Ruff for linting

## Testing Guidelines

- Write tests for all new features
- Maintain >80% code coverage
- Use pytest fixtures for common setup
- Mock external dependencies (HTTP, file system)

### Test Structure

```python
def test_feature_name():
    """Test description."""
    # Arrange
    config = SecurityConfig.production()
    
    # Act
    result = some_function(config)
    
    # Assert
    assert result.success
```

## Documentation

- Add docstrings to all public classes and functions
- Update README.md if adding new features
- Add examples for new functionality
- Keep CHANGELOG.md updated

### Docstring Format

```python
def validate_message(message: Message) -> ValidationResult:
    """Validate an A2A message.
    
    Args:
        message: The message to validate
        
    Returns:
        ValidationResult with success status and issues
        
    Raises:
        CapiscIOValidationError: If validation fails critically
    """
```

## Pull Request Guidelines

### Before Submitting

- [ ] All tests pass
- [ ] Code is formatted (black)
- [ ] Code is linted (ruff)
- [ ] Type checking passes (mypy)
- [ ] Documentation is updated
- [ ] CHANGELOG.md is updated

### PR Description

Include:
1. What does this PR do?
2. Why is this change needed?
3. How has it been tested?
4. Any breaking changes?

## Issue Guidelines

### Reporting Bugs

Include:
- Python version
- Package version
- Minimal reproduction steps
- Expected vs actual behavior
- Error messages/stack traces

### Feature Requests

Include:
- Use case description
- Proposed API/interface
- Why this benefits users
- Alternatives considered

## Community

- Be respectful and inclusive
- Provide constructive feedback
- Help others learn

## Questions?

- Open a [GitHub Discussion](https://github.com/capiscio/a2a-security/discussions)
- Check existing [Issues](https://github.com/capiscio/a2a-security/issues)
- Visit [capisc.io](https://capisc.io)

Thank you for contributing! 🎉
