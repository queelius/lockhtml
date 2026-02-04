# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Development

```bash
# Setup
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run all tests
pytest tests/ -v

# Run a single test file or test
pytest tests/test_parser.py -v
pytest tests/test_parser.py::TestEncryptHtml::test_basic_encryption -v

# Coverage
pytest tests/ -v --cov=lockhtml

# Lint
ruff check src/ tests/
ruff format --check src/ tests/
```

## Architecture

**Data flow:** CLI (`cli.py`) loads config (`config.py`), then calls parser (`parser.py`) which orchestrates crypto operations (`crypto.py`) and injects browser runtime via template generation (`template.py`).

```
cli.py  →  config.py (cascade: CLI args > env vars > .lockhtml.yaml > defaults)
   ↓
parser.py  →  crypto.py (PBKDF2-SHA256 + AES-256-GCM, WebCrypto-compatible)
   ↓
template.py  →  templates/lockhtml.{js,css} (browser-side Web Component)
```

- **parser.py** is the core module (~800 lines). It handles HTML manipulation with BeautifulSoup/lxml, wraps elements via CSS selectors, encrypts/decrypts content, and injects the self-contained JS/CSS runtime into output HTML.
- **crypto.py** implements encryption matching the browser Web Crypto API exactly (310,000 PBKDF2 iterations, AES-256-GCM). Output is base64-encoded JSON for browser consumption.
- **template.py** generates the `<lockhtml-encrypt>` Web Component JS and CSS that gets injected into encrypted HTML files, making them self-contained.
- **config.py** uses dataclasses (`LockhtmlConfig`, `DefaultsConfig`, `TemplateConfig`) with directory traversal to find `.lockhtml.yaml`.

## Key Design Constraints

- **Closure property**: Encrypt output must be valid encrypt input (composable encryption). Tests verify this via roundtrip and multi-pass scenarios.
- **Attribute preservation**: Original `hint`, `title`, `remember` attributes must survive encryption/decryption cycles.
- **Self-contained output**: Encrypted HTML must include all JS/CSS — no external dependencies at runtime.
- **WebCrypto parity**: Python crypto parameters must exactly match the browser-side JS in `templates/lockhtml.js`. Changing crypto params requires updating both sides.

## Testing Patterns

- CLI tests use Click's `CliRunner` with temp directory fixtures
- Parser/crypto tests use pytest parametrize for edge cases (unicode, empty content, large content, multiple elements)
- Integration tests (`test_integration.py`) verify full encrypt→decrypt roundtrips and multi-password workflows
