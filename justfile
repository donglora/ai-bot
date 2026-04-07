set shell := ["bash", "-c"]

default: run

[private]
_ensure_tools:
    @mise trust --yes . 2>/dev/null; mise install --quiet

# Run the AI bot
run *args: _ensure_tools
    @uv run ai_bot.py {{args}}

# Run all checks (fmt, lint)
check: fmt-check lint

# Format code
fmt: _ensure_tools
    @uv run ruff format .

# Check formatting without changing files
fmt-check: _ensure_tools
    @uv run ruff format --check .

# Lint
lint: _ensure_tools
    @uv run ruff check .
